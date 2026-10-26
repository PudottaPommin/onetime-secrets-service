package storage

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valyala/bytebufferpool"
)

type valkeyStorage struct {
	client    valkey.Client
	generator func(ID, Key) Record[ID, Key]
	encoder   Encoder
	encryptor Encryptor
}

func NewValkey(client valkey.Client, encryptor Encryptor, generator func(ID, Key) Record[ID, Key]) Storage[ID, Key] {
	return &valkeyStorage{
		encoder:   &GobEncoder{},
		encryptor: encryptor,
		client:    client,
		generator: generator,
	}
}

func (s *valkeyStorage) resolveEncryptor(k Key) (Encryptor, error) {
	if s.encryptor != nil {
		return s.encryptor, nil
	}
	encryptor, err := NewDefaultEncryptor(k)
	if err != nil {
		return nil, fmt.Errorf("valkeya: error creating default encryptor: %w", err)
	}
	return encryptor, nil
}

func (s *valkeyStorage) Store(ctx context.Context, record Record[ID, Key]) (*InsertResult[ID, Key], error) {
	record.Seal()

	encryptor, err := s.resolveEncryptor(record.Key())
	if err != nil {
		return nil, err
	}

	rk, rck, _, rfk := s.generateStorageKeys(record.ID())
	ttlSeconds := int64(record.Expiration().Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = 1
	}

	files := record.Files()
	fileMetas := make([]storageFileMeta, len(files))
	wroteFiles := false

	for i, f := range files {
		size := int64(len(f.Content))
		if size == 0 && f.Size > 0 {
			size = f.Size
		}
		fileMetas[i] = storageFileMeta{
			Name: f.Name,
			Size: size,
		}
		if len(f.Content) == 0 {
			continue
		}

		ciphertext, encErr := encryptor.EncryptBytes(f.Content)
		if encErr != nil {
			if wroteFiles {
				_ = s.client.Do(ctx, s.client.B().Del().Key(rfk).Build()).Error()
			}
			return nil, fmt.Errorf("valkeya: error encrypting file %d: %w", i, encErr)
		}
		f.Content = nil

		cHset := s.client.B().
			Hset().
			Key(rfk).
			FieldValue().
			FieldValue(strconv.Itoa(i), valkey.BinaryString(ciphertext)).
			Build()
		cExpire := s.client.B().Expire().Key(rfk).Seconds(ttlSeconds).Build()
		for _, res := range s.client.DoMulti(ctx, cHset, cExpire) {
			if res.Error() != nil {
				_ = s.client.Do(ctx, s.client.B().Del().Key(rfk).Build()).Error()
				return nil, fmt.Errorf("valkeya: error storing file %d: %w", i, res.Error())
			}
		}
		wroteFiles = true
	}

	sr := storageRecord{
		ID:         record.ID(),
		Value:      record.Value(),
		Passphrase: record.Passphrase(),
		ExpiresAt:  record.ExpiresAt(),
		Files:      fileMetas,
	}

	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	ew, err := encryptor.EncryptStream(buf)
	if err != nil {
		if wroteFiles {
			_ = s.client.Do(ctx, s.client.B().Del().Key(rfk).Build()).Error()
		}
		return nil, fmt.Errorf("valkeya: error creating encrypt stream: %w", err)
	}

	if err = s.encoder.EncodeStream(ew, sr); err != nil {
		if wroteFiles {
			_ = s.client.Do(ctx, s.client.B().Del().Key(rfk).Build()).Error()
		}
		return nil, fmt.Errorf("valkeya: error encoding record: %w", err)
	}

	expiresAt := time.Now().Add(record.Expiration()).UTC()
	c1 := s.client.B().Set().Key(rck).Value(fmt.Sprintf("%d", record.MaxViews())).Nx().Ex(record.Expiration()).Build()
	c2 := s.client.B().Set().Key(rk).Value(valkey.BinaryString(buf.Bytes())).Nx().Ex(record.Expiration()).Build()

	for _, result := range s.client.DoMulti(ctx, c1, c2) {
		if result.Error() != nil {
			_ = s.client.Do(ctx, s.client.B().Del().Key(rfk, rck, rk).Build()).Error()
			return nil, fmt.Errorf("valkeya: error storing record: %w", result.Error())
		}
	}
	return newInsertResult(record.ID(), record.Key(), expiresAt), nil
}

func (s *valkeyStorage) Get(ctx context.Context, id ID, k Key) (Record[ID, Key], error) {
	rk, rck, rdk, _ := s.generateStorageKeys(id)
	counter, err := s.client.Do(ctx, s.client.B().Get().Key(rck).Build()).AsInt64()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, ErrRecordNotFound
		}
		return nil, fmt.Errorf("valkeya: error getting counter: %w", err)
	}
	if counter <= 0 {
		hasGrant, _ := s.client.Do(ctx, s.client.B().Exists().Key(rdk).Build()).AsInt64()
		if hasGrant == 0 {
			_ = s.Burn(ctx, id)
		} else {
			_ = s.client.Do(ctx, s.client.B().Del().Key(rck).Build()).Error()
		}
		return nil, ErrRecordNotFound
	}

	return s.loadRecord(ctx, rk, k)
}

func (s *valkeyStorage) Load(ctx context.Context, id ID, k Key) (Record[ID, Key], error) {
	rk, _, _, _ := s.generateStorageKeys(id)
	exists, err := s.client.Do(ctx, s.client.B().Exists().Key(rk).Build()).AsInt64()
	if err != nil {
		return nil, fmt.Errorf("valkeya: error checking existence: %w", err)
	}
	if exists == 0 {
		return nil, ErrRecordNotFound
	}
	return s.loadRecord(ctx, rk, k)
}

func (s *valkeyStorage) StreamFile(ctx context.Context, id ID, k Key, index int, w io.Writer) error {
	_, _, _, rfk := s.generateStorageKeys(id)
	field := strconv.Itoa(index)

	exists, err := s.client.Do(ctx, s.client.B().Hexists().Key(rfk).Field(field).Build()).AsBool()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return ErrRecordNotFound
		}
		return fmt.Errorf("valkeya: error checking file existence: %w", err)
	}
	if !exists {
		return ErrRecordNotFound
	}

	encryptor, err := s.resolveEncryptor(k)
	if err != nil {
		return err
	}

	dw := encryptor.NewDecryptWriter(w)
	c := s.client.DoStream(ctx, s.client.B().Hget().Key(rfk).Field(field).Build())
	if _, err = c.WriteTo(dw); err != nil {
		if valkey.IsValkeyNil(err) {
			return ErrRecordNotFound
		}
		return fmt.Errorf("valkeya: error streaming file: %w", err)
	}
	if err = dw.Close(); err != nil {
		return fmt.Errorf("valkeya: error finalizing file stream: %w", err)
	}
	return nil
}

func (s *valkeyStorage) loadRecord(ctx context.Context, rk string, k Key) (Record[ID, Key], error) {
	pr, pw := io.Pipe()
	defer func() {
		_ = pr.Close()
	}()
	go func() {
		defer pw.Close()
		c := s.client.DoStream(ctx, s.client.B().Get().Key(rk).Build())
		if _, err := c.WriteTo(pw); err != nil {
			_ = pw.CloseWithError(fmt.Errorf("valkeya: error reading message: %w", err))
		}
	}()

	encryptor, err := s.resolveEncryptor(k)
	if err != nil {
		return nil, err
	}

	dr, err := encryptor.DecryptStream(pr)
	if err != nil {
		return nil, fmt.Errorf("valkeya: error decrypting message: %w", err)
	}

	var sr storageRecord
	if err = s.encoder.DecodeStream(dr, &sr); err != nil {
		return nil, fmt.Errorf("valkeya: error decoding message: %w", err)
	}
	files := make([]*FileRecord, len(sr.Files))
	for i, fm := range sr.Files {
		files[i] = &FileRecord{
			Name:    fm.Name,
			Size:    fm.Size,
			Content: nil,
		}
	}
	record := s.generator(sr.ID, k)
	record.Reinit(sr.Value, sr.Passphrase, sr.ExpiresAt, files)
	return record, nil
}

func (s *valkeyStorage) ViewsLeft(ctx context.Context, id ID) (uint64, error) {
	_, recordCounterKey, _, _ := s.generateStorageKeys(id)
	views, err := s.client.Do(ctx, s.client.B().Get().Key(recordCounterKey).Build()).AsUint64()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return 0, ErrRecordNotFound
		}
		return 0, fmt.Errorf("valkeya: error getting views left: %w", err)
	}
	return views, nil
}

func (s *valkeyStorage) Viewed(ctx context.Context, id ID) error {
	_, recordCounterKey, recordDownloadKey, _ := s.generateStorageKeys(id)
	remaining, err := s.client.Do(ctx, s.client.B().Decr().Key(recordCounterKey).Build()).AsInt64()
	if err != nil {
		return fmt.Errorf("valkeya: error decrementing views left: %w", err)
	}
	if remaining <= 0 {
		hasGrant, err := s.client.Do(ctx, s.client.B().Exists().Key(recordDownloadKey).Build()).AsInt64()
		if err == nil && hasGrant > 0 {
			return s.client.Do(ctx, s.client.B().Del().Key(recordCounterKey).Build()).Error()
		}
		return s.Burn(ctx, id)
	}
	return nil
}

func (s *valkeyStorage) Burn(ctx context.Context, id ID) error {
	recordKey, recordCounterKey, recordDownloadKey, recordFilesKey := s.generateStorageKeys(id)
	for _, r := range s.client.DoMulti(ctx,
		s.client.B().Del().Key(recordCounterKey).Build(),
		s.client.B().Del().Key(recordKey).Build(),
		s.client.B().Del().Key(recordDownloadKey).Build(),
		s.client.B().Del().Key(recordFilesKey).Build(),
	) {
		if r.Error() != nil {
			return r.Error()
		}
	}
	return nil
}

func (s *valkeyStorage) IssueDownloadGrant(ctx context.Context, id ID) (string, error) {
	recordKey, _, recordDownloadKey, _ := s.generateStorageKeys(id)
	ttl, err := s.client.Do(ctx, s.client.B().Ttl().Key(recordKey).Build()).AsInt64()
	if err != nil {
		return "", fmt.Errorf("valkeya: error getting ttl: %w", err)
	}
	if ttl <= 0 {
		return "", ErrRecordNotFound
	}

	token := hex.EncodeToString(GenerateRandomKey(32))
	res := s.client.Do(
		ctx,
		s.client.B().Set().Key(recordDownloadKey).Value(token).Nx().Ex(time.Duration(ttl)*time.Second).Build(),
	)
	if err := res.Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			existingToken, getErr := s.client.Do(ctx, s.client.B().Get().Key(recordDownloadKey).Build()).ToString()
			if getErr != nil {
				return "", fmt.Errorf("valkeya: error getting existing grant: %w", getErr)
			}
			return existingToken, nil
		}
		return "", fmt.Errorf("valkeya: error setting grant: %w", err)
	}
	return token, nil
}

func (s *valkeyStorage) ValidDownloadGrant(ctx context.Context, id ID, token string) error {
	if token == "" {
		return ErrRecordNotFound
	}
	_, _, recordDownloadKey, _ := s.generateStorageKeys(id)
	storedToken, err := s.client.Do(ctx, s.client.B().Get().Key(recordDownloadKey).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return ErrRecordNotFound
		}
		return fmt.Errorf("valkeya: error getting grant: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(storedToken)) != 1 {
		return ErrRecordNotFound
	}
	return nil
}

func (*valkeyStorage) generateStorageKeys(
	id ID,
) (recordKey, recordCounterKey, recordDownloadKey, recordFilesKey string) { //nolint:nonamedreturns // I want this
	return string(id), string(id + "_counter"), string(id + "_download"), string(id + "_files")
}
