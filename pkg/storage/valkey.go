package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
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

func (s *valkeyStorage) Store(ctx context.Context, record Record[ID, Key]) (*InsertResult[ID, Key], error) {
	record.Seal()
	sr := storageRecord{
		ID:         record.ID(),
		Value:      record.Value(),
		Passphrase: record.Passphrase(),
		ExpiresAt:  record.ExpiresAt(),
		Files:      record.Files(),
	}

	buf, err := s.encoder.Encode(sr)
	if err != nil {
		return nil, fmt.Errorf("valkeya: error encoding record: %w", err)
	}
	if s.encryptor != nil {
		buf, err = s.encryptor.Encrypt(buf)
		if err != nil {
			return nil, fmt.Errorf("valkeya: error encrypting record: %w", err)
		}
	}

	expiresAt := time.Now().Add(record.Expiration()).UTC()
	rk, rck := s.generateStorageKeys(record.ID())
	c1 := s.client.B().Set().Key(rck).
		Value(fmt.Sprintf("%d", record.MaxViews())).
		Nx().
		Ex(record.Expiration()).
		Build()
	c2 := s.client.B().Set().Key(rk).Value(valkey.BinaryString(buf)).Nx().Ex(record.Expiration()).Build()

	for _, result := range s.client.DoMulti(ctx,
		c1,
		c2,
	) {
		if result.Error() != nil {
			return nil, fmt.Errorf("valkeya: error storing record: %w", result.Error())
		}
	}
	return newInsertResult(record.ID(), record.Key(), expiresAt), nil
}

func (s *valkeyStorage) Get(ctx context.Context, id ID, k Key) (Record[ID, Key], error) {
	rk, rck := s.generateStorageKeys(id)
	counter, err := s.client.Do(ctx, s.client.B().Get().Key(rck).Build()).AsUint64()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, ErrRecordNotFound
		}
		return nil, fmt.Errorf("valkeya: error getting counter: %w", err)
	}
	if counter == 0 {
		return nil, s.Burn(ctx, id)
	}

	buf, err := s.client.Do(ctx, s.client.B().Get().Key(rk).Build()).AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, ErrRecordNotFound
		}
		return nil, fmt.Errorf("valkeya: error getting message: %w", err)
	}

	if s.encryptor != nil {
		buf, err = s.encryptor.Decrypt(buf)
		if err != nil {
			return nil, fmt.Errorf("valkeya: error decrypting message: %w", err)
		}
	}

	var sr storageRecord
	if err = s.encoder.Decode(buf, &sr); err != nil {
		return nil, fmt.Errorf("valkeya: error decoding message: %w", err)
	}
	record := s.generator(sr.ID, k)
	record.Reinit(sr.Value, sr.Passphrase, sr.ExpiresAt, sr.Files)
	return record, nil
}

func (s *valkeyStorage) ViewsLeft(ctx context.Context, id ID) (uint64, error) {
	_, recordCounterKey := s.generateStorageKeys(id)
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
	_, recordCounterKey := s.generateStorageKeys(id)
	viewsLeft, err := s.ViewsLeft(ctx, id)
	if err != nil {
		return err
	}
	if viewsLeft == 0 {
		return s.Burn(ctx, id)
	}
	return s.client.Do(ctx, s.client.B().Decr().Key(recordCounterKey).Build()).Error()
}

func (s *valkeyStorage) Burn(ctx context.Context, id ID) error {
	recordKey, recordCounterKey := s.generateStorageKeys(id)
	for _, r := range s.client.DoMulti(ctx,
		s.client.B().Del().Key(recordCounterKey).Build(),
		s.client.B().Del().Key(recordKey).Build(),
	) {
		if r.Error() != nil {
			return r.Error()
		}
	}
	return nil
}

func (_ *valkeyStorage) generateStorageKeys(id ID) (recordKey string, recordCounterKey string) {
	return string(id), string(id + "_counter")
}
