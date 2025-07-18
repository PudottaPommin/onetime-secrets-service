package storage

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/pudottapommin/secret-notes/pkg/encryption"
	"github.com/valkey-io/valkey-go"
)

var _ Storage[ID, Key] = (*ValkeyStorage)(nil)

type ValkeyStorage struct {
	client    valkey.Client
	generator func(ID, Key) Record[ID, Key]
}

func NewValkeyStorage(client valkey.Client, generator func(ID, Key) Record[ID, Key]) *ValkeyStorage {
	return &ValkeyStorage{client: client, generator: generator}
}

func (s *ValkeyStorage) Store(ctx context.Context, record Record[ID, Key]) (*InsertResult[ID, Key], error) {
	var v string
	switch t := record.(type) {
	case encryption.Marshaler:
		bytes, err := t.MarshalEncrypt()
		if err != nil {
			return nil, fmt.Errorf("valkeya: error marshaling record: %w", err)
		}
		v = hex.EncodeToString(bytes)
	case json.Marshaler:
		bytes, err := t.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("valkeya: error marshaling record: %w", err)
		}
		v = string(bytes)
	}
	expiresAt := time.Now().Add(record.Expiration()).UTC()

	recordKey, recordCounterKey := s.generateStorageKeys(record.ID())
	for _, result := range s.client.DoMulti(ctx,
		s.client.B().Set().Key(recordCounterKey).
			Value(fmt.Sprintf("%d", record.MaxViews())).
			Nx().Ex(record.Expiration()).
			Build(),
		s.client.B().Set().Key(recordKey).Value(v).Nx().Ex(record.Expiration()).Build(),
	) {
		if result.Error() != nil {
			return nil, result.Error()
		}
	}
	return newInsertResult(record.ID(), record.Key(), expiresAt), nil
}

func (s *ValkeyStorage) Get(ctx context.Context, id ID, k Key) (Record[ID, Key], error) {
	recordKey, recordCounterKey := s.generateStorageKeys(id)
	counter, err := s.client.Do(ctx, s.client.B().Get().Key(recordCounterKey).Build()).AsUint64()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, ErrRecordNotFound
		}
		return nil, fmt.Errorf("valkeya: error getting counter: %w", err)
	}
	if counter == 0 {
		return nil, s.Burn(ctx, id)
	}
	defer func() {
		if err = s.client.Do(ctx, s.client.B().Decr().Key(recordCounterKey).Build()).Error(); err != nil {
			log.Println(err)
		}
	}()

	message, err := s.client.Do(ctx, s.client.B().Get().Key(recordKey).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, ErrRecordNotFound
		}
		return nil, fmt.Errorf("valkeya: error getting message: %w", err)
	}

	record := s.generator(id, k)
	switch t := record.(type) {
	case encryption.Unmarshaler:
		v, err := hex.DecodeString(message)
		if err != nil {
			return nil, fmt.Errorf("valkeya: error decoding message: %w", err)
		}
		if err = t.UnmarshalEncrypt(v); err != nil {
			return nil, fmt.Errorf("valkeya: error decrypting message: %w", err)
		}
	case json.Unmarshaler:
		if err != nil {
			return nil, fmt.Errorf("valkeya: error decoding message: %w", err)
		}
		if err = t.UnmarshalJSON([]byte(message)); err != nil {
			return nil, fmt.Errorf("valkeya: error decrypting message: %w", err)
		}
	}
	return record, nil
}

func (s *ValkeyStorage) Burn(ctx context.Context, id ID) error {
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

func (_ *ValkeyStorage) generateStorageKeys(id ID) (recordKey string, recordCounterKey string) {
	return string(id), string(id + "_counter")
}
