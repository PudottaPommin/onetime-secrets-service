package storage

import (
	"context"
	"time"
)

type (
	ID  string
	Key []byte

	storageRecord struct {
		ID         ID
		Value      string
		Passphrase *string
		ExpiresAt  time.Time
		Files      []*FileRecord
	}

	Storage[I ~string, K ~[]byte] interface {
		Store(context.Context, Record[I, K]) (*InsertResult[I, K], error)
		Get(context.Context, ID, K) (Record[I, K], error)
		Burn(context.Context, ID) error

		ViewsLeft(context.Context, ID) (uint64, error)
		Viewed(ctx context.Context, id ID) error
	}

	Record[I ~string, K ~[]byte] interface {
		ID() I
		Key() K
		Expiration() time.Duration
		ExpiresAt() time.Time
		MaxViews() uint64
		Passphrase() *string
		Value() string
		SetValue(string)
		SetPassphrase(string)
		Files() []*FileRecord

		Reinit(value string, passphrase *string, expiresAt time.Time, files []*FileRecord)
		Seal()
	}

	FileRecord struct {
		Name    string `json:"name"`
		Content []byte `json:"content"`
	}

	InsertResult[I ~string, K ~[]byte] struct {
		ID        I
		Key       K
		ExpiresAt time.Time
	}
)

func newInsertResult[I ~string, K ~[]byte](id I, key K, expiresAt time.Time) *InsertResult[I, K] {
	return &InsertResult[I, K]{ID: id, Key: key, ExpiresAt: expiresAt}
}
