package secrets

import (
	"time"

	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
)

type (
	Secret struct {
		id         storage.ID
		key        storage.Key
		expiration time.Duration
		maxViews   uint64
		passphrase *string
		value      string
		expiresAt  time.Time
		files      []*storage.FileRecord
	}
)

var (
	_ storage.Record[storage.ID, storage.Key] = (*Secret)(nil)
)

func NewSecret(id storage.ID, key storage.Key) *Secret {
	return &Secret{id: id, key: key, maxViews: 1, expiration: time.Minute * 30, files: make([]*storage.FileRecord, 0)}
}

func (s *Secret) ID() storage.ID {
	return s.id
}

func (s *Secret) Key() storage.Key {
	return s.key
}

func (s *Secret) Expiration() time.Duration {
	return s.expiration
}

func (s *Secret) ExpiresAt() time.Time {
	return s.expiresAt
}

func (s *Secret) MaxViews() uint64 {
	return s.maxViews
}

func (s *Secret) Passphrase() *string {
	return s.passphrase
}

func (s *Secret) Value() string {
	return s.value
}

func (s *Secret) SetValue(value string) {
	s.value = value
}

func (s *Secret) SetExpiration(expiration time.Duration) {
	s.expiration = expiration
}

func (s *Secret) SetMaxViews(maxViews uint64) {
	s.maxViews = maxViews
}

func (s *Secret) SetPassphrase(passphrase string) {
	s.passphrase = &passphrase
}

func (s *Secret) AddFile(name string, content []byte) {
	s.files = append(s.files, &storage.FileRecord{Name: name, Content: content})
}

func (s *Secret) Files() []*storage.FileRecord {
	return s.files
}

func (s *Secret) Seal() {
	s.expiresAt = time.Now().Add(s.expiration).UTC()
}

func (s *Secret) Reinit(value string, passphrase *string, expiresAt time.Time, files []*storage.FileRecord) {
	s.value = value
	s.passphrase = passphrase
	s.expiresAt = expiresAt
	s.files = files
}
