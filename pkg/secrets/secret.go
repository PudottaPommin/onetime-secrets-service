package secrets

import (
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/pudottapommin/onetime-secrets-service/pkg/encryption"
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

	secretJson struct {
		Value     string                `json:"value"`
		Password  *string               `json:"passphrase,omitempty"`
		ExpiresAt time.Time             `json:"expires_at"`
		Files     []*storage.FileRecord `json:"files,omitempty"`
	}
)

var (
	_ storage.Record[storage.ID, storage.Key] = (*Secret)(nil)
	_ encryption.Marshaler                    = (*Secret)(nil)
	_ encryption.Unmarshaler                  = (*Secret)(nil)
)

func NewSecret(id storage.ID, key storage.Key) *Secret {
	return &Secret{id: id, key: key, maxViews: 1, expiration: time.Minute * 30}
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

func (s *Secret) seal() {
	s.expiresAt = time.Now().Add(s.expiration).UTC()
}

func (s Secret) MarshalEncrypt() ([]byte, error) {
	bytes, err := s.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("secret: error marshaling secret: %w", err)
	}
	enc, err := encryption.Encrypt(bytes, s.key)
	if err != nil {
		return nil, fmt.Errorf("secret: error encrypting secret: %w", err)
	}
	return enc, nil
}

func (s *Secret) UnmarshalEncrypt(end []byte) error {
	dec, err := encryption.Decrypt(end, s.key)
	if err != nil {
		return fmt.Errorf("secret: error decrypting secret: %w", err)
	}
	return s.UnmarshalJSON([]byte(dec))
}

func (s Secret) MarshalJSON() ([]byte, error) {
	s.seal()
	d := secretJson{
		Value:     s.value,
		Password:  s.passphrase,
		ExpiresAt: s.expiresAt,
		Files:     s.files,
	}
	return json.Marshal(d)
}

func (s *Secret) UnmarshalJSON(data []byte) error {
	var d secretJson
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	s.value = d.Value
	s.passphrase = d.Password
	s.expiresAt = d.ExpiresAt
	s.files = d.Files
	return nil
}
