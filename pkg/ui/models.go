package ui

import (
	"time"
)

type (
	FormModel struct {
		CsrfField string
		CsrfToken string
	}
	PageIndex struct {
		*FormModel

		IsAuthenticated bool
	}
	PageSecret struct {
		*FormModel

		NotFound   bool
		URL        string
		Secret     string
		Passphrase *string
		ViewsLeft  uint64
	}
	CardSecretCreated struct {
		URL       string
		ExpiresAt time.Time
	}
	SecretFileLink struct {
		Name string
		URL  string
	}
	CardSecretDecrypted struct {
		URL       string
		Secret    string
		ExpiresAt time.Time
		Files     []SecretFileLink
	}
)
