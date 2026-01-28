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
		Url        string
		Secret     string
		Passphrase *string
		ViewsLeft  uint64
	}
	CardSecretCreated struct {
		Url       string
		ExpiresAt time.Time
	}
	CardSecretDecrypted struct {
		Url       string
		Secret    string
		ExpiresAt time.Time
	}
)
