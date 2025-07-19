package ui

import (
	"time"
)

type (
	PageIndex struct {
		IsAuthenticated bool
	}
	PageSecret struct {
		NotFound  bool
		Url       string
		Secret    string
		Password  *string
		ViewsLeft uint64
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
