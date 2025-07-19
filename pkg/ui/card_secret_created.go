package ui

import (
	"time"
)

type CardSecretCreated struct {
	Url       string
	ExpiresAt time.Time
}

type CardSecretDecrypted struct {
	Url       string
	Secret    string
	ExpiresAt time.Time
}
