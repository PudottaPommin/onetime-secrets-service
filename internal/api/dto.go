package api

import (
	"time"
)

type (
	SecretsRequestData struct {
		Value      string  `json:"value"`
		Password   *string `json:"password,omitempty"`
		Expiration *int    `json:"expiration,omitempty"`
		MaxViews   *uint64 `json:"max_views,omitempty"`
	}
	SecretResponseData struct {
		Url       string    `json:"url"`
		ExpiresAt time.Time `json:"expires_at"`
	}
)
