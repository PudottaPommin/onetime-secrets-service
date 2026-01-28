package server

import (
	"context"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
)

var authTokens = make(map[string]time.Time)

func NewAuthToken() (token string, expiresAt time.Time) {
	token = strings.ReplaceAll(uuid.Must(uuid.NewV4()).String(), "-", "")
	expiresAt = time.Now().Add(time.Hour * 12)
	authTokens[token] = expiresAt
	return
}

func AuthTokenValid(token string) bool {
	if expiresAt, ok := authTokens[token]; ok {
		return expiresAt.After(time.Now())
	}
	return false
}

func AuthTokenCleanup(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(time.Minute * 1)
			for token, expiresAt := range authTokens {
				if expiresAt.Before(time.Now()) {
					delete(authTokens, token)
				}
			}
		}
	}
}
