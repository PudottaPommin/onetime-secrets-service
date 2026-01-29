package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pudottapommin/golib/pkg/id"
)

type authContextKey uint

const (
	AuthContextKey authContextKey = 0
	authExpiration                = time.Hour * 12
	authCookieName                = "oss_auth"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAuthCookie  = errors.New("invalid auth cookie")

	authState = new(sync.Map)
)

func newAuthToken() (token string, expiresAt time.Time) {
	token = id.New().String()
	expiresAt = time.Now().Add(authExpiration)
	authState.Store(token, expiresAt)
	return
}

func AuthSetCookie(w http.ResponseWriter) {
	token, _ := newAuthToken()
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		MaxAge:   int(authExpiration.Seconds()),
		SameSite: http.SameSiteStrictMode,
	})

}

func AuthValidateToken(r *http.Request) error {
	ck, err := r.Cookie(authCookieName)
	if err != nil {
		return errors.New("auth cookie not found")
	}
	if err = ck.Valid(); err != nil {
		return fmt.Errorf("invalid auth cookie: %w", err)
	}

	expiresAt, ok := authState.Load(ck.Value)
	if !ok {
		return ErrInvalidAuthCookie
	}
	if expiresAt.(time.Time).Before(time.Now()) {
		return ErrInvalidAuthCookie
	}
	return nil
}

func AuthValidateHeader(r *http.Request, username, password string) error {
	value := r.Header.Get("Authorization")
	if username == "" && password == "" {
		return nil
	}

	if !strings.HasPrefix(value, "Basic ") {
		return errors.New("invalid authorization header")
	}

	payload, err := base64.StdEncoding.DecodeString(value[6:])
	if err != nil {
		return fmt.Errorf("failed to decode authorization header: %w", err)
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return errors.New("invalid authorization payload format")
	}

	if subtle.ConstantTimeCompare([]byte(pair[0]), []byte(username)) != 1 || subtle.ConstantTimeCompare([]byte(pair[1]), []byte(password)) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

func AuthTokenCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute * 1)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			time.Sleep(time.Minute * 1)
			authState.Range(func(k, v any) bool {
				expiresAt := v.(time.Time)
				if expiresAt.Before(time.Now()) {
					authState.Delete(k)
				}
				return true
			})
		}
	}
}
