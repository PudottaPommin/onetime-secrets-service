package api

import (
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pudottapommin/golib/id"

	"github.com/pudottapommin/onetime-secrets-service/pkg/encryption"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
)

const (
	defaultKeyLength = 32
	secretPathParts  = 2
)

func (h *handlers) secretPUT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var dto SecretsRequestData
	defer r.Body.Close()
	decoder := jsontext.NewDecoder(r.Body)
	if err := json.UnmarshalDecode(decoder, &dto); err != nil {
		h.l.ErrorContext(ctx, "failed to decode request body", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sid := storage.ID(id.New().String())
	key := encryption.GenerateNewKey(defaultKeyLength)
	secret := secrets.NewSecret(sid, key)
	secret.SetValue(dto.Value)

	if dto.Expiration != nil && *dto.Expiration > 30 {
		secret.SetExpiration(time.Second * time.Duration(*dto.Expiration))
	}

	if dto.MaxViews != nil && *dto.MaxViews > 1 {
		secret.SetMaxViews(*dto.MaxViews)
	}

	if dto.Password != nil && *dto.Password != "" {
		secret.SetPassphrase(*dto.Password)
	}

	insert, err := h.db.Store(ctx, secret)
	if err != nil {
		h.l.ErrorContext(ctx, "failed to store secret", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := jsontext.NewEncoder(w)
	normalizedID := strings.ReplaceAll(string(sid), "-", "")
	if err = json.MarshalEncode(encoder, SecretResponseData{
		URL:       fmt.Sprintf("%s/%x-%s", h.cfg.Load().Server.Domain, insert.Key, normalizedID),
		ExpiresAt: insert.ExpiresAt,
	}); err != nil {
		h.l.ErrorContext(ctx, "failed to encode response", slog.Any("error", err))
		w.Header().Del("Content-Type")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handlers) secretGET(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	value := strings.TrimSpace(r.PathValue("value"))
	if value == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	parts := strings.SplitN(value, "-", secretPathParts)
	if len(parts) != secretPathParts {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	encKey, err := hex.DecodeString(parts[0])
	if err != nil {
		h.l.ErrorContext(ctx, "failed to decode encryption key", slog.Any("err", err), slog.String("path", r.URL.Path))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sid := storage.ID(parts[1])
	secret, err := h.db.Get(ctx, sid, encKey)
	switch {
	case errors.Is(err, storage.ErrRecordNotFound) || (err == nil && secret == nil):
		w.WriteHeader(http.StatusNotFound)
		return
	case err != nil:
		h.l.ErrorContext(ctx, "failed to get secret", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if _, err = io.WriteString(w, secret.Value()); err != nil { //nolint:gosec // plain text response with nosniff
		h.l.ErrorContext(ctx, "failed to write secret response", slog.Any("error", err))
		return
	}

	if err = h.db.Viewed(ctx, sid); err != nil {
		h.l.ErrorContext(ctx, "failed to mark secret as viewed", slog.Any("error", err))
	}
}
