package api

import (
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pudottapommin/golib/pkg/id"
	"github.com/pudottapommin/onetime-secrets-service/pkg/encryption"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
)

func (h *handlers) secretPUT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var dto SecretsRequestData
	defer r.Body.Close()
	decoder := jsontext.NewDecoder(r.Body)
	if err := json.UnmarshalDecode(decoder, &dto); err != nil {
		slog.Error("failed to decode request body", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sid := storage.ID(id.New().String())
	key := encryption.GenerateNewKey(32)
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
		slog.Error("failed to store secret", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := jsontext.NewEncoder(w)
	normalizedID := strings.ReplaceAll(string(sid), "-", "")
	if err = json.MarshalEncode(encoder, SecretResponseData{
		Url:       fmt.Sprintf("%s/%x-%s", h.cfg.Load().Server.Domain, insert.Key, normalizedID),
		ExpiresAt: insert.ExpiresAt,
	}); err != nil {
		slog.Error("failed to encode response", "error", err)
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

	parts := strings.Split(value, "-")
	encKey, err := hex.DecodeString(parts[0])
	if err != nil {
		slog.Error("failed to decode encryption key", "error", err)
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
		slog.Error("failed to get secret", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "%s", secret.Value())
}
