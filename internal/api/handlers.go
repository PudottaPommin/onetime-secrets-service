package api

import (
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
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
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id := storage.ID(uuid.Must(uuid.NewV4()).String())
	key := make([]byte, 32)
	if err := encryption.GenerateNewKey(key); err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	secret := secrets.NewSecret(id, key)
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
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := jsontext.NewEncoder(w)
	normalizedID := strings.ReplaceAll(string(id), "-", "")
	if err = json.MarshalEncode(encoder, SecretResponseData{
		Url:       fmt.Sprintf("%s/%x-%s", h.cfg.Domaine, insert.Key, normalizedID),
		ExpiresAt: insert.ExpiresAt,
	}); err != nil {
		log.Println(err)
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
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	gid, err := uuid.FromString(parts[1])
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id := storage.ID(gid.String())

	secret, err := h.db.Get(ctx, id, encKey)
	switch {
	case errors.Is(err, storage.ErrRecordNotFound) || (err == nil && secret == nil):
		w.WriteHeader(http.StatusNotFound)
		return
	case err != nil:
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "%s", secret.Value())
}
