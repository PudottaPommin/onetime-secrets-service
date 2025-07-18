package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/pudottapommin/secret-notes/pkg/encryption"
	"github.com/pudottapommin/secret-notes/pkg/secrets"
	"github.com/pudottapommin/secret-notes/pkg/storage"
)

func (h *handlers) secretsPOST(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var dto SecretsRequestData
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	if err := decoder.Decode(&dto); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	id := storage.ID(uuid.Must(uuid.NewV4()).String())
	key := make([]byte, 32)
	if err := encryption.GenerateNewKey(key); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
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
		secret.SetPassword(*dto.Password)
	}

	insert, err := h.db.Store(ctx, secret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	normalizedID := strings.ReplaceAll(string(id), "-", "")
	if err = encoder.Encode(SecretResponseData{
		Url:       fmt.Sprintf("%s/%x-%s", h.cfg.Domaine, insert.Key, normalizedID),
		ExpiresAt: insert.ExpiresAt,
	}); err != nil {
		log.Println(err)
		w.Header().Del("Content-Type")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

func (h *handlers) secretsGET(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slug := strings.TrimSpace(r.PathValue("slug"))
	if slug == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	parts := strings.Split(slug, "-")
	encKey, err := hex.DecodeString(parts[0])
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	gid, err := uuid.FromString(parts[1])
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id := storage.ID(gid.String())

	secret, err := h.db.Get(ctx, id, encKey)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if secret == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = fmt.Fprintf(w, "%s", secret.Value())
}
