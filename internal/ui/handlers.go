package ui

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/pudottapommin/golib/http/middleware/csrf"
	"github.com/pudottapommin/golib/pkg/id"
	"github.com/pudottapommin/onetime-secrets-service/pkg/encryption"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/server"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
	"github.com/pudottapommin/onetime-secrets-service/pkg/ui"
	"github.com/valyala/bytebufferpool"
)

func (h *handlers) indexGET(w http.ResponseWriter, r *http.Request) {
	isAuthenticated := r.Context().Value(server.AuthContextKey).(bool)

	csrfToken := csrf.FromContextStringed(r.Context())
	csrfField := csrf.FromContextFieldName(r.Context())
	model := ui.PageIndex{IsAuthenticated: isAuthenticated, FormModel: &ui.FormModel{CsrfField: csrfField, CsrfToken: csrfToken}}
	if err := ui.Index.ExecutePage(w, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handlers) indexPUT(w http.ResponseWriter, r *http.Request) {
	sid := storage.ID(id.New().String())
	key := encryption.GenerateNewKey(32)
	secret := secrets.NewSecret(sid, key)

	value := r.FormValue("secret")
	if value == "" {
		if err := ui.Index.ExecuteHTMXSecretError(w, "Secret is required"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
	secret.SetValue(value)

	passphrase := r.FormValue("passphrase")
	if passphrase != "" {
		secret.SetPassphrase(passphrase)
	}

	maxViews, err := strconv.ParseUint(r.FormValue("maxViews"), 10, 64)
	switch {
	case err != nil:
		if err = ui.Index.ExecuteHTMXSecretError(w, "Invalid max views value"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	case maxViews > 1:
		secret.SetMaxViews(maxViews)
	}

	expiration, err := strconv.ParseUint(r.FormValue("expiration"), 10, 64)
	switch {
	case err != nil:
		if err = ui.Index.ExecuteHTMXSecretError(w, "Invalid expiration value"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	case expiration > 0:
		secret.SetExpiration(time.Second * time.Duration(expiration))
	}

	for k, mpf := range r.MultipartForm.File {
		if k != "attachments" {
			continue
		}
		for _, file := range mpf {
			b, err := readFile(file)
			if err != nil {
				h.l.Error("failed to read file", slog.Any("err", err), slog.String("name", file.Filename))
				continue
			}
			secret.AddFile(file.Filename, b)
		}
	}

	insert, err := h.db.Store(r.Context(), secret)
	if err = ui.Index.ExecuteHTMXSecretError(w, "Failed to store secret"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	model := ui.CardSecretCreated{
		Url:       fmt.Sprintf("%s/%x-%s", h.cfg.Load().Server.Domain, insert.Key, sid),
		ExpiresAt: insert.ExpiresAt,
	}
	if err = ui.Index.ExecuteHTMXSecretCreatedCard(w, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handlers) secretGET(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	value := strings.TrimSpace(r.PathValue("value"))
	if value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	parts := strings.Split(value, "-")
	encKey, err := hex.DecodeString(parts[0])
	if err != nil {
		h.l.Error("failed to decode encryption key", slog.Any("err", err), slog.String("path", r.URL.Path))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	csrfToken := csrf.FromContextStringed(r.Context())
	csrfField := csrf.FromContextFieldName(r.Context())
	sid := storage.ID(parts[1])
	secret, err := h.db.Get(ctx, sid, encKey)
	switch {
	case errors.Is(err, storage.ErrRecordNotFound) || (err == nil && secret == nil):
		model := ui.PageSecret{
			Url:       r.URL.Path,
			NotFound:  true,
			FormModel: &ui.FormModel{CsrfField: csrfField, CsrfToken: csrfToken},
		}
		if err = ui.Secret.ExecutePage(w, model); err != nil {
			h.l.Error("failed to execute secret page template", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	case err != nil:
		h.l.Error("failed to get secret from database", "error", err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	viewsLeft, err := h.db.ViewsLeft(ctx, sid)
	if err != nil {
		h.l.Error("failed to get views left", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if viewsLeft == 0 {
		http.Error(w, "no views left", http.StatusForbidden)
		return
	}

	model := ui.PageSecret{
		Url:        r.URL.Path,
		Secret:     secret.Value(),
		Passphrase: secret.Passphrase(),
		ViewsLeft:  viewsLeft,
		FormModel:  &ui.FormModel{CsrfField: csrfField, CsrfToken: csrfToken},
	}
	if err = ui.Secret.ExecutePage(w, model); err != nil {
		h.l.Error("failed to execute secret page template", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handlers) secretPOST(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	value := strings.TrimSpace(r.PathValue("value"))
	if value == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	parts := strings.Split(value, "-")
	encKey, err := hex.DecodeString(parts[0])
	if err != nil {
		h.l.Error("failed to decode encryption key", slog.Any("err", err), slog.String("path", r.URL.Path))
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
		h.l.Error("failed to get secret from database", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if secret.Passphrase() != nil && *secret.Passphrase() != "" {
		passphrase := r.FormValue("passphrase")
		if subtle.ConstantTimeCompare([]byte(passphrase), []byte(*secret.Passphrase())) != 1 {
			if err = ui.Secret.ExecuteHTMXDecryptError(w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
	}

	if err = h.db.Viewed(ctx, sid); err != nil {
		h.l.Error("failed to mark secret as viewed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	model := ui.CardSecretDecrypted{
		Url:       r.URL.Path,
		Secret:    secret.Value(),
		ExpiresAt: secret.ExpiresAt(),
		Files:     secret.Files(),
	}
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)
	if err = ui.Secret.ExecuteHTMXSecretDecrypted(bb, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sse := server.NewSSEWriter(w, r)
	if err = sse.WriteHTML(bb.String()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(model.Files) > 0 {
		bb.Reset()
		if err = ui.Secret.ExecuteHTMXSecretDecryptedFiles(bb, model); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err = sse.WriteHTML(bb.String()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func (h *handlers) authenticatePOST(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	cfg := h.cfg.Load()
	if username == "" || password == "" {
		if err := ui.Index.ExecuteHTMXAuthError(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	} else if subtle.ConstantTimeCompare([]byte(username), []byte(cfg.Auth.Username)) != 1 || subtle.ConstantTimeCompare([]byte(password), []byte(cfg.Auth.Password)) != 1 {
		if err := ui.Index.ExecuteHTMXAuthError(w); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	server.AuthSetCookie(w)

	csrfToken := csrf.FromContextStringed(r.Context())
	csrfField := csrf.FromContextFieldName(r.Context())
	if err := ui.Index.ExecuteHTMXSecretForm(w, ui.FormModel{CsrfToken: csrfToken, CsrfField: csrfField}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func readFile(file *multipart.FileHeader) ([]byte, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return b, nil
}
