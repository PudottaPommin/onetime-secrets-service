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
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pudottapommin/golib/http/middleware/csrf"
	"github.com/pudottapommin/golib/id"
	"github.com/pudottapommin/onetime-secrets-service/pkg/encryption"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/server"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
	"github.com/pudottapommin/onetime-secrets-service/pkg/ui"
	"github.com/valyala/bytebufferpool"
)

const (
	maxAttachmentsSize = 256 << 20       // 256 MiB
	maxBodySize        = (256 + 1) << 20 // 257 MiB (256 MiB attachments + 1 MiB form overhead)
	defaultMaxMemory   = 32 << 20        // 32 MiB
)

func (h *handlers) indexGET(w http.ResponseWriter, r *http.Request) {
	isAuthenticated, ok := r.Context().Value(server.AuthContextKey).(bool)
	if !ok {
		isAuthenticated = !h.cfg.Load().Auth.IsEnabled
	}

	csrfToken := csrf.FromContextStringed(r.Context())
	csrfField := csrf.FromContextFieldName(r.Context())
	model := ui.PageIndex{IsAuthenticated: isAuthenticated, FormModel: &ui.FormModel{CsrfField: csrfField, CsrfToken: csrfToken}}
	if err := ui.Index.ExecutePage(w, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handlers) indexPUT(w http.ResponseWriter, r *http.Request) {
	isAuthenticated, ok := r.Context().Value(server.AuthContextKey).(bool)
	if !ok {
		isAuthenticated = !h.cfg.Load().Auth.IsEnabled
	}
	if !isAuthenticated {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if r.MultipartForm == nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		if err := r.ParseMultipartForm(defaultMaxMemory); err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				if err = ui.Index.ExecuteHTMXSecretError(w, "Attachments exceed maximum allowed size (256 MiB)"); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
			if err = ui.Index.ExecuteHTMXSecretError(w, "Invalid form data"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
	}

	var totalAttachmentsSize int64
	if r.MultipartForm != nil {
		for _, file := range r.MultipartForm.File["attachments"] {
			totalAttachmentsSize += file.Size
		}
	}
	if totalAttachmentsSize > maxAttachmentsSize {
		if err := ui.Index.ExecuteHTMXSecretError(w, "Attachments exceed maximum allowed size (256 MiB)"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

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

	if r.MultipartForm != nil {
		for _, file := range r.MultipartForm.File["attachments"] {
			b, err := readFile(file)
			if err != nil {
				h.l.Error("failed to read file", slog.Any("err", err), slog.String("name", file.Filename))
				if err = ui.Index.ExecuteHTMXSecretError(w, "Failed to read attachment"); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
			secret.AddFile(file.Filename, b)
		}
	}

	insert, err := h.db.Store(r.Context(), secret)
	if err != nil {
		h.l.Error("failed to store secret", slog.Any("err", err))
		if err = ui.Index.ExecuteHTMXSecretError(w, "Failed to store secret"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
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

func parseSecretValue(value string) ([]byte, storage.ID, error) {
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 {
		return nil, "", errors.New("invalid secret value format")
	}
	encKey, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, "", err
	}
	return encKey, storage.ID(parts[1]), nil
}

func (h *handlers) secretGET(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	value := strings.TrimSpace(r.PathValue("value"))
	if value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	encKey, sid, err := parseSecretValue(value)
	if err != nil {
		h.l.Error("failed to decode encryption key", slog.Any("err", err), slog.String("path", r.URL.Path))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	csrfToken := csrf.FromContextStringed(r.Context())
	csrfField := csrf.FromContextFieldName(r.Context())
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

	encKey, sid, err := parseSecretValue(value)
	if err != nil {
		h.l.Error("failed to decode encryption key", slog.Any("err", err), slog.String("path", r.URL.Path))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err = ui.Secret.ExecuteHTMXDecryptError(w); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
	}

	var fileLinks []ui.SecretFileLink
	if len(secret.Files()) > 0 {
		token, err := h.db.IssueDownloadGrant(ctx, sid)
		if err != nil {
			h.l.Error("failed to issue download grant", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fileLinks = make([]ui.SecretFileLink, len(secret.Files()))
		for i, f := range secret.Files() {
			fileLinks[i] = ui.SecretFileLink{
				Name: f.Name,
				URL:  fmt.Sprintf("%s/files/%d?g=%s", r.URL.Path, i, token),
			}
		}
	}

	model := ui.CardSecretDecrypted{
		Url:       r.URL.Path,
		Secret:    secret.Value(),
		ExpiresAt: secret.ExpiresAt(),
		Files:     fileLinks,
	}
	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)
	if err = ui.Secret.ExecuteHTMXSecretDecrypted(bb, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err = w.Write(bb.Bytes()); err != nil {
		h.l.Error("failed to write decrypted response", "error", err)
		return
	}

	if err = h.db.Viewed(ctx, sid); err != nil {
		h.l.Error("failed to mark secret as viewed", "error", err)
		return
	}
}

func (h *handlers) secretFileGET(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	value := strings.TrimSpace(r.PathValue("value"))
	if value == "" {
		http.NotFound(w, r)
		return
	}

	encKey, sid, err := parseSecretValue(value)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	token := r.URL.Query().Get("g")
	if token == "" {
		http.NotFound(w, r)
		return
	}

	if err = h.db.ValidDownloadGrant(ctx, sid, token); err != nil {
		http.NotFound(w, r)
		return
	}

	idxStr := r.PathValue("index")
	idx, err := strconv.Atoi(idxStr)
	if err != nil || idx < 0 {
		http.NotFound(w, r)
		return
	}

	record, err := h.db.Load(ctx, sid, encKey)
	if err != nil {
		if errors.Is(err, storage.ErrRecordNotFound) {
			http.NotFound(w, r)
			return
		}
		h.l.Error("failed to load secret for download", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if record == nil {
		http.NotFound(w, r)
		return
	}

	files := record.Files()
	if idx >= len(files) {
		http.NotFound(w, r)
		return
	}

	file := files[idx]
	filename := path.Base(strings.ReplaceAll(file.Name, `\`, "/"))
	filename = strings.ReplaceAll(filename, `"`, "")
	filename = strings.ReplaceAll(filename, "\r", "")
	filename = strings.ReplaceAll(filename, "\n", "")
	if filename == "" || filename == "." || filename == "/" {
		filename = "attachment"
	}

	disposition := fmt.Sprintf(`attachment; filename="%s"`, filename)
	for i := 0; i < len(filename); i++ {
		if filename[i] >= 0x80 {
			disposition = fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, filename, url.PathEscape(filename))
			break
		}
	}

	w.Header().Set("No-Gzip-Compression", "true")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("Content-Length", strconv.Itoa(len(file.Content)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(file.Content)
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
	b := make([]byte, file.Size)
	if _, err = io.ReadFull(f, b); err != nil {
		return nil, err
	}
	return b, nil
}
