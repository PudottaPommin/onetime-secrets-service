package ui

import (
	"context"
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
	"github.com/valyala/bytebufferpool"

	"github.com/pudottapommin/onetime-secrets-service/pkg/encryption"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/server"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
	"github.com/pudottapommin/onetime-secrets-service/pkg/ui"
)

const (
	maxAttachmentsSize = 512 << 20       // 512 MiB
	maxBodySize        = (512 + 1) << 20 //nolint:mnd // 513 MiB (512 MiB attachments + 1 MiB form overhead)
	defaultMaxMemory   = 1 << 20         // 1 MiB
	defaultKeyLength   = 32
	secretPathParts    = 2
	nonASCIIByte       = 0x80
)

func (h *handlers) indexGET(w http.ResponseWriter, r *http.Request) {
	isAuthenticated, ok := r.Context().Value(server.AuthContextKey).(bool)
	if !ok {
		isAuthenticated = !h.cfg.Load().Auth.IsEnabled
	}

	csrfToken := csrf.FromContextStringed(r.Context())
	csrfField := csrf.FromContextFieldName(r.Context())
	model := ui.PageIndex{
		IsAuthenticated: isAuthenticated,
		FormModel:       &ui.FormModel{CsrfField: csrfField, CsrfToken: csrfToken},
	}
	if err := ui.Index.ExecutePage(w, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (h *handlers) ensureMultipartForm(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.MultipartForm != nil {
		return "", true
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseMultipartForm(defaultMaxMemory); err != nil { //nolint:gosec // bounded by http.MaxBytesReader
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			return "Attachments exceed maximum allowed size (512 MiB)", false
		}
		return "Invalid form data", false
	}
	return "", true
}

func (h *handlers) buildSecretFromForm(r *http.Request) (*secrets.Secret, string, bool) {
	value := r.FormValue("secret")
	if value == "" {
		return nil, "Secret is required", false
	}

	maxViews, err := strconv.ParseUint(r.FormValue("maxViews"), 10, 64)
	if err != nil {
		return nil, "Invalid max views value", false
	}

	expiration, err := strconv.ParseUint(r.FormValue("expiration"), 10, 64)
	if err != nil {
		return nil, "Invalid expiration value", false
	}

	sid := storage.ID(id.New().String())
	key := encryption.GenerateNewKey(defaultKeyLength)
	secret := secrets.NewSecret(sid, key)
	secret.SetValue(value)

	if passphrase := r.FormValue("passphrase"); passphrase != "" {
		secret.SetPassphrase(passphrase)
	}
	if maxViews > 1 {
		secret.SetMaxViews(maxViews)
	}
	if expiration > 0 {
		secret.SetExpiration(time.Second * time.Duration(expiration))
	}
	return secret, "", true
}

func (h *handlers) loadAttachments(ctx context.Context, form *multipart.Form, secret *secrets.Secret) (string, bool) {
	if form == nil {
		return "", true
	}
	for _, file := range form.File["attachments"] {
		b, err := readFile(file)
		if err != nil {
			h.l.ErrorContext(ctx, "failed to read file", slog.Any("err", err), slog.String("name", file.Filename))
			return "Failed to read attachment", false
		}
		secret.AddFile(file.Filename, b)
	}
	return "", true
}

func checkAttachmentsSize(form *multipart.Form) bool {
	if form == nil {
		return true
	}
	var totalAttachmentsSize int64
	for _, file := range form.File["attachments"] {
		totalAttachmentsSize += file.Size
	}
	return totalAttachmentsSize <= maxAttachmentsSize
}

func (h *handlers) indexPUT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	isAuthenticated, ok := ctx.Value(server.AuthContextKey).(bool)
	if !ok {
		isAuthenticated = !h.cfg.Load().Auth.IsEnabled
	}
	if !isAuthenticated {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if errMsg, valid := h.ensureMultipartForm(w, r); !valid {
		if execErr := ui.Index.ExecuteHTMXSecretError(w, errMsg); execErr != nil {
			http.Error(w, execErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.MultipartForm != nil {
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	if !checkAttachmentsSize(r.MultipartForm) {
		if err := ui.Index.ExecuteHTMXSecretError(w, "Attachments exceed maximum allowed size (512 MiB)"); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	secret, errMsg, valid := h.buildSecretFromForm(r)
	if !valid {
		if execErr := ui.Index.ExecuteHTMXSecretError(w, errMsg); execErr != nil {
			http.Error(w, execErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	if loadErrMsg, loadValid := h.loadAttachments(ctx, r.MultipartForm, secret); !loadValid {
		if execErr := ui.Index.ExecuteHTMXSecretError(w, loadErrMsg); execErr != nil {
			http.Error(w, execErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	insert, err := h.db.Store(ctx, secret)
	if err != nil {
		h.l.ErrorContext(ctx, "failed to store secret", slog.Any("err", err))
		if execErr := ui.Index.ExecuteHTMXSecretError(w, "Failed to store secret"); execErr != nil {
			http.Error(w, execErr.Error(), http.StatusInternalServerError)
		}
		return
	}

	model := ui.CardSecretCreated{
		URL:       fmt.Sprintf("%s/%x-%s", h.cfg.Load().Server.Domain, insert.Key, secret.ID()),
		ExpiresAt: insert.ExpiresAt,
	}
	if err = ui.Index.ExecuteHTMXSecretCreatedCard(w, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func parseSecretValue(value string) ([]byte, storage.ID, error) {
	parts := strings.SplitN(value, "-", secretPathParts)
	if len(parts) != secretPathParts {
		return nil, "", errors.New("invalid secret value format")
	}
	encKey, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode encryption key: %w", err)
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
		h.l.ErrorContext(ctx, "failed to decode encryption key", slog.Any("err", err), slog.String("path", r.URL.Path))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	csrfToken := csrf.FromContextStringed(r.Context())
	csrfField := csrf.FromContextFieldName(r.Context())
	secret, err := h.db.Get(ctx, sid, encKey)
	switch {
	case errors.Is(err, storage.ErrRecordNotFound) || (err == nil && secret == nil):
		model := ui.PageSecret{
			URL:        r.URL.Path,
			NotFound:   true,
			Secret:     "",
			Passphrase: nil,
			ViewsLeft:  0,
			FormModel:  &ui.FormModel{CsrfField: csrfField, CsrfToken: csrfToken},
		}
		if err = ui.Secret.ExecutePage(w, model); err != nil {
			h.l.ErrorContext(ctx, "failed to execute secret page template", slog.Any("error", err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	case err != nil:
		h.l.ErrorContext(ctx, "failed to get secret from database", slog.Any("error", err))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	viewsLeft, err := h.db.ViewsLeft(ctx, sid)
	if err != nil {
		h.l.ErrorContext(ctx, "failed to get views left", slog.Any("error", err))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if viewsLeft == 0 {
		http.Error(w, "no views left", http.StatusForbidden)
		return
	}

	model := ui.PageSecret{
		URL:        r.URL.Path,
		NotFound:   false,
		Secret:     "",
		Passphrase: secret.Passphrase(),
		ViewsLeft:  viewsLeft,
		FormModel:  &ui.FormModel{CsrfField: csrfField, CsrfToken: csrfToken},
	}
	if err = ui.Secret.ExecutePage(w, model); err != nil {
		h.l.ErrorContext(ctx, "failed to execute secret page template", slog.Any("error", err))
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
		h.l.ErrorContext(ctx, "failed to decode encryption key", slog.Any("err", err), slog.String("path", r.URL.Path))
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	secret, err := h.db.Get(ctx, sid, encKey)
	switch {
	case errors.Is(err, storage.ErrRecordNotFound) || (err == nil && secret == nil):
		w.WriteHeader(http.StatusNotFound)
		return
	case err != nil:
		h.l.ErrorContext(ctx, "failed to get secret from database", slog.Any("error", err))
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
		token, grantErr := h.db.IssueDownloadGrant(ctx, sid)
		if grantErr != nil {
			h.l.ErrorContext(ctx, "failed to issue download grant", slog.Any("error", grantErr))
			http.Error(w, grantErr.Error(), http.StatusInternalServerError)
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
		URL:       r.URL.Path,
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
		h.l.ErrorContext(ctx, "failed to write decrypted response", slog.Any("error", err))
		return
	}

	if err = h.db.Viewed(ctx, sid); err != nil {
		h.l.ErrorContext(ctx, "failed to mark secret as viewed", slog.Any("error", err))
		return
	}
}

var dispositionSanitizeReplacer = strings.NewReplacer( //nolint:gochecknoglobals // noop
	`\`,
	"/",
	`"`,
	"",
	"\r",
	"",
	"\n",
	"",
)

func sanitizeDisposition(file *storage.FileRecord) string {
	filename := path.Base(dispositionSanitizeReplacer.Replace(file.Name))
	if filename == "" || filename == "." || filename == "/" {
		filename = "attachment"
	}

	for i := range len(filename) {
		if filename[i] >= nonASCIIByte {
			return fmt.Sprintf(
				`attachment; filename="%s"; filename*=UTF-8''%s`,
				filename,
				url.PathEscape(filename),
			)
		}
	}
	return fmt.Sprintf(`attachment; filename="%s"`, filename)
}

func (h *handlers) streamAttachment(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	sid storage.ID,
	encKey storage.Key,
	idx int,
	file *storage.FileRecord,
	disposition string,
) {
	setDownloadHeaders := func() {
		w.Header().Set("No-Gzip-Compression", "true")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", disposition)
		w.Header().Set("Content-Length", strconv.FormatInt(file.Size, 10))
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}

	if file.Size <= 0 {
		setDownloadHeaders()
		return
	}

	hw := &headerCommitWriter{
		w:         w,
		commit:    setDownloadHeaders,
		committed: false,
	}
	if err := h.db.StreamFile(ctx, sid, encKey, idx, hw); err != nil {
		if !hw.committed {
			if errors.Is(err, storage.ErrRecordNotFound) {
				http.NotFound(w, r)
				return
			}
			h.l.ErrorContext(r.Context(), "failed to stream attachment", slog.Any("error", err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		h.l.ErrorContext(r.Context(), "failed to stream attachment after headers committed", slog.Any("error", err))
		return
	}
	if !hw.committed {
		setDownloadHeaders()
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
	if token == "" || h.db.ValidDownloadGrant(ctx, sid, token) != nil {
		http.NotFound(w, r)
		return
	}

	idx, err := strconv.Atoi(r.PathValue("index"))
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
		h.l.ErrorContext(ctx, "failed to load secret for download", slog.Any("error", err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if record == nil || idx >= len(record.Files()) {
		http.NotFound(w, r)
		return
	}

	file := record.Files()[idx]
	h.streamAttachment(ctx, w, r, sid, encKey, idx, file, sanitizeDisposition(file))
}

type headerCommitWriter struct {
	w         io.Writer
	commit    func()
	committed bool
}

func (h *headerCommitWriter) Write(p []byte) (int, error) {
	if !h.committed {
		h.committed = true
		if h.commit != nil {
			h.commit()
		}
	}
	n, err := h.w.Write(p)
	if err != nil {
		return n, fmt.Errorf("failed to write in headerCommitWritter: %w", err)
	}
	return n, nil
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
		return nil, fmt.Errorf("failed to open form file: %w", err)
	}
	defer f.Close()
	b := make([]byte, file.Size)
	if _, err = io.ReadFull(f, b); err != nil {
		return nil, fmt.Errorf("failed to read form file: %w", err)
	}
	return b, nil
}
