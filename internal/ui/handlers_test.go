package ui

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexedwards/flow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
)

type mockStorage struct {
	storeFunc              func(ctx context.Context, record storage.Record[storage.ID, storage.Key]) (*storage.InsertResult[storage.ID, storage.Key], error)
	getFunc                func(ctx context.Context, id storage.ID, key storage.Key) (storage.Record[storage.ID, storage.Key], error)
	loadFunc               func(ctx context.Context, id storage.ID, key storage.Key) (storage.Record[storage.ID, storage.Key], error)
	streamFileFunc         func(ctx context.Context, id storage.ID, key storage.Key, index int, w io.Writer) error
	burnFunc               func(ctx context.Context, id storage.ID) error
	viewsLeftFunc          func(ctx context.Context, id storage.ID) (uint64, error)
	viewedFunc             func(ctx context.Context, id storage.ID) error
	issueDownloadGrantFunc func(ctx context.Context, id storage.ID) (string, error)
	validDownloadGrantFunc func(ctx context.Context, id storage.ID, token string) error

	storeCalled      int
	getCalled        int
	loadCalled       int
	streamFileCalled int
	viewedCalled     int
	grantIssued      int
	grantChecked     int
}

func (m *mockStorage) Store(
	ctx context.Context,
	record storage.Record[storage.ID, storage.Key],
) (*storage.InsertResult[storage.ID, storage.Key], error) {
	m.storeCalled++
	if m.storeFunc != nil {
		return m.storeFunc(ctx, record)
	}
	return &storage.InsertResult[storage.ID, storage.Key]{
		ID:        record.ID(),
		Key:       record.Key(),
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func (m *mockStorage) Get(
	ctx context.Context,
	id storage.ID,
	key storage.Key,
) (storage.Record[storage.ID, storage.Key], error) {
	m.getCalled++
	if m.getFunc != nil {
		return m.getFunc(ctx, id, key)
	}
	return nil, storage.ErrRecordNotFound
}

func (m *mockStorage) Load(
	ctx context.Context,
	id storage.ID,
	key storage.Key,
) (storage.Record[storage.ID, storage.Key], error) {
	m.loadCalled++
	if m.loadFunc != nil {
		return m.loadFunc(ctx, id, key)
	}
	return nil, storage.ErrRecordNotFound
}

func (m *mockStorage) StreamFile(ctx context.Context, id storage.ID, key storage.Key, index int, w io.Writer) error {
	m.streamFileCalled++
	if m.streamFileFunc != nil {
		return m.streamFileFunc(ctx, id, key, index, w)
	}
	return storage.ErrRecordNotFound
}

func (m *mockStorage) Burn(ctx context.Context, id storage.ID) error {
	if m.burnFunc != nil {
		return m.burnFunc(ctx, id)
	}
	return nil
}

func (m *mockStorage) ViewsLeft(ctx context.Context, id storage.ID) (uint64, error) {
	if m.viewsLeftFunc != nil {
		return m.viewsLeftFunc(ctx, id)
	}
	return 1, nil
}

func (m *mockStorage) Viewed(ctx context.Context, id storage.ID) error {
	m.viewedCalled++
	if m.viewedFunc != nil {
		return m.viewedFunc(ctx, id)
	}
	return nil
}

func (m *mockStorage) IssueDownloadGrant(ctx context.Context, id storage.ID) (string, error) {
	m.grantIssued++
	if m.issueDownloadGrantFunc != nil {
		return m.issueDownloadGrantFunc(ctx, id)
	}
	return "testgranttoken123", nil
}

func (m *mockStorage) ValidDownloadGrant(ctx context.Context, id storage.ID, token string) error {
	m.grantChecked++
	if m.validDownloadGrantFunc != nil {
		return m.validDownloadGrantFunc(ctx, id, token)
	}
	if token == "testgranttoken123" {
		return nil
	}
	return storage.ErrRecordNotFound
}

func setupTestRouter(db storage.Storage[storage.ID, storage.Key]) (*flow.Mux, *handlers) {
	cfg := &config.Config{}
	cfg.Server.Domain = "http://localhost:8080"
	pCfg := new(atomic.Pointer[config.Config])
	pCfg.Store(cfg)

	h := &handlers{
		cfg: pCfg,
		l:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		db:  db,
	}

	mux := flow.New()
	h.AddHandlers(mux)
	return mux, h
}

func createMultipartRequest(
	t *testing.T,
	method, target string,
	fields map[string]string,
	files map[string][]byte,
) *http.Request {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for k, v := range fields {
		require.NoError(t, writer.WriteField(k, v))
	}

	for filename, content := range files {
		part, err := writer.CreateFormFile("attachments", filename)
		require.NoError(t, err)
		_, err = part.Write(content)
		require.NoError(t, err)
	}

	require.NoError(t, writer.Close())

	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestIndexPUT_StoreError(t *testing.T) {
	mock := &mockStorage{
		storeFunc: func(ctx context.Context, record storage.Record[storage.ID, storage.Key]) (*storage.InsertResult[storage.ID, storage.Key], error) {
			return nil, errors.New("valkey connection error")
		},
	}
	router, _ := setupTestRouter(mock)

	req := createMultipartRequest(t, http.MethodPut, "/", map[string]string{
		"secret":     "my confidential text",
		"maxViews":   "1",
		"expiration": "3600",
	}, nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "Failed to store secret")
	assert.NotContains(t, body, "http://localhost:8080/")
	assert.NotContains(t, body, "card-secret-created")
	assert.Equal(t, 1, mock.storeCalled)
}

func TestIndexPUT_StoreSuccess(t *testing.T) {
	mock := &mockStorage{}
	router, _ := setupTestRouter(mock)

	req := createMultipartRequest(t, http.MethodPut, "/", map[string]string{
		"secret":     "my confidential text",
		"maxViews":   "1",
		"expiration": "3600",
	}, nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.NotContains(t, body, "Failed to store secret")
	assert.Contains(t, body, "http://localhost:8080/")
	assert.Equal(t, 1, mock.storeCalled)
}

type infiniteMultipartReader struct {
	prefix []byte
	offset int
}

func (r *infiniteMultipartReader) Read(p []byte) (int, error) {
	if r.offset < len(r.prefix) {
		n := copy(p, r.prefix[r.offset:])
		r.offset += n
		return n, nil
	}
	for i := range p {
		p[i] = 'A'
	}
	return len(p), nil
}

func TestIndexPUT_BodyExceedsMaxBytes(t *testing.T) {
	mock := &mockStorage{}
	router, _ := setupTestRouter(mock)

	boundary := "----WebKitFormBoundary7MA4YWxkTrZu0gW"
	prefix := fmt.Sprintf(
		"--%s\r\nContent-Disposition: form-data; name=\"secret\"\r\n\r\nmy secret\r\n--%s\r\nContent-Disposition: form-data; name=\"attachments\"; filename=\"large.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n",
		boundary,
		boundary,
	)

	reader := &infiniteMultipartReader{prefix: []byte(prefix)}
	req := httptest.NewRequest(http.MethodPut, "/", reader)
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Attachments exceed maximum allowed size (512 MiB)")
	assert.Equal(t, 0, mock.storeCalled)
}

func TestIndexPUT_OversizeAttachments(t *testing.T) {
	mock := &mockStorage{}
	_, hHandler := setupTestRouter(mock)

	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.PostForm = map[string][]string{
		"secret":     {"hello"},
		"maxViews":   {"1"},
		"expiration": {"3600"},
	}
	req.Form = req.PostForm
	req.MultipartForm = &multipart.Form{
		Value: req.PostForm,
		File: map[string][]*multipart.FileHeader{
			"attachments": {
				{
					Filename: "oversized.bin",
					Header:   nil,
					Size:     maxAttachmentsSize + 1,
				},
			},
		},
	}
	rr := httptest.NewRecorder()
	hHandler.indexPUT(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Attachments exceed maximum allowed size (512 MiB)")
	assert.Equal(t, 0, mock.storeCalled)
}

func TestIndexPUT_FileReadFailure(t *testing.T) {
	mock := &mockStorage{}
	_, hHandler := setupTestRouter(mock)

	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.PostForm = map[string][]string{
		"secret":     {"hello"},
		"maxViews":   {"1"},
		"expiration": {"3600"},
	}
	req.Form = req.PostForm
	req.MultipartForm = &multipart.Form{
		Value: req.PostForm,
		File: map[string][]*multipart.FileHeader{
			"attachments": {
				{Filename: "broken.bin", Size: 100}, // Open() will fail because no file is associated
			},
		},
	}
	rr := httptest.NewRecorder()
	hHandler.indexPUT(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Failed to read attachment")
	assert.Equal(t, 0, mock.storeCalled)
}

func TestSecretPOST_SuccessWithFiles(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901") // 32 bytes
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")
	urlPath := fmt.Sprintf("/%s-%s", keyHex, sid)

	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.SetValue("sensitive payload")
	secretRecord.AddFile("document.pdf", []byte("%PDF-dummy-content"))
	secretRecord.AddFile("setup.msi", []byte("MZ-dummy-msi-binary"))

	mock := &mockStorage{
		getFunc: func(ctx context.Context, id storage.ID, key storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			assert.Equal(t, sid, id)
			assert.Equal(t, storage.Key(testKey), key)
			return secretRecord, nil
		},
		issueDownloadGrantFunc: func(ctx context.Context, id storage.ID) (string, error) {
			return "tok12345", nil
		},
	}
	router, _ := setupTestRouter(mock)

	req := httptest.NewRequest(http.MethodPost, urlPath, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/html; charset=utf-8", rr.Header().Get("Content-Type"))
	body := rr.Body.String()
	// Must contain links to the files
	assert.Contains(t, body, fmt.Sprintf("%s/files/0?g=tok12345", urlPath))
	assert.Contains(t, body, fmt.Sprintf("%s/files/1?g=tok12345", urlPath))
	assert.Contains(t, body, "document.pdf")
	assert.Contains(t, body, "setup.msi")

	// Must NOT contain SSE data: prefixes, base64 or raw file bytes
	assert.NotContains(t, body, "data:")
	assert.NotContains(t, body, "data :")
	assert.NotContains(t, body, "data:application")
	assert.NotContains(t, body, "base64")
	assert.NotContains(t, body, "%PDF-dummy-content")
	assert.NotContains(t, body, "MZ-dummy-msi-binary")

	// Must have issued grant and marked viewed
	assert.Equal(t, 1, mock.grantIssued)
	assert.Equal(t, 1, mock.viewedCalled)
}

func TestSecretPOST_WrongPassphrase(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901")
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")
	urlPath := fmt.Sprintf("/%s-%s", keyHex, sid)

	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.SetValue("sensitive payload")
	secretRecord.SetPassphrase("correcthorse")
	secretRecord.AddFile("secret.txt", []byte("hello"))

	mock := &mockStorage{
		getFunc: func(ctx context.Context, id storage.ID, key storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			return secretRecord, nil
		},
	}
	router, _ := setupTestRouter(mock)

	form := strings.NewReader("passphrase=wrongpassword")
	req := httptest.NewRequest(http.MethodPost, urlPath, form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Provided wrong password")
	assert.Equal(t, 0, mock.grantIssued)
	assert.Equal(t, 0, mock.viewedCalled)
}

func TestSecretFileGET_ValidGrant(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901")
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")
	fileURL := fmt.Sprintf("/%s-%s/files/0?g=validgrant99", keyHex, sid)

	fileData := []byte("binary installer content for msi file")
	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.Reinit("secret", nil, time.Now().Add(time.Hour), []*storage.FileRecord{
		{Name: "installer.msi", Size: int64(len(fileData)), Content: nil},
	})

	mock := &mockStorage{
		validDownloadGrantFunc: func(ctx context.Context, id storage.ID, token string) error {
			assert.Equal(t, sid, id)
			assert.Equal(t, "validgrant99", token)
			return nil
		},
		loadFunc: func(ctx context.Context, id storage.ID, key storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			assert.Equal(t, sid, id)
			assert.Equal(t, storage.Key(testKey), key)
			return secretRecord, nil
		},
		streamFileFunc: func(_ context.Context, id storage.ID, key storage.Key, index int, w io.Writer) error {
			assert.Equal(t, sid, id)
			assert.Equal(t, storage.Key(testKey), key)
			assert.Equal(t, 0, index)
			_, err := w.Write(fileData)
			return err
		},
	}
	router, _ := setupTestRouter(mock)

	req := httptest.NewRequest(http.MethodGet, fileURL, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/octet-stream", rr.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="installer.msi"`, rr.Header().Get("Content-Disposition"))
	assert.Equal(t, fmt.Sprintf("%d", len(fileData)), rr.Header().Get("Content-Length"))
	assert.Equal(t, "true", rr.Header().Get("No-Gzip-Compression"))
	assert.Equal(t, "no-store", rr.Header().Get("Cache-Control"))
	assert.Equal(t, "nosniff", rr.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, fileData, rr.Body.Bytes())

	// Verify Load and StreamFile were called, while Get and Viewed were NOT called
	assert.Equal(t, 1, mock.loadCalled)
	assert.Equal(t, 1, mock.streamFileCalled)
	assert.Equal(t, 0, mock.getCalled)
	assert.Equal(t, 0, mock.viewedCalled)
}

func TestSecretFileGET_MissingBlobReturns404(t *testing.T) {
	t.Parallel()
	testKey := []byte("01234567890123456789012345678901")
	keyHex := hex.EncodeToString(testKey)
	sid := storage.ID("test-secret-id")
	fileURL := fmt.Sprintf("/%s-%s/files/0?g=validgrant99", keyHex, sid)

	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.Reinit("secret", nil, time.Now().Add(time.Hour), []*storage.FileRecord{
		{Name: "installer.msi", Size: 1024, Content: nil},
	})

	mock := &mockStorage{ //nolint:exhaustruct_v5 // mock
		validDownloadGrantFunc: func(_ context.Context, _ storage.ID, _ string) error {
			return nil
		},
		loadFunc: func(_ context.Context, _ storage.ID, _ storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			return secretRecord, nil
		},
		streamFileFunc: func(_ context.Context, _ storage.ID, _ storage.Key, _ int, _ io.Writer) error {
			return storage.ErrRecordNotFound
		},
	}
	router, _ := setupTestRouter(mock)

	req := httptest.NewRequest(http.MethodGet, fileURL, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Empty(t, rr.Header().Get("Content-Disposition"))
	assert.Empty(t, rr.Header().Get("No-Gzip-Compression"))
	assert.Equal(t, 1, mock.loadCalled)
	assert.Equal(t, 1, mock.streamFileCalled)
}

func TestSecretFileGET_InvalidOrMissingGrant(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901")
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")

	mock := &mockStorage{
		validDownloadGrantFunc: func(ctx context.Context, id storage.ID, token string) error {
			return storage.ErrRecordNotFound
		},
	}
	router, _ := setupTestRouter(mock)

	// Missing grant token ?g=
	reqMissing := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s-%s/files/0", keyHex, sid), nil)
	rrMissing := httptest.NewRecorder()
	router.ServeHTTP(rrMissing, reqMissing)
	assert.Equal(t, http.StatusNotFound, rrMissing.Code)
	assert.Equal(t, 0, mock.loadCalled)

	// Invalid grant token
	reqInvalid := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s-%s/files/0?g=badtoken", keyHex, sid), nil)
	rrInvalid := httptest.NewRecorder()
	router.ServeHTTP(rrInvalid, reqInvalid)
	assert.Equal(t, http.StatusNotFound, rrInvalid.Code)
	assert.Equal(t, 0, mock.loadCalled)
}

func TestSecretFileGET_IndexOutOfRange(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901")
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")

	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.AddFile("onlyone.txt", []byte("hello"))

	mock := &mockStorage{
		validDownloadGrantFunc: func(ctx context.Context, id storage.ID, token string) error {
			return nil
		},
		loadFunc: func(ctx context.Context, id storage.ID, key storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			return secretRecord, nil
		},
	}
	router, _ := setupTestRouter(mock)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s-%s/files/5?g=token", keyHex, sid), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestSecretFileGET_BadPath(t *testing.T) {
	mock := &mockStorage{}
	router, _ := setupTestRouter(mock)

	// Value with no hyphen
	req := httptest.NewRequest(http.MethodGet, "/nohyphenhere/files/0?g=token", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)

	// Non-numeric index
	reqNonNum := httptest.NewRequest(http.MethodGet, "/abc-123/files/notanumber?g=token", nil)
	rrNonNum := httptest.NewRecorder()
	router.ServeHTTP(rrNonNum, reqNonNum)
	assert.Equal(t, http.StatusNotFound, rrNonNum.Code)
}

func TestSecretFileGET_SanitizeFilename(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901")
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")

	payloads := [][]byte{
		[]byte("safe content"),
		[]byte("msi content"),
		[]byte("pdf content"),
	}
	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.Reinit("secret", nil, time.Now().Add(time.Hour), []*storage.FileRecord{
		{Name: "../../dangerous\"path\r\nfile.txt", Size: int64(len(payloads[0])), Content: nil},
		{Name: `C:\fakepath\installer.msi`, Size: int64(len(payloads[1])), Content: nil},
		{Name: "zmluva_ščťž.pdf", Size: int64(len(payloads[2])), Content: nil},
	})

	mock := &mockStorage{
		validDownloadGrantFunc: func(_ context.Context, _ storage.ID, _ string) error {
			return nil
		},
		loadFunc: func(_ context.Context, _ storage.ID, _ storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			return secretRecord, nil
		},
		streamFileFunc: func(_ context.Context, _ storage.ID, _ storage.Key, index int, w io.Writer) error {
			_, err := w.Write(payloads[index])
			return err
		},
	}
	router, _ := setupTestRouter(mock)

	// 0: dangerous path traversal + CRLF + quote
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s-%s/files/0?g=token", keyHex, sid), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	disposition := rr.Header().Get("Content-Disposition")
	assert.Equal(t, `attachment; filename="dangerouspathfile.txt"`, disposition)
	assert.NotContains(t, disposition, "..")
	assert.NotContains(t, disposition, "/")
	assert.NotContains(t, disposition, "\n")
	assert.NotContains(t, disposition, "\r")

	// 1: Windows backslash path
	reqWin := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s-%s/files/1?g=token", keyHex, sid), nil)
	rrWin := httptest.NewRecorder()
	router.ServeHTTP(rrWin, reqWin)
	assert.Equal(t, http.StatusOK, rrWin.Code)
	assert.Equal(t, `attachment; filename="installer.msi"`, rrWin.Header().Get("Content-Disposition"))

	// 2: UTF-8 filename with RFC 5987 encoding
	reqUTF8 := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s-%s/files/2?g=token", keyHex, sid), nil)
	rrUTF8 := httptest.NewRecorder()
	router.ServeHTTP(rrUTF8, reqUTF8)
	assert.Equal(t, http.StatusOK, rrUTF8.Code)
	assert.Contains(t, rrUTF8.Header().Get("Content-Disposition"), "filename*=UTF-8''")
}

func TestSecretFileGET_ZeroByteAttachment(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901")
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")

	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.AddFile("empty.bin", []byte{})

	mock := &mockStorage{
		validDownloadGrantFunc: func(ctx context.Context, id storage.ID, token string) error {
			return nil
		},
		loadFunc: func(ctx context.Context, id storage.ID, key storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			return secretRecord, nil
		},
	}
	router, _ := setupTestRouter(mock)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/%s-%s/files/0?g=token", keyHex, sid), nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "0", rr.Header().Get("Content-Length"))
	assert.Empty(t, rr.Body.Bytes())
}

func TestIndexGET_And_IndexPUT_Auth(t *testing.T) {
	mock := &mockStorage{}
	router, h := setupTestRouter(mock)

	// 1. Auth disabled (default): GET / does not panic and renders secret form
	reqGet := httptest.NewRequest(http.MethodGet, "/", nil)
	rrGet := httptest.NewRecorder()
	router.ServeHTTP(rrGet, reqGet)
	assert.Equal(t, http.StatusOK, rrGet.Code)
	assert.Contains(t, rrGet.Body.String(), "secret-form")

	// 2. Enable Auth: unauthenticated GET / renders login form, unauthenticated PUT / returns 401
	cfg := new(config.Config)
	_ = cfg.Load()
	cfg.Auth.IsEnabled = true
	cfg.Auth.Username = "admin"
	cfg.Auth.Password = "secretpass"
	h.cfg.Store(cfg)

	reqGetAuth := httptest.NewRequest(http.MethodGet, "/", nil)
	rrGetAuth := httptest.NewRecorder()
	router.ServeHTTP(rrGetAuth, reqGetAuth)
	assert.Equal(t, http.StatusOK, rrGetAuth.Code)
	assert.Contains(t, rrGetAuth.Body.String(), "login-form")

	reqPutUnauth := createMultipartRequest(t, http.MethodPut, "/", map[string]string{
		"secret":     "my secret message",
		"maxViews":   "1",
		"expiration": "3600",
	}, nil)
	rrPutUnauth := httptest.NewRecorder()
	router.ServeHTTP(rrPutUnauth, reqPutUnauth)
	assert.Equal(t, http.StatusUnauthorized, rrPutUnauth.Code)
	assert.Equal(t, 0, mock.storeCalled)
}

func TestOneViewSecret_DownloadSurvivesSecondVisit(t *testing.T) {
	testKey := []byte("01234567890123456789012345678901")
	keyHex := fmt.Sprintf("%x", testKey)
	sid := storage.ID("test-secret-id")
	urlPath := fmt.Sprintf("/%s-%s", keyHex, sid)

	fileBytes := []byte("important-installer-binary")
	secretRecord := secrets.NewSecret(sid, testKey)
	secretRecord.Reinit("one-time secret", nil, time.Now().Add(time.Hour), []*storage.FileRecord{
		{Name: "installer.msi", Size: int64(len(fileBytes)), Content: nil},
	})

	viewsRemaining := 1
	grantActive := false

	mock := &mockStorage{
		getFunc: func(_ context.Context, _ storage.ID, _ storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			if viewsRemaining <= 0 {
				return nil, storage.ErrRecordNotFound
			}
			return secretRecord, nil
		},
		viewedFunc: func(_ context.Context, _ storage.ID) error {
			viewsRemaining--
			return nil
		},
		issueDownloadGrantFunc: func(_ context.Context, _ storage.ID) (string, error) {
			grantActive = true
			return "grant-tok-1", nil
		},
		validDownloadGrantFunc: func(_ context.Context, _ storage.ID, token string) error {
			if grantActive && token == "grant-tok-1" {
				return nil
			}
			return storage.ErrRecordNotFound
		},
		loadFunc: func(_ context.Context, _ storage.ID, _ storage.Key) (storage.Record[storage.ID, storage.Key], error) {
			return secretRecord, nil
		},
		streamFileFunc: func(_ context.Context, _ storage.ID, _ storage.Key, index int, w io.Writer) error {
			assert.Equal(t, 0, index)
			_, err := w.Write(fileBytes)
			return err
		},
	}
	router, _ := setupTestRouter(mock)

	// 1. User A reveals the 1-view secret
	reqReveal := httptest.NewRequest(http.MethodPost, urlPath, nil)
	rrReveal := httptest.NewRecorder()
	router.ServeHTTP(rrReveal, reqReveal)
	assert.Equal(t, http.StatusOK, rrReveal.Code)
	assert.Contains(t, rrReveal.Body.String(), "/files/0?g=grant-tok-1")

	// 2. Second visit to GET /:value shows "Nothing found"
	reqSecond := httptest.NewRequest(http.MethodGet, urlPath, nil)
	rrSecond := httptest.NewRecorder()
	router.ServeHTTP(rrSecond, reqSecond)
	assert.Equal(t, http.StatusOK, rrSecond.Code)
	assert.Contains(t, rrSecond.Body.String(), "Nothing found")

	// 3. User A clicks the attachment download link and still receives the file via StreamFile
	reqDownload := httptest.NewRequest(http.MethodGet, urlPath+"/files/0?g=grant-tok-1", nil)
	rrDownload := httptest.NewRecorder()
	router.ServeHTTP(rrDownload, reqDownload)
	assert.Equal(t, http.StatusOK, rrDownload.Code)
	assert.Equal(t, fileBytes, rrDownload.Body.Bytes())
	assert.Equal(t, 1, mock.streamFileCalled)
}
