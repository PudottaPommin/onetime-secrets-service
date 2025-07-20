package ui

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/pudottapommin/secret-notes/pkg/encryption"
	"github.com/pudottapommin/secret-notes/pkg/secrets"
	"github.com/pudottapommin/secret-notes/pkg/server"
	"github.com/pudottapommin/secret-notes/pkg/storage"
	"github.com/pudottapommin/secret-notes/pkg/ui"
	"github.com/starfederation/datastar-go/datastar"
)

func (h *handlers) indexGET(w http.ResponseWriter, r *http.Request) {
	isAuthenticated, ok := r.Context().Value("isAuthenticated").(bool)
	if !ok {
		isAuthenticated = true
	}
	model := ui.PageIndex{IsAuthenticated: isAuthenticated}
	if err := ui.RenderPageIndex(w, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (h *handlers) indexPUT(w http.ResponseWriter, r *http.Request) {
	var signal struct {
		Value      string  `json:"value"`
		Passphrase *string `json:"passphrase,omitempty"`
		Expiration int     `json:"expiration,omitempty"`
		MaxViews   uint64  `json:"maxViews,omitempty"`
	}
	if err := datastar.ReadSignals(r, &signal); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if signal.Value == "" {
		var errorSignal struct {
			ErrorValue string `json:"errorValue"`
		}
		errorSignal.ErrorValue = "value is required"
		sse := datastar.NewSSE(w, r, datastar.WithCompression(datastar.WithServerPriority()))
		sse.MarshalAndPatchSignals(errorSignal)
		return
	}

	id := storage.ID(uuid.Must(uuid.NewV4()).String())
	key := make([]byte, 32)
	if err := encryption.GenerateNewKey(key); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	secret := secrets.NewSecret(id, key)
	secret.SetValue(signal.Value)
	if signal.Passphrase != nil && *signal.Passphrase != "" {
		secret.SetPassphrase(*signal.Passphrase)
	}
	if signal.MaxViews > 1 {
		secret.SetMaxViews(signal.MaxViews)
	}
	if signal.Expiration > 0 {
		secret.SetExpiration(time.Second * time.Duration(signal.Expiration))
	}

	insert, err := h.db.Store(r.Context(), secret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	normalizedID := strings.ReplaceAll(string(id), "-", "")

	model := ui.CardSecretCreated{
		Url:       fmt.Sprintf("%s/%x-%s", h.cfg.Domaine, insert.Key, normalizedID),
		ExpiresAt: insert.ExpiresAt,
	}
	sb := new(strings.Builder)
	if err = ui.RenderCardSecretCreated(sb, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sse := datastar.NewSSE(w, r, datastar.WithCompression(datastar.WithServerPriority()))
	sse.PatchElements(sb.String(), datastar.WithSelectorID("secret-form"), datastar.WithModeReplace())
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
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	gid, err := uuid.FromString(parts[1])
	if err != nil {
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	id := storage.ID(gid.String())
	secret, err := h.db.Get(ctx, id, encKey)
	switch {
	case errors.Is(err, storage.ErrRecordNotFound) || (err == nil && secret == nil):
		model := ui.PageSecret{
			Url:      r.URL.Path,
			NotFound: true,
		}
		if err = ui.RenderPageSecret(w, model); err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	case err != nil:
		log.Println(err)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	viewsLeft, err := h.db.ViewsLeft(ctx, id)
	if err != nil {
		log.Println(err)
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
	}
	if err = ui.RenderPageSecret(w, model); err != nil {
		log.Println(err)
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

	if secret.Passphrase() != nil && *secret.Passphrase() != "" {
		var signal struct {
			Passphrase string `json:"passphrase"`
		}
		if err = datastar.ReadSignals(r, &signal); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if signal.Passphrase != *secret.Passphrase() {
			var errorSignal struct {
				ErrorPassphrase string `json:"errorPassphrase"`
			}
			errorSignal.ErrorPassphrase = "unable to unlock secret"
			sse := datastar.NewSSE(w, r, datastar.WithCompression(datastar.WithServerPriority()))
			sse.MarshalAndPatchSignals(errorSignal)
			return
		}
	}
	if err = h.db.Viewed(ctx, id); err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	model := ui.CardSecretDecrypted{
		Url:       r.URL.Path,
		Secret:    secret.Value(),
		ExpiresAt: secret.ExpiresAt(),
	}
	sb := new(strings.Builder)
	if err = ui.RenderCardSecretDecrypted(sb, model); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sse := datastar.NewSSE(w, r, datastar.WithCompression(datastar.WithServerPriority()))
	sse.PatchElements(sb.String(), datastar.WithSelectorID("secret-detail"), datastar.WithModeReplace())
}

func (h *handlers) authenticatePOST(w http.ResponseWriter, r *http.Request) {
	var signal struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := datastar.ReadSignals(r, &signal); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if signal.Username == "" || signal.Password == "" {
		var errorSignal struct {
			ErrorUsername string `json:"errorUsername"`
			ErrorPassword string `json:"errorPassword"`
		}
		if signal.Username == "" {
			errorSignal.ErrorUsername = "username is required"
		}
		if signal.Password == "" {
			errorSignal.ErrorPassword = "password is required"
		}
		sse := datastar.NewSSE(w, r, datastar.WithCompression(datastar.WithServerPriority()))
		sse.MarshalAndPatchSignals(errorSignal)
		return
	}

	if signal.Username != h.cfg.BasicAuthUsername || signal.Password != h.cfg.BasicAuthPassword {
		var errorSignal struct {
			ErrorUsername string `json:"errorUsername"`
		}
		errorSignal.ErrorUsername = "wrong username or password"
		sse := datastar.NewSSE(w, r, datastar.WithCompression(datastar.WithServerPriority()))
		sse.MarshalAndPatchSignals(errorSignal)
		return
	}

	token, _ := server.NewAuthToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "onetimesecretsecret",
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	sb := new(strings.Builder)
	if err := ui.RenderCardSecretForm(sb); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sse := datastar.NewSSE(w, r, datastar.WithCompression(datastar.WithServerPriority()))
	signal.Username = ""
	signal.Password = ""
	sse.MarshalAndPatchSignals(signal)
	sse.PatchElements(sb.String(), datastar.WithSelectorID("login-form"), datastar.WithModeReplace())
}
