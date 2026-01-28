package ui

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/alexedwards/flow"
	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/server"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
	"github.com/valkey-io/valkey-go"
)

type handlers struct {
	l   *slog.Logger
	cfg *config.Config
	db  *storage.ValkeyStorage
}

func NewHandlers(cfg *config.Config, client valkey.Client, l *slog.Logger) *handlers {
	return &handlers{
		cfg: cfg,
		l:   l,
		db: storage.NewValkeyStorage(client, func(id storage.ID, key storage.Key) storage.Record[storage.ID, storage.Key] {
			return secrets.NewSecret(id, key)
		}),
	}
}

func (h *handlers) AddHandlers(e *flow.Mux) {
	e.Group(func(g *flow.Mux) {
		if h.cfg.BasicAuthEnabled {
			g.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					isAuthenticated := true
					if r.URL.Path == "/" {
						isAuthenticated = false
						if cv, err := r.Cookie("onetimesecretsecret"); err == nil {
							if err = cv.Valid(); err == nil {
								isAuthenticated = server.AuthTokenValid(cv.Value)
							}
						}

					}
					r = r.WithContext(context.WithValue(r.Context(), "isAuthenticated", isAuthenticated))
					next.ServeHTTP(w, r)
				})
			})
		}
		g.HandleFunc("/authenticate", h.authenticatePOST, "post")
		g.HandleFunc("/", h.indexPUT, "PUT")
		g.HandleFunc("/", h.indexGET, "GET")
	})
	e.HandleFunc("/:value", h.secretPOST, "POST")
	e.HandleFunc("/:value", h.secretGET, "GET")
}
