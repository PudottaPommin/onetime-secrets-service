package api

import (
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/alexedwards/flow"
	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/pkg/secrets"
	"github.com/pudottapommin/onetime-secrets-service/pkg/server"
	"github.com/pudottapommin/onetime-secrets-service/pkg/storage"
	"github.com/valkey-io/valkey-go"
)

type handlers struct {
	l   *slog.Logger
	cfg *atomic.Pointer[config.Config]
	db  storage.Storage[storage.ID, storage.Key]
}

func NewHandlers(cfg *atomic.Pointer[config.Config], client valkey.Client, l *slog.Logger) *handlers {
	encryptor, _ := storage.NewDefaultEncryptor(cfg.Load().SecretKey)
	return &handlers{
		cfg: cfg,
		l:   l,
		db: storage.NewValkey(client,
			encryptor,
			func(id storage.ID, key storage.Key) storage.Record[storage.ID, storage.Key] {
				return secrets.NewSecret(id, key)
			}),
	}
}

func (h *handlers) AddHandlers(e *flow.Mux) {
	e.Group(func(g *flow.Mux) {
		g.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cfg := h.cfg.Load()
				if !cfg.Auth.IsEnabled {
					next.ServeHTTP(w, r)
					return
				}

				switch r.Method {
				case http.MethodPost:
					if err := server.AuthValidateHeader(r, cfg.Auth.Username, cfg.Auth.Password); err != nil {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
				}
				next.ServeHTTP(w, r)
			})
		})

		g.HandleFunc("/api/create", h.secretPUT, "PUT")
	})
	e.HandleFunc("/api/:value", h.secretGET, "GET")
}
