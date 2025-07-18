package api

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/alexedwards/flow"
	"github.com/pudottapommin/secret-notes/config"
	"github.com/pudottapommin/secret-notes/pkg/secrets"
	"github.com/pudottapommin/secret-notes/pkg/storage"
	"github.com/valkey-io/valkey-go"
)

type handlers struct {
	cfg *config.Config
	db  *storage.ValkeyStorage
}

func NewHandlers(cfg *config.Config, client valkey.Client) *handlers {
	return &handlers{
		cfg: cfg,
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
					if r.URL.Path == "/create" && r.Method == "POST" {
						authHeader := r.Header.Get("Authorization")
						if authHeader == "" {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}

						if !strings.HasPrefix(authHeader, "Basic ") {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}

						payload, err := base64.StdEncoding.DecodeString(authHeader[6:])
						if err != nil {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}

						pair := strings.SplitN(string(payload), ":", 2)
						if len(pair) != 2 || pair[0] != h.cfg.BasicAuthUsername || pair[1] != h.cfg.BasicAuthPassword {
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
					}
					next.ServeHTTP(w, r)
				})
			})
		}
		g.HandleFunc("/create", h.secretsPOST, "POST")
	})
	e.HandleFunc("/:slug", h.secretsGET, "GET")
}
