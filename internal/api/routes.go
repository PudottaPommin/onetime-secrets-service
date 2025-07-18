package api

import (
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
	e.HandleFunc("/create", h.secretsPOST, "POST")
	e.HandleFunc("/:slug", h.secretsGET, "GET")
}
