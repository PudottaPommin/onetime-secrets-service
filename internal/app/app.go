package app

import (
	"context"
	"log"

	"github.com/alexedwards/flow"
	"github.com/pudottapommin/secret-notes/config"
	"github.com/pudottapommin/secret-notes/internal/api"
	"github.com/pudottapommin/secret-notes/internal/ui"
	"github.com/pudottapommin/secret-notes/pkg/server"
	"github.com/valkey-io/valkey-go"
)

type (
	App struct {
		*server.Server
		db  valkey.Client
		cfg *config.Config
	}
)

func New(ctx context.Context, db valkey.Client, cfg *config.Config) *App {
	return &App{Server: server.New(ctx, flow.New()), db: db, cfg: cfg}
}

func (a *App) Run(addr string) (err error) {
	{
		h := api.NewHandlers(a.cfg, a.db)
		h.AddHandlers(a.E())
	}
	{
		h := ui.NewHandlers(a.cfg, a.db)
		h.AddHandlers(a.E())
	}

	if a.cfg.BasicAuthEnabled {
		go server.AuthTokenCleanup(a.Server.Ctx())
	}

	log.Println("Server started on ", addr)
	return a.Server.Run(addr)
}

func (a *App) Shutdown(ctx context.Context) error {
	return a.Server.Shutdown(ctx)
}
