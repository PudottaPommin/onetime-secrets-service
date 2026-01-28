package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/alexedwards/flow"
	"github.com/pudottapommin/golib/http/cookie"
	"github.com/pudottapommin/golib/http/middleware/compressor"
	"github.com/pudottapommin/golib/http/middleware/csrf"
	"github.com/pudottapommin/golib/http/middleware/logger"
	"github.com/pudottapommin/golib/http/middleware/requestid"
	"github.com/pudottapommin/golib/http/middleware/static"
	"github.com/pudottapommin/golib/pkg/assetsfs"
	"github.com/pudottapommin/onetime-secrets-service/assets"
	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/internal/api"
	"github.com/pudottapommin/onetime-secrets-service/internal/ui"
	"github.com/pudottapommin/onetime-secrets-service/pkg/server"
	pui "github.com/pudottapommin/onetime-secrets-service/pkg/ui"
	"github.com/valkey-io/valkey-go"
)

type App struct {
	*server.Server
	db  valkey.Client
	cfg *config.Config
	l   *slog.Logger
}

func New(ctx context.Context, db valkey.Client, cfg *config.Config, l *slog.Logger) *App {
	return &App{Server: server.New(ctx, flow.New()), db: db, cfg: cfg, l: l}
}

func (a *App) Run(addr string) (err error) {
	if !a.cfg.IsProd {
		a.E().Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pui.ReloadTemplates()
				next.ServeHTTP(w, r)
			})
		})
	}

	if a.cfg.CsrfHashKey == "" {
		a.cfg.CsrfHashKey = base64.StdEncoding.EncodeToString(cookie.GenerateRandomKey(32))
		a.l.Warn("generated csrf hash key", "key", a.cfg.CsrfHashKey)
	}
	if a.cfg.CsrfBlockKey == "" {
		a.cfg.CsrfBlockKey = base64.StdEncoding.EncodeToString(cookie.GenerateRandomKey(32))
		a.l.Warn("generated csrf block key", "key", a.cfg.CsrfBlockKey)
	}

	csrfHashKey, err := base64.StdEncoding.DecodeString(a.cfg.CsrfHashKey)
	if err != nil {
		return fmt.Errorf("failed to decode csrf hash key: %w", err)
	}
	csrfBlockKey, err := base64.StdEncoding.DecodeString(a.cfg.CsrfBlockKey)
	if err != nil {
		return fmt.Errorf("failed to decode csrf block key: %w", err)
	}

	sc, err := cookie.New(csrfHashKey, csrfBlockKey)
	if err != nil {
		return fmt.Errorf("failed to create cookie: %w", err)
	}

	a.E().Use(
		requestid.New().Handler,
		logger.New(logger.WithLogger(a.l, "[HTTP]"), logger.WithNext(func(w http.ResponseWriter, r *http.Request) bool {
			return strings.HasPrefix(r.URL.Path, "/static") || strings.HasPrefix(r.URL.Path, "/.well-known")
		})).Handler,
		compressor.MustNew(),
		csrf.New(sc).Handler,
	)

	{
		h := api.NewHandlers(a.cfg, a.db, a.l)
		h.AddHandlers(a.E())
	}
	if a.cfg.UI {
		h := ui.NewHandlers(a.cfg, a.db, a.l)
		h.AddHandlers(a.E())
	}

	if a.cfg.BasicAuthEnabled {
		go server.AuthTokenCleanup(a.Server.Ctx())
	}

	a.E().Group(func(r *flow.Mux) {
		ls := assetsfs.NewLayered(assets.BuiltinAssets())
		r.Handle("/static/...", http.StripPrefix("/static/",
			static.New(ls, static.WithEtag(), static.WithSetProd(a.cfg.IsProd))))
	})

	a.l.Debug("Server started", "address", addr)
	return a.Server.Run(addr)
}

func (a *App) Shutdown(ctx context.Context) error {
	return a.Server.Shutdown(ctx)
}
