package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync/atomic"

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
	cfg *atomic.Pointer[config.Config]
	l   *slog.Logger
}

func New(ctx context.Context, db valkey.Client, cfg *atomic.Pointer[config.Config], l *slog.Logger) *App {
	return &App{Server: server.New(ctx, flow.New()), db: db, cfg: cfg, l: l}
}

func (a *App) Run() (err error) {
	cfg := a.cfg.Load()

	// if enabled, reload template from FS
	if cfg.Server.UIHotReload {
		a.E().Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pui.Recompile()
				next.ServeHTTP(w, r)
			})
		})
	}

	a.E().Use(
		requestid.New().Handler,
		logger.New(logger.WithLogger(a.l, "[HTTP]"), logger.WithNext(func(w http.ResponseWriter, r *http.Request) bool {
			return strings.HasPrefix(r.URL.Path, "/static") || strings.HasPrefix(r.URL.Path, "/.well-known")
		})).Handler,
		compressor.MustNew(),
	)

	if cfg.Csrf.IsEnabled {
		sc, err := cookie.New(cfg.Csrf.HashKey, cfg.Csrf.BlockKey)
		if err != nil {
			return fmt.Errorf("failed to create cookie: %w", err)
		}
		a.E().Use(csrf.New(sc, csrf.WithCookieName("oss_csrf")).Handler)
	}

	api.NewHandlers(a.cfg, a.db, a.l).AddHandlers(a.E())
	if cfg.Server.UI {
		ui.NewHandlers(a.cfg, a.db, a.l).AddHandlers(a.E())
	}

	if cfg.Pprof.IsEnabled {
		a.E().Group(func(r *flow.Mux) {
			r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline, http.MethodGet)
			r.HandleFunc("/debug/pprof/profile", pprof.Profile, http.MethodGet)
			r.HandleFunc("/debug/pprof/symbol", pprof.Symbol, http.MethodGet)
			r.HandleFunc("/debug/pprof/trace", pprof.Trace, http.MethodGet)
			r.HandleFunc("/debug/pprof/...", pprof.Index, http.MethodGet)
		})
	}

	if cfg.Auth.IsEnabled {
		go server.AuthTokenCleanup(a.Server.Ctx())
	}

	a.E().Group(func(r *flow.Mux) {
		ls := assetsfs.NewLayered(assets.BuiltinAssets())
		r.Handle("/static/...", http.StripPrefix("/static/",
			static.New(ls, static.WithEtag(), static.WithSetProd(cfg.IsProd))))
	})

	a.l.Debug("Server started", "address", cfg.Server.Addr)
	return a.Server.Run(cfg.Server.Addr)
}
