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
	"github.com/pudottapommin/golib/http/middleware"
	"github.com/pudottapommin/golib/http/middleware/compressor"
	"github.com/pudottapommin/golib/http/middleware/csrf"
	"github.com/pudottapommin/golib/http/middleware/static"
	"github.com/pudottapommin/golib/http/securecookie"
	"github.com/pudottapommin/golib/vfs"
	"github.com/valkey-io/valkey-go"

	"github.com/pudottapommin/onetime-secrets-service/assets"
	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/internal/api"
	"github.com/pudottapommin/onetime-secrets-service/internal/ui"
	"github.com/pudottapommin/onetime-secrets-service/pkg/server"
	pui "github.com/pudottapommin/onetime-secrets-service/pkg/ui"
	"github.com/pudottapommin/onetime-secrets-service/pkg/version"
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

func (a *App) Run() error {
	cfg := a.cfg.Load()

	// if enabled, reload template from FS
	if cfg.Server.UIHotReload {
		a.E().Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/static") &&
					!strings.HasPrefix(r.URL.Path, "/debug/pprof") &&
					!strings.HasPrefix(r.URL.Path, "/api/") &&
					!strings.HasPrefix(r.URL.Path, "/.well-known") &&
					r.URL.Path != "/favicon.ico" {
					pui.Recompile()
				}
				next.ServeHTTP(w, r)
			})
		})
	}

	a.E().Use(
		middleware.RequestID().Handler,
		middleware.Logger(middleware.LoggerWithLogger(a.l.With(
			slog.String("version", version.Version),
			slog.String("commit", version.Commit),
		)), middleware.LoggerWithNext(func(_ http.ResponseWriter, r *http.Request) bool {
			return strings.HasPrefix(r.URL.Path, "/static") ||
				strings.HasPrefix(r.URL.Path, "/.well-known") ||
				r.URL.Path == "/favicon.ico"
		})).
			Handler,
		compressor.MustNew(),
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-App-Version", version.Version)
				w.Header().Set("X-App-Date", version.Date)
				w.Header().Set("X-App-Revision", version.Commit)
				next.ServeHTTP(w, r)
			})
		},
	)

	if cfg.Csrf.IsEnabled {
		sc, err := securecookie.New(cfg.Csrf.HashKey, cfg.Csrf.BlockKey)
		if err != nil {
			return fmt.Errorf("failed to create cookie: %w", err)
		}
		a.E().Use(csrf.New(sc,
			csrf.WithCookieName("oss_csrf"),
			csrf.WithNext(func(_ http.ResponseWriter, r *http.Request) bool {
				return strings.HasPrefix(r.URL.Path, "/api/")
			}),
		).Handler)
	}

	a.E().HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, assets.URL("favicon.ico"), http.StatusMovedPermanently)
	}, http.MethodGet)

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
		ls := vfs.NewLayered(assets.BuiltinAssets())
		r.Handle("/static/...", http.StripPrefix("/static/",
			static.New(ls, static.WithEtag(), static.WithSetProd(cfg.IsProd))))
	})

	a.l.Debug("Server started", "address", cfg.Server.Addr)
	return a.Server.Run(cfg.Server.Addr)
}
