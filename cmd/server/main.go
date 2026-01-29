package main

import (
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/internal/app"
	"github.com/valkey-io/valkey-go"
)

var pCfg = new(atomic.Pointer[config.Config])

func main() {
	cfg := new(config.Config)
	if err := cfg.Load(); err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	if hk, bk, ok := cfg.InitCSRF(); ok {
		slog.Warn("Generated new CSRF keys",
			slog.String("hash", base64.StdEncoding.EncodeToString(hk)),
			slog.String("block", base64.StdEncoding.EncodeToString(bk)))
	}
	
	pCfg.Store(cfg)

	logLvl := slog.LevelWarn
	if !cfg.IsProd {
		logLvl = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLvl}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM)
	defer stop()

	db, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{cfg.Server.DB}})
	if err != nil {
		slog.Error("failed to create valkey client", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	webApp := app.New(ctx, db, pCfg, logger)
	if err = webApp.Run(); err != nil {
		slog.Error("failed to run server", "error", err)
		os.Exit(1)
	}
}
