package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/valkey-io/valkey-go"

	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/internal/app"
)

func main() {
	if err := run(); err != nil {
		slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level:       slog.LevelError,
			AddSource:   false,
			ReplaceAttr: nil,
		})).Error("server terminated with error", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	cfg := new(config.Config)
	if err := cfg.Load(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	logLvl := slog.LevelWarn
	if !cfg.IsProd {
		logLvl = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:       logLvl,
		AddSource:   false,
		ReplaceAttr: nil,
	}))

	if hk, bk, ok := cfg.InitCSRF(); ok {
		logger.Warn("Generated new CSRF keys",
			slog.String("hash", base64.StdEncoding.EncodeToString(hk)),
			slog.String("block", base64.StdEncoding.EncodeToString(bk)))
	}

	pCfg := new(atomic.Pointer[config.Config])
	pCfg.Store(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM)
	defer stop()

	db, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{cfg.Server.DB}})
	if err != nil {
		return fmt.Errorf("failed to create valkey client: %w", err)
	}
	defer db.Close()

	webApp := app.New(ctx, db, pCfg, logger)
	if err = webApp.Run(); err != nil {
		return fmt.Errorf("failed to run server: %w", err)
	}
	return nil
}
