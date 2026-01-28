package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/pudottapommin/onetime-secrets-service/config"
	"github.com/pudottapommin/onetime-secrets-service/internal/app"
	"github.com/valkey-io/valkey-go"
)

var cfg = new(config.Config)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := cfg.Load(); err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	db, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{cfg.DB}})
	if err != nil {
		slog.Error("failed to create valkey client", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	webApp := app.New(ctx, db, cfg, logger)
	defer webApp.Shutdown(ctx)
	if err = webApp.Run(cfg.Host); err != nil {
		slog.Error("failed to run server", "error", err)
		os.Exit(1)
	}
}
