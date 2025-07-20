package main

import (
	"context"
	"log"

	"github.com/pudottapommin/secret-notes/config"
	"github.com/pudottapommin/secret-notes/internal/app"
	"github.com/valkey-io/valkey-go"
)

var cfg = new(config.Config)

func main() {
	if err := cfg.Load(); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	db, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{cfg.DB}})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	
	webApp := app.New(ctx, db, cfg)
	defer webApp.Shutdown(ctx)
	if err = webApp.Run(cfg.Host); err != nil {
		log.Fatal(err)
	}
}
