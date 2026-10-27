package config

import (
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/caarlos0/env/v11"

	"github.com/pudottapommin/onetime-secrets-service/pkg/encryption"
)

const csrfKeyLength = 32

type Config struct {
	IsProd    bool   `env:"OSS_PROD"       envDefault:"false"`
	SecretKey []byte `env:"OSS_SECRET_KEY"`

	Server struct {
		Addr        string `env:"ADDR,required" envDefault:"127.0.0.1:8080"`
		Domain      string `env:"DOMAIN,required" envDefault:"http://localhost:8080"`
		DB          string `env:"DB,required" envDefault:"127.0.0.1:6379"`
		UI          bool   `env:"UI" envDefault:"true"`
		UIHotReload bool   `env:"UI_HOT_RELOAD" envDefault:"false"`
	} `envPrefix:"OSS_SERVER_"`

	Auth struct {
		IsEnabled bool   `env:"ENABLED" envDefault:"false"`
		Username  string `env:"USERNAME"`
		Password  string `env:"PASSWORD"`
	} `envPrefix:"OSS_AUTH_"`

	Csrf struct {
		IsEnabled bool   `env:"ENABLED" envDefault:"true"`
		HashKey   []byte `env:"HASH_KEY"`
		BlockKey  []byte `env:"BLOCK_KEY"`
	} `envPrefix:"OSS_CSRF_"`

	Pprof struct {
		IsEnabled bool `env:"ENABLED" envDefault:"false"`
	} `envPrefix:"OSS_PPROF_"`
}

func (c *Config) Load() error {
	if err := env.ParseWithOptions(c, env.Options{
		FuncMap: map[reflect.Type]env.ParserFunc{
			reflect.TypeFor[[]byte](): func(val string) (any, error) {
				if val == "" {
					return []byte(nil), nil
				}
				b, err := base64.StdEncoding.DecodeString(val)
				if err != nil {
					return nil, fmt.Errorf("failed to decode base64: %w", err)
				}
				return b, nil
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to parse env config: %w", err)
	}
	return nil
}

func (c *Config) InitCSRF() ([]byte, []byte, bool) {
	if !c.Csrf.IsEnabled {
		return nil, nil, false
	}
	var (
		hk []byte
		bk []byte
	)
	if c.Csrf.HashKey == nil {
		c.Csrf.HashKey = encryption.GenerateNewKey(csrfKeyLength)
		hk = c.Csrf.HashKey
	}
	if c.Csrf.BlockKey == nil {
		c.Csrf.BlockKey = encryption.GenerateNewKey(csrfKeyLength)
		bk = c.Csrf.BlockKey
	}
	return hk, bk, hk != nil || bk != nil
}
