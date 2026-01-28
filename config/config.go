package config

import (
	"github.com/caarlos0/env/v11"
)

type Config struct {
	IsProd            bool   `env:"OSS_PROD" envDefault:"false"`
	Domain            string `env:"OSS_DOMAIN" envDefault:"http://localhost:8080"`
	DB                string `env:"OSS_DB" envDefault:"localhost:8081"`
	Host              string `env:"OSS_HOST" envDefault:"localhost:8080"`
	BasicAuthEnabled  bool   `env:"OSS_BASIC_AUTH_ENABLED" envDefault:"false"`
	BasicAuthUsername string `env:"OSS_BASIC_AUTH_USERNAME" envDefault:"admin"`
	BasicAuthPassword string `env:"OSS_BASIC_AUTH_PASSWORD" envDefault:"admin"`
	UI                bool   `env:"OSS_UI" envDefault:"true"`
	CsrfHashKey       string `env:"OSS_CSRF_HASH_KEY"`
	CsrfBlockKey      string `env:"OSS_CSRF_BLOCK_KEY"`
}

func (c *Config) Load() error {
	return env.Parse(c)
}
