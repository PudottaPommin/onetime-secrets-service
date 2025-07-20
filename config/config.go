package config

import (
	"github.com/caarlos0/env/v11"
)

type Config struct {
	Domaine           string `env:"OSS_DOMAIN" envDefault:"http://localhost:8080"`
	DB                string `env:"OSS_DB" envDefault:"localhost:8081"`
	Host              string `env:"OSS_HOST" envDefault:"localhost:8080"`
	UI                bool   `env:"OSS_UI" envDefault:"true"`
	BasicAuthEnabled  bool   `env:"OSS_BASIC_AUTH_ENABLED" envDefault:"false"`
	BasicAuthUsername string `env:"OSS_BASIC_AUTH_USERNAME" envDefault:"admin"`
	BasicAuthPassword string `env:"OSS_BASIC_AUTH_PASSWORD" envDefault:"admin"`
}

func (c *Config) Load() error {
	return env.Parse(c)
}
