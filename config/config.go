package config

import (
	"github.com/caarlos0/env/v11"
)

type Config struct {
	Domaine string `env:"SECRET_SERVICE_DOMAIN" envDefault:"http://localhost:8080"`
	DB      string `env:"SECRET_SERVICE_DB" envDefault:"localhost:8081"`
	Host    string `env:"SECRET_SERVICE_HOST" envDefault:"localhost:8080"`
}

func (c *Config) Load() error {
	return env.Parse(c)
}
