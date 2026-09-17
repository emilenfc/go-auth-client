package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Config is everything this service needs, loaded from the environment.
//
// Same approach as the auth service: read it once at startup, validate it, and
// report every problem at once. A missing JWKS URL should stop the process with
// a clear message, not surface as a 401 on the first request.
type Config struct {
	Addr string

	// AuthURL is the auth service's base URL. Everything needed to verify a
	// token -- the issuer, the audience, and where the public keys live -- is
	// read from <AuthURL>/.well-known/openid-configuration at startup.
	//
	// That is why this is the only auth setting here. Configuring the issuer
	// and audience by hand works too (authclient.Config takes them), but each
	// one is a string that silently rejects every token when it is wrong.
	AuthURL string
}

// LoadConfig reads and validates the configuration. A .env file in the working
// directory is loaded first if present; real environment variables win over it.
func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		Addr:    env("ORDERS_ADDR", ":9090"),
		AuthURL: env("AUTH_URL", ""),
	}

	var problems []string
	if cfg.AuthURL == "" {
		problems = append(problems, "AUTH_URL is required (e.g. http://localhost:8080)")
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
	}

	return cfg, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
