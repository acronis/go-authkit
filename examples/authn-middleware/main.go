/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package main

import (
	"errors"
	"fmt"
	golog "log"
	"net/http"

	"github.com/acronis/go-appkit/config"
	"github.com/acronis/go-appkit/httpserver/middleware"
	"github.com/acronis/go-appkit/log"

	"github.com/acronis/go-authkit"
)

const (
	serviceErrorDomain  = "MyService"
	serviceEnvVarPrefix = "MY_SERVICE"
)

func main() {
	if err := runApp(); err != nil {
		golog.Fatal(err)
	}
}

func runApp() error {
	cfg := NewAppConfig()
	if err := config.NewDefaultLoader(serviceEnvVarPrefix).LoadFromFile("config.yml", config.DataTypeYAML, cfg); err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger, loggerClose := log.NewLogger(cfg.Log)
	defer loggerClose()

	jwtParser, err := authkit.NewJWTParser(cfg.Auth)
	if err != nil {
		return fmt.Errorf("create JWT parser: %w", err)
	}

	authNMw := authkit.JWTAuthMiddleware(serviceErrorDomain, jwtParser)

	srvMux := http.NewServeMux()
	srvMux.Handle("/", authNMw(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		jwtClaims := authkit.GetJWTClaimsFromContext(r.Context()) // get JWT claims from the request context
		_, _ = rw.Write([]byte(fmt.Sprintf("Hello, %s", jwtClaims.Subject)))
	})))
	if err = http.ListenAndServe(":8080", middleware.Logging(logger)(srvMux)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen and HTTP server: %w", err)
	}

	return nil
}

type AppConfig struct {
	Auth *authkit.Config `config:"auth"`
	Log  *log.Config     `config:"log"`
}

func NewAppConfig() *AppConfig {
	return &AppConfig{
		Log:  log.NewConfig(),
		Auth: authkit.NewConfig(),
	}
}

func (c *AppConfig) SetProviderDefaults(dp config.DataProvider) {
	config.CallSetProviderDefaultsForFields(c, dp)
}

func (c *AppConfig) Set(dp config.DataProvider) error {
	return config.CallSetForFields(c, dp)
}
