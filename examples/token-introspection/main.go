/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	golog "log"
	"net/http"

	"github.com/acronis/go-appkit/config"
	"github.com/acronis/go-appkit/httpserver/middleware"
	"github.com/acronis/go-appkit/log"

	"github.com/acronis/go-authkit"
	"github.com/acronis/go-authkit/jwt"
)

const (
	serviceErrorDomain  = "MyService"
	serviceEnvVarPrefix = "MY_SERVICE"
	serviceAccessPolicy = "my_service"
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

	// Create JWT parser.
	jwtParser, err := authkit.NewJWTParser(cfg.Auth)
	if err != nil {
		return fmt.Errorf("create JWT parser: %w", err)
	}

	// Create token introspector.
	tokenIntrospector, err := authkit.NewTokenIntrospector(cfg.Auth,
		introspectionTokenProvider{}, jwt.ScopeFilter{{ResourceNamespace: serviceAccessPolicy}})
	if err != nil {
		return fmt.Errorf("create token introspector: %w", err)
	}
	if tokenIntrospector.GRPCClient != nil {
		logger.Info("introspection will be performed via gRPC")
		defer func() {
			if closeErr := tokenIntrospector.GRPCClient.Close(); closeErr != nil {
				logger.Error("failed to close gRPC client", log.Error(closeErr))
			}
		}()
	}

	// Configure JWTAuthMiddleware that performs only authentication via OAuth2 token introspection endpoint.
	authNMw := authkit.JWTAuthMiddleware(serviceErrorDomain, jwtParser,
		authkit.WithJWTAuthMiddlewareTokenIntrospector(tokenIntrospector))

	// Configure JWTAuthMiddleware that performs authentication via token introspection endpoint
	// and authorization based on the user's roles.
	authZMw := authkit.JWTAuthMiddleware(serviceErrorDomain, jwtParser,
		authkit.WithJWTAuthMiddlewareTokenIntrospector(tokenIntrospector),
		authkit.WithJWTAuthMiddlewareVerifyAccess(
			authkit.NewVerifyAccessByRolesInJWT(authkit.Role{Namespace: serviceAccessPolicy, Name: "admin"})))

	// Create HTTP server and start it.
	srvMux := http.NewServeMux()
	// "/" endpoint will be available for all authenticated users.
	srvMux.Handle("/", authNMw(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		jwtClaims := authkit.GetJWTClaimsFromContext(r.Context()) // get JWT claims from the request context
		tokenSubject, _ := jwtClaims.GetSubject()                 // error is always nil here unless custom claims are used
		_, _ = rw.Write([]byte(fmt.Sprintf("Hello, %s", tokenSubject)))
	})))
	// "/admin" endpoint will be available only for users with the "admin" role.
	srvMux.Handle("/admin", authZMw(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		jwtClaims := authkit.GetJWTClaimsFromContext(r.Context()) // Get JWT claims from the request context.
		tokenSubject, _ := jwtClaims.GetSubject()                 // error is always nil here unless custom claims are used
		_, _ = rw.Write([]byte(fmt.Sprintf("Hi, %s", tokenSubject)))
	})))
	srvHandler := middleware.RequestID()(middleware.Logging(logger)(srvMux))
	if err = http.ListenAndServe(":8080", srvHandler); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen and HTTP server: %w", err)
	}

	return nil
}

type AppConfig struct {
	Auth *authkit.Config
	Log  *log.Config
}

func NewAppConfig() *AppConfig {
	return &AppConfig{
		Log:  log.NewConfig(log.WithKeyPrefix("log")),
		Auth: authkit.NewConfig(authkit.WithKeyPrefix("auth")),
	}
}

func (c *AppConfig) SetProviderDefaults(dp config.DataProvider) {
	config.CallSetProviderDefaultsForFields(c, dp)
}

func (c *AppConfig) Set(dp config.DataProvider) error {
	return config.CallSetForFields(c, dp)
}

type introspectionTokenProvider struct {
}

func (introspectionTokenProvider) GetToken(ctx context.Context, scope ...string) (string, error) {
	return "access-token-with-introspection-permission", nil
}

func (introspectionTokenProvider) Invalidate() {}
