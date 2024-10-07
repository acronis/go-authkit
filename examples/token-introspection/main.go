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
	"github.com/acronis/go-authkit/idptoken"

	"github.com/acronis/go-authkit"
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

	// create JWT parser and token introspector
	jwtParser, err := authkit.NewJWTParser(cfg.Auth, authkit.WithJWTParserLogger(logger))
	if err != nil {
		return fmt.Errorf("create JWT parser: %w", err)
	}
	introspectionScopeFilter := []idptoken.IntrospectionScopeFilterAccessPolicy{
		{ResourceNamespace: serviceAccessPolicy}}
	tokenIntrospector, err := authkit.NewTokenIntrospector(cfg.Auth, introspectionTokenProvider{},
		introspectionScopeFilter, authkit.WithTokenIntrospectorLogger(logger))

	logMw := middleware.Logging(logger)

	// configure JWTAuthMiddleware that performs only authentication via OAuth2 token introspection endpoint
	authNMw := authkit.JWTAuthMiddleware(serviceErrorDomain, jwtParser,
		authkit.WithJWTAuthMiddlewareTokenIntrospector(tokenIntrospector))

	// configure JWTAuthMiddleware that performs authentication via token introspection endpoint
	// and authorization based on the user's roles
	authZMw := authkit.JWTAuthMiddleware(serviceErrorDomain, jwtParser,
		authkit.WithJWTAuthMiddlewareTokenIntrospector(tokenIntrospector),
		authkit.WithJWTAuthMiddlewareVerifyAccess(
			authkit.NewVerifyAccessByRolesInJWT(authkit.Role{Namespace: serviceAccessPolicy, Name: "admin"})))

	// create HTTP server and start it
	srvMux := http.NewServeMux()
	// "/" endpoint will be available for all authenticated users
	srvMux.Handle("/", logMw(authNMw(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		jwtClaims := authkit.GetJWTClaimsFromContext(r.Context()) // get JWT claims from the request context
		_, _ = rw.Write([]byte(fmt.Sprintf("Hello, %s", jwtClaims.Subject)))
	}))))
	// "/admin" endpoint will be available only for users with the "admin" role
	srvMux.Handle("/admin", logMw(authZMw(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		jwtClaims := authkit.GetJWTClaimsFromContext(r.Context()) // get JWT claims from the request context
		_, _ = rw.Write([]byte(fmt.Sprintf("Hi, %s", jwtClaims.Subject)))
	}))))
	if err = http.ListenAndServe(":8080", srvMux); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

type introspectionTokenProvider struct {
}

func (introspectionTokenProvider) GetToken(ctx context.Context, scope ...string) (string, error) {
	return "token-with-introspection-permission", nil
}

func (introspectionTokenProvider) Invalidate() {}