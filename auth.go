/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/acronis/go-appkit/httpserver/middleware"
	"github.com/acronis/go-appkit/log"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/libinfo"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

// NewJWTParser creates a new JWTParser with the given configuration.
// If cfg.JWT.ClaimsCache.Enabled is true, then jwt.CachingParser created, otherwise - jwt.Parser.
func NewJWTParser(cfg *Config, opts ...JWTParserOption) (JWTParser, error) {
	options := jwtParserOptions{loggerProvider: middleware.GetLoggerFromContext}
	for _, opt := range opts {
		opt(&options)
	}

	// Make caching JWKS client.
	jwksCacheUpdateMinInterval := cfg.JWKS.Cache.UpdateMinInterval
	if jwksCacheUpdateMinInterval == 0 {
		jwksCacheUpdateMinInterval = jwks.DefaultCacheUpdateMinInterval
	}
	jwksClientOpts := jwks.CachingClientOpts{
		ClientOpts: jwks.ClientOpts{
			LoggerProvider:             options.loggerProvider,
			HTTPClient:                 idputil.MakeDefaultHTTPClient(cfg.HTTPClient.RequestTimeout, options.loggerProvider),
			PrometheusLibInstanceLabel: options.prometheusLibInstanceLabel,
		},
		CacheUpdateMinInterval: jwksCacheUpdateMinInterval,
	}
	jwksClient := jwks.NewCachingClientWithOpts(jwksClientOpts)

	// Make JWT parser.

	if len(cfg.JWT.TrustedIssuers) == 0 && len(cfg.JWT.TrustedIssuerURLs) == 0 {
		idputil.GetLoggerFromProvider(context.Background(), options.loggerProvider).Warn(
			"list of trusted issuers is empty, jwt parsing may not work properly")
	}

	parserOpts := jwt.ParserOpts{
		RequireAudience:               cfg.JWT.RequireAudience,
		ExpectedAudience:              cfg.JWT.ExpectedAudience,
		TrustedIssuerNotFoundFallback: options.trustedIssuerNotFoundFallback,
		LoggerProvider:                options.loggerProvider,
		ClaimsTemplate:                options.claimsTemplate,
		ScopeFilter:                   options.scopeFilter,
	}

	if cfg.JWT.ClaimsCache.Enabled {
		cachingJWTParser, err := jwt.NewCachingParserWithOpts(jwksClient, jwt.CachingParserOpts{
			ParserOpts:      parserOpts,
			CacheMaxEntries: cfg.JWT.ClaimsCache.MaxEntries,
		})
		if err != nil {
			return nil, fmt.Errorf("new caching JWT parser: %w", err)
		}
		if err = addTrustedIssuers(cachingJWTParser, cfg.JWT.TrustedIssuers, cfg.JWT.TrustedIssuerURLs); err != nil {
			return nil, err
		}
		return cachingJWTParser, nil
	}

	jwtParser := jwt.NewParserWithOpts(jwksClient, parserOpts)
	if err := addTrustedIssuers(jwtParser, cfg.JWT.TrustedIssuers, cfg.JWT.TrustedIssuerURLs); err != nil {
		return nil, err
	}
	return jwtParser, nil
}

type jwtParserOptions struct {
	loggerProvider                func(ctx context.Context) log.FieldLogger
	prometheusLibInstanceLabel    string
	trustedIssuerNotFoundFallback jwt.TrustedIssNotFoundFallback
	claimsTemplate                jwt.Claims
	scopeFilter                   jwt.ScopeFilter
}

// JWTParserOption is an option for creating JWTParser.
type JWTParserOption func(options *jwtParserOptions)

// WithJWTParserLoggerProvider sets the logger provider for JWTParser.
func WithJWTParserLoggerProvider(loggerProvider func(ctx context.Context) log.FieldLogger) JWTParserOption {
	return func(options *jwtParserOptions) {
		options.loggerProvider = loggerProvider
	}
}

// WithJWTParserPrometheusLibInstanceLabel sets the Prometheus lib instance label for JWTParser.
func WithJWTParserPrometheusLibInstanceLabel(label string) JWTParserOption {
	return func(options *jwtParserOptions) {
		options.prometheusLibInstanceLabel = label
	}
}

// WithJWTParserTrustedIssuerNotFoundFallback sets the fallback for JWTParser when trusted issuer is not found.
func WithJWTParserTrustedIssuerNotFoundFallback(fallback jwt.TrustedIssNotFoundFallback) JWTParserOption {
	return func(options *jwtParserOptions) {
		options.trustedIssuerNotFoundFallback = fallback
	}
}

// WithJWTParserClaimsTemplate sets the claims template for JWTParser.
func WithJWTParserClaimsTemplate(claimsTemplate jwt.Claims) JWTParserOption {
	return func(options *jwtParserOptions) {
		options.claimsTemplate = claimsTemplate
	}
}

// WithJWTParserScopeFilter sets the scope filter for JWTParser.
// If it's used, then only access policies in scope that match at least one of the filtering policies will be returned.
// It's useful when the claims cache is used (cfg.JWT.ClaimsCache.Enabled is true),
// and we want to store only some of the access policies in the cache to reduce memory usage.
func WithJWTParserScopeFilter(scopeFilter jwt.ScopeFilter) JWTParserOption {
	return func(options *jwtParserOptions) {
		options.scopeFilter = scopeFilter
	}
}

// NewTokenIntrospector creates a new TokenIntrospector with the given configuration, token provider and scope filter.
// If cfg.Introspection.ClaimsCache.Enabled or cfg.Introspection.NegativeCache.Enabled is true,
// then idptoken.CachingIntrospector created, otherwise - idptoken.Introspector.
// Please note that the tokenProvider should be able to provide access token with the policy for introspection.
// scopeFilter is a list of filters that will be applied to the introspected token.
func NewTokenIntrospector(
	cfg *Config,
	tokenProvider idptoken.IntrospectionTokenProvider,
	scopeFilter jwt.ScopeFilter,
	opts ...TokenIntrospectorOption,
) (*idptoken.Introspector, error) {
	options := tokenIntrospectorOptions{loggerProvider: middleware.GetLoggerFromContext}
	for _, opt := range opts {
		opt(&options)
	}

	if len(cfg.JWT.TrustedIssuers) == 0 && len(cfg.JWT.TrustedIssuerURLs) == 0 {
		idputil.GetLoggerFromProvider(context.Background(), options.loggerProvider).Warn(
			"list of trusted issuers is empty, jwt introspection may not work properly")
	}

	var grpcClient *idptoken.GRPCClient
	if cfg.Introspection.GRPC.Endpoint != "" {
		transportCreds, err := makeGRPCTransportCredentials(cfg.Introspection.GRPC.TLS)
		if err != nil {
			return nil, fmt.Errorf("make grpc transport credentials: %w", err)
		}
		grpcClientOpts := idptoken.GRPCClientOpts{
			RequestTimeout: cfg.GRPCClient.RequestTimeout,
			LoggerProvider: options.loggerProvider,
			UserAgent:      libinfo.UserAgent(),
		}
		if grpcClient, err = idptoken.NewGRPCClientWithOpts(
			cfg.Introspection.GRPC.Endpoint, transportCreds, grpcClientOpts,
		); err != nil {
			return nil, fmt.Errorf("new grpc client: %w", err)
		}
	}

	introspectorOpts := idptoken.IntrospectorOpts{
		HTTPEndpoint:                  cfg.Introspection.Endpoint,
		GRPCClient:                    grpcClient,
		HTTPClient:                    idputil.MakeDefaultHTTPClient(cfg.HTTPClient.RequestTimeout, options.loggerProvider),
		AccessTokenScope:              cfg.Introspection.AccessTokenScope,
		LoggerProvider:                options.loggerProvider,
		ResultTemplate:                options.resultTemplate,
		ScopeFilter:                   scopeFilter,
		TrustedIssuerNotFoundFallback: options.trustedIssuerNotFoundFallback,
		PrometheusLibInstanceLabel:    options.prometheusLibInstanceLabel,
		ClaimsCache: idptoken.IntrospectorCacheOpts{
			Enabled:    cfg.Introspection.ClaimsCache.Enabled,
			MaxEntries: cfg.Introspection.ClaimsCache.MaxEntries,
			TTL:        cfg.Introspection.ClaimsCache.TTL,
		},
		NegativeCache: idptoken.IntrospectorCacheOpts{
			Enabled:    cfg.Introspection.NegativeCache.Enabled,
			MaxEntries: cfg.Introspection.NegativeCache.MaxEntries,
			TTL:        cfg.Introspection.NegativeCache.TTL,
		},
	}
	introspector, err := idptoken.NewIntrospectorWithOpts(tokenProvider, introspectorOpts)
	if err != nil {
		return nil, err
	}

	if err = addTrustedIssuers(introspector, cfg.JWT.TrustedIssuers, cfg.JWT.TrustedIssuerURLs); err != nil {
		return nil, err
	}

	return introspector, nil
}

type tokenIntrospectorOptions struct {
	loggerProvider                func(ctx context.Context) log.FieldLogger
	prometheusLibInstanceLabel    string
	trustedIssuerNotFoundFallback idptoken.TrustedIssNotFoundFallback
	resultTemplate                idptoken.IntrospectionResult
}

// TokenIntrospectorOption is an option for creating TokenIntrospector.
type TokenIntrospectorOption func(options *tokenIntrospectorOptions)

// WithTokenIntrospectorLoggerProvider sets the logger provider for TokenIntrospector.
func WithTokenIntrospectorLoggerProvider(loggerProvider func(ctx context.Context) log.FieldLogger) TokenIntrospectorOption {
	return func(options *tokenIntrospectorOptions) {
		options.loggerProvider = loggerProvider
	}
}

// WithTokenIntrospectorPrometheusLibInstanceLabel sets the Prometheus lib instance label for TokenIntrospector.
func WithTokenIntrospectorPrometheusLibInstanceLabel(label string) TokenIntrospectorOption {
	return func(options *tokenIntrospectorOptions) {
		options.prometheusLibInstanceLabel = label
	}
}

// WithTokenIntrospectorTrustedIssuerNotFoundFallback sets the fallback for TokenIntrospector
// when trusted issuer is not found.
func WithTokenIntrospectorTrustedIssuerNotFoundFallback(
	fallback idptoken.TrustedIssNotFoundFallback,
) TokenIntrospectorOption {
	return func(options *tokenIntrospectorOptions) {
		options.trustedIssuerNotFoundFallback = fallback
	}
}

// WithTokenIntrospectorResultTemplate sets the result template for TokenIntrospector.
func WithTokenIntrospectorResultTemplate(resultTemplate idptoken.IntrospectionResult) TokenIntrospectorOption {
	return func(options *tokenIntrospectorOptions) {
		options.resultTemplate = resultTemplate
	}
}

// Role is a representation of role which may be used for verifying access.
type Role struct {
	Namespace string
	Name      string
}

// NewVerifyAccessByRolesInJWT creates a new function which may be used for verifying access by roles in JWT scope.
func NewVerifyAccessByRolesInJWT(roles ...Role) func(r *http.Request, claims jwt.Claims) bool {
	return func(_ *http.Request, claims jwt.Claims) bool {
		claimsScope := claims.GetScope()
		for i := range roles {
			for j := range claimsScope {
				if roles[i].Name == claimsScope[j].Role && roles[i].Namespace == claimsScope[j].ResourceNamespace {
					return true
				}
			}
		}
		return false
	}
}

// NewVerifyAccessByRolesInJWTMaker creates a new function which may be used for verifying access by roles in JWT scope given a namespace.
func NewVerifyAccessByRolesInJWTMaker(namespace string) func(roleNames ...string) func(r *http.Request, claims jwt.Claims) bool {
	return func(roleNames ...string) func(r *http.Request, claims jwt.Claims) bool {
		roles := make([]Role, 0, len(roleNames))
		for i := range roleNames {
			roles = append(roles, Role{Namespace: namespace, Name: roleNames[i]})
		}
		return NewVerifyAccessByRolesInJWT(roles...)
	}
}

// SetDefaultLogger sets the default logger for the library.
func SetDefaultLogger(logger log.FieldLogger) {
	idputil.DefaultLogger = logger
}

type issuerParser interface {
	AddTrustedIssuer(issName string, issURL string)
	AddTrustedIssuerURL(issURL string) error
}

func addTrustedIssuers(issParser issuerParser, issuers map[string]string, issuerURLs []string) error {
	for issName, issURL := range issuers {
		issParser.AddTrustedIssuer(issName, issURL)
	}
	for _, issURL := range issuerURLs {
		if err := issParser.AddTrustedIssuerURL(issURL); err != nil {
			return fmt.Errorf("add trusted issuer URL: %w", err)
		}
	}
	return nil
}

func makeGRPCTransportCredentials(tlsCfg GRPCTLSConfig) (credentials.TransportCredentials, error) {
	if !tlsCfg.Enabled {
		return insecure.NewCredentials(), nil
	}

	config := &tls.Config{} // nolint: gosec // TLS 1.2 is used by default.
	if tlsCfg.CACert != "" {
		caCert, err := os.ReadFile(tlsCfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA's certificate: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to add CA's certificate")
		}
		config.RootCAs = certPool
	}
	if tlsCfg.ClientCert != "" && tlsCfg.ClientKey != "" {
		clientCert, err := tls.LoadX509KeyPair(tlsCfg.ClientCert, tlsCfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client's certificate and key: %w", err)
		}
		config.Certificates = []tls.Certificate{clientCert}
	}
	return credentials.NewTLS(config), nil
}
