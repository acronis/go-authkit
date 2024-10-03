/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/acronis/go-appkit/log"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

// Default values.
const (
	DefaultHTTPClientRequestTimeout = time.Second * 30
	DefaultGRPCClientRequestTimeout = time.Second * 30
)

// NewJWTParser creates a new JWTParser with the given configuration.
// If cfg.JWT.ClaimsCache.Enabled is true, then jwt.CachingParser created, otherwise - jwt.Parser.
func NewJWTParser(cfg *Config, opts ...JWTParserOption) (JWTParser, error) {
	var options jwtParserOptions
	for _, opt := range opts {
		opt(&options)
	}
	logger := options.logger
	if logger == nil {
		logger = log.NewDisabledLogger()
	}

	// Make caching JWKS client.
	jwksCacheUpdateMinInterval := cfg.JWKS.Cache.UpdateMinInterval
	if jwksCacheUpdateMinInterval == 0 {
		jwksCacheUpdateMinInterval = jwks.DefaultCacheUpdateMinInterval
	}
	httpClientRequestTimeout := cfg.HTTPClient.RequestTimeout
	if httpClientRequestTimeout == 0 {
		httpClientRequestTimeout = DefaultHTTPClientRequestTimeout
	}
	jwksClientOpts := jwks.CachingClientOpts{
		ClientOpts:             jwks.ClientOpts{PrometheusLibInstanceLabel: options.prometheusLibInstanceLabel},
		CacheUpdateMinInterval: jwksCacheUpdateMinInterval,
	}
	jwksClient := jwks.NewCachingClientWithOpts(&http.Client{Timeout: httpClientRequestTimeout}, logger, jwksClientOpts)

	// Make JWT parser.

	if len(cfg.JWT.TrustedIssuers) == 0 && len(cfg.JWT.TrustedIssuerURLs) == 0 {
		logger.Warn("list of trusted issuers is empty, jwt parsing may not work properly")
	}

	parserOpts := jwt.ParserOpts{
		RequireAudience:               cfg.JWT.RequireAudience,
		ExpectedAudience:              cfg.JWT.ExpectedAudience,
		TrustedIssuerNotFoundFallback: options.trustedIssuerNotFoundFallback,
	}

	if cfg.JWT.ClaimsCache.Enabled {
		cachingJWTParser, err := jwt.NewCachingParserWithOpts(jwksClient, logger, jwt.CachingParserOpts{
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

	jwtParser := jwt.NewParserWithOpts(jwksClient, logger, parserOpts)
	if err := addTrustedIssuers(jwtParser, cfg.JWT.TrustedIssuers, cfg.JWT.TrustedIssuerURLs); err != nil {
		return nil, err
	}
	return jwtParser, nil
}

type jwtParserOptions struct {
	logger                        log.FieldLogger
	prometheusLibInstanceLabel    string
	trustedIssuerNotFoundFallback jwt.TrustedIssNotFoundFallback
}

// JWTParserOption is an option for creating JWTParser.
type JWTParserOption func(options *jwtParserOptions)

// WithJWTParserLogger sets the logger for JWTParser.
func WithJWTParserLogger(logger log.FieldLogger) JWTParserOption {
	return func(options *jwtParserOptions) {
		options.logger = logger
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

// NewTokenIntrospector creates a new TokenIntrospector with the given configuration, token provider and scope filter.
// If cfg.Introspection.ClaimsCache.Enabled or cfg.Introspection.NegativeCache.Enabled is true,
// then idptoken.CachingIntrospector created, otherwise - idptoken.Introspector.
// Please note that the tokenProvider should be able to provide access token with the policy for introspection.
// scopeFilter is a list of filters that will be applied to the introspected token.
func NewTokenIntrospector(
	cfg *Config,
	tokenProvider idptoken.IntrospectionTokenProvider,
	scopeFilter []idptoken.IntrospectionScopeFilterAccessPolicy,
	opts ...TokenIntrospectorOption,
) (TokenIntrospector, error) {
	var options tokenIntrospectorOptions
	for _, opt := range opts {
		opt(&options)
	}
	logger := options.logger
	if logger == nil {
		logger = log.NewDisabledLogger()
	}

	if len(cfg.JWT.TrustedIssuers) == 0 && len(cfg.JWT.TrustedIssuerURLs) == 0 {
		logger.Warn("list of trusted issuers is empty, jwt introspection may not work properly")
	}

	var grpcClient *idptoken.GRPCClient
	if cfg.Introspection.GRPC.Target != "" {
		transportCreds, err := makeGRPCTransportCredentials(cfg.Introspection.GRPC.TLS)
		if err != nil {
			return nil, fmt.Errorf("make grpc transport credentials: %w", err)
		}
		grpcClient, err = idptoken.NewGRPCClientWithOpts(cfg.Introspection.GRPC.Target, transportCreds,
			idptoken.GRPCClientOpts{RequestTimeout: cfg.GRPCClient.RequestTimeout, Logger: logger})
		if err != nil {
			return nil, fmt.Errorf("new grpc client: %w", err)
		}
	}

	httpClientRequestTimeout := cfg.HTTPClient.RequestTimeout
	if httpClientRequestTimeout == 0 {
		httpClientRequestTimeout = DefaultHTTPClientRequestTimeout
	}

	introspectorOpts := idptoken.IntrospectorOpts{
		StaticHTTPEndpoint:            cfg.Introspection.Endpoint,
		GRPCClient:                    grpcClient,
		HTTPClient:                    &http.Client{Timeout: httpClientRequestTimeout},
		AccessTokenScope:              cfg.Introspection.AccessTokenScope,
		Logger:                        logger,
		ScopeFilter:                   scopeFilter,
		TrustedIssuerNotFoundFallback: options.trustedIssuerNotFoundFallback,
		PrometheusLibInstanceLabel:    options.prometheusLibInstanceLabel,
	}

	if cfg.Introspection.ClaimsCache.Enabled || cfg.Introspection.NegativeCache.Enabled {
		cachingIntrospector, err := idptoken.NewCachingIntrospectorWithOpts(tokenProvider, idptoken.CachingIntrospectorOpts{
			IntrospectorOpts: introspectorOpts,
			ClaimsCache: idptoken.CachingIntrospectorCacheOpts{
				Enabled:    cfg.Introspection.ClaimsCache.Enabled,
				MaxEntries: cfg.Introspection.ClaimsCache.MaxEntries,
				TTL:        cfg.Introspection.ClaimsCache.TTL,
			},
			NegativeCache: idptoken.CachingIntrospectorCacheOpts{
				Enabled:    cfg.Introspection.NegativeCache.Enabled,
				MaxEntries: cfg.Introspection.NegativeCache.MaxEntries,
				TTL:        cfg.Introspection.NegativeCache.TTL,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("new caching introspector: %w", err)
		}
		if err = addTrustedIssuers(cachingIntrospector, cfg.JWT.TrustedIssuers, cfg.JWT.TrustedIssuerURLs); err != nil {
			return nil, err
		}
		return cachingIntrospector, nil
	}

	introspector := idptoken.NewIntrospectorWithOpts(tokenProvider, introspectorOpts)
	if err := addTrustedIssuers(introspector, cfg.JWT.TrustedIssuers, cfg.JWT.TrustedIssuerURLs); err != nil {
		return nil, err
	}
	return introspector, nil
}

type tokenIntrospectorOptions struct {
	logger                        log.FieldLogger
	prometheusLibInstanceLabel    string
	trustedIssuerNotFoundFallback idptoken.TrustedIssNotFoundFallback
}

// TokenIntrospectorOption is an option for creating TokenIntrospector.
type TokenIntrospectorOption func(options *tokenIntrospectorOptions)

// WithTokenIntrospectorLogger sets the logger for TokenIntrospector.
func WithTokenIntrospectorLogger(logger log.FieldLogger) TokenIntrospectorOption {
	return func(options *tokenIntrospectorOptions) {
		options.logger = logger
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

// Role is a representation of role which may be used for verifying access.
type Role struct {
	Namespace string
	Name      string
}

// NewVerifyAccessByRolesInJWT creates a new function which may be used for verifying access by roles in JWT scope.
func NewVerifyAccessByRolesInJWT(roles ...Role) func(r *http.Request, claims *jwt.Claims) bool {
	return func(_ *http.Request, claims *jwt.Claims) bool {
		for i := range roles {
			for j := range claims.Scope {
				if roles[i].Name == claims.Scope[j].Role && roles[i].Namespace == claims.Scope[j].ResourceNamespace {
					return true
				}
			}
		}
		return false
	}
}

// NewVerifyAccessByRolesInJWTMaker creates a new function which may be used for verifying access by roles in JWT scope given a namespace.
func NewVerifyAccessByRolesInJWTMaker(namespace string) func(roleNames ...string) func(r *http.Request, claims *jwt.Claims) bool {
	return func(roleNames ...string) func(r *http.Request, claims *jwt.Claims) bool {
		roles := make([]Role, 0, len(roleNames))
		for i := range roleNames {
			roles = append(roles, Role{Namespace: namespace, Name: roleNames[i]})
		}
		return NewVerifyAccessByRolesInJWT(roles...)
	}
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
