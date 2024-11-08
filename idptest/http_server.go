/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/acronis/go-appkit/testutil"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

const (
	OpenIDConfigurationPath        = "/.well-known/openid-configuration"
	JWKSEndpointPath               = "/idp/keys"
	TokenEndpointPath              = "/idp/token"
	TokenIntrospectionEndpointPath = "/idp/introspect_token" // nolint:gosec // This server is used for testing purposes only.
)

const localhostWithDynamicPortAddr = "127.0.0.1:0"

var ErrUnauthorized = errors.New("unauthorized")

// HTTPClaimsProvider is an interface for providing JWT claims for an issuing token request via HTTP.
type HTTPClaimsProvider interface {
	Provide(r *http.Request) (jwt.Claims, error)
}

// HTTPClaimsProviderFunc is a function that implements HTTPClaimsProvider interface.
type HTTPClaimsProviderFunc func(r *http.Request) (jwt.Claims, error)

// Provide implements HTTPClaimsProvider interface.
func (f HTTPClaimsProviderFunc) Provide(r *http.Request) (jwt.Claims, error) {
	return f(r)
}

// HTTPTokenIntrospector is an interface for introspecting tokens via HTTP.
type HTTPTokenIntrospector interface {
	IntrospectToken(r *http.Request, token string) (idptoken.IntrospectionResult, error)
}

// HTTPTokenIntrospectorFunc is a function that implements HTTPTokenIntrospector interface.
type HTTPTokenIntrospectorFunc func(r *http.Request, token string) (idptoken.IntrospectionResult, error)

// IntrospectToken implements HTTPTokenIntrospector interface.
func (f HTTPTokenIntrospectorFunc) IntrospectToken(r *http.Request, token string) (idptoken.IntrospectionResult, error) {
	return f(r, token)
}

// HTTPServerOption is an option for HTTPServer.
type HTTPServerOption func(s *HTTPServer)

// WithHTTPAddress is an option to set HTTP server address.
func WithHTTPAddress(addr string) HTTPServerOption {
	return func(s *HTTPServer) {
		s.addr.Store(addr)
	}
}

// WithHTTPEndpointPaths is an option to set custom paths for different IDP endpoints.
func WithHTTPEndpointPaths(paths HTTPPaths) HTTPServerOption {
	return func(s *HTTPServer) {
		s.paths = paths
	}
}

// WithHTTPKeysHandler is an option to set custom handler for GET /idp/keys.
// Otherwise, JWKSHandler will be used.
func WithHTTPKeysHandler(handler http.Handler) HTTPServerOption {
	return func(s *HTTPServer) {
		s.KeysHandler = handler
	}
}

// WithHTTPPublicJWKS is an option to set public JWKS for JWKSHandler which will be used for GET /idp/keys.
func WithHTTPPublicJWKS(keys []PublicJWK) HTTPServerOption {
	return func(s *HTTPServer) {
		s.KeysHandler = &JWKSHandler{PublicJWKS: keys}
	}
}

// WithHTTPTokenHandler is an option to set custom handler for POST /idp/token.
func WithHTTPTokenHandler(handler http.Handler) HTTPServerOption {
	return func(s *HTTPServer) {
		s.TokenHandler = handler
	}
}

// WithHTTPClaimsProvider is an option to set ClaimsProvider for TokenHandler
// which will be used for POST /idp/token.
func WithHTTPClaimsProvider(claimsProvider HTTPClaimsProvider) HTTPServerOption {
	return func(s *HTTPServer) {
		h := &TokenHandler{ClaimsProvider: claimsProvider}
		s.TokenHandler = h
		s.afterListenCallbacks = append(s.afterListenCallbacks, func() {
			h.Issuer = s.URL()
		})
	}
}

// WithHTTPIntrospectTokenHandler is an option to set custom handler for POST /idp/introspect_token.
func WithHTTPIntrospectTokenHandler(handler http.Handler) HTTPServerOption {
	return func(s *HTTPServer) {
		s.TokenIntrospectionHandler = handler
	}
}

// WithHTTPTokenIntrospector is an option to set TokenIntrospector for TokenIntrospectionHandler
// which will be used for POST /idp/introspect_token.
func WithHTTPTokenIntrospector(introspector HTTPTokenIntrospector) HTTPServerOption {
	return func(s *HTTPServer) {
		h := &TokenIntrospectionHandler{TokenIntrospector: introspector}
		s.TokenIntrospectionHandler = h
		s.afterListenCallbacks = append(s.afterListenCallbacks, func() {
			h.JWTParser = s.makeJWTParser()
		})
	}
}

func WithHTTPMiddleware(mw func(http.Handler) http.Handler) HTTPServerOption {
	return func(s *HTTPServer) {
		s.middleware = mw
	}
}

// HTTPPaths contains paths for different IDP endpoints.
type HTTPPaths struct {
	OpenIDConfiguration string
	Token               string
	TokenIntrospection  string
	JWKS                string
}

// HTTPServer is a mock IDP server for testing purposes.
type HTTPServer struct {
	*http.Server
	addr                       atomic.Value
	middleware                 func(http.Handler) http.Handler
	paths                      HTTPPaths
	KeysHandler                http.Handler
	TokenHandler               http.Handler
	TokenIntrospectionHandler  http.Handler
	OpenIDConfigurationHandler http.Handler
	Router                     *http.ServeMux
	afterListenCallbacks       []func()
}

// NewHTTPServer creates a new IDPMockServer with provided options.
func NewHTTPServer(options ...HTTPServerOption) *HTTPServer {
	s := &HTTPServer{}
	for _, opt := range options {
		opt(s)
	}

	if s.TokenHandler == nil {
		tokenHandler := &TokenHandler{}
		s.TokenHandler = tokenHandler
		s.afterListenCallbacks = append(s.afterListenCallbacks, func() {
			tokenHandler.Issuer = s.URL()
		})
	}

	if s.TokenIntrospectionHandler == nil {
		introspectionHandler := &TokenIntrospectionHandler{}
		s.TokenIntrospectionHandler = introspectionHandler
		s.afterListenCallbacks = append(s.afterListenCallbacks, func() {
			introspectionHandler.JWTParser = s.makeJWTParser()
		})
	}

	if s.KeysHandler == nil {
		s.KeysHandler = &JWKSHandler{}
	}

	// Configure OpenIDConfigurationHandler.
	if s.paths.OpenIDConfiguration == "" {
		s.paths.OpenIDConfiguration = OpenIDConfigurationPath
	}
	if s.paths.Token == "" {
		s.paths.Token = TokenEndpointPath
	}
	if s.paths.TokenIntrospection == "" {
		s.paths.TokenIntrospection = TokenIntrospectionEndpointPath
	}
	if s.paths.JWKS == "" {
		s.paths.JWKS = JWKSEndpointPath
	}
	openIDCfgHandler := &OpenIDConfigurationHandler{}
	s.OpenIDConfigurationHandler = openIDCfgHandler
	s.afterListenCallbacks = append(s.afterListenCallbacks, func() {
		openIDCfgHandler.JWKSURL = s.URL() + s.paths.JWKS
		openIDCfgHandler.TokenEndpointURL = s.URL() + s.paths.Token
		openIDCfgHandler.IntrospectionEndpointURL = s.URL() + s.paths.TokenIntrospection
	})

	s.Router = http.NewServeMux()
	s.Router.Handle(s.paths.OpenIDConfiguration, s.OpenIDConfigurationHandler)
	s.Router.Handle(s.paths.JWKS, s.KeysHandler)
	s.Router.Handle(s.paths.Token, s.TokenHandler)
	s.Router.Handle(s.paths.TokenIntrospection, s.TokenIntrospectionHandler)

	// nolint:gosec // This server is used for testing purposes only.
	s.Server = &http.Server{Handler: s.Router}
	if s.middleware != nil {
		s.Server.Handler = s.middleware(s.Router)
	}

	return s
}

// URL method returns the URL of the server.
func (s *HTTPServer) URL() string {
	if srvURL := s.addr.Load(); srvURL != nil {
		return "http://" + srvURL.(string)
	}
	return ""
}

// Start starts the HTTPServer.
func (s *HTTPServer) Start() error {
	addr, ok := s.addr.Load().(string)
	if !ok {
		addr = localhostWithDynamicPortAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}
	s.addr.Store(ln.Addr().String())

	for _, cb := range s.afterListenCallbacks {
		cb()
	}

	go func() { _ = s.Server.Serve(ln) }()

	return nil
}

// StartAndWaitForReady starts the server waits for the server to start listening.
func (s *HTTPServer) StartAndWaitForReady(timeout time.Duration) error {
	if err := s.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	return testutil.WaitListeningServer(s.addr.Load().(string), timeout)
}

func (s *HTTPServer) makeJWTParser() *jwt.Parser {
	p := jwt.NewParser(jwks.NewClient())
	_ = p.AddTrustedIssuerURL(s.URL())
	return p
}
