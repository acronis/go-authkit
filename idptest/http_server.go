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

// HTTPClaimsProvider is an interface for providing JWT claims in HTTP handlers.
type HTTPClaimsProvider interface {
	Provide(r *http.Request) (jwt.Claims, error)
}

// HTTPTokenIntrospector is an interface for introspecting tokens.
type HTTPTokenIntrospector interface {
	IntrospectToken(r *http.Request, token string) (idptoken.IntrospectionResult, error)
}

type HTTPServerOption func(s *HTTPServer)

// WithHTTPAddress is an option to set HTTP server address.
func WithHTTPAddress(addr string) HTTPServerOption {
	return func(s *HTTPServer) {
		s.addr.Store(addr)
	}
}

// WithHTTPOpenIDConfigurationHandler is an option to set custom handler for GET /.well-known/openid-configuration.
// Otherwise, OpenIDConfigurationHandler will be used.
func WithHTTPOpenIDConfigurationHandler(handler http.HandlerFunc) HTTPServerOption {
	return func(s *HTTPServer) {
		s.OpenIDConfigurationHandler = handler
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
		s.TokenHandler = &TokenHandler{ClaimsProvider: claimsProvider}
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
		s.TokenIntrospectionHandler = &TokenIntrospectionHandler{TokenIntrospector: introspector}
	}
}

func WithHTTPMiddleware(mw func(http.Handler) http.Handler) HTTPServerOption {
	return func(s *HTTPServer) {
		s.middleware = mw
	}
}

// HTTPServer is a mock IDP server for testing purposes.
type HTTPServer struct {
	*http.Server
	addr                       atomic.Value
	middleware                 func(http.Handler) http.Handler
	KeysHandler                http.Handler
	TokenHandler               http.Handler
	TokenIntrospectionHandler  http.Handler
	OpenIDConfigurationHandler http.Handler
	Router                     *http.ServeMux
}

// NewHTTPServer creates a new IDPMockServer with provided options.
func NewHTTPServer(options ...HTTPServerOption) *HTTPServer {
	s := &HTTPServer{
		Router:                    http.NewServeMux(),
		TokenHandler:              &TokenHandler{},
		KeysHandler:               &JWKSHandler{},
		TokenIntrospectionHandler: &TokenIntrospectionHandler{},
	}
	s.OpenIDConfigurationHandler = &OpenIDConfigurationHandler{
		BaseURLFunc:              s.URL,
		JWKSURL:                  JWKSEndpointPath,
		TokenEndpointURL:         TokenEndpointPath,
		IntrospectionEndpointURL: TokenIntrospectionEndpointPath,
	}

	for _, opt := range options {
		opt(s)
	}

	s.Router.Handle(OpenIDConfigurationPath, s.OpenIDConfigurationHandler)
	s.Router.Handle(JWKSEndpointPath, s.KeysHandler)
	s.Router.Handle(TokenEndpointPath, s.TokenHandler)
	s.Router.Handle(TokenIntrospectionEndpointPath, s.TokenIntrospectionHandler)

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
