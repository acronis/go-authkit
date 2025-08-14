/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/acronis/go-appkit/log"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/jwt"
)

// DefaultGRPCClientRequestTimeout is a default timeout for the gRPC requests.
const DefaultGRPCClientRequestTimeout = time.Second * 30

const (
	grpcMetaAuthorization = "authorization"
	grpcMetaRequestID     = "x-request-id"
	grpcMetaSessionID     = "x-session-id"
)

// GRPCClientOpts contains options for the GRPCClient.
type GRPCClientOpts struct {
	// LoggerProvider is a function that provides a logger for the client.
	LoggerProvider func(ctx context.Context) log.FieldLogger

	// RequestIDProvider is a function that provides a request ID for the client.
	// This request ID will be used for outgoing gRPC requests in the x-request-id metadata.
	RequestIDProvider func(ctx context.Context) string

	// RequestTimeout is a timeout for the gRPC requests.
	RequestTimeout time.Duration

	// UserAgent is a user agent string for the client.
	UserAgent string

	// PrometheusLibInstanceLabel is a label for Prometheus metrics.
	// It allows distinguishing metrics from different instances of the same library.
	PrometheusLibInstanceLabel string

	// ResultTemplate is a custom introspection result
	// that will be used instead of DefaultIntrospectionResult for unmarshalling introspection response.
	// It must implement IntrospectionResult interface.
	ResultTemplate IntrospectionResult
}

// GRPCClient is a client for the IDP token service that uses gRPC.
type GRPCClient struct {
	client            pb.IDPTokenServiceClient
	clientConn        *grpc.ClientConn
	reqTimeout        time.Duration
	promMetrics       *metrics.PrometheusMetrics
	requestIDProvider func(ctx context.Context) string
	resultTemplate    IntrospectionResult
	sessionID         atomic.Value
}

// NewGRPCClient creates a new GRPCClient instance that communicates with the IDP token service.
func NewGRPCClient(
	target string, transportCreds credentials.TransportCredentials,
) (*GRPCClient, error) {
	return NewGRPCClientWithOpts(target, transportCreds, GRPCClientOpts{})
}

// NewGRPCClientWithOpts creates a new GRPCClient instance that communicates with the IDP token service
// with the specified options.
func NewGRPCClientWithOpts(
	target string, transportCreds credentials.TransportCredentials, opts GRPCClientOpts,
) (*GRPCClient, error) {
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = DefaultGRPCClientRequestTimeout
	}
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithStatsHandler(&statsHandler{loggerProvider: opts.LoggerProvider}),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithUserAgent(opts.UserAgent),
	)
	if err != nil {
		return nil, fmt.Errorf("dial to %q: %w", target, err)
	}
	return &GRPCClient{
		client:            pb.NewIDPTokenServiceClient(conn),
		clientConn:        conn,
		reqTimeout:        opts.RequestTimeout,
		promMetrics:       metrics.GetPrometheusMetrics(opts.PrometheusLibInstanceLabel, metrics.SourceGRPCClient),
		requestIDProvider: opts.RequestIDProvider,
		resultTemplate:    opts.ResultTemplate,
	}, nil
}

// Close closes the client gRPC connection.
func (c *GRPCClient) Close() error {
	return c.clientConn.Close()
}

// TokenData contains the data of the token issuing response from the IDP service.
type TokenData struct {
	// AccessToken is the issued access token.
	AccessToken string

	// TokenType is the type of the issued access token.
	TokenType string

	// ExpiresIn is the duration of the access token validity.
	ExpiresIn time.Duration
}

// IntrospectToken introspects the token using the IDP token service.
func (c *GRPCClient) IntrospectToken(
	ctx context.Context, token string, scopeFilter jwt.ScopeFilter, accessToken string,
) (IntrospectionResult, error) {
	req := pb.IntrospectTokenRequest{
		Token:       token,
		ScopeFilter: make([]*pb.IntrospectionScopeFilter, len(scopeFilter)),
	}
	for i := range scopeFilter {
		req.ScopeFilter[i] = &pb.IntrospectionScopeFilter{ResourceNamespace: scopeFilter[i].ResourceNamespace}
	}

	if sessID := c.getSessionID(); sessID != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, grpcMetaSessionID, sessID)
	} else {
		ctx = metadata.AppendToOutgoingContext(ctx, grpcMetaAuthorization, makeBearerToken(accessToken))
	}
	if c.requestIDProvider != nil {
		ctx = metadata.AppendToOutgoingContext(ctx, grpcMetaRequestID, c.requestIDProvider(ctx))
	}

	var headerMD metadata.MD
	var resp *pb.IntrospectTokenResponse
	if err := c.do(ctx, "IDPTokenService/IntrospectToken", func(ctx context.Context) error {
		var innerErr error
		resp, innerErr = c.client.IntrospectToken(ctx, &req, grpc.Header(&headerMD))
		return innerErr
	}, &headerMD); err != nil {
		if errors.Is(err, ErrUnauthenticated) {
			c.setSessionID("")
		}
		return nil, err
	}

	if sessionIDMeta := headerMD.Get(grpcMetaSessionID); len(sessionIDMeta) > 0 {
		c.setSessionID(sessionIDMeta[0])
	}

	result := c.resultTemplate
	if result == nil {
		result = &DefaultIntrospectionResult{}
	}
	result.SetIsActive(resp.GetActive())
	if !result.IsActive() {
		return result, nil
	}

	result.SetTokenType(resp.GetTokenType())

	claims := result.GetClaims()
	claims.SetIssuer(resp.GetIss())
	claims.SetSubject(resp.GetSub())
	claims.SetAudience(resp.GetAud())
	claims.SetID(resp.GetJti())
	if resp.GetExp() != 0 {
		claims.SetExpirationTime(jwtgo.NewNumericDate(time.Unix(resp.GetExp(), 0)))
	}
	if resp.GetIat() != 0 {
		claims.SetIssuedAt(jwtgo.NewNumericDate(time.Unix(resp.GetIat(), 0)))
	}
	if resp.GetNbf() != 0 {
		claims.SetNotBefore(jwtgo.NewNumericDate(time.Unix(resp.GetNbf(), 0)))
	}
	scope := make([]jwt.AccessPolicy, len(resp.GetScope()))
	for i, s := range resp.GetScope() {
		scope[i] = jwt.AccessPolicy{
			ResourceNamespace: s.GetResourceNamespace(),
			Role:              s.GetRoleName(),
			ResourceServerID:  s.GetResourceServer(),
			ResourcePath:      s.GetResourcePath(),
			TenantUUID:        s.GetTenantUuid(),
		}
		if s.GetTenantIntId() != 0 {
			scope[i].TenantID = strconv.FormatInt(s.GetTenantIntId(), 10)
		}
	}
	claims.SetScope(scope)

	if customClaimsJSON := resp.GetCustomClaimsJson(); customClaimsJSON != "" {
		if err := json.Unmarshal(stringToBytesUnsafe(customClaimsJSON), result); err != nil {
			return nil, fmt.Errorf("unmarshal custom claims: %w", err)
		}
	}

	return result, nil
}

func (c *GRPCClient) getSessionID() string {
	id, ok := c.sessionID.Load().(string)
	if !ok {
		return ""
	}
	return id
}

func (c *GRPCClient) setSessionID(id string) {
	c.sessionID.Store(id)
}

type exchangeTokenOptions struct {
	notRequiredIntrospection bool
}

// ExchangeTokenOption is an option for the ExchangeToken method.
type ExchangeTokenOption func(*exchangeTokenOptions)

// WithNotRequiredIntrospection specifies that the new issued token will not require introspection.
func WithNotRequiredIntrospection(b bool) ExchangeTokenOption {
	return func(opts *exchangeTokenOptions) {
		opts.notRequiredIntrospection = b
	}
}

// ExchangeToken exchanges the token requesting a new token with the specified version.
func (c *GRPCClient) ExchangeToken(ctx context.Context, token string, opts ...ExchangeTokenOption) (TokenData, error) {
	var options exchangeTokenOptions
	for _, opt := range opts {
		opt(&options)
	}

	req := pb.CreateTokenRequest{
		GrantType:                idputil.GrantTypeJWTBearer,
		Assertion:                token,
		NotRequiredIntrospection: options.notRequiredIntrospection,
	}

	if c.requestIDProvider != nil {
		ctx = metadata.AppendToOutgoingContext(ctx, grpcMetaRequestID, c.requestIDProvider(ctx))
	}

	var headerMD metadata.MD
	var resp *pb.CreateTokenResponse
	if err := c.do(ctx, "IDPTokenService/CreateToken", func(ctx context.Context) error {
		var innerErr error
		resp, innerErr = c.client.CreateToken(ctx, &req, grpc.Header(&headerMD))
		return innerErr
	}, &headerMD); err != nil {
		return TokenData{}, err
	}

	return TokenData{
		AccessToken: resp.GetAccessToken(),
		TokenType:   resp.GetTokenType(),
		ExpiresIn:   time.Second * time.Duration(resp.GetExpiresIn()),
	}, nil
}

func (c *GRPCClient) do(
	ctx context.Context, methodName string, call func(ctx context.Context) error, headerMD *metadata.MD,
) error {
	getRetryAfter := func() string {
		if mdRetryAfter := headerMD.Get("retry-after"); len(mdRetryAfter) > 0 {
			return mdRetryAfter[0]
		}
		return ""
	}

	ctx, ctxCancel := context.WithTimeout(ctx, c.reqTimeout)
	defer ctxCancel()

	startTime := time.Now()
	err := call(ctx)
	elapsed := time.Since(startTime)
	if err != nil {
		var code grpccodes.Code
		if st, ok := grpcstatus.FromError(err); ok {
			code = st.Code()
		}
		c.promMetrics.ObserveGRPCClientRequest(methodName, code, elapsed)
		switch code {
		case grpccodes.Unauthenticated:
			return ErrUnauthenticated
		case grpccodes.PermissionDenied:
			return ErrPermissionDenied
		case grpccodes.ResourceExhausted:
			return &ThrottledError{RetryAfter: getRetryAfter(), Err: err}
		case grpccodes.Unavailable:
			return &ServiceUnavailableError{RetryAfter: getRetryAfter(), Err: err}
		}
		return err
	}
	c.promMetrics.ObserveGRPCClientRequest(methodName, grpccodes.OK, elapsed)

	return nil
}

type statsHandler struct {
	loggerProvider func(ctx context.Context) log.FieldLogger
}

func (sh *statsHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return ctx
}

func (sh *statsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
}

func (sh *statsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return ctx
}

func (sh *statsHandler) HandleConn(ctx context.Context, s stats.ConnStats) {
	switch s.(type) {
	case *stats.ConnBegin:
		idputil.GetLoggerFromProvider(ctx, sh.loggerProvider).Infof("grpc connection established")
	case *stats.ConnEnd:
		idputil.GetLoggerFromProvider(ctx, sh.loggerProvider).Infof("grpc connection closed")
	}
}

// stringToBytesUnsafe converts string to byte slice without memory allocation.
func stringToBytesUnsafe(s string) []byte {
	// nolint: gosec // memory optimization to prevent redundant slice copying
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
