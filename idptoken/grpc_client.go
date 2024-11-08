/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"context"
	"fmt"
	"strconv"
	"time"

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

const grpcMetaAuthorization = "authorization"

// GRPCClientOpts contains options for the GRPCClient.
type GRPCClientOpts struct {
	// LoggerProvider is a function that provides a logger for the client.
	LoggerProvider func(ctx context.Context) log.FieldLogger

	// RequestTimeout is a timeout for the gRPC requests.
	RequestTimeout time.Duration

	// UserAgent is a user agent string for the client.
	UserAgent string

	// PrometheusLibInstanceLabel is a label for Prometheus metrics.
	// It allows distinguishing metrics from different instances of the same library.
	PrometheusLibInstanceLabel string
}

// GRPCClient is a client for the IDP token service that uses gRPC.
type GRPCClient struct {
	client      pb.IDPTokenServiceClient
	clientConn  *grpc.ClientConn
	reqTimeout  time.Duration
	promMetrics *metrics.PrometheusMetrics
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
		client:      pb.NewIDPTokenServiceClient(conn),
		clientConn:  conn,
		reqTimeout:  opts.RequestTimeout,
		promMetrics: metrics.GetPrometheusMetrics(opts.PrometheusLibInstanceLabel, "grpc_client"),
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
	ctx context.Context, token string, scopeFilter []IntrospectionScopeFilterAccessPolicy, accessToken string,
) (IntrospectionResult, error) {
	req := pb.IntrospectTokenRequest{
		Token:       token,
		ScopeFilter: make([]*pb.IntrospectionScopeFilter, len(scopeFilter)),
	}
	for i := range scopeFilter {
		req.ScopeFilter[i] = &pb.IntrospectionScopeFilter{ResourceNamespace: scopeFilter[i].ResourceNamespace}
	}

	ctx = metadata.AppendToOutgoingContext(ctx, grpcMetaAuthorization, makeBearerToken(accessToken))

	var resp *pb.IntrospectTokenResponse
	if err := c.do(ctx, "IDPTokenService/IntrospectToken", func(ctx context.Context) error {
		var innerErr error
		resp, innerErr = c.client.IntrospectToken(ctx, &req)
		return innerErr
	}); err != nil {
		return IntrospectionResult{}, err
	}

	res := IntrospectionResult{
		Active:    resp.GetActive(),
		TokenType: resp.GetTokenType(),
		Claims: jwt.Claims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Issuer:   resp.GetIss(),
				Subject:  resp.GetSub(),
				Audience: resp.GetAud(),
				ID:       resp.GetJti(),
			},
			SubType:         resp.GetSubType(),
			ClientID:        resp.GetClientId(),
			OwnerTenantUUID: resp.GetOwnerTenantUuid(),
			Scope:           make([]jwt.AccessPolicy, len(resp.GetScope())),
		},
	}
	if resp.GetExp() != 0 {
		res.Claims.ExpiresAt = jwtgo.NewNumericDate(time.Unix(resp.GetExp(), 0))
	}
	for i, s := range resp.GetScope() {
		res.Claims.Scope[i] = jwt.AccessPolicy{
			ResourceNamespace: s.GetResourceNamespace(),
			Role:              s.GetRoleName(),
			ResourceServerID:  s.GetResourceServer(),
			ResourcePath:      s.GetResourcePath(),
			TenantUUID:        s.GetTenantUuid(),
		}
		if s.GetTenantIntId() != 0 {
			res.Claims.Scope[i].TenantID = strconv.FormatInt(s.GetTenantIntId(), 10)
		}
	}
	return res, nil
}

// ExchangeToken exchanges the token requesting a new token with the specified version.
func (c *GRPCClient) ExchangeToken(ctx context.Context, token string, tokenVersion uint32) (TokenData, error) {
	req := pb.CreateTokenRequest{
		GrantType:    idputil.GrantTypeJWTBearer,
		Assertion:    token,
		TokenVersion: tokenVersion,
	}

	var resp *pb.CreateTokenResponse
	if err := c.do(ctx, "IDPTokenService/CreateToken", func(ctx context.Context) error {
		var innerErr error
		resp, innerErr = c.client.CreateToken(ctx, &req)
		return innerErr
	}); err != nil {
		return TokenData{}, err
	}

	return TokenData{
		AccessToken: resp.GetAccessToken(),
		TokenType:   resp.GetTokenType(),
		ExpiresIn:   time.Second * time.Duration(resp.GetExpiresIn()),
	}, nil
}

func (c *GRPCClient) do(ctx context.Context, methodName string, call func(ctx context.Context) error) error {
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
		if code == grpccodes.Unauthenticated {
			return ErrUnauthenticated
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
