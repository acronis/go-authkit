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
	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/jwt"
)

// GRPCClientOpts contains options for the GRPCClient.
type GRPCClientOpts struct {
	// Logger is a logger for the client.
	Logger log.FieldLogger

	// RequestTimeout is a timeout for the gRPC requests.
	RequestTimeout time.Duration

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

const grpcMetaAuthorization = "authorization"

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
	if opts.Logger == nil {
		opts.Logger = log.NewDisabledLogger()
	}
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = time.Second * 30
	}
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(transportCreds),
		grpc.WithStatsHandler(&statsHandler{logger: opts.Logger}),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
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

	ctx, ctxCancel := context.WithTimeout(ctx, c.reqTimeout)
	defer ctxCancel()

	const methodName = "IDPTokenService/IntrospectToken"
	startTime := time.Now()
	resp, err := c.client.IntrospectToken(ctx, &req)
	elapsed := time.Since(startTime)
	if err != nil {
		var code grpccodes.Code
		if st, ok := grpcstatus.FromError(err); ok {
			code = st.Code()
		}
		c.promMetrics.ObserveGRPCClientRequest(methodName, code, elapsed)
		if code == grpccodes.Unauthenticated {
			return IntrospectionResult{}, ErrTokenIntrospectionUnauthenticated
		}
		return IntrospectionResult{}, fmt.Errorf("introspect token: %w", err)
	}
	c.promMetrics.ObserveGRPCClientRequest(methodName, grpccodes.OK, elapsed)

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

type statsHandler struct {
	logger log.FieldLogger
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
		sh.logger.Infof("grpc connection established")
	case *stats.ConnEnd:
		sh.logger.Infof("grpc connection closed")
	}
}
