/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package testing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/jwt"
)

type JWTParser interface {
	Parse(ctx context.Context, token string) (jwt.Claims, error)
}

type httpServerIntrospectionResult struct {
	result idptoken.IntrospectionResult
	err    error
}

type HTTPServerTokenIntrospectorMock struct {
	JWTParser JWTParser

	introspectionResults map[[sha256.Size]byte]httpServerIntrospectionResult
	jwtScopes            map[string][]jwt.AccessPolicy

	accessTokenForIntrospection string

	called                  atomic.Bool
	lastAuthorizationHeader atomic.Pointer[string]
	lastIntrospectedToken   atomic.Pointer[string]
	lastUserAgentHeader     atomic.Pointer[string]
	lastFormValues          atomic.Pointer[url.Values]
}

func NewHTTPServerTokenIntrospectorMock() *HTTPServerTokenIntrospectorMock {
	return &HTTPServerTokenIntrospectorMock{
		introspectionResults: make(map[[sha256.Size]byte]httpServerIntrospectionResult),
		jwtScopes:            make(map[string][]jwt.AccessPolicy),
	}
}

func (m *HTTPServerTokenIntrospectorMock) SetResultForToken(token string, result idptoken.IntrospectionResult, err error) {
	m.introspectionResults[tokenToKey(token)] = httpServerIntrospectionResult{result, err}
}

func (m *HTTPServerTokenIntrospectorMock) SetScopeForJWTID(jwtID string, scope []jwt.AccessPolicy) {
	m.jwtScopes[jwtID] = scope
}

func (m *HTTPServerTokenIntrospectorMock) SetAccessTokenForIntrospection(accessToken string) {
	m.accessTokenForIntrospection = accessToken
}

func (m *HTTPServerTokenIntrospectorMock) IntrospectToken(
	r *http.Request, token string,
) (idptoken.IntrospectionResult, error) {
	m.called.Store(true)
	authHeader := r.Header.Get("Authorization")
	userAgent := r.UserAgent()
	m.lastAuthorizationHeader.Store(&authHeader)
	m.lastUserAgentHeader.Store(&userAgent)
	m.lastIntrospectedToken.Store(&token)
	m.lastFormValues.Store(&r.Form)

	if authHeader != "Bearer "+m.accessTokenForIntrospection {
		return nil, idptest.ErrUnauthorized
	}

	if result, ok := m.introspectionResults[tokenToKey(token)]; ok {
		return result.result, result.err
	}

	claims, err := m.JWTParser.Parse(r.Context(), token)
	if err != nil {
		return &idptoken.DefaultIntrospectionResult{Active: false}, nil
	}
	defaultClaims := claims.(*jwt.DefaultClaims)
	result := &idptoken.DefaultIntrospectionResult{Active: true, TokenType: idputil.TokenTypeBearer, DefaultClaims: *defaultClaims}
	if scopes, ok := m.jwtScopes[defaultClaims.ID]; ok {
		result.Scope = scopes
	}
	return result, nil
}

func (m *HTTPServerTokenIntrospectorMock) ResetCallsInfo() {
	m.called.Store(false)
	emptyString := ""
	m.lastAuthorizationHeader.Store(&emptyString)
	m.lastIntrospectedToken.Store(&emptyString)
	m.lastUserAgentHeader.Store(&emptyString)
	var nilFormValues url.Values
	m.lastFormValues.Store(&nilFormValues)
}

func (m *HTTPServerTokenIntrospectorMock) Called() bool {
	return m.called.Load()
}

func (m *HTTPServerTokenIntrospectorMock) LastAuthorizationHeader() string {
	if ptr := m.lastAuthorizationHeader.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

func (m *HTTPServerTokenIntrospectorMock) LastIntrospectedToken() string {
	if ptr := m.lastIntrospectedToken.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

func (m *HTTPServerTokenIntrospectorMock) LastUserAgentHeader() string {
	if ptr := m.lastUserAgentHeader.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

func (m *HTTPServerTokenIntrospectorMock) LastFormValues() url.Values {
	if ptr := m.lastFormValues.Load(); ptr != nil {
		return *ptr
	}
	return nil
}

const (
	TestMetaRequestedRespCode = "x-requested-resp-code"
)

type grpcServerIntrospectionResult struct {
	response *pb.IntrospectTokenResponse
	err      error
}

type GRPCServerTokenIntrospectorMock struct {
	JWTParser JWTParser

	introspectionResults map[[sha256.Size]byte]grpcServerIntrospectionResult
	scopes               map[string][]*pb.AccessTokenScope

	accessTokenForIntrospection string

	called                atomic.Bool
	lastAuthorizationMeta atomic.Pointer[string]
	lastSessionMeta       atomic.Pointer[string]
	lastRequest           atomic.Pointer[pb.IntrospectTokenRequest]
	lastUserAgentMeta     atomic.Pointer[string]
}

func NewGRPCServerTokenIntrospectorMock() *GRPCServerTokenIntrospectorMock {
	return &GRPCServerTokenIntrospectorMock{
		introspectionResults: make(map[[sha256.Size]byte]grpcServerIntrospectionResult),
		scopes:               make(map[string][]*pb.AccessTokenScope),
	}
}

func (m *GRPCServerTokenIntrospectorMock) SetResultForToken(token string, response *pb.IntrospectTokenResponse, err error) {
	m.introspectionResults[tokenToKey(token)] = grpcServerIntrospectionResult{response: response, err: err}
}

func (m *GRPCServerTokenIntrospectorMock) SetScopeForJWTID(jwtID string, scope []*pb.AccessTokenScope) {
	m.scopes[jwtID] = scope
}

func (m *GRPCServerTokenIntrospectorMock) SetAccessTokenForIntrospection(accessToken string) {
	m.accessTokenForIntrospection = accessToken
}

func (m *GRPCServerTokenIntrospectorMock) IntrospectToken(
	ctx context.Context, req *pb.IntrospectTokenRequest,
) (*pb.IntrospectTokenResponse, error) {
	m.called.Store(true)
	md, found := metadata.FromIncomingContext(ctx)
	if !found {
		return nil, status.Error(codes.Internal, "incoming context contains no metadata")
	}
	var userAgent string
	if mdVal := md.Get("user-agent"); len(mdVal) != 0 {
		userAgent = mdVal[0]
	}
	m.lastUserAgentMeta.Store(&userAgent)

	var authMeta string
	if mdVal := md.Get("authorization"); len(mdVal) != 0 {
		authMeta = mdVal[0]
	}
	m.lastAuthorizationMeta.Store(&authMeta)

	var sessionMeta string
	if mdVal := md.Get("x-session-id"); len(mdVal) != 0 {
		sessionMeta = mdVal[0]
	}
	m.lastSessionMeta.Store(&sessionMeta)
	var requestedResponseCode codes.Code
	if mdVal := md.Get(TestMetaRequestedRespCode); len(mdVal) != 0 {
		if code, err := strconv.ParseUint(mdVal[0], 10, 32); err == nil {
			requestedResponseCode = codes.Code(code)
		}
	} else {
		requestedResponseCode = 0
	}
	m.lastRequest.Store(req)

	if requestedResponseCode != 0 {
		return nil, status.Error(requestedResponseCode, "Explicitly requested response code is returned")
	}

	if authMeta == "" && sessionMeta == "" {
		return nil, status.Error(codes.Unauthenticated, "Access Token or Session ID is missing")
	}
	if authMeta != "" && authMeta != "Bearer "+m.accessTokenForIntrospection {
		return nil, status.Error(codes.Unauthenticated, "Access Token is invalid")
	}
	if sessionMeta != "" && sessionMeta != GenerateSessionID(m.accessTokenForIntrospection) {
		return nil, status.Error(codes.Unauthenticated, "Session ID is invalid")
	}

	sessionMD := metadata.Pairs("x-session-id", GenerateSessionID(m.accessTokenForIntrospection))
	if err := grpc.SetHeader(ctx, sessionMD); err != nil {
		return nil, status.Error(codes.Internal, "set x-session-id header")
	}

	if result, ok := m.introspectionResults[tokenToKey(req.Token)]; ok {
		return result.response, result.err
	}

	claims, err := m.JWTParser.Parse(ctx, req.Token)
	if err != nil {
		return &pb.IntrospectTokenResponse{Active: false}, nil
	}
	defaultClaims := claims.(*jwt.DefaultClaims)
	result := &pb.IntrospectTokenResponse{
		Active:    true,
		TokenType: idputil.TokenTypeBearer,
		Exp:       defaultClaims.ExpiresAt.Unix(),
		Aud:       defaultClaims.Audience,
		Jti:       defaultClaims.ID,
		Iss:       defaultClaims.Issuer,
		Sub:       defaultClaims.Subject,
	}
	if scopes, ok := m.scopes[defaultClaims.ID]; ok {
		result.Scope = scopes
	}
	return result, nil
}

func (m *GRPCServerTokenIntrospectorMock) ResetCallsInfo() {
	m.called.Store(false)
	emptyString := ""
	m.lastAuthorizationMeta.Store(&emptyString)
	m.lastSessionMeta.Store(&emptyString)
	m.lastUserAgentMeta.Store(&emptyString)
	var nilRequest *pb.IntrospectTokenRequest
	m.lastRequest.Store(nilRequest)
}

func (m *GRPCServerTokenIntrospectorMock) Called() bool {
	return m.called.Load()
}

func (m *GRPCServerTokenIntrospectorMock) LastAuthorizationMeta() string {
	if ptr := m.lastAuthorizationMeta.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

func (m *GRPCServerTokenIntrospectorMock) LastSessionMeta() string {
	if ptr := m.lastSessionMeta.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

func (m *GRPCServerTokenIntrospectorMock) LastRequest() *pb.IntrospectTokenRequest {
	return m.lastRequest.Load()
}

func (m *GRPCServerTokenIntrospectorMock) LastUserAgentMeta() string {
	if ptr := m.lastUserAgentMeta.Load(); ptr != nil {
		return *ptr
	}
	return ""
}

func tokenToKey(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

func GenerateSessionID(token string) string {
	sha := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(sha[:sha256.Size])
}
