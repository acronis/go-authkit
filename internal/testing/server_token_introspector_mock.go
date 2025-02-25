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

	Called                  bool
	LastAuthorizationHeader string
	LastIntrospectedToken   string
	LastFormValues          url.Values
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
	m.Called = true
	m.LastAuthorizationHeader = r.Header.Get("Authorization")
	m.LastIntrospectedToken = token
	m.LastFormValues = r.Form

	if m.LastAuthorizationHeader != "Bearer "+m.accessTokenForIntrospection {
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
	m.Called = false
	m.LastAuthorizationHeader = ""
	m.LastIntrospectedToken = ""
	m.LastFormValues = nil
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

	Called                bool
	LastAuthorizationMeta string
	LastSessionMeta       string
	LastRequest           *pb.IntrospectTokenRequest
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
	m.Called = true
	md, found := metadata.FromIncomingContext(ctx)
	if !found {
		return nil, status.Error(codes.Internal, "incoming context contains no metadata")
	}
	if mdVal := md.Get("authorization"); len(mdVal) != 0 {
		m.LastAuthorizationMeta = mdVal[0]
	} else {
		m.LastAuthorizationMeta = ""
	}
	if mdVal := md.Get("x-session-id"); len(mdVal) != 0 {
		m.LastSessionMeta = mdVal[0]
	} else {
		m.LastSessionMeta = ""
	}
	var requestedResponseCode codes.Code
	if mdVal := md.Get(TestMetaRequestedRespCode); len(mdVal) != 0 {
		if code, err := strconv.ParseUint(mdVal[0], 10, 32); err == nil {
			requestedResponseCode = codes.Code(code)
		}
	} else {
		requestedResponseCode = 0
	}
	m.LastRequest = req

	if requestedResponseCode != 0 {
		return nil, status.Error(requestedResponseCode, "Explicitly requested response code is returned")
	}

	if m.LastAuthorizationMeta == "" && m.LastSessionMeta == "" {
		return nil, status.Error(codes.Unauthenticated, "Access Token or Session ID is missing")
	}
	if m.LastAuthorizationMeta != "" && m.LastAuthorizationMeta != "Bearer "+m.accessTokenForIntrospection {
		return nil, status.Error(codes.Unauthenticated, "Access Token is invalid")
	}
	if m.LastSessionMeta != "" && m.LastSessionMeta != GenerateSessionID(m.accessTokenForIntrospection) {
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
	m.Called = false
	m.LastAuthorizationMeta = ""
	m.LastSessionMeta = ""
	m.LastRequest = nil
}

func tokenToKey(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}

func GenerateSessionID(token string) string {
	sha := sha256.Sum256([]byte(token))
	return base64.StdEncoding.EncodeToString(sha[:sha256.Size])
}
