/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package testing

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"

	"google.golang.org/grpc/metadata"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/jwt"
)

type JWTParser interface {
	Parse(ctx context.Context, token string) (*jwt.Claims, error)
}

type HTTPServerTokenIntrospectorMock struct {
	JWTParser JWTParser

	introspectionResults map[[sha256.Size]byte]idptoken.IntrospectionResult
	jwtScopes            map[string][]jwt.AccessPolicy

	Called                  bool
	LastAuthorizationHeader string
	LastIntrospectedToken   string
	LastFormValues          url.Values
}

func NewHTTPServerTokenIntrospectorMock() *HTTPServerTokenIntrospectorMock {
	return &HTTPServerTokenIntrospectorMock{
		introspectionResults: make(map[[sha256.Size]byte]idptoken.IntrospectionResult),
		jwtScopes:            make(map[string][]jwt.AccessPolicy),
	}
}

func (m *HTTPServerTokenIntrospectorMock) SetResultForToken(token string, result idptoken.IntrospectionResult) {
	m.introspectionResults[tokenToKey(token)] = result
}

func (m *HTTPServerTokenIntrospectorMock) SetScopeForJWTID(jwtID string, scope []jwt.AccessPolicy) {
	m.jwtScopes[jwtID] = scope
}

func (m *HTTPServerTokenIntrospectorMock) IntrospectToken(r *http.Request, token string) idptoken.IntrospectionResult {
	m.Called = true
	m.LastAuthorizationHeader = r.Header.Get("Authorization")
	m.LastIntrospectedToken = token
	m.LastFormValues = r.Form

	if result, ok := m.introspectionResults[tokenToKey(token)]; ok {
		return result
	}

	claims, err := m.JWTParser.Parse(r.Context(), token)
	if err != nil {
		return idptoken.IntrospectionResult{Active: false}
	}
	result := idptoken.IntrospectionResult{Active: true, TokenType: idptoken.TokenTypeBearer, Claims: *claims}
	if scopes, ok := m.jwtScopes[claims.ID]; ok {
		result.Scope = scopes
	}
	return result
}

func (m *HTTPServerTokenIntrospectorMock) ResetCallsInfo() {
	m.Called = false
	m.LastAuthorizationHeader = ""
	m.LastIntrospectedToken = ""
	m.LastFormValues = nil
}

type GRPCServerTokenIntrospectorMock struct {
	JWTParser JWTParser

	introspectionResults map[[sha256.Size]byte]*pb.IntrospectTokenResponse
	scopes               map[string][]*pb.AccessTokenScope

	Called                bool
	LastAuthorizationMeta string
	LastRequest           *pb.IntrospectTokenRequest
}

func NewGRPCServerTokenIntrospectorMock() *GRPCServerTokenIntrospectorMock {
	return &GRPCServerTokenIntrospectorMock{
		introspectionResults: make(map[[sha256.Size]byte]*pb.IntrospectTokenResponse),
		scopes:               make(map[string][]*pb.AccessTokenScope),
	}
}

func (m *GRPCServerTokenIntrospectorMock) SetResultForToken(token string, result *pb.IntrospectTokenResponse) {
	m.introspectionResults[tokenToKey(token)] = result
}

func (m *GRPCServerTokenIntrospectorMock) SetScopeForJWTID(jwtID string, scope []*pb.AccessTokenScope) {
	m.scopes[jwtID] = scope
}

func (m *GRPCServerTokenIntrospectorMock) IntrospectToken(
	ctx context.Context, req *pb.IntrospectTokenRequest,
) (*pb.IntrospectTokenResponse, error) {
	m.Called = true
	if mdVal := metadata.ValueFromIncomingContext(ctx, "authorization"); len(mdVal) != 0 {
		m.LastAuthorizationMeta = mdVal[0]
	} else {
		m.LastAuthorizationMeta = ""
	}
	m.LastRequest = req

	if result, ok := m.introspectionResults[tokenToKey(req.Token)]; ok {
		return result, nil
	}

	claims, err := m.JWTParser.Parse(ctx, req.Token)
	if err != nil {
		return &pb.IntrospectTokenResponse{Active: false}, nil
	}
	result := &pb.IntrospectTokenResponse{
		Active:          true,
		TokenType:       idptoken.TokenTypeBearer,
		Exp:             claims.ExpiresAt.Unix(),
		Aud:             claims.Audience,
		Jti:             claims.ID,
		Iss:             claims.Issuer,
		Sub:             claims.Subject,
		SubType:         claims.SubType,
		ClientId:        claims.ClientID,
		OwnerTenantUuid: claims.OwnerTenantUUID,
	}
	if scopes, ok := m.scopes[claims.ID]; ok {
		result.Scope = scopes
	}
	return result, nil
}

func (m *GRPCServerTokenIntrospectorMock) ResetCallsInfo() {
	m.Called = false
	m.LastAuthorizationMeta = ""
	m.LastRequest = nil
}

func tokenToKey(token string) [sha256.Size]byte {
	return sha256.Sum256([]byte(token))
}
