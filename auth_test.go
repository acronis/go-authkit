/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package authkit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	gotesting "testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/idptoken/pb"
	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/testing"
	"github.com/acronis/go-authkit/jwt"
)

func TestNewJWTParser(t *gotesting.T) {
	const testIss = "test-issuer"

	idpSrv := idptest.NewHTTPServer()
	require.NoError(t, idpSrv.StartAndWaitForReady(time.Second))
	defer func() { _ = idpSrv.Shutdown(context.Background()) }()

	claims := &jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    idpSrv.URL(),
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(10 * time.Second)),
		},
		Scope: []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "ro_admin"}},
	}
	token := idptest.MustMakeTokenStringSignedWithTestKey(claims)

	claimsWithNamedIssuer := &jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    testIss,
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(10 * time.Second)),
		},
		Scope: []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "admin"}},
	}
	tokenWithNamedIssuer := idptest.MustMakeTokenStringSignedWithTestKey(claimsWithNamedIssuer)

	tests := []struct {
		name           string
		token          string
		cfg            *Config
		expectedClaims *jwt.Claims
		checkFn        func(t *gotesting.T, jwtParser JWTParser)
	}{
		{
			name:           "new jwt parser, trusted issuers map",
			cfg:            &Config{JWT: JWTConfig{TrustedIssuers: map[string]string{testIss: idpSrv.URL()}}},
			token:          tokenWithNamedIssuer,
			expectedClaims: claimsWithNamedIssuer,
			checkFn: func(t *gotesting.T, jwtParser JWTParser) {
				require.IsType(t, &jwt.Parser{}, jwtParser)
			},
		},
		{
			name:           "new jwt parser, trusted issuer urls",
			cfg:            &Config{JWT: JWTConfig{TrustedIssuerURLs: []string{idpSrv.URL()}}},
			token:          token,
			expectedClaims: claims,
			checkFn: func(t *gotesting.T, jwtParser JWTParser) {
				require.IsType(t, &jwt.Parser{}, jwtParser)
			},
		},
		{
			name:           "new caching jwt parser, trusted issuers map",
			cfg:            &Config{JWT: JWTConfig{TrustedIssuers: map[string]string{testIss: idpSrv.URL()}, ClaimsCache: ClaimsCacheConfig{Enabled: true}}},
			token:          tokenWithNamedIssuer,
			expectedClaims: claimsWithNamedIssuer,
			checkFn: func(t *gotesting.T, jwtParser JWTParser) {
				require.IsType(t, &jwt.CachingParser{}, jwtParser)
				cachingParser := jwtParser.(*jwt.CachingParser)
				require.Equal(t, 1, cachingParser.ClaimsCache.Len())
			},
		},
		{
			name:           "new caching jwt parser, trusted issuer urls",
			cfg:            &Config{JWT: JWTConfig{TrustedIssuerURLs: []string{idpSrv.URL()}, ClaimsCache: ClaimsCacheConfig{Enabled: true}}},
			token:          token,
			expectedClaims: claims,
			checkFn: func(t *gotesting.T, jwtParser JWTParser) {
				require.IsType(t, &jwt.CachingParser{}, jwtParser)
				cachingParser := jwtParser.(*jwt.CachingParser)
				require.Equal(t, 1, cachingParser.ClaimsCache.Len())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			jwtParser, err := NewJWTParser(tt.cfg)
			require.NoError(t, err)

			parsedClaims, err := jwtParser.Parse(context.Background(), tt.token)
			require.NoError(t, err)
			require.Equal(t, tt.expectedClaims, parsedClaims)
			if tt.checkFn != nil {
				tt.checkFn(t, jwtParser)
			}
		})
	}
}

func TestNewTokenIntrospector(t *gotesting.T) {
	const testIss = "test-issuer"
	const validAccessToken = "access-token-with-introspection-permission"

	httpServerIntrospector := testing.NewHTTPServerTokenIntrospectorMock()
	httpServerIntrospector.SetAccessTokenForIntrospection(validAccessToken)
	grpcServerIntrospector := testing.NewGRPCServerTokenIntrospectorMock()
	grpcServerIntrospector.SetAccessTokenForIntrospection(validAccessToken)

	// Start testing HTTP IDP server.
	httpIDPSrv := idptest.NewHTTPServer(idptest.WithHTTPTokenIntrospector(httpServerIntrospector))
	require.NoError(t, httpIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { _ = httpIDPSrv.Shutdown(context.Background()) }()

	// Generate a self-signed certificate for the testing gRPC IDP server and start it.
	tlsCert, certPEM, _ := generateSelfSignedRSACert(t)
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	require.NoError(t, os.WriteFile(certFile, certPEM, 0644))
	grpcIDPSrv := idptest.NewGRPCServer(
		idptest.WithGRPCTokenIntrospector(grpcServerIntrospector),
		idptest.WithGRPCServerOptions(grpc.Creds(credentials.NewServerTLSFromCert(&tlsCert))))
	require.NoError(t, grpcIDPSrv.StartAndWaitForReady(time.Second))
	defer func() { grpcIDPSrv.GracefulStop() }()

	claims := &jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    httpIDPSrv.URL(),
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(10 * time.Second)),
		},
		Scope: []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "ro_admin"}},
	}
	token := idptest.MustMakeTokenStringSignedWithTestKey(claims)

	claimsWithNamedIssuer := &jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    testIss,
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(10 * time.Second)),
		},
		Scope: []jwt.AccessPolicy{{ResourceNamespace: "my-service", Role: "admin"}},
	}
	tokenWithNamedIssuer := idptest.MustMakeTokenStringSignedWithTestKey(claimsWithNamedIssuer)

	opaqueToken := "opaque-token-" + uuid.NewString()
	opaqueTokenScope := []jwt.AccessPolicy{{
		TenantUUID:        uuid.NewString(),
		ResourceNamespace: "account-server",
		Role:              "admin",
		ResourcePath:      "resource-" + uuid.NewString(),
	}}
	httpServerIntrospector.SetResultForToken(opaqueToken, idptoken.IntrospectionResult{
		Active: true, TokenType: idputil.TokenTypeBearer, Claims: jwt.Claims{Scope: opaqueTokenScope}})
	grpcServerIntrospector.SetResultForToken(opaqueToken, &pb.IntrospectTokenResponse{
		Active: true, TokenType: idputil.TokenTypeBearer, Scope: []*pb.AccessTokenScope{
			{
				TenantUuid:        opaqueTokenScope[0].TenantUUID,
				ResourceNamespace: opaqueTokenScope[0].ResourceNamespace,
				RoleName:          opaqueTokenScope[0].Role,
				ResourcePath:      opaqueTokenScope[0].ResourcePath,
			},
		}})

	tests := []struct {
		name           string
		cfg            *Config
		token          string
		expectedResult idptoken.IntrospectionResult
		checkCacheFn   func(t *gotesting.T, introspector *idptoken.Introspector)
	}{
		{
			name:  "new token introspector, dynamic endpoint, trusted issuers map",
			cfg:   &Config{JWT: JWTConfig{TrustedIssuers: map[string]string{testIss: httpIDPSrv.URL()}}, Introspection: IntrospectionConfig{Enabled: true}},
			token: tokenWithNamedIssuer,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    *claimsWithNamedIssuer,
			},
			checkCacheFn: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Empty(t, introspector.ClaimsCache.Len(context.Background()))
				require.Empty(t, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name:  "new token introspector, dynamic endpoint, trusted issuer urls",
			cfg:   &Config{JWT: JWTConfig{TrustedIssuerURLs: []string{httpIDPSrv.URL()}}, Introspection: IntrospectionConfig{Enabled: true}},
			token: token,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    *claims,
			},
			checkCacheFn: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Empty(t, introspector.ClaimsCache.Len(context.Background()))
				require.Empty(t, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "new caching token introspector, dynamic endpoint, trusted issuers map",
			cfg: &Config{
				JWT:           JWTConfig{TrustedIssuers: map[string]string{testIss: httpIDPSrv.URL()}},
				Introspection: IntrospectionConfig{Enabled: true, ClaimsCache: IntrospectionCacheConfig{Enabled: true}},
			},
			token: tokenWithNamedIssuer,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    *claimsWithNamedIssuer,
			},
			checkCacheFn: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Empty(t, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "new caching token introspector, dynamic endpoint, trusted issuer urls",
			cfg: &Config{
				JWT:           JWTConfig{TrustedIssuerURLs: []string{httpIDPSrv.URL()}},
				Introspection: IntrospectionConfig{Enabled: true, ClaimsCache: IntrospectionCacheConfig{Enabled: true}},
			},
			token: token,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    *claims,
			},
			checkCacheFn: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Empty(t, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "new caching token introspector, static http endpoint",
			cfg: &Config{
				Introspection: IntrospectionConfig{
					Enabled:     true,
					ClaimsCache: IntrospectionCacheConfig{Enabled: true},
					Endpoint:    httpIDPSrv.URL() + idptest.TokenIntrospectionEndpointPath,
				},
			},
			token: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    jwt.Claims{Scope: opaqueTokenScope},
			},
			checkCacheFn: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Equal(t, 1, introspector.ClaimsCache.Len(context.Background()))
				require.Empty(t, introspector.NegativeCache.Len(context.Background()))
			},
		},
		{
			name: "new token introspector, gRPC target, tls enabled",
			cfg: &Config{
				JWT: JWTConfig{TrustedIssuerURLs: []string{httpIDPSrv.URL()}},
				Introspection: IntrospectionConfig{
					Enabled: true,
					GRPC: IntrospectionGRPCConfig{
						Endpoint: grpcIDPSrv.Addr(),
						TLS: GRPCTLSConfig{
							Enabled: true,
							CACert:  certFile,
						},
					},
				},
			},
			token: opaqueToken,
			expectedResult: idptoken.IntrospectionResult{
				Active:    true,
				TokenType: idputil.TokenTypeBearer,
				Claims:    jwt.Claims{Scope: opaqueTokenScope},
			},
			checkCacheFn: func(t *gotesting.T, introspector *idptoken.Introspector) {
				require.Empty(t, introspector.ClaimsCache.Len(context.Background()))
				require.Empty(t, introspector.NegativeCache.Len(context.Background()))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			jwtParser, err := NewJWTParser(tt.cfg)
			require.NoError(t, err)
			httpServerIntrospector.JWTParser = jwtParser
			grpcServerIntrospector.JWTParser = jwtParser

			introspector, err := NewTokenIntrospector(tt.cfg, idptest.NewSimpleTokenProvider(validAccessToken), nil)
			require.NoError(t, err)

			result, err := introspector.IntrospectToken(context.Background(), tt.token)
			require.NoError(t, err)
			require.Equal(t, tt.expectedResult, result)
			if tt.checkCacheFn != nil {
				tt.checkCacheFn(t, introspector)
			}
		})
	}
}

func TestNewVerifyAccessByJWTRoles(t *gotesting.T) {
	jwtClaims := &jwt.Claims{Scope: []jwt.AccessPolicy{
		{ResourceNamespace: "policy_manager", Role: "admin"},
		{ResourceNamespace: "scan_service", Role: "admin"},
		{Role: "backup_user"},
		{ResourceNamespace: "agent_manager", Role: "agent_viewer"},
	}}
	cases := []struct {
		roles []Role
		want  bool
	}{
		{[]Role{{Name: "tenant_viewer"}}, false},
		{[]Role{{Name: "backup_user"}}, true},
		{[]Role{{Namespace: "alert_manager", Name: "admin"}}, false},
		{[]Role{{Namespace: "policy_manager", Name: "admin"}}, true},
		{[]Role{{Namespace: "alert_manager", Name: "admin"}, {Name: "tenant_viewer"}}, false},
		{[]Role{{Namespace: "alert_manager", Name: "admin"}, {Name: "tenant_viewer"}, {Namespace: "policy_manager", Name: "admin"}}, true},
	}
	for _, c := range cases {
		got := NewVerifyAccessByRolesInJWT(c.roles...)(httptest.NewRequest(http.MethodGet, "/", nil), jwtClaims)
		require.Equal(t, c.want, got, "want %v, got %v, roles %+v", c.want, got, c.roles)
	}
}

func TestNewVerifyAccessByJWTRolesMaker(t *gotesting.T) {
	jwtClaims := &jwt.Claims{Scope: []jwt.AccessPolicy{
		{ResourceNamespace: "policy_manager", Role: "admin"},
		{ResourceNamespace: "scan_service", Role: "admin"},
		{Role: "backup_user"},
		{ResourceNamespace: "agent_manager", Role: "agent_viewer"},
		{ResourceNamespace: "agent_manager", Role: "agent_registrar"},
	}}
	cases := []struct {
		roleNamespace string
		roleNames     []string
		want          bool
	}{
		{"agent_manager", []string{"agent_viewer", "agent_registrar"}, true},
		{"policy_manager", []string{"admin"}, true},
		{"", []string{"backup_user"}, true},
		{"alert_manager", []string{"admin"}, false},
	}

	for _, c := range cases {
		got := NewVerifyAccessByRolesInJWTMaker(c.roleNamespace)(c.roleNames...)(httptest.NewRequest(http.MethodGet, "/", nil), jwtClaims)
		require.Equal(t, c.want, got, "want %v, got %v, roleNamespace: %v, roleNames %+v", c.want, got, c.roleNamespace, c.roleNames)
	}
}

func generateSelfSignedRSACert(t *gotesting.T) (tlsCert tls.Certificate, certPEM []byte, keyPEM []byte) {
	t.Helper()

	// Create a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, &certTemplate, &priv.PublicKey, priv)
	require.NoError(t, err)

	// PEM encode the certificate and private key
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// Load the certificate and key as tls.Certificate
	tlsCert, err = tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return tlsCert, certPEM, keyPEM
}
