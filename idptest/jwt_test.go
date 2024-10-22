/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/acronis/go-appkit/log"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

const testIss = "test-issuer"

func TestMakeTokenStringWithHeader(t *testing.T) {
	jwksServer := httptest.NewServer(&JWKSHandler{})
	defer jwksServer.Close()

	issuerConfigServer := httptest.NewServer(&OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
	defer issuerConfigServer.Close()

	logger := log.NewDisabledLogger()

	jwtClaims := &jwt.Claims{
		RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    testIss,
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
		},
		Scope: []jwt.AccessPolicy{
			{ResourceNamespace: "policy_manager", Role: "admin"},
		},
	}

	parser := jwt.NewParser(jwks.NewCachingClient(), logger)
	parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
	parsedClaims, err := parser.Parse(context.Background(), MustMakeTokenStringSignedWithTestKey(jwtClaims))
	require.NoError(t, err)
	require.Equal(
		t,
		[]jwt.AccessPolicy{{ResourceNamespace: "policy_manager", Role: "admin"}},
		parsedClaims.Scope,
	)
}
