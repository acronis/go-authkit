/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt_test

import (
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/acronis/go-appkit/log"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/jwks"
	"github.com/acronis/go-authkit/jwt"
)

func getTokenHash(token []byte) [sha256.Size]byte {
	tokenCheckSum := sha256.Sum256(token)
	return tokenCheckSum
}

func TestGetTokenHash(t *testing.T) {
	claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: testIss, ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute))}}
	tokenString := []byte(idptest.MustMakeTokenStringSignedWithTestKey(claims))

	th := getTokenHash(tokenString)
	require.NotEmpty(t, th, "generated token hash must not be an empty string")
	th2 := getTokenHash(tokenString)
	require.Equal(t, th, th2, "two hashes of the same token must be equal")

	claims2 := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: "other" + testIss, ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(12 * time.Minute))}}
	tokenString2 := []byte(idptest.MustMakeTokenStringSignedWithTestKey(claims2))
	th3 := getTokenHash(tokenString2)
	require.NotEqual(t, th, th3, "two hashes of different tokens must be different")
}

func TestCachingParser_Parse(t *testing.T) {
	logger := log.NewDisabledLogger()
	jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
	defer jwksServer.Close()

	issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
	defer issuerConfigServer.Close()

	claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: testIss, ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute))}}
	tokenString := idptest.MustMakeTokenStringSignedWithTestKey(claims)

	parser, err := jwt.NewCachingParser(jwks.NewCachingClient(), logger)
	require.NoError(t, err)
	parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)

	var parsedClaims *jwt.Claims
	parsedClaims, err = parser.Parse(context.Background(), tokenString)
	require.NoError(t, err, "caching parser must not return error from Parse method")
	require.Equal(t, claims.Scope, parsedClaims.Scope, "unexpected claims value produced by caching parser")

	require.Equal(t, 1, parser.ClaimsCache.Len(),
		"one claims object must be cached after successful parse operation")

	tokenKey := getTokenHash([]byte(tokenString))
	cachedClaims, found := parser.ClaimsCache.Get(tokenKey)
	require.True(t, found, "cached claims object must be found by token hash")
	require.Equal(t, claims.Scope, cachedClaims.Scope, "unexpected claims value fetched from parser cache")

	parser.InvalidateClaimsCache()
	require.Equal(t, 0, parser.ClaimsCache.Len(),
		"parser cache must be empty after invalidation")
}

func TestCachingParser_CheckExpiration(t *testing.T) {
	const jwtTTL = 2 * time.Second

	logger := log.NewDisabledLogger()
	jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
	defer jwksServer.Close()

	issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
	defer issuerConfigServer.Close()

	claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: testIss, ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(jwtTTL))}}
	tokenString := idptest.MustMakeTokenStringSignedWithTestKey(claims)

	parser, err := jwt.NewCachingParser(jwks.NewCachingClient(), logger)
	require.NoError(t, err)
	parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)

	var parsedClaims *jwt.Claims
	parsedClaims, err = parser.Parse(context.Background(), tokenString)
	require.NoError(t, err, "caching parser must not return error from Parse method")
	require.Equal(t, claims.Scope, parsedClaims.Scope, "unexpected claims value produced by caching parser")

	require.Equal(t, 1, parser.ClaimsCache.Len(),
		"one claims object must be cached after successful parse operation")

	time.Sleep(jwtTTL * 2)

	parsedClaims, err = parser.Parse(context.Background(), tokenString)
	require.Error(t, err, "caching parser must return error since cached jwt is expired")
	require.Nil(t, parsedClaims)
}
