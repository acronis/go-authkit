/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt_test

import (
	"context"
	"net/http"
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

const testIss = "test-issuer"

func TestJWTParser_Parse(t *testing.T) {
	jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
	defer jwksServer.Close()

	issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
	defer issuerConfigServer.Close()

	logger := log.NewDisabledLogger()

	t.Run("ok", func(t *testing.T) {
		claims := &jwt.Claims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Issuer:    testIss,
				ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
			},
			Scope:    []jwt.AccessPolicy{{Role: "company_admin"}},
			TOTPTime: time.Now().Unix(),
			SubType:  "task_manager",
		}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
		parsedClaims, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.NoError(t, err)
		require.Equal(t, claims.Scope, parsedClaims.Scope)
		require.Equal(t, claims.TOTPTime, parsedClaims.TOTPTime)
		require.Equal(t, claims.SubType, parsedClaims.SubType)
	})

	t.Run("ok for empty kid", func(t *testing.T) {
		claims := &jwt.Claims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Issuer:    testIss,
				ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
			},
		}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
		parsedClaims, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.NoError(t, err)
		require.Equal(t, claims, parsedClaims)
	})

	t.Run("ok for trusted issuer url (glob pattern)", func(t *testing.T) {
		claims := &jwt.Claims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Issuer:    issuerConfigServer.URL,
				ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
			},
			Scope: []jwt.AccessPolicy{{Role: "company_admin"}},
		}
		issURLs := []string{
			issuerConfigServer.URL,
			"http://127.0.0.*",
			"http://127.*",
		}
		for _, issURL := range issURLs {
			parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
			require.NoError(t, parser.AddTrustedIssuerURL(issURL))
			parsedClaims, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
			require.NoError(t, err)
			require.Equal(t, claims, parsedClaims)
		}
	})

	t.Run("ok for expected audience (glob pattern)", func(t *testing.T) {
		for _, aud := range []string{"region1.cloud.com", "region2.cloud.com"} {
			claims := &jwt.Claims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Audience:  []string{aud},
					Issuer:    issuerConfigServer.URL,
					ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
				},
				Scope: []jwt.AccessPolicy{{Role: "company_admin"}},
			}
			parser := jwt.NewParserWithOpts(jwks.NewCachingClient(http.DefaultClient, logger), logger, jwt.ParserOpts{
				ExpectedAudience: []string{"*.cloud.com"},
			})
			require.NoError(t, parser.AddTrustedIssuerURL(issuerConfigServer.URL))
			parsedClaims, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
			require.NoError(t, err)
			require.Equal(t, claims, parsedClaims)
		}
	})

	t.Run("malformed jwt", func(t *testing.T) {
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		_, err := parser.Parse(context.Background(), "invalid-jwt")
		require.ErrorIs(t, err, jwtgo.ErrTokenMalformed)
		require.ErrorContains(t, err, "token contains an invalid number of segments")
	})

	t.Run("unsigned jwt", func(t *testing.T) {
		claims := &jwt.Claims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Issuer:    testIss,
				ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
			},
			Scope: []jwt.AccessPolicy{{Role: "company_admin"}},
		}
		token := jwtgo.NewWithClaims(jwtgo.SigningMethodNone, claims)
		tokenString, err := token.SignedString(jwtgo.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		_, err = parser.Parse(context.Background(), tokenString)
		require.ErrorIs(t, err, jwtgo.NoneSignatureTypeDisallowedError)
	})

	t.Run("jwt issuer missing", func(t *testing.T) {
		claims := &jwt.Claims{
			RegisteredClaims: jwtgo.RegisteredClaims{Audience: []string{"https://cloud.acronis.com"}},
		}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenUnverifiable)
		var issMissingErr *jwt.IssuerMissingError
		require.ErrorAs(t, err, &issMissingErr)
		require.Equal(t, claims, issMissingErr.Claims)
	})

	t.Run("jwt has untrusted issuer", func(t *testing.T) {
		const issuer = "untrusted-issuer"
		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenUnverifiable)
		var issUntrustedErr *jwt.IssuerUntrustedError
		require.ErrorAs(t, err, &issUntrustedErr)
		require.Equal(t, claims, issUntrustedErr.Claims)
	})

	t.Run("jwt has untrusted issuer url", func(t *testing.T) {
		const issuer = "https://3rd-party-idp.com"
		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: issuer}}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		require.NoError(t, parser.AddTrustedIssuerURL("https://*.acronis.com"))
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenUnverifiable)
		var issUntrustedErr *jwt.IssuerUntrustedError
		require.ErrorAs(t, err, &issUntrustedErr)
		require.Equal(t, claims, issUntrustedErr.Claims)
	})

	t.Run("jwt has untrusted issuer url, callback adds it to trusted", func(t *testing.T) {
		var callbackCallCount int
		claims := &jwt.Claims{
			RegisteredClaims: jwtgo.RegisteredClaims{
				Audience:  []string{issuerConfigServer.URL},
				Issuer:    issuerConfigServer.URL,
				ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
			},
			Scope: []jwt.AccessPolicy{{Role: "company_admin"}},
		}
		parser := jwt.NewParserWithOpts(jwks.NewCachingClient(http.DefaultClient, logger), logger, jwt.ParserOpts{
			TrustedIssuerNotFoundFallback: func(ctx context.Context, p *jwt.Parser, iss string) (issURL string, issFound bool) {
				callbackCallCount++
				addErr := p.AddTrustedIssuerURL(iss)
				if addErr != nil {
					return "", false
				}
				return iss, true
			},
		})
		require.Equal(t, 0, callbackCallCount)
		parsedClaims, pErr := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.NoError(t, pErr, "issuer must be considered as trusted and no error returned")
		require.Equalf(t, 1, callbackCallCount, "Callback was not called by parser")
		require.Equal(t, claims, parsedClaims)
		parsedClaims, pErr = parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.NoError(t, pErr, "issuer must be considered as trusted and no error returned")
		require.Equal(t, claims, parsedClaims)
		require.Equalf(t, 1, callbackCallCount, "Callback should be called exactly once")
	})

	t.Run("jwt exp is missing", func(t *testing.T) {
		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: testIss}}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenInvalidClaims)
		require.ErrorIs(t, err, jwtgo.ErrTokenRequiredClaimMissing)
	})

	t.Run("jwt expired", func(t *testing.T) {
		expiresAt := time.Now().Add(-time.Second)
		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: testIss, ExpiresAt: jwtgo.NewNumericDate(expiresAt)}}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenInvalidClaims)
		require.ErrorIs(t, err, jwtgo.ErrTokenExpired)
	})

	t.Run("jwt not valid yet", func(t *testing.T) {
		notBefore := time.Now().Add(time.Minute)
		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    testIss,
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Hour)),
			NotBefore: jwtgo.NewNumericDate(notBefore),
		}}
		parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
		parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenInvalidClaims)
		require.ErrorIs(t, err, jwtgo.ErrTokenNotValidYet)
	})

	t.Run("required jwt audience is missing", func(t *testing.T) {
		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{
			Issuer:    testIss,
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
		}}
		parser := jwt.NewParserWithOpts(jwks.NewCachingClient(http.DefaultClient, logger), logger, jwt.ParserOpts{
			RequireAudience: true,
		})
		parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenInvalidClaims)
		require.ErrorIs(t, err, jwtgo.ErrTokenRequiredClaimMissing)
		var jwtErr *jwt.AudienceMissingError
		require.ErrorAs(t, err, &jwtErr)
		require.Equal(t, claims, jwtErr.Claims)
	})

	t.Run("jwt audience is not expected", func(t *testing.T) {
		const audience = "not-expected-audience"
		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{
			Audience:  []string{audience},
			Issuer:    testIss,
			ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute)),
		}}
		parser := jwt.NewParserWithOpts(jwks.NewCachingClient(http.DefaultClient, logger), logger, jwt.ParserOpts{
			ExpectedAudience: []string{"expected-audience"},
		})
		parser.AddTrustedIssuer(testIss, issuerConfigServer.URL)
		_, err := parser.Parse(context.Background(), idptest.MustMakeTokenStringSignedWithTestKey(claims))
		require.ErrorIs(t, err, jwtgo.ErrTokenInvalidClaims)
		require.ErrorIs(t, err, jwtgo.ErrTokenInvalidAudience)
		var jwtErr *jwt.AudienceNotExpectedError
		require.ErrorAs(t, err, &jwtErr)
		require.Equal(t, claims, jwtErr.Claims)
	})

	t.Run("verification error", func(t *testing.T) {
		jwksServer2 := httptest.NewServer(&idptest.JWKSHandler{})
		defer jwksServer2.Close()

		openIDCfgHandler2 := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer2.URL}
		openIDCfgServer2 := httptest.NewServer(openIDCfgHandler2)
		defer openIDCfgServer2.Close()

		const cacheUpdateMinInterval = time.Second

		claims := &jwt.Claims{RegisteredClaims: jwtgo.RegisteredClaims{Issuer: testIss, ExpiresAt: jwtgo.NewNumericDate(time.Now().Add(time.Minute))}}
		tokenString, err := idptest.MakeTokenString(claims, "737c5114f09b5ed05276bd4b520245982f7fb29f", idptest.GetTestRSAPrivateKey())
		require.NoError(t, err)
		jwksClient := jwks.NewCachingClientWithOpts(http.DefaultClient, logger, jwks.CachingClientOpts{CacheUpdateMinInterval: cacheUpdateMinInterval})
		parser := jwt.NewParser(jwksClient, logger)
		parser.AddTrustedIssuer(testIss, openIDCfgServer2.URL)

		for i := 0; i < 2; i++ {
			_, err = parser.Parse(context.Background(), tokenString)
			require.ErrorIs(t, err, jwtgo.ErrTokenSignatureInvalid)
			require.EqualValues(t, 1, openIDCfgHandler2.ServedCount())
			require.EqualValues(t, 1, openIDCfgHandler2.ServedCount())
		}

		time.Sleep(cacheUpdateMinInterval * 2)

		_, err = parser.Parse(context.Background(), tokenString)
		require.ErrorIs(t, err, jwtgo.ErrTokenSignatureInvalid)
		require.EqualValues(t, 2, openIDCfgHandler2.ServedCount())
		require.EqualValues(t, 2, openIDCfgHandler2.ServedCount())
	})
}

func TestParser_getURLForIssuer(t *testing.T) {
	tests := []struct {
		Name              string
		IssURLPattern     string
		TrustedIssURLs    []string
		NotTrustedIssURLs []string
	}{
		{
			Name:          "wildcard in host",
			IssURLPattern: "https://*.acronis.com/bc",
			TrustedIssURLs: []string{
				"https://us-cloud.acronis.com/bc",
				"https://eu2-cloud.acronis.com/bc",
			},
			NotTrustedIssURLs: []string{
				"http://eu2-cloud.acronis.com/bc",
				"https://eu2-cloud.acronis.com",
				"https://eu2-cloud.acronis.com/bc/foobar",
				"https://my-site.com/eu2-cloud.acronis.com/bc",
				"https://my-site.com?foo=eu2-cloud.acronis.com/bc",
				"https://eu2-cloud.acronis.com/bc?foo=bar",
			},
		},
		{
			Name:           "no wildcard in path",
			IssURLPattern:  "https://eu3-cloud.acronis.com/bc",
			TrustedIssURLs: []string{"https://eu3-cloud.acronis.com/bc"},
			NotTrustedIssURLs: []string{
				"https://eu1-cloud.acronis.com/bc",
				"https://eu2-cloud.acronis.com/bc",
			},
		},
	}
	for i := range tests {
		tt := tests[i]
		t.Run(tt.Name, func(t *testing.T) {
			logger := log.NewDisabledLogger()
			parser := jwt.NewParser(jwks.NewCachingClient(http.DefaultClient, logger), logger)
			require.NoError(t, parser.AddTrustedIssuerURL(tt.IssURLPattern))
			for _, issURL := range tt.TrustedIssURLs {
				u, ok := parser.GetURLForIssuer(issURL)
				require.True(t, ok)
				require.Equal(t, u, issURL)
			}
			for _, issURL := range tt.NotTrustedIssURLs {
				_, ok := parser.GetURLForIssuer(issURL)
				require.False(t, ok)
			}
		})
	}
}
