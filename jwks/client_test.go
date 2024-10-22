/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwks_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/jwks"
)

func TestClient_GetRSAPublicKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
		defer jwksServer.Close()
		issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
		defer issuerConfigServer.Close()

		client := jwks.NewClient()
		pubKey, err := client.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		require.IsType(t, &rsa.PublicKey{}, pubKey)
	})

	t.Run("issuer openid configuration unavailable", func(t *testing.T) {
		jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
		defer jwksServer.Close()
		issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
		issuerConfigServer.Close() // Close the server immediately.

		client := jwks.NewClient()
		pubKey, err := client.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.Error(t, err)
		var openIDCfgErr *jwks.GetOpenIDConfigurationError
		require.True(t, errors.As(err, &openIDCfgErr))
		require.Equal(t, issuerConfigServer.URL+jwks.OpenIDConfigurationPath, openIDCfgErr.URL)
		requireLocalhostConnRefusedError(t, openIDCfgErr.Inner)
		require.Nil(t, pubKey)
	})

	t.Run("openid configuration server respond internal error", func(t *testing.T) {
		issuerConfigServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		}))
		defer issuerConfigServer.Close()

		client := jwks.NewClient()
		pubKey, err := client.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.Error(t, err)
		var openIDCfgErr *jwks.GetOpenIDConfigurationError
		require.True(t, errors.As(err, &openIDCfgErr))
		require.Equal(t, issuerConfigServer.URL+jwks.OpenIDConfigurationPath, openIDCfgErr.URL)
		require.EqualError(t, openIDCfgErr.Inner, "unexpected HTTP code 500")
		require.Nil(t, pubKey)
	})

	t.Run("openid configuration server respond invalid json", func(t *testing.T) {
		issuerConfigServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			_, err := rw.Write([]byte(`{"invalid-json"]`))
			require.NoError(t, err)
		}))
		defer issuerConfigServer.Close()

		client := jwks.NewClient()
		pubKey, err := client.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.Error(t, err)
		var openIDCfgErr *jwks.GetOpenIDConfigurationError
		require.True(t, errors.As(err, &openIDCfgErr))
		require.Equal(t, issuerConfigServer.URL+jwks.OpenIDConfigurationPath, openIDCfgErr.URL)
		var jsonSyntaxErr *json.SyntaxError
		require.True(t, errors.As(openIDCfgErr, &jsonSyntaxErr))
		require.Nil(t, pubKey)
	})

	t.Run("jwks server unavailable", func(t *testing.T) {
		jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
		jwksServer.Close() // Close the server immediately.
		issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
		defer issuerConfigServer.Close()

		client := jwks.NewClient()
		pubKey, err := client.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.Error(t, err)
		var jwksErr *jwks.GetJWKSError
		require.True(t, errors.As(err, &jwksErr))
		require.Equal(t, jwksServer.URL, jwksErr.URL)
		require.Equal(t, issuerConfigServer.URL+jwks.OpenIDConfigurationPath, jwksErr.OpenIDConfigurationURL)
		requireLocalhostConnRefusedError(t, jwksErr.Inner)
		require.Nil(t, pubKey)
	})

	t.Run("jwks server respond internal error", func(t *testing.T) {
		jwksServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusInternalServerError)
		}))
		defer jwksServer.Close()
		issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
		defer issuerConfigServer.Close()

		client := jwks.NewClient()
		pubKey, err := client.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.Error(t, err)
		var jwksErr *jwks.GetJWKSError
		require.True(t, errors.As(err, &jwksErr))
		require.Equal(t, jwksServer.URL, jwksErr.URL)
		require.Equal(t, issuerConfigServer.URL+jwks.OpenIDConfigurationPath, jwksErr.OpenIDConfigurationURL)
		require.EqualError(t, jwksErr.Inner, "unexpected HTTP code 500")
		require.Nil(t, pubKey)
	})

	t.Run("jwk not found", func(t *testing.T) {
		jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
		defer jwksServer.Close()
		issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
		defer issuerConfigServer.Close()

		const unknownKeyID = "77777777-7777-7777-7777-777777777777"

		client := jwks.NewClient()
		pubKey, err := client.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, unknownKeyID)
		require.Error(t, err)
		var jwkErr *jwks.JWKNotFoundError
		require.True(t, errors.As(err, &jwkErr))
		require.Equal(t, issuerConfigServer.URL, jwkErr.IssuerURL)
		require.Equal(t, unknownKeyID, jwkErr.KeyID)
		require.Nil(t, pubKey)
	})

	t.Run("context canceled", func(t *testing.T) {
		jwksServer := httptest.NewServer(&idptest.JWKSHandler{})
		defer jwksServer.Close()
		issuerConfigServer := httptest.NewServer(&idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL})
		defer issuerConfigServer.Close()

		client := jwks.NewClient()
		ctx, cancelCtxFn := context.WithCancel(context.Background())
		cancelCtxFn() // Emulate canceling context.
		pubKey, err := client.GetRSAPublicKey(ctx, issuerConfigServer.URL, idptest.TestKeyID)
		require.Error(t, err)
		var openIDCfgErr *jwks.GetOpenIDConfigurationError
		require.True(t, errors.As(err, &openIDCfgErr))
		require.Equal(t, issuerConfigServer.URL+jwks.OpenIDConfigurationPath, openIDCfgErr.URL)
		require.ErrorIs(t, openIDCfgErr, context.Canceled)
		require.Nil(t, pubKey)
	})
}

func requireLocalhostConnRefusedError(t *testing.T, err error) {
	t.Helper()
	require.True(t,
		strings.Contains(err.Error(), "dial tcp 127.0.0.1:") && strings.Contains(err.Error(), "refused"),
		`Error %q doesn't contain "dial tcp 127.0.0.1 ... refused"`, err)
}
