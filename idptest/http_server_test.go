/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	gotesting "testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/idputil"
)

func TestHTTPServerOpenIDConfiguration(t *gotesting.T) {
	customURL, _ := url.Parse("http://idp.example.com:1234")
	tests := []struct {
		name          string
		options       []HTTPServerOption
		openIDCfgPath string
		checkResponse func(t *gotesting.T, idpSrv *HTTPServer, respData OpenIDConfigurationResponse)
	}{
		{
			name:          "default endpoints",
			openIDCfgPath: OpenIDConfigurationPath,
			checkResponse: func(t *gotesting.T, idpSrv *HTTPServer, respData OpenIDConfigurationResponse) {
				require.Equal(t, OpenIDConfigurationResponse{
					TokenEndpoint:         idpSrv.URL() + TokenEndpointPath,
					IntrospectionEndpoint: idpSrv.URL() + TokenIntrospectionEndpointPath,
					JWKSURI:               idpSrv.URL() + JWKSEndpointPath,
				}, respData)
			},
		},
		{
			name:          "default endpoints, custom host",
			openIDCfgPath: OpenIDConfigurationPath,
			options: []HTTPServerOption{
				WithOpenIDCustomURL(customURL),
			},
			checkResponse: func(t *gotesting.T, idpSrv *HTTPServer, respData OpenIDConfigurationResponse) {
				require.Equal(t, OpenIDConfigurationResponse{
					TokenEndpoint:         "http://idp.example.com:1234" + TokenEndpointPath,
					IntrospectionEndpoint: "http://idp.example.com:1234" + TokenIntrospectionEndpointPath,
					JWKSURI:               "http://idp.example.com:1234" + JWKSEndpointPath,
				}, respData)
			},
		},
		{
			name: "custom endpoints",
			options: []HTTPServerOption{
				WithHTTPEndpointPaths(HTTPPaths{
					OpenIDConfiguration: "/custom/openid-configuration",
					Token:               "/custom/token",
					TokenIntrospection:  "/custom/introspect_token",
					JWKS:                "/custom/keys",
				}),
			},
			openIDCfgPath: "/custom/openid-configuration",
			checkResponse: func(t *gotesting.T, idpSrv *HTTPServer, respData OpenIDConfigurationResponse) {
				require.Equal(t, OpenIDConfigurationResponse{
					TokenEndpoint:         idpSrv.URL() + "/custom/token",
					IntrospectionEndpoint: idpSrv.URL() + "/custom/introspect_token",
					JWKSURI:               idpSrv.URL() + "/custom/keys",
				}, respData)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *gotesting.T) {
			idpSrv := NewHTTPServer(tt.options...)
			require.NoError(t, idpSrv.StartAndWaitForReady(time.Second*3))
			defer func() {
				require.NoError(t, idpSrv.Shutdown(context.Background()))
			}()

			client := &http.Client{Timeout: time.Second * 5}
			resp, err := client.Get(idpSrv.URL() + tt.openIDCfgPath)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			respBody, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())

			var respData OpenIDConfigurationResponse
			require.NoError(t, json.Unmarshal(respBody, &respData))
			tt.checkResponse(t, idpSrv, respData)
		})
	}
}

func TestHTTPServerDefault(t *gotesting.T) {
	idpSrv := NewHTTPServer()
	require.NoError(t, idpSrv.StartAndWaitForReady(time.Second*3))
	defer func() { require.NoError(t, idpSrv.Shutdown(context.Background())) }()

	client := &http.Client{Timeout: time.Second * 5}

	// Issue new token.
	resp, err := client.Post(idpSrv.URL()+TokenEndpointPath, "application/x-www-form-urlencoded", http.NoBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	var tokenRespData TokenResponse
	require.NoError(t, json.Unmarshal(respBody, &tokenRespData))
	require.NotEmpty(t, tokenRespData.AccessToken)
	require.Equal(t, idputil.TokenTypeBearer, tokenRespData.TokenType)
	require.Greater(t, tokenRespData.ExpiresIn, int64(0))

	// Introspect token.
	resp, err = client.Post(idpSrv.URL()+TokenIntrospectionEndpointPath, "application/x-www-form-urlencoded",
		bytes.NewReader([]byte("token="+tokenRespData.AccessToken)))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	respBody, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	var introspectionRespData idptoken.DefaultIntrospectionResult
	require.NoError(t, json.Unmarshal(respBody, &introspectionRespData))
	require.True(t, introspectionRespData.Active)
	require.Equal(t, idpSrv.URL(), introspectionRespData.Issuer)
}
