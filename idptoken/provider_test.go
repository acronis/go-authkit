/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/acronis/go-appkit/httpclient"
	"github.com/acronis/go-appkit/log"
	"github.com/acronis/go-appkit/testutil"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/jwt"
)

const (
	expectedUserAgent              = "Token MultiSourceProvider/1.0"
	expectedXRequestID             = "test"
	testClientID                   = "89cadd1f-8649-4531-8b1d-a25de5aa3cd6"
	defaultTestTokenExpirationTime = 2
)

type tTokenResponseBody struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope,omitempty"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

type tFailingIDPTokenHandler struct{}

func (h *tFailingIDPTokenHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusInternalServerError)
	response := tTokenResponseBody{
		Error: "server_error",
	}
	encoder := json.NewEncoder(rw)
	err := encoder.Encode(response)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

type tHeaderCheckingIDPTokenHandler struct {
	t *testing.T
}

func (h *tHeaderCheckingIDPTokenHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	require.Equal(h.t, expectedUserAgent, r.Header.Get("User-Agent"))
	require.Equal(h.t, expectedXRequestID, r.Header.Get("X-Request-ID"))
	rw.WriteHeader(http.StatusOK)
	response := tTokenResponseBody{
		AccessToken: "success",
		ExpiresIn:   defaultTestTokenExpirationTime,
		Scope:       "tenants:viewer",
	}
	encoder := json.NewEncoder(rw)
	err := encoder.Encode(response)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

func TestProviderWithCache(t *testing.T) {
	tr, _ := httpclient.NewRetryableRoundTripperWithOpts(
		http.DefaultTransport, httpclient.RetryableRoundTripperOpts{MaxRetryAttempts: 3},
	)
	httpClient := &http.Client{Transport: tr}
	logger := log.NewDisabledLogger()

	t.Run("custom headers", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPTokenHandler(&tHeaderCheckingIDPTokenHandler{t}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: "DAGztV5L2hMZyECzer6SXS",
				URL:          server.URL(),
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
			CustomHeaders:    map[string]string{"User-Agent": expectedUserAgent},
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())
		_, tokenErr := provider.GetTokenWithHeaders(
			context.Background(), testClientID, server.URL(),
			map[string]string{"X-Request-ID": expectedXRequestID}, "tenants:read",
		)
		require.NoError(t, tokenErr)
	})

	t.Run("get token", func(t *testing.T) {
		const tokenTTL = 2 * time.Second

		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: tokenTTL}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: "DAGztV5L2hMZyECzer6SXS",
				URL:          server.URL(),
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())
		cachedToken, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)

		newToken, newTokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, newTokenErr)
		require.Equal(t, cachedToken, newToken, "token was not cached")
		time.Sleep(tokenTTL * 2)

		reissuedToken, reissuedTokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, reissuedTokenErr)
		require.Greater(t, reissuedToken, cachedToken, "token was not re-issued")
	})

	t.Run("automatic refresh", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: "DAGztV5L2hMZyECzer6SXS",
				URL:          server.URL(),
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())

		tokenOld, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)
		time.Sleep(3 * time.Second)
		token, refreshErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, refreshErr)
		require.Greater(t, token, tokenOld, "token should have already been refreshed")
	})

	t.Run("invalidate", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: "DAGztV5L2hMZyECzer6SXS",
				URL:          server.URL(),
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 10 * time.Second,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())

		tokenOld, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)
		provider.Invalidate()
		time.Sleep(1 * time.Second)
		token, refreshErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, refreshErr)
		require.Greater(t, token, tokenOld, "token should have already been refreshed")
	})

	t.Run("failing idp endpoint", func(t *testing.T) {
		server := idptest.NewHTTPServer(idptest.WithHTTPTokenHandler(&tFailingIDPTokenHandler{}))
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: "DAGztV5L2hMZyECzer6SXS",
				URL:          server.URL(),
			},
			{
				ClientID:     testClientID,
				ClientSecret: "DAGztV5L2hMZyECzer6SXS",
				URL:          server.URL() + "/weird",
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())
		_, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.Error(t, tokenErr)
		labels := prometheus.Labels{
			metrics.HTTPClientRequestLabelMethod:     http.MethodPost,
			metrics.HTTPClientRequestLabelURL:        server.URL() + idptest.TokenEndpointPath,
			metrics.HTTPClientRequestLabelStatusCode: "500",
			metrics.HTTPClientRequestLabelError:      "unexpected_status_code",
		}
		promMetrics := metrics.GetPrometheusMetrics("", "token_provider")
		hist := promMetrics.HTTPClientRequestDuration.With(labels).(prometheus.Histogram)
		testutil.AssertSamplesCountInHistogram(t, hist, 1)
	})

	t.Run("metrics", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: "DAGztV5L2hMZyECzer6SXS",
				URL:          server.URL(),
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())
		_, tokenErr := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
		require.NoError(t, tokenErr)
		labels := prometheus.Labels{
			metrics.HTTPClientRequestLabelMethod:     http.MethodPost,
			metrics.HTTPClientRequestLabelURL:        server.URL() + idptest.TokenEndpointPath,
			metrics.HTTPClientRequestLabelStatusCode: "200",
			metrics.HTTPClientRequestLabelError:      "",
		}
		promMetrics := metrics.GetPrometheusMetrics("", "token_provider")
		hist := promMetrics.HTTPClientRequestDuration.With(labels).(prometheus.Histogram)
		testutil.AssertSamplesCountInHistogram(t, hist, 1)
	})

	t.Run("multiple sources", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		server2 := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
			idptest.WithHTTPAddress(":8082"),
		)
		require.NoError(t, server2.StartAndWaitForReady(time.Second))
		defer func() { _ = server2.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
			},
			{
				ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXs", URL: server2.URL(),
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())
		_, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)

		_, tokenErr = provider.GetToken(
			context.Background(), testClientID, server2.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)
	})

	t.Run("multiple sources", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		server2 := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
			idptest.WithHTTPAddress(":8082"),
		)
		require.NoError(t, server2.StartAndWaitForReady(time.Second))
		defer func() { _ = server2.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
			},
			{
				ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXs", URL: server2.URL(),
			},
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials[:1], opts)
		go provider.RefreshTokensPeriodically(context.Background())
		provider.RegisterSource(credentials[1])
		_, tokenErr := provider.GetToken(
			context.Background(), testClientID, server2.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)
	})

	t.Run("single source provider", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := idptoken.Source{
			ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
		}
		opts := idptoken.ProviderOpts{
			Logger:           logger,
			MinRefreshPeriod: 1 * time.Second,
		}
		provider := idptoken.NewProviderWithOpts(credentials, opts)
		go provider.RefreshTokensPeriodically(context.Background())
		_, tokenErr := provider.GetToken(context.Background(), "tenants:read")
		require.NoError(t, tokenErr)
	})

	t.Run("start with no sources and register later", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := idptoken.Source{
			ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(nil, idptoken.ProviderOpts{HTTPClient: httpClient})
		go provider.RefreshTokensPeriodically(context.Background())
		provider.RegisterSource(credentials)
		_, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)
	})

	t.Run("register source twice", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := idptoken.Source{
			ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
		}
		tokenCache := idptoken.NewInMemoryTokenCache()
		provider := idptoken.NewMultiSourceProviderWithOpts(nil, idptoken.ProviderOpts{
			CustomCacheInstance: tokenCache, HTTPClient: httpClient})
		go provider.RefreshTokensPeriodically(context.Background())
		provider.RegisterSource(credentials)
		credentials.ClientSecret = "newsecret"
		provider.RegisterSource(credentials)
		_, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)
		provider.RegisterSource(credentials)
		require.Equal(t, 1, len(tokenCache.Keys()), "updating with same secret does not reset the cache")
		credentials.ClientSecret = "evennewersecret"
		provider.RegisterSource(credentials)
		require.Equal(t, 0, len(tokenCache.Keys()), "updating with a new secret does reset the cache")
	})
}

type claimsProviderWithExpiration struct {
	ExpTime time.Duration
}

func (d *claimsProviderWithExpiration) Provide(_ *http.Request) (jwt.Claims, error) {
	claims := jwt.Claims{
		// nolint:staticcheck // StandardClaims are used here for test purposes
		RegisteredClaims: jwtgo.RegisteredClaims{
			ID:       uuid.NewString(),
			IssuedAt: jwtgo.NewNumericDate(time.Now().UTC()),
		},
		Scope: []jwt.AccessPolicy{
			{
				TenantID:   "1",
				TenantUUID: uuid.NewString(),
				Role:       "tenant:viewer",
			},
		},
		Version: 1,
		UserID:  "1",
	}

	if d.ExpTime <= 0 {
		d.ExpTime = 24 * time.Hour
	}
	claims.ExpiresAt = jwtgo.NewNumericDate(time.Now().UTC().Add(d.ExpTime))

	return claims, nil
}
