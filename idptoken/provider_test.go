/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
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
				ClientSecret: uuid.NewString(),
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
				ClientSecret: uuid.NewString(),
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
		require.NotEqual(t, reissuedToken, cachedToken, "token was not re-issued")
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
				ClientSecret: uuid.NewString(),
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
		require.NotEqual(t, token, tokenOld, "token should have already been refreshed")
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
				ClientSecret: uuid.NewString(),
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
		require.NotEqual(t, token, tokenOld, "token should have already been refreshed")
	})

	t.Run("failing idp endpoint", func(t *testing.T) {
		server := idptest.NewHTTPServer(idptest.WithHTTPTokenHandler(&tFailingIDPTokenHandler{}))
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: uuid.NewString(),
				URL:          server.URL(),
			},
			{
				ClientID:     testClientID,
				ClientSecret: uuid.NewString(),
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
		promMetrics := metrics.GetPrometheusMetrics("", metrics.SourceTokenProvider)
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
				ClientSecret: uuid.NewString(),
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
		promMetrics := metrics.GetPrometheusMetrics("", metrics.SourceTokenProvider)
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
		)
		require.NoError(t, server2.StartAndWaitForReady(time.Second))
		defer func() { _ = server2.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server.URL(),
			},
			{
				ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server2.URL(),
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
		)
		require.NoError(t, server2.StartAndWaitForReady(time.Second))
		defer func() { _ = server2.Shutdown(context.Background()) }()

		credentials := []idptoken.Source{
			{
				ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server.URL(),
			},
			{
				ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server2.URL(),
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
			ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server.URL(),
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
			ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server.URL(),
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
			ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server.URL(),
		}
		tokenCache := idptoken.NewInMemoryTokenCache()
		provider := idptoken.NewMultiSourceProviderWithOpts(nil, idptoken.ProviderOpts{
			CustomCacheInstance: tokenCache, HTTPClient: httpClient})
		go provider.RefreshTokensPeriodically(context.Background())
		provider.RegisterSource(credentials)
		credentials.ClientSecret = uuid.NewString()
		provider.RegisterSource(credentials)
		_, tokenErr := provider.GetToken(
			context.Background(), testClientID, server.URL(), "tenants:read",
		)
		require.NoError(t, tokenErr)
		provider.RegisterSource(credentials)
		require.Equal(t, 1, len(tokenCache.Keys()), "updating with same secret does not reset the cache")
		credentials.ClientSecret = uuid.NewString()
		provider.RegisterSource(credentials)
		require.Equal(t, 0, len(tokenCache.Keys()), "updating with a new secret does reset the cache")
	})
}

func TestProviderConcurrency(t *testing.T) {
	t.Run("concurrent GetToken calls with same parameters", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		provider := idptoken.NewProvider(idptoken.Source{
			ClientID:     testClientID,
			ClientSecret: uuid.NewString(),
			URL:          server.URL(),
		})

		const numGoroutines = 100
		var wg sync.WaitGroup
		tokens := make([]string, numGoroutines)
		errors := make([]error, numGoroutines)

		// All goroutines request the same token simultaneously
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				token, err := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
				tokens[idx] = token
				errors[idx] = err
			}(i)
		}

		wg.Wait()

		// All should succeed
		for i := 0; i < numGoroutines; i++ {
			require.NoError(t, errors[i], "goroutine %d failed", i)
			require.NotEmpty(t, tokens[i], "goroutine %d got empty token", i)
		}

		// All should get the same token (singleflight should deduplicate)
		firstToken := tokens[0]
		for i := 1; i < numGoroutines; i++ {
			require.Equal(t, firstToken, tokens[i], "token mismatch at index %d", i)
		}
	})

	t.Run("concurrent GetToken calls with different parameters", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		provider := idptoken.NewProvider(idptoken.Source{
			ClientID:     testClientID,
			ClientSecret: uuid.NewString(),
			URL:          server.URL(),
		})

		scopes := []string{"scope1", "scope2", "scope3", "scope4", "scope5"}
		const goroutinesPerScope = 20
		var wg sync.WaitGroup
		tokens := make(map[string][]string)
		var tokensMu sync.Mutex
		errors := make([]error, 0)
		var errorsMu sync.Mutex

		// Multiple goroutines request different scopes simultaneously
		for _, scope := range scopes {
			for i := 0; i < goroutinesPerScope; i++ {
				wg.Add(1)
				go func(s string) {
					defer wg.Done()
					token, err := provider.GetToken(context.Background(), testClientID, server.URL(), s)
					if err != nil {
						errorsMu.Lock()
						errors = append(errors, err)
						errorsMu.Unlock()
						return
					}
					tokensMu.Lock()
					tokens[s] = append(tokens[s], token)
					tokensMu.Unlock()
				}(scope)
			}
		}

		wg.Wait()

		// All should succeed
		require.Empty(t, errors, "some goroutines failed")
		require.Equal(t, len(scopes), len(tokens), "not all scopes were requested")

		// Tokens for the same scope should be identical
		for scope, scopeTokens := range tokens {
			require.Equal(t, goroutinesPerScope, len(scopeTokens), "missing tokens for scope %s", scope)
			firstToken := scopeTokens[0]
			for i, token := range scopeTokens {
				require.Equal(t, firstToken, token, "token mismatch for scope %s at index %d", scope, i)
			}
		}
	})

	t.Run("concurrent RegisterSource calls", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		provider := idptoken.NewMultiSourceProvider(nil)

		const numGoroutines = 50
		var wg sync.WaitGroup

		// Multiple goroutines register sources simultaneously
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				source := idptoken.Source{
					ClientID:     fmt.Sprintf("client-%d", idx),
					ClientSecret: uuid.NewString(),
					URL:          server.URL(),
				}
				provider.RegisterSource(source)
			}(i)
		}

		wg.Wait()

		// All sources should be registered successfully
		// Try to get tokens for all registered sources
		for i := 0; i < numGoroutines; i++ {
			clientID := fmt.Sprintf("client-%d", i)
			_, err := provider.GetToken(context.Background(), clientID, server.URL(), "scope")
			require.NoError(t, err, "failed to get token for client-%d", i)
		}
	})

	t.Run("concurrent GetToken and Invalidate", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		provider := idptoken.NewProvider(idptoken.Source{
			ClientID:     testClientID,
			ClientSecret: uuid.NewString(),
			URL:          server.URL(),
		})

		const numGoroutines = 50
		var wg sync.WaitGroup
		successCount := int32(0)

		// Some goroutines get tokens while others invalidate
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				if idx%5 == 0 {
					provider.Invalidate()
				}
				_, err := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
				if err == nil {
					atomic.AddInt32(&successCount, 1)
				}
			}(i)
		}

		wg.Wait()

		// All GetToken calls should succeed
		require.Equal(t, int(successCount), numGoroutines, "some GetToken calls failed")
	})

	t.Run("concurrent GetToken with refresh loop", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 3 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		provider := idptoken.NewProviderWithOpts(idptoken.Source{
			ClientID:     testClientID,
			ClientSecret: uuid.NewString(),
			URL:          server.URL(),
		}, idptoken.ProviderOpts{
			MinRefreshPeriod: 500 * time.Millisecond,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go provider.RefreshTokensPeriodically(ctx)

		const numGoroutines = 30
		const duration = 5 * time.Second
		var wg sync.WaitGroup
		stopTime := time.Now().Add(duration)

		// Continuously request tokens while refresh loop is running
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				for time.Now().Before(stopTime) {
					_, err := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
					if err != nil {
						t.Logf("goroutine %d got error: %v", idx, err)
					}
					time.Sleep(100 * time.Millisecond)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent GetTokenWithHeaders", func(t *testing.T) {
		server := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()

		provider := idptoken.NewProvider(idptoken.Source{
			ClientID:     testClientID,
			ClientSecret: uuid.NewString(),
			URL:          server.URL(),
		})

		const numGoroutines = 50
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)

		// Multiple goroutines request tokens with different headers
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				headers := map[string]string{
					"X-Request-ID": fmt.Sprintf("request-%d", idx),
				}
				_, err := provider.GetTokenWithHeaders(context.Background(), headers, "tenants:read")
				errors[idx] = err
			}(i)
		}

		wg.Wait()

		// All should succeed
		for i := 0; i < numGoroutines; i++ {
			require.NoError(t, errors[i], "goroutine %d failed", i)
		}
	})

	t.Run("concurrent cache operations", func(t *testing.T) {
		cache := idptoken.NewInMemoryTokenCache()

		const numGoroutines = 100
		var wg sync.WaitGroup

		// Mix of Put, Get, Delete, Keys, GetAll operations
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				key := fmt.Sprintf("key-%d", idx%10) // Reuse some keys

				// Put
				details := &idptoken.TokenDetails{}
				cache.Put(key, details)

				// Get
				_ = cache.Get(key)

				// Keys
				_ = cache.Keys()

				// GetAll
				_ = cache.GetAll()

				// Delete some
				if idx%3 == 0 {
					cache.Delete(key)
				}
			}(i)
		}

		wg.Wait()
	})

	t.Run("concurrent multi-source access", func(t *testing.T) {
		server1 := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server1.StartAndWaitForReady(time.Second))
		defer func() { _ = server1.Shutdown(context.Background()) }()

		server2 := idptest.NewHTTPServer(
			idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		)
		require.NoError(t, server2.StartAndWaitForReady(time.Second))
		defer func() { _ = server2.Shutdown(context.Background()) }()

		provider := idptoken.NewMultiSourceProvider([]idptoken.Source{
			{
				ClientID:     "client1",
				ClientSecret: uuid.NewString(),
				URL:          server1.URL(),
			},
			{
				ClientID:     "client2",
				ClientSecret: uuid.NewString(),
				URL:          server2.URL(),
			},
		})

		const numGoroutines = 100
		var wg sync.WaitGroup
		errors := make([]error, numGoroutines)

		// Goroutines randomly access different sources
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				if idx%2 == 0 {
					_, err := provider.GetToken(context.Background(), "client1", server1.URL(), "scope1")
					errors[idx] = err
				} else {
					_, err := provider.GetToken(context.Background(), "client2", server2.URL(), "scope2")
					errors[idx] = err
				}
			}(i)
		}

		wg.Wait()

		// All should succeed
		for i := 0; i < numGoroutines; i++ {
			require.NoError(t, errors[i], "goroutine %d failed", i)
		}
	})
}

func TestProvider_OpenIDConfigurationErrors(t *testing.T) {
	const retryAfterValue = "120"

	t.Run("error, openid config returns 503", func(t *testing.T) {
		// Create a test server that returns 503 for OpenID configuration endpoint
		testServer := http.NewServeMux()
		testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", retryAfterValue)
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
		listener, err := net.Listen("tcp", server.Addr)
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()

		go func() { _ = server.Serve(listener) }()
		defer func() { _ = server.Shutdown(context.Background()) }()

		serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: uuid.NewString(),
				URL:          serverURL,
			},
		}
		// Use a custom HTTP client with minimal timeout and no retries
		httpClient := &http.Client{Timeout: 2 * time.Second}
		opts := idptoken.ProviderOpts{
			HTTPClient: httpClient,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

		_, err = provider.GetToken(context.Background(), testClientID, serverURL)
		var svcUnavailableErr *idptoken.ServiceUnavailableError
		require.ErrorAs(t, err, &svcUnavailableErr)
		require.Equal(t, retryAfterValue, svcUnavailableErr.RetryAfter)
	})

	t.Run("error, openid config returns 429", func(t *testing.T) {
		// Create a test server that returns 429 for OpenID configuration endpoint
		testServer := http.NewServeMux()
		testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", retryAfterValue)
			w.WriteHeader(http.StatusTooManyRequests)
		})
		server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
		listener, err := net.Listen("tcp", server.Addr)
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()

		go func() { _ = server.Serve(listener) }()
		defer func() { _ = server.Shutdown(context.Background()) }()

		serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: uuid.NewString(),
				URL:          serverURL,
			},
		}
		// Use a custom HTTP client with minimal timeout and no retries
		httpClient := &http.Client{Timeout: 2 * time.Second}
		opts := idptoken.ProviderOpts{
			HTTPClient: httpClient,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

		_, err = provider.GetToken(context.Background(), testClientID, serverURL)
		var throttledErr *idptoken.ThrottledError
		require.ErrorAs(t, err, &throttledErr)
		require.Equal(t, retryAfterValue, throttledErr.RetryAfter)
	})
}

func TestProvider_TokenEndpointErrors(t *testing.T) {
	const retryAfterValue = "120"

	t.Run("error, token endpoint returns 503", func(t *testing.T) {
		// Create a test server that returns 503 for token endpoint
		testServer := http.NewServeMux()
		// OpenID configuration needs to be served to get the token URL
		testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]string{
				"token_endpoint": fmt.Sprintf("http://%s%s", r.Host, idptest.TokenEndpointPath),
			}
			_ = json.NewEncoder(w).Encode(resp)
		})
		testServer.HandleFunc(idptest.TokenEndpointPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", retryAfterValue)
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
		listener, err := net.Listen("tcp", server.Addr)
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()

		go func() { _ = server.Serve(listener) }()
		defer func() { _ = server.Shutdown(context.Background()) }()

		serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: uuid.NewString(),
				URL:          serverURL,
			},
		}
		// Use a custom HTTP client with minimal timeout and no retries
		httpClient := &http.Client{Timeout: 2 * time.Second}
		opts := idptoken.ProviderOpts{
			HTTPClient: httpClient,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

		_, err = provider.GetToken(context.Background(), testClientID, serverURL)
		var svcUnavailableErr *idptoken.ServiceUnavailableError
		require.ErrorAs(t, err, &svcUnavailableErr)
		require.Equal(t, retryAfterValue, svcUnavailableErr.RetryAfter)
	})

	t.Run("error, token endpoint returns 429", func(t *testing.T) {
		// Create a test server that returns 429 for token endpoint
		testServer := http.NewServeMux()
		// OpenID configuration needs to be served to get the token URL
		testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]string{
				"token_endpoint": fmt.Sprintf("http://%s%s", r.Host, idptest.TokenEndpointPath),
			}
			_ = json.NewEncoder(w).Encode(resp)
		})
		testServer.HandleFunc(idptest.TokenEndpointPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", retryAfterValue)
			w.WriteHeader(http.StatusTooManyRequests)
		})
		server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
		listener, err := net.Listen("tcp", server.Addr)
		require.NoError(t, err)
		defer func() { _ = listener.Close() }()

		go func() { _ = server.Serve(listener) }()
		defer func() { _ = server.Shutdown(context.Background()) }()

		serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

		credentials := []idptoken.Source{
			{
				ClientID:     testClientID,
				ClientSecret: uuid.NewString(),
				URL:          serverURL,
			},
		}
		// Use a custom HTTP client with minimal timeout and no retries
		httpClient := &http.Client{Timeout: 2 * time.Second}
		opts := idptoken.ProviderOpts{
			HTTPClient: httpClient,
		}
		provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

		_, err = provider.GetToken(context.Background(), testClientID, serverURL)
		var throttledErr *idptoken.ThrottledError
		require.ErrorAs(t, err, &throttledErr)
		require.Equal(t, retryAfterValue, throttledErr.RetryAfter)
	})
}

type claimsProviderWithExpiration struct {
	ExpTime time.Duration
}

func (d *claimsProviderWithExpiration) Provide(_ *http.Request) (jwt.Claims, error) {
	claims := &jwt.DefaultClaims{
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
	}

	if d.ExpTime <= 0 {
		d.ExpTime = 24 * time.Hour
	}
	claims.ExpiresAt = jwtgo.NewNumericDate(time.Now().UTC().Add(d.ExpTime))

	return claims, nil
}
