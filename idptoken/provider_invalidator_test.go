/*
Copyright © 2026 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acronis/go-appkit/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/jwt"
)

// The method set of go-appkit httpclient.InvalidatableAuthProvider.
type invalidatableAuthProvider interface {
	GetTokenWithInvalidator(ctx context.Context, scope ...string) (token string, invalidate func() bool, err error)
}

var _ invalidatableAuthProvider = (*idptoken.Provider)(nil)

type countingClaimsProvider struct {
	inner  claimsProviderWithExpiration
	issued atomic.Int32
}

func (c *countingClaimsProvider) Provide(r *http.Request) (jwt.Claims, error) {
	c.issued.Add(1)
	return c.inner.Provide(r)
}

func startCountingIDPServer(t *testing.T) (*idptest.HTTPServer, *countingClaimsProvider) {
	t.Helper()
	claimsProvider := &countingClaimsProvider{inner: claimsProviderWithExpiration{ExpTime: time.Hour}}
	server := idptest.NewHTTPServer(idptest.WithHTTPClaimsProvider(claimsProvider))
	require.NoError(t, server.StartAndWaitForReady(time.Second))
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return server, claimsProvider
}

func newTestMultiSourceProvider(serverURL string, minInvalidationInterval time.Duration) *idptoken.MultiSourceProvider {
	return idptoken.NewMultiSourceProviderWithOpts(
		[]idptoken.Source{{ClientID: testClientID, ClientSecret: uuid.NewString(), URL: serverURL}},
		idptoken.ProviderOpts{Logger: log.NewDisabledLogger(), MinInvalidationInterval: minInvalidationInterval},
	)
}

func TestMultiSourceProvider_GetTokenWithInvalidator(t *testing.T) {
	ctx := context.Background()

	t.Run("invalidator removes only its own token", func(t *testing.T) {
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		tokenA, invalidateA, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		tokenB, _, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:b")
		require.NoError(t, err)
		require.EqualValues(t, 2, claims.issued.Load())

		require.True(t, invalidateA())

		sameTokenB, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:b")
		require.NoError(t, err)
		require.Equal(t, tokenB, sameTokenB)
		require.EqualValues(t, 2, claims.issued.Load(), "token of another scope must not be reissued")

		newTokenA, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.NotEqual(t, tokenA, newTokenA)
		require.EqualValues(t, 3, claims.issued.Load())
	})

	t.Run("first invalidation of a fresh token is not throttled", func(t *testing.T) {
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		token, invalidate, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.True(t, invalidate())

		newToken, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.NotEqual(t, token, newToken)
		require.EqualValues(t, 2, claims.issued.Load())
	})

	t.Run("second invalidation of the same entry within min invalidation interval is throttled", func(t *testing.T) {
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		_, invalidate, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.True(t, invalidate())

		newToken, invalidateNew, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.False(t, invalidateNew())

		sameToken, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.Equal(t, newToken, sameToken)
		require.EqualValues(t, 2, claims.issued.Load())
	})

	t.Run("min invalidation interval is per entry", func(t *testing.T) {
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		_, invalidateA, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		_, invalidateB, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:b")
		require.NoError(t, err)

		require.True(t, invalidateA())
		require.True(t, invalidateB(), "invalidation of another entry must not be throttled")
		require.EqualValues(t, 2, claims.issued.Load())
	})

	t.Run("entry can be invalidated again after min invalidation interval", func(t *testing.T) {
		const minInvalidationInterval = 200 * time.Millisecond
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), minInvalidationInterval)

		_, invalidate, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.True(t, invalidate())

		token, invalidateNew, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.False(t, invalidateNew())
		time.Sleep(minInvalidationInterval + 100*time.Millisecond)
		require.True(t, invalidateNew())

		newToken, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.NotEqual(t, token, newToken)
		require.EqualValues(t, 3, claims.issued.Load())
	})

	t.Run("invalidator is idempotent", func(t *testing.T) {
		server, _ := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		_, invalidate, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.True(t, invalidate())
		require.False(t, invalidate())
	})

	t.Run("stale invalidator keeps the reissued token", func(t *testing.T) {
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		oldToken, invalidateOld, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.True(t, invalidateOld())

		newToken, _, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.NotEqual(t, oldToken, newToken)

		require.False(t, invalidateOld())
		sameToken, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.Equal(t, newToken, sameToken)
		require.EqualValues(t, 2, claims.issued.Load())
	})

	t.Run("stale invalidator without throttling keeps the reissued token", func(t *testing.T) {
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		_, invalidateOld, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		provider.Invalidate() // Removes the entry without throttling the next invalidation.
		newToken, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)

		require.False(t, invalidateOld())
		sameToken, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.Equal(t, newToken, sameToken)
		require.EqualValues(t, 2, claims.issued.Load())
	})

	t.Run("shared scope slice is not modified", func(t *testing.T) {
		const goroutines = 20
		server, _ := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)
		scope := []string{"scope:b", "scope:a", "scope:b"}

		var wg sync.WaitGroup
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), scope...)
				require.NoError(t, err)
			}()
		}
		wg.Wait()
		require.Equal(t, []string{"scope:b", "scope:a", "scope:b"}, scope)
	})

	t.Run("concurrent invalidators remove the token once", func(t *testing.T) {
		const goroutines = 20
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		invalidators := make([]func() bool, goroutines)
		for i := range invalidators {
			var err error
			_, invalidators[i], err = provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
			require.NoError(t, err)
		}
		require.EqualValues(t, 1, claims.issued.Load())

		var removed atomic.Int32
		var wg sync.WaitGroup
		for _, invalidate := range invalidators {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if invalidate() {
					removed.Add(1)
				}
			}()
		}
		wg.Wait()
		require.EqualValues(t, 1, removed.Load())

		_, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		require.EqualValues(t, 2, claims.issued.Load())
	})

	t.Run("invalidator after Invalidate does nothing", func(t *testing.T) {
		server, _ := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		_, invalidate, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		provider.Invalidate()
		require.False(t, invalidate())
	})

	t.Run("Invalidate still removes all tokens", func(t *testing.T) {
		server, claims := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), time.Hour)

		tokenA, _, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		tokenB, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:b")
		require.NoError(t, err)

		provider.Invalidate()

		newTokenA, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:a")
		require.NoError(t, err)
		newTokenB, err := provider.GetToken(ctx, testClientID, server.URL(), "scope:b")
		require.NoError(t, err)
		require.NotEqual(t, tokenA, newTokenA)
		require.NotEqual(t, tokenB, newTokenB)
		require.EqualValues(t, 4, claims.issued.Load())
	})

	t.Run("error returns a no-op invalidator", func(t *testing.T) {
		server, _ := startCountingIDPServer(t)
		provider := newTestMultiSourceProvider(server.URL(), 0)

		token, invalidate, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL()+"/unknown", "scope:a")
		require.ErrorIs(t, err, idptoken.ErrSourceNotRegistered)
		require.Empty(t, token)
		require.NotNil(t, invalidate)
		require.False(t, invalidate())
	})

	t.Run("failing idp endpoint returns a no-op invalidator", func(t *testing.T) {
		server := idptest.NewHTTPServer(idptest.WithHTTPTokenHandler(&tFailingIDPTokenHandler{}))
		require.NoError(t, server.StartAndWaitForReady(time.Second))
		defer func() { _ = server.Shutdown(context.Background()) }()
		provider := newTestMultiSourceProvider(server.URL(), 0)

		token, invalidate, err := provider.GetTokenWithInvalidator(ctx, testClientID, server.URL(), "scope:a")
		require.Error(t, err)
		require.Empty(t, token)
		require.NotNil(t, invalidate)
		require.False(t, invalidate())
	})
}

func TestProvider_GetTokenWithInvalidator(t *testing.T) {
	ctx := context.Background()
	server, claims := startCountingIDPServer(t)
	provider := idptoken.NewProviderWithOpts(
		idptoken.Source{ClientID: testClientID, ClientSecret: uuid.NewString(), URL: server.URL()},
		idptoken.ProviderOpts{Logger: log.NewDisabledLogger()},
	)

	token, invalidate, err := provider.GetTokenWithInvalidator(ctx, "scope:a")
	require.NoError(t, err)
	sameToken, err := provider.GetToken(ctx, "scope:a")
	require.NoError(t, err)
	require.Equal(t, token, sameToken)
	require.EqualValues(t, 1, claims.issued.Load())

	require.True(t, invalidate())
	newToken, err := provider.GetToken(ctx, "scope:a")
	require.NoError(t, err)
	require.NotEqual(t, token, newToken)
	require.EqualValues(t, 2, claims.issued.Load())
}
