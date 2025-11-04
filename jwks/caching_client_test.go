/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwks_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/jwks"
)

func TestCachingClient_GetRSAPublicKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{CacheUpdateMinInterval: time.Second * 10})
		var wg sync.WaitGroup
		const callsNum = 10
		wg.Add(callsNum)
		errs := make(chan error, callsNum)
		pubKeys := make(chan interface{}, callsNum)
		for i := 0; i < callsNum; i++ {
			go func() {
				defer wg.Done()
				pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
				if err != nil {
					errs <- err
					return
				}
				pubKeys <- pubKey
			}()
		}
		wg.Wait()
		close(errs)
		close(pubKeys)
		for err := range errs {
			require.NoError(t, err)
		}
		for pubKey := range pubKeys {
			require.NotNil(t, pubKey)
			require.IsType(t, &rsa.PublicKey{}, pubKey)
		}
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())
	})

	t.Run("jwk not found", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const unknownKeyID = "77777777-7777-7777-7777-777777777777"
		const cacheUpdateMinInterval = time.Second * 1

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{CacheUpdateMinInterval: cacheUpdateMinInterval})

		doGetPublicKeyByUnknownID := func(callsNum int) {
			t.Helper()
			var wg sync.WaitGroup
			wg.Add(callsNum)
			for i := 0; i < callsNum; i++ {
				go func() {
					defer wg.Done()
					pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, unknownKeyID)
					require.Error(t, err)
					var jwkErr *jwks.JWKNotFoundError
					require.True(t, errors.As(err, &jwkErr))
					require.Equal(t, issuerConfigServer.URL, jwkErr.IssuerURL)
					require.Equal(t, unknownKeyID, jwkErr.KeyID)
					require.Nil(t, pubKey)
				}()
			}
			wg.Wait()
		}

		doGetPublicKeyByUnknownID(10)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		time.Sleep(cacheUpdateMinInterval * 2)

		doGetPublicKeyByUnknownID(10)
		require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 2, jwksHandler.ServedCount())
	})

	t.Run("cache TTL expiration", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheTTL = time.Second
		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheUpdateMinInterval: time.Millisecond * 100, // Short interval to not interfere with TTL
			CacheTTL:               cacheTTL,
		})

		// First call - should fetch from server
		pubKey1, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey1)
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Second call within TTL - should use cache
		pubKey2, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey2)
		require.EqualValues(t, 1, jwksHandler.ServedCount(), "should still use cache")

		// Wait for cache to expire
		time.Sleep(cacheTTL * 2)

		// Third call after TTL - should fetch from server again
		pubKey3, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey3)
		require.EqualValues(t, 2, jwksHandler.ServedCount(), "cache should have expired, requiring refresh")
	})

	t.Run("cache TTL with concurrent access", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheTTL = time.Second
		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheUpdateMinInterval: time.Millisecond * 100,
			CacheTTL:               cacheTTL,
		})

		// First call to populate cache
		pubKey1, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey1)
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Wait for cache to expire
		time.Sleep(cacheTTL * 2)

		// Make concurrent calls after expiration
		const callsNum = 10
		var wg sync.WaitGroup
		wg.Add(callsNum)
		errs := make(chan error, callsNum)
		for i := 0; i < callsNum; i++ {
			go func() {
				defer wg.Done()
				pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
				if err != nil {
					errs <- err
					return
				}
				if pubKey == nil {
					errs <- errors.New("pubKey is nil")
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}

		// Should have refreshed once due to TTL expiration
		// (rate limiting ensures only one refresh despite concurrent access)
		require.EqualValues(t, 2, jwksHandler.ServedCount())
	})
}

func TestCachingClient_InvalidateCacheIfPossible(t *testing.T) {
	t.Run("cache does not exist for issuer", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		cachingClient := jwks.NewCachingClient()

		// Invalidate cache for issuer that doesn't exist in cache
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated for new issuer")

		// Verify that JWKS was fetched
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Verify that the key is now in cache
		pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		require.IsType(t, &rsa.PublicKey{}, pubKey)

		// No additional fetches should have occurred
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())
	})

	t.Run("cache exists but minimum update interval not passed", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheUpdateMinInterval = time.Second * 10
		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// First invalidation - should fetch
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated on first call")
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Second invalidation immediately - should not fetch due to min interval
		invalidated, err = cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.False(t, invalidated, "cache should not be invalidated within min interval")
		require.EqualValues(t, 1, jwksHandler.ServedCount(), "should not fetch within min interval")

		// Third invalidation immediately - still should not fetch
		invalidated, err = cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.False(t, invalidated, "cache should not be invalidated within min interval")
		require.EqualValues(t, 1, jwksHandler.ServedCount(), "should not fetch within min interval")
	})

	t.Run("cache exists and minimum update interval passed", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheUpdateMinInterval = time.Millisecond * 500
		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// First invalidation - should fetch
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated")
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Wait for minimum interval to pass
		time.Sleep(cacheUpdateMinInterval * 2)

		// Second invalidation after interval - should fetch again
		invalidated, err = cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated after min interval")
		require.EqualValues(t, 2, jwksHandler.ServedCount(), "should fetch after min interval passed")
	})

	t.Run("preserves missing keys cache across invalidations", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheUpdateMinInterval = time.Millisecond * 500
		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// First, try to get a key that doesn't exist - this should populate missing keys cache
		const unknownKeyID = "unknown-key-id"
		pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, unknownKeyID)
		require.Error(t, err)
		require.Nil(t, pubKey)
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Try to get the same unknown key again - should not fetch due to missing keys cache
		pubKey, err = cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, unknownKeyID)
		require.Error(t, err)
		require.Nil(t, pubKey)
		require.EqualValues(t, 1, jwksHandler.ServedCount(), "should not fetch due to missing keys cache")

		// Invalidate cache immediately (within min interval)
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		// Should not fetch because min interval hasn't passed
		require.False(t, invalidated, "cache should not be invalidated within min interval")
		require.EqualValues(t, 1, jwksHandler.ServedCount(), "should not fetch within min interval")

		// Try to get the unknown key again immediately - should still not fetch due to missing keys cache being preserved
		pubKey, err = cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, unknownKeyID)
		require.Error(t, err)
		require.Nil(t, pubKey)
		require.EqualValues(t, 1, jwksHandler.ServedCount(), "missing keys cache should be preserved and no fetch due to min interval")

		// Wait for minimum interval to pass
		time.Sleep(cacheUpdateMinInterval * 2)

		// Now invalidate cache after interval has passed
		invalidated, err = cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated after min interval")
		require.EqualValues(t, 2, jwksHandler.ServedCount(), "should fetch after min interval")

		// The missing keys cache is preserved with its LRU structure intact
		// However, since enough time has passed since the key was marked as missing,
		// trying to get it again will trigger a fetch
		pubKey, err = cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, unknownKeyID)
		require.Error(t, err)
		require.Nil(t, pubKey)
		require.EqualValues(t, 3, jwksHandler.ServedCount(), "fetch occurs because time since missing key was recorded has passed min interval")
	})

	t.Run("concurrent invalidations respect minimum interval", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheUpdateMinInterval = time.Second * 2
		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// First invalidation to initialize cache
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated on first call")
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Launch concurrent invalidations immediately
		const callsNum = 10
		var wg sync.WaitGroup
		wg.Add(callsNum)
		errs := make(chan error, callsNum)
		for i := 0; i < callsNum; i++ {
			go func() {
				defer wg.Done()
				if _, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)

		for err := range errs {
			require.NoError(t, err)
		}

		// Should still be at 1 because minimum interval hasn't passed
		require.EqualValues(t, 1, jwksHandler.ServedCount(), "concurrent calls should respect min interval")
	})

	t.Run("updates cache TTL on invalidation", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheTTL = time.Second
		const cacheUpdateMinInterval = time.Millisecond * 100
		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheUpdateMinInterval: cacheUpdateMinInterval,
			CacheTTL:               cacheTTL,
		})

		// First invalidation - should fetch
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated")
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Get key immediately - should use cache
		pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Wait for cache to expire
		time.Sleep(cacheTTL * 2)

		// Get key after TTL expiration - should fetch due to TTL
		pubKey, err = cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		require.EqualValues(t, 2, jwksHandler.ServedCount(), "cache should have expired")

		// Now invalidate explicitly
		time.Sleep(cacheUpdateMinInterval * 2)
		invalidated, err = cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated")
		require.EqualValues(t, 3, jwksHandler.ServedCount())

		// Get key immediately after invalidation - should use cache (TTL was reset)
		pubKey, err = cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		require.EqualValues(t, 3, jwksHandler.ServedCount(), "should use cache after invalidation reset TTL")
	})

	t.Run("error from getRSAPubKeysForIssuer", func(t *testing.T) {
		// Create server that returns invalid OpenID configuration
		invalidServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer invalidServer.Close()

		cachingClient := jwks.NewCachingClient()

		// Invalidate cache for issuer that returns error
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), invalidServer.URL)
		require.Error(t, err)
		require.False(t, invalidated, "cache should not be invalidated on error")
		require.Contains(t, err.Error(), "get rsa public keys for issuer")
	})

	t.Run("different issuers maintain separate caches", func(t *testing.T) {
		jwksHandler1 := &idptest.JWKSHandler{}
		jwksServer1 := httptest.NewServer(jwksHandler1)
		defer jwksServer1.Close()
		issuerConfigHandler1 := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer1.URL}
		issuerConfigServer1 := httptest.NewServer(issuerConfigHandler1)
		defer issuerConfigServer1.Close()

		jwksHandler2 := &idptest.JWKSHandler{}
		jwksServer2 := httptest.NewServer(jwksHandler2)
		defer jwksServer2.Close()
		issuerConfigHandler2 := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer2.URL}
		issuerConfigServer2 := httptest.NewServer(issuerConfigHandler2)
		defer issuerConfigServer2.Close()

		cachingClient := jwks.NewCachingClient()

		// Invalidate cache for first issuer
		invalidated, err := cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer1.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated for first issuer")
		require.EqualValues(t, 1, jwksHandler1.ServedCount())
		require.EqualValues(t, 0, jwksHandler2.ServedCount())

		// Invalidate cache for second issuer
		invalidated, err = cachingClient.InvalidateCacheIfPossible(context.Background(), issuerConfigServer2.URL)
		require.NoError(t, err)
		require.True(t, invalidated, "cache should be invalidated for second issuer")
		require.EqualValues(t, 1, jwksHandler1.ServedCount())
		require.EqualValues(t, 1, jwksHandler2.ServedCount())

		// Both caches should be independent
		pubKey1, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer1.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey1)
		require.EqualValues(t, 1, jwksHandler1.ServedCount())

		pubKey2, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer2.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey2)
		require.EqualValues(t, 1, jwksHandler2.ServedCount())
	})
}
