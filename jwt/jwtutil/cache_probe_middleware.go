/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package jwtutil

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/acronis/go-appkit/lrucache"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/internal/strutil"
)

type cacheProbeMiddlewareOpts struct {
	prometheusLibInstanceLabel string
	ttl                        time.Duration
}

// CacheProbeMiddlewareOption is an option for CacheProbeMiddleware.
type CacheProbeMiddlewareOption func(options *cacheProbeMiddlewareOpts)

// WithCacheProbeMiddlewarePrometheusLibInstanceLabel is an option to set a label for Prometheus metrics
// that are used by CacheProbeMiddleware.
func WithCacheProbeMiddlewarePrometheusLibInstanceLabel(label string) CacheProbeMiddlewareOption {
	return func(options *cacheProbeMiddlewareOpts) {
		options.prometheusLibInstanceLabel = label
	}
}

// WithCacheProbeMiddlewareTTL is an option to set the TTL (time-to-live) for cached tokens.
// Default is 1 minute.
func WithCacheProbeMiddlewareTTL(ttl time.Duration) CacheProbeMiddlewareOption {
	return func(options *cacheProbeMiddlewareOpts) {
		options.ttl = ttl
	}
}

// CacheProbeMiddleware is a middleware that simulates token caching from the Authorization header of incoming requests.
// It hashes the bearer token and stores it in multiple LRU caches with different sizes to measure cache hit rates.
// The middleware creates one cache for each size specified in the cacheSizes parameter.
//
// This middleware is useful for:
//   - Probing cache hit ratios in environments where real token caching is not yet implemented.
//   - Estimating potential load on the introspection endpoint, since introspection result caches work similarly.
//   - Determining optimal cache sizes for your workload before implementing actual caching.
//
// The middleware exposes Prometheus metrics with the "go_authkit_token_claims" namespace and includes
// a "size" label to distinguish between different cache sizes. The metrics include hits, misses, evictions,
// and entries amount for each cache size. Note: This namespace is shared with actual JWT claims caching
// to allow direct comparison of cache behavior between probing and production caching. The metrics have
// a "source" label set to "cache_probe_middleware" to distinguish them from other components.
//
// Parameters:
//   - cacheSizes: Slice of cache sizes to create. Each size will have its own LRU cache.
//     Example: []int{1000, 10000} creates two caches with 1k and 10k entries.
//     IMPORTANT: All cache sizes must be positive integers (> 0), otherwise the function will panic.
//   - opts: Optional configuration options:
//   - WithCacheProbeMiddlewarePrometheusLibInstanceLabel: set custom Prometheus lib_instance label
//   - WithCacheProbeMiddlewareTTL: set TTL for cached tokens (default: 1 minute)
//
// Panics if any cache size is not a positive integer.
func CacheProbeMiddleware(cacheSizes []int, opts ...CacheProbeMiddlewareOption) func(next http.Handler) http.Handler {
	options := cacheProbeMiddlewareOpts{
		ttl: time.Minute, // default TTL
	}
	for _, opt := range opts {
		opt(&options)
	}

	promMetrics := metrics.GetPrometheusMetrics(options.prometheusLibInstanceLabel, metrics.SourceCacheProbeMiddleware)

	caches := make([]*lrucache.LRUCache[[sha256.Size]byte, struct{}], 0, len(cacheSizes))
	for _, size := range cacheSizes {
		cacheMetrics := promMetrics.TokenClaimsCache.MustCurryWith(prometheus.Labels{metrics.CacheLabelSize: strconv.Itoa(size)})
		cache, err := lrucache.New[[sha256.Size]byte, struct{}](size, cacheMetrics)
		if err != nil {
			panic(fmt.Errorf("new cache: %w", err)) // can only happen if size <= 0
		}
		caches = append(caches, cache)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") || strings.HasPrefix(authHeader, "bearer ") {
				token := authHeader[7:] // strip "Bearer " or "bearer " prefix
				tokenHash := sha256.Sum256(strutil.StringToBytesUnsafe(token))
				for _, cache := range caches {
					cache.GetOrAddWithTTL(tokenHash, func() struct{} { return struct{}{} }, options.ttl)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
