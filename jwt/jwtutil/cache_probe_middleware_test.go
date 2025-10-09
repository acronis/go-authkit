/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package jwtutil

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/acronis/go-appkit/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/internal/metrics"
)

func TestCacheProbeMiddleware(t *testing.T) {
	const promLabel = "cache_probe_test"

	middleware := CacheProbeMiddleware([]int{10, 100},
		WithCacheProbeMiddlewarePrometheusLibInstanceLabel(promLabel))

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	promMetrics := metrics.GetPrometheusMetrics(promLabel, metrics.SourceCacheProbeMiddleware)

	t.Run("bearer token - first request is miss, subsequent are hits", func(t *testing.T) {
		// Check initial state
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10"), 0)
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"), 0)

		// Send the same token multiple times
		token := "Bearer unique-token-for-metrics"
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			require.Equal(t, http.StatusOK, rr.Code)
		}

		// First access is a miss, next 4 are hits
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10"), 4)
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"), 1)
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("100"), 4)
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("100"), 1)
	})

	t.Run("different token causes miss", func(t *testing.T) {
		hitsBeforeSize10 := getCounterValue(t, promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10"))
		missesBeforeSize10 := getCounterValue(t, promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"))
		hitsBeforeSize100 := getCounterValue(t, promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("100"))
		missesBeforeSize100 := getCounterValue(t, promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("100"))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer another-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		// New token causes a miss in both caches
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10"), int(hitsBeforeSize10))
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"), int(missesBeforeSize10+1))
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("100"), int(hitsBeforeSize100))
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("100"), int(missesBeforeSize100+1))
	})

	t.Run("lowercase bearer token is processed", func(t *testing.T) {
		missesBeforeSize10 := getCounterValue(t, promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "bearer lowercase-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		// Lowercase bearer should be processed and cause a miss
		testutil.RequireSamplesCountInCounter(t,
			promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"), int(missesBeforeSize10+1))
	})

	t.Run("no authorization header - no metrics change", func(t *testing.T) {
		hitsBeforeSize10 := getCounterValue(t, promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10"))
		missesBeforeSize10 := getCounterValue(t, promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		// No metrics change
		require.Equal(t, hitsBeforeSize10,
			getCounterValue(t, promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10")))
		require.Equal(t, missesBeforeSize10,
			getCounterValue(t, promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10")))
	})

	t.Run("non-bearer authorization - no metrics change", func(t *testing.T) {
		hitsBeforeSize10 := getCounterValue(t, promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10"))
		missesBeforeSize10 := getCounterValue(t, promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10"))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		// No metrics change for non-bearer
		require.Equal(t, hitsBeforeSize10,
			getCounterValue(t, promMetrics.TokenClaimsCache.HitsTotal.WithLabelValues("10")))
		require.Equal(t, missesBeforeSize10,
			getCounterValue(t, promMetrics.TokenClaimsCache.MissesTotal.WithLabelValues("10")))
	})
}

// getCounterValue is a helper function to extract counter value from prometheus metric
func getCounterValue(t *testing.T, counter interface{ Write(*dto.Metric) error }) float64 {
	var metric dto.Metric
	err := counter.Write(&metric)
	require.NoError(t, err)
	return metric.GetCounter().GetValue()
}

func TestCacheProbeMiddleware_PanicOnInvalidSize(t *testing.T) {
	t.Run("panics with zero size", func(t *testing.T) {
		require.Panics(t, func() {
			CacheProbeMiddleware([]int{0})
		})
	})

	t.Run("panics with negative size", func(t *testing.T) {
		require.Panics(t, func() {
			CacheProbeMiddleware([]int{-1})
		})
	})

	t.Run("panics with mixed valid and invalid sizes", func(t *testing.T) {
		require.Panics(t, func() {
			CacheProbeMiddleware([]int{100, 0, 1000})
		})
	})
}
