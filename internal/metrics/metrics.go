/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package metrics

import (
	"strconv"
	"sync"
	"time"

	"github.com/acronis/go-appkit/lrucache"
	"github.com/prometheus/client_golang/prometheus"
	grpccodes "google.golang.org/grpc/codes"

	"github.com/acronis/go-authkit/internal/libinfo"
)

const PrometheusNamespace = "go_authkit"

const DefaultPrometheusLibInstanceLabel = "default"

const (
	PrometheusLibInstanceLabel = "lib_instance"
	PrometheusLibSourceLabel   = "lib_source"
)

func PrometheusLabels() prometheus.Labels {
	return prometheus.Labels{"lib_version": libinfo.GetLibVersion()}
}

const (
	HTTPClientRequestLabelMethod     = "method"
	HTTPClientRequestLabelURL        = "url"
	HTTPClientRequestLabelStatusCode = "status_code"
	HTTPClientRequestLabelError      = "error"

	GRPCClientRequestLabelMethod = "grpc_method"
	GRPCClientRequestLabelCode   = "grpc_code"
)

const (
	HTTPRequestErrorDo                   = "do_request_error"
	HTTPRequestErrorDecodeBody           = "decode_body_error"
	HTTPRequestErrorUnexpectedStatusCode = "unexpected_status_code"
)

var requestDurationBuckets = []float64{0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

var (
	prometheusMetrics     *PrometheusMetrics
	prometheusMetricsOnce sync.Once
)

// PrometheusMetrics represents the collector of metrics.
type PrometheusMetrics struct {
	HTTPClientRequestDuration *prometheus.HistogramVec
	GRPCClientRequestDuration *prometheus.HistogramVec
	TokenClaimsCache          *lrucache.PrometheusMetrics
	TokenNegativeCache        *lrucache.PrometheusMetrics
}

func GetPrometheusMetrics(instance string, source string) *PrometheusMetrics {
	prometheusMetricsOnce.Do(func() {
		prometheusMetrics = newPrometheusMetrics()
		prometheusMetrics.MustRegister()
	})
	if instance == "" {
		instance = DefaultPrometheusLibInstanceLabel
	}
	return prometheusMetrics.MustCurryWith(map[string]string{
		PrometheusLibInstanceLabel: instance,
		PrometheusLibSourceLabel:   source,
	})
}

func newPrometheusMetrics() *PrometheusMetrics {
	curriedLabelNames := []string{PrometheusLibInstanceLabel, PrometheusLibSourceLabel}
	makeLabelNames := func(names ...string) []string {
		l := append(make([]string, 0, len(curriedLabelNames)+len(names)), curriedLabelNames...)
		return append(l, names...)
	}

	httpClientReqDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   PrometheusNamespace,
			Name:        "http_client_request_duration_seconds",
			Help:        "A histogram of the http client request durations to IDP endpoints.",
			Buckets:     requestDurationBuckets,
			ConstLabels: PrometheusLabels(),
		},
		makeLabelNames(HTTPClientRequestLabelMethod, HTTPClientRequestLabelURL,
			HTTPClientRequestLabelStatusCode, HTTPClientRequestLabelError),
	)
	grpcClientReqDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace:   PrometheusNamespace,
			Name:        "grpc_client_request_duration_seconds",
			Help:        "A histogram of the grpc client request durations to IDP endpoints.",
			Buckets:     requestDurationBuckets,
			ConstLabels: PrometheusLabels(),
		},
		makeLabelNames(GRPCClientRequestLabelMethod, GRPCClientRequestLabelCode),
	)

	tokenClaimsCache := lrucache.NewPrometheusMetricsWithOpts(lrucache.PrometheusMetricsOpts{
		Namespace:         PrometheusNamespace + "_token_claims",
		ConstLabels:       PrometheusLabels(),
		CurriedLabelNames: curriedLabelNames,
	})

	tokenNegativeCache := lrucache.NewPrometheusMetricsWithOpts(lrucache.PrometheusMetricsOpts{
		Namespace:         PrometheusNamespace + "_token_negative",
		ConstLabels:       PrometheusLabels(),
		CurriedLabelNames: curriedLabelNames,
	})

	return &PrometheusMetrics{
		HTTPClientRequestDuration: httpClientReqDuration,
		GRPCClientRequestDuration: grpcClientReqDuration,
		TokenClaimsCache:          tokenClaimsCache,
		TokenNegativeCache:        tokenNegativeCache,
	}
}

// MustCurryWith curries the metrics collector with the provided labels.
func (pm *PrometheusMetrics) MustCurryWith(labels prometheus.Labels) *PrometheusMetrics {
	return &PrometheusMetrics{
		HTTPClientRequestDuration: pm.HTTPClientRequestDuration.MustCurryWith(labels).(*prometheus.HistogramVec),
		GRPCClientRequestDuration: pm.GRPCClientRequestDuration.MustCurryWith(labels).(*prometheus.HistogramVec),
		TokenClaimsCache:          pm.TokenClaimsCache.MustCurryWith(labels),
		TokenNegativeCache:        pm.TokenNegativeCache.MustCurryWith(labels),
	}
}

// MustRegister does registration of metrics collector in Prometheus and panics if any error occurs.
func (pm *PrometheusMetrics) MustRegister() {
	prometheus.MustRegister(
		pm.HTTPClientRequestDuration,
		pm.GRPCClientRequestDuration,
	)
	pm.TokenClaimsCache.MustRegister()
	pm.TokenNegativeCache.MustRegister()
}

// Unregister cancels registration of metrics collector in Prometheus.
func (pm *PrometheusMetrics) Unregister() {
	prometheus.Unregister(pm.HTTPClientRequestDuration)
	prometheus.Unregister(pm.GRPCClientRequestDuration)
	pm.TokenClaimsCache.Unregister()
	pm.TokenNegativeCache.Unregister()
}

func (pm *PrometheusMetrics) ObserveHTTPClientRequest(
	method string, targetURL string, statusCode int, elapsed time.Duration, errorType string,
) {
	pm.HTTPClientRequestDuration.With(prometheus.Labels{
		HTTPClientRequestLabelMethod:     method,
		HTTPClientRequestLabelURL:        targetURL,
		HTTPClientRequestLabelStatusCode: strconv.Itoa(statusCode),
		HTTPClientRequestLabelError:      errorType,
	}).Observe(elapsed.Seconds())
}

func (pm *PrometheusMetrics) ObserveGRPCClientRequest(
	method string, code grpccodes.Code, elapsed time.Duration,
) {
	pm.GRPCClientRequestDuration.With(prometheus.Labels{
		GRPCClientRequestLabelMethod: method,
		GRPCClientRequestLabelCode:   code.String(),
	}).Observe(elapsed.Seconds())
}
