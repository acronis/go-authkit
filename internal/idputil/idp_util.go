/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idputil

import (
	"context"
	"net/http"
	"time"

	"github.com/acronis/go-appkit/httpclient"
	"github.com/acronis/go-appkit/log"

	"github.com/acronis/go-authkit/internal/libinfo"
)

const GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint: gosec // false positive

const JWTTypeAccessToken = "at+jwt"

const JWTTypeAppAccessToken = "application/at+jwt"

const TokenTypeBearer = "Bearer"

const (
	DefaultHTTPRequestTimeout          = 30 * time.Second
	DefaultHTTPRequestMaxRetryAttempts = 3
)

var DefaultLogger = log.NewDisabledLogger()

func MakeDefaultHTTPClient(reqTimeout time.Duration, loggerProvider func(ctx context.Context) log.FieldLogger) *http.Client {
	if reqTimeout == 0 {
		reqTimeout = DefaultHTTPRequestTimeout
	}
	var tr http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	retryableOpts := httpclient.RetryableRoundTripperOpts{
		MaxRetryAttempts: DefaultHTTPRequestMaxRetryAttempts,
		LoggerProvider:   loggerProvider,
	}
	tr, _ = httpclient.NewRetryableRoundTripperWithOpts(tr, retryableOpts) // error is always nil
	tr = httpclient.NewUserAgentRoundTripper(tr, libinfo.UserAgent())
	return &http.Client{Timeout: reqTimeout, Transport: tr}
}

func PrepareLogger(logger log.FieldLogger) log.FieldLogger {
	if logger == nil {
		return DefaultLogger
	}
	return log.NewPrefixedLogger(logger, libinfo.LogPrefix())
}

func GetLoggerFromProvider(ctx context.Context, provider func(ctx context.Context) log.FieldLogger) log.FieldLogger {
	if provider != nil {
		if logger := provider(ctx); logger != nil {
			return log.NewPrefixedLogger(logger, libinfo.LogPrefix())
		}
	}
	return DefaultLogger
}
