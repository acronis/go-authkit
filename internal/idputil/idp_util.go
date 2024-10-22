/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idputil

import (
	"fmt"
	"net/http"
	"time"

	"github.com/acronis/go-appkit/httpclient"
	"github.com/acronis/go-appkit/log"

	"github.com/acronis/go-authkit/internal/libinfo"
)

const (
	DefaultHTTPRequestTimeout          = 30 * time.Second
	DefaultHTTPRequestMaxRetryAttempts = 3
)

func MakeDefaultHTTPClient(reqTimeout time.Duration, logger log.FieldLogger) *http.Client {
	if reqTimeout == 0 {
		reqTimeout = DefaultHTTPRequestTimeout
	}
	var tr http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	tr, _ = httpclient.NewRetryableRoundTripperWithOpts(tr, httpclient.RetryableRoundTripperOpts{
		MaxRetryAttempts: DefaultHTTPRequestMaxRetryAttempts, Logger: logger}) // error is always nil
	tr = httpclient.NewUserAgentRoundTripper(tr, libinfo.LibName+"/"+libinfo.GetLibVersion())
	return &http.Client{Timeout: reqTimeout, Transport: tr}
}

func PrepareLogger(logger log.FieldLogger) log.FieldLogger {
	if logger == nil {
		return log.NewDisabledLogger()
	}
	return log.NewPrefixedLogger(logger, fmt.Sprintf("[%s/%s] ", libinfo.LibName, libinfo.GetLibVersion()))
}
