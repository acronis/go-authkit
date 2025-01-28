/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/acronis/go-appkit/log"
	"golang.org/x/sync/singleflight"

	"github.com/acronis/go-authkit/internal/idputil"
	"github.com/acronis/go-authkit/internal/metrics"
)

const (
	defaultMinRefreshPeriod = time.Second * 10
	defaultExpirationOffset = time.Minute * 30
	expiryDeltaMaxOffset    = 5
)

// ErrSourceNotRegistered is returned if GetToken is requested for the unknown Source
var ErrSourceNotRegistered = errors.New("cannot issue token for unknown source")

// UnexpectedIDPResponseError is an error representing an unexpected response
type UnexpectedIDPResponseError struct {
	HTTPCode int
	IssueURL string
}

func (e *UnexpectedIDPResponseError) Error() string {
	return fmt.Sprintf(`%s responded with unexpected code %d`, e.IssueURL, e.HTTPCode)
}

// tokenData represents API-related token information
type tokenData struct {
	Data     string
	ClientID string
	issueURL string
	Scope    []string
	Expires  time.Time
}

// Source serves to provide auth source information to MultiSourceProvider and Provider
type Source struct {
	URL          string
	ClientID     string
	ClientSecret string
}

var zeroTime = time.Time{}

// TokenDetails represents the data to be stored in TokenCache
type TokenDetails struct {
	token          tokenData
	requestedScope []string
	sourceURL      string
	issued         time.Time
	nextRefresh    time.Time
	invalidation   time.Time
}

// TokenCache is a cache entry used to store TokenDetails based on a string key
type TokenCache interface {
	// Get returns a value from the cache by key.
	Get(key string) *TokenDetails

	// Put sets a new value to the cache by key.
	Put(key string, val *TokenDetails)

	// Delete removes a value from the cache by key.
	Delete(key string)

	// ClearAll removes all values from the cache.
	ClearAll()

	// Keys returns all keys from the cache.
	Keys() []string
}

type InMemoryTokenCache struct {
	mu    sync.RWMutex
	items map[string]*TokenDetails
}

func NewInMemoryTokenCache() *InMemoryTokenCache {
	return &InMemoryTokenCache{items: make(map[string]*TokenDetails)}
}

func (c *InMemoryTokenCache) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]string, 0, len(c.items))
	for k := range c.items {
		result = append(result, k)
	}
	return result
}

func (c *InMemoryTokenCache) Get(key string) *TokenDetails {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.items[key]
	if !found {
		return nil
	}
	return item
}

func (c *InMemoryTokenCache) Put(key string, val *TokenDetails) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = val
}

func (c *InMemoryTokenCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

func (c *InMemoryTokenCache) ClearAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*TokenDetails)
}

// MultiSourceProvider is a caching token provider for multiple datacenters and clients
type MultiSourceProvider struct {
	tokenIssuers map[string]*oauth2Issuer

	rescheduleSignal chan struct{}
	minRefreshPeriod time.Duration
	httpClient       *http.Client
	logger           log.FieldLogger
	promMetrics      *metrics.PrometheusMetrics

	cache         TokenCache
	customHeaders map[string]string
	sfGroup       singleflight.Group

	nextRefreshMu sync.RWMutex
	nextRefresh   time.Time
}

// NewMultiSourceProvider returns a new instance of MultiSourceProvider with default settings
func NewMultiSourceProvider(sources []Source) *MultiSourceProvider {
	return NewMultiSourceProviderWithOpts(sources, ProviderOpts{})
}

// NewMultiSourceProviderWithOpts returns a new instance of MultiSourceProvider with custom settings
func NewMultiSourceProviderWithOpts(sources []Source, opts ProviderOpts) *MultiSourceProvider {
	p := MultiSourceProvider{
		rescheduleSignal: make(chan struct{}, 1),
		nextRefresh:      zeroTime,
		minRefreshPeriod: opts.MinRefreshPeriod,
		logger:           idputil.PrepareLogger(opts.Logger),
		tokenIssuers:     make(map[string]*oauth2Issuer),
		promMetrics:      metrics.GetPrometheusMetrics(opts.PrometheusLibInstanceLabel, metrics.SourceTokenProvider),
		customHeaders:    opts.CustomHeaders,
		cache:            opts.CustomCacheInstance,
		httpClient:       opts.HTTPClient,
	}

	if p.minRefreshPeriod == 0 {
		p.minRefreshPeriod = defaultMinRefreshPeriod
	}
	if p.cache == nil {
		p.cache = NewInMemoryTokenCache()
	}
	if p.httpClient == nil {
		p.httpClient = idputil.MakeDefaultHTTPClient(idputil.DefaultHTTPRequestTimeout,
			func(_ context.Context) log.FieldLogger { return p.logger }, nil)
	}

	for _, source := range sources {
		p.RegisterSource(source)
	}

	return &p
}

// RegisterSource allows registering a new Source into MultiSourceProvider
func (p *MultiSourceProvider) RegisterSource(source Source) {
	key := keyForIssuer(source.ClientID, source.URL)
	if iss, found := p.tokenIssuers[key]; found {
		if iss.clientSecret != source.ClientSecret {
			iss.clientSecret = source.ClientSecret
			p.cache.ClearAll()
		}
	}
	newIssuer := p.newOAuth2Issuer(source.URL, source.ClientID, source.ClientSecret)
	p.tokenIssuers[keyForIssuer(source.ClientID, source.URL)] = newIssuer
}

// GetToken returns raw token for `clientID`, `sourceURL` and `scope`
func (p *MultiSourceProvider) GetToken(
	ctx context.Context, clientID, sourceURL string, scope ...string,
) (string, error) {
	return p.GetTokenWithHeaders(ctx, clientID, sourceURL, nil, scope...)
}

// GetTokenWithHeaders returns raw token for `clientID`, `sourceURL` and `scope` while using `headers`
func (p *MultiSourceProvider) GetTokenWithHeaders(
	ctx context.Context, clientID, sourceURL string, headers map[string]string, scope ...string,
) (string, error) {
	return p.ensureToken(ctx, clientID, sourceURL, headers, scope)
}

// Invalidate fully invalidates all tokens cache
func (p *MultiSourceProvider) Invalidate() {
	p.cache.ClearAll()
	p.setNextRefreshSafe(zeroTime)
}

// RefreshTokensPeriodically starts a goroutine which refreshes tokens
func (p *MultiSourceProvider) RefreshTokensPeriodically(ctx context.Context) {
	p.refreshLoop(ctx)
}

func (p *MultiSourceProvider) issueToken(
	ctx context.Context, clientID, sourceURL string, customHeaders map[string]string, scope []string,
) (tokenData, error) {
	issuer, found := p.tokenIssuers[keyForIssuer(clientID, sourceURL)]

	if !found {
		return tokenData{}, ErrSourceNotRegistered
	}

	headers := make(map[string]string)
	for k := range p.customHeaders {
		headers[k] = p.customHeaders[k]
	}
	for k := range customHeaders {
		headers[k] = customHeaders[k]
	}

	_, errEns, _ := p.sfGroup.Do(keyForIssuer(clientID, sourceURL), func() (interface{}, error) {
		return nil, issuer.ensureTokenURL(ctx, headers)
	})
	if errEns != nil {
		p.logger.Error(fmt.Sprintf("(%s, %s): ensure issuer URL", sourceURL, clientID), log.Error(errEns))
		return tokenData{}, errEns
	}

	sortedScope := uniqAndSort(scope)
	key := keyForCache(clientID, issuer.loadTokenURL(), sortedScope)
	token, err, _ := p.sfGroup.Do(key, func() (interface{}, error) {
		result, issErr := issuer.issueToken(ctx, headers, sortedScope)
		p.cacheToken(result, sourceURL)
		return result, issErr
	})
	if err != nil {
		p.logger.Error(fmt.Sprintf("(%s, %s): issuing token", issuer.loadTokenURL(), clientID), log.Error(err))
		return tokenData{}, err
	}

	return token.(tokenData), nil
}

func (p *MultiSourceProvider) ensureToken(
	ctx context.Context, clientID, sourceURL string, customHeaders map[string]string, scope []string,
) (string, error) {
	token, err := p.getCachedOrInvalidate(clientID, sourceURL, scope)
	if err == nil {
		return token.Data, nil
	}
	p.logger.Infof("(%s, %s): could not get token from cache: %v", sourceURL, clientID, err.Error())

	token, err = p.issueToken(ctx, clientID, sourceURL, customHeaders, scope)

	if err != nil {
		return "", err
	}
	return token.Data, nil
}

func (p *MultiSourceProvider) cacheToken(token tokenData, sourceURL string) {
	issued := time.Now().UTC()
	randInt, err := rand.Int(rand.Reader, big.NewInt(expiryDeltaMaxOffset))
	if err != nil {
		p.logger.Error("rand init error", log.Error(err))
		return
	}
	deltaMinutes := time.Minute * time.Duration(randInt.Int64())
	realExpiration := token.Expires.Sub(issued)
	refreshDuration := token.Expires.Sub(issued) - defaultExpirationOffset - deltaMinutes
	if realExpiration < defaultExpirationOffset {
		refreshDuration = realExpiration / 5
	}

	nextRefresh := issued.Add(refreshDuration)
	invalidation := issued.Add(realExpiration)
	details := &TokenDetails{
		token:        token,
		issued:       issued,
		nextRefresh:  nextRefresh,
		invalidation: invalidation,
		sourceURL:    sourceURL,
	}

	key := keyForCache(token.ClientID, token.issueURL, uniqAndSort(token.Scope))
	p.cache.Put(key, details)
	pNextRefresh := p.getNextRefreshSafe()
	if pNextRefresh == zeroTime || nextRefresh.UnixNano() <= pNextRefresh.UnixNano() {
		p.setNextRefreshSafe(nextRefresh)
		select {
		case p.rescheduleSignal <- struct{}{}:
		default:
		}
	}
}

func (p *MultiSourceProvider) getCachedOrInvalidate(clientID, sourceURL string, scope []string) (tokenData, error) {
	now := time.Now().UnixNano()
	issuer, found := p.tokenIssuers[keyForIssuer(clientID, sourceURL)]
	if !found {
		return tokenData{}, fmt.Errorf("(%s, %s): not registered", sourceURL, clientID)
	}
	if issuer.loadTokenURL() == "" {
		return tokenData{}, fmt.Errorf("(%s, %s): issuer URL not acquired", sourceURL, clientID)
	}

	key := keyForCache(clientID, issuer.loadTokenURL(), uniqAndSort(scope))
	details := p.cache.Get(key)
	if details == nil {
		return tokenData{}, errors.New("token not found in cache")
	}
	if details.token.Expires.UnixNano() < now {
		p.cache.Delete(key)
		return tokenData{}, errors.New("token is expired")
	}
	if details.invalidation.UnixNano() < now {
		p.cache.Delete(key)
		return tokenData{}, errors.New("token needs to be refreshed")
	}
	if details.issued.UnixNano() > now {
		p.cache.Delete(key)
		return tokenData{}, errors.New("token's issued time is invalid")
	}
	return details.token, nil
}

func (p *MultiSourceProvider) setNextRefreshSafe(nextRefresh time.Time) {
	p.nextRefreshMu.Lock()
	p.nextRefresh = nextRefresh
	p.nextRefreshMu.Unlock()
}

func (p *MultiSourceProvider) getNextRefreshSafe() time.Time {
	p.nextRefreshMu.RLock()
	nextRefresh := p.nextRefresh
	p.nextRefreshMu.RUnlock()
	return nextRefresh
}

func (p *MultiSourceProvider) refreshTokens(ctx context.Context) {
	now := time.Now().UTC()

	resultMap := make(map[*TokenDetails]struct{})
	nextRefresh := zeroTime
	for _, key := range p.cache.Keys() {
		details := p.cache.Get(key)
		if details == nil {
			continue
		}
		if details.nextRefresh.UnixNano() <= now.UnixNano() {
			resultMap[details] = struct{}{}
			continue
		}
		if nextRefresh == zeroTime {
			nextRefresh = details.nextRefresh
		}
		if details.nextRefresh.UnixNano() <= nextRefresh.UnixNano() {
			nextRefresh = details.nextRefresh
		}
	}
	p.setNextRefreshSafe(nextRefresh)
	toRefresh := make([]*TokenDetails, 0, len(resultMap))
	for token := range resultMap {
		toRefresh = append(toRefresh, token)
	}

	for _, details := range toRefresh {
		_, err := p.issueToken(ctx, details.token.ClientID, details.sourceURL, nil, details.requestedScope)
		if err != nil {
			p.setNextRefreshSafe(now)
			p.logger.Error(
				fmt.Sprintf("(%s, %s): refresh error", details.sourceURL, details.token.ClientID), log.Error(err),
			)
		}
	}
}

func (p *MultiSourceProvider) refreshLoop(ctx context.Context) {
	t := time.NewTimer(time.Hour)
	if !t.Stop() {
		<-t.C
	}
	stopped := true
	lastRefresh := time.Now().UTC()
	currentRefresh := zeroTime
	scheduleNext := func() {
		nextRefresh := p.getNextRefreshSafe()

		currentRefresh = nextRefresh
		if nextRefresh == zeroTime {
			stopped = true
			return
		}

		now := time.Now().UTC()
		next := nextRefresh.Sub(now)
		if nextRefresh.Sub(lastRefresh) < p.minRefreshPeriod {
			next = lastRefresh.Add(p.minRefreshPeriod).Sub(now)
		}

		stopped = false
		t.Reset(next)
	}
	scheduleNext()
	for {
		select {
		case <-t.C:
			lastRefresh = time.Now().UTC()
			p.refreshTokens(ctx)
			scheduleNext()
		case <-p.rescheduleSignal:
			nextRefresh := p.getNextRefreshSafe()

			if currentRefresh != nextRefresh {
				if !stopped && !t.Stop() {
					<-t.C
				}

				if stopped {
					// Token was issued a moment ago.
					lastRefresh = time.Now().UTC()
				}

				scheduleNext()
			}
		case <-ctx.Done():
			if !stopped && !t.Stop() {
				<-t.C
			}
			return
		}
	}
}

// Provider is a caching token provider for a single credentials set
type Provider struct {
	provider *MultiSourceProvider
	source   Source
}

// NewProvider returns a new instance of Provider
func NewProvider(source Source) *Provider {
	return NewProviderWithOpts(source, ProviderOpts{})
}

// NewProviderWithOpts returns a new instance of Provider with custom options
func NewProviderWithOpts(source Source, opts ProviderOpts) *Provider {
	mp := Provider{
		source:   source,
		provider: NewMultiSourceProviderWithOpts([]Source{source}, opts),
	}
	return &mp
}

// RefreshTokensPeriodically starts a goroutine which refreshes tokens
func (mp *Provider) RefreshTokensPeriodically(ctx context.Context) {
	mp.provider.RefreshTokensPeriodically(ctx)
}

// GetToken returns raw token for `scope`
func (mp *Provider) GetToken(
	ctx context.Context, scope ...string,
) (string, error) {
	return mp.provider.GetToken(ctx, mp.source.ClientID, mp.source.URL, scope...)
}

// GetTokenWithHeaders returns raw token for `scope` while using `headers`
func (mp *Provider) GetTokenWithHeaders(
	ctx context.Context, headers map[string]string, scope ...string,
) (string, error) {
	return mp.provider.GetTokenWithHeaders(ctx, mp.source.ClientID, mp.source.URL, headers, scope...)
}

func (mp *Provider) Invalidate() {
	mp.provider.Invalidate()
}

type oauth2Issuer struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	logger       log.FieldLogger
	tokenURL     atomic.Value
	promMetrics  *metrics.PrometheusMetrics
}

func (p *MultiSourceProvider) newOAuth2Issuer(baseURL, clientID, clientSecret string) *oauth2Issuer {
	return &oauth2Issuer{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   p.httpClient,
		logger:       p.logger,
		promMetrics:  p.promMetrics,
	}
}

func (ti *oauth2Issuer) loadTokenURL() string {
	if v := ti.tokenURL.Load(); v != nil {
		return v.(string)
	}
	return ""
}

func (ti *oauth2Issuer) ensureTokenURL(ctx context.Context, customHeaders map[string]string) error {
	if ti.loadTokenURL() != "" {
		return nil
	}

	openIDCfgURL := strings.TrimSuffix(ti.baseURL, "/") + idputil.OpenIDConfigurationPath
	openIDCfg, err := idputil.GetOpenIDConfiguration(
		ctx, ti.httpClient, openIDCfgURL, customHeaders, ti.logger, ti.promMetrics)
	if err != nil {
		return fmt.Errorf("(%s, %s): get OpenID configuration: %w", ti.baseURL, ti.clientID, err)
	}

	if _, err = url.ParseRequestURI(openIDCfg.TokenURL); err != nil {
		return fmt.Errorf("(%s, %s): issuer have returned a non-valid URL %q: %w",
			ti.baseURL, ti.clientID, openIDCfg.TokenURL, err)
	}
	ti.tokenURL.Store(openIDCfg.TokenURL)
	return nil
}

func (ti *oauth2Issuer) issueToken(
	ctx context.Context, customHeaders map[string]string, scope []string,
) (tokenData, error) {
	tokenURL := ti.loadTokenURL()
	if tokenURL == "" {
		return tokenData{}, fmt.Errorf("token URL is empty")
	}
	values := url.Values{}
	values.Add("grant_type", "client_credentials")
	scopeStr := strings.Join(scope, " ")
	if scopeStr != "" {
		values.Add("scope", scopeStr)
	}
	req, reqErr := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(values.Encode()))
	if reqErr != nil {
		return tokenData{}, reqErr
	}
	req = req.WithContext(ctx)
	req.SetBasicAuth(ti.clientID, ti.clientSecret)

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for key := range customHeaders {
		req.Header.Add(key, customHeaders[key])
	}
	start := time.Now()
	resp, err := ti.httpClient.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		ti.promMetrics.ObserveHTTPClientRequest(http.MethodPost, tokenURL, 0, elapsed, metrics.HTTPRequestErrorDo)
		return tokenData{}, fmt.Errorf("do http request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			ti.logger.Error(
				fmt.Sprintf("(%s, %s): closing body", ti.loadTokenURL(), ti.clientID), log.Error(err),
			)
		}
	}()

	tokenResponse := tokenResponseBody{}
	if err = json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		ti.promMetrics.ObserveHTTPClientRequest(
			http.MethodPost, tokenURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorDecodeBody)
		return tokenData{}, fmt.Errorf(
			"(%s, %s): read and unmarshal IDP response: %w", ti.loadTokenURL(), ti.clientID, err,
		)
	}

	if resp.StatusCode != http.StatusOK {
		ti.promMetrics.ObserveHTTPClientRequest(
			http.MethodPost, tokenURL, resp.StatusCode, elapsed, metrics.HTTPRequestErrorUnexpectedStatusCode)
		return tokenData{}, &UnexpectedIDPResponseError{HTTPCode: resp.StatusCode, IssueURL: ti.loadTokenURL()}
	}

	ti.promMetrics.ObserveHTTPClientRequest(http.MethodPost, tokenURL, resp.StatusCode, elapsed, "")
	expires := time.Now().Add(time.Second * time.Duration(tokenResponse.ExpiresIn))
	ti.logger.Infof("(%s, %s): issued token, expires on %s", ti.loadTokenURL(), ti.clientID, expires.UTC())
	return tokenData{
		Data:     tokenResponse.AccessToken,
		Scope:    scope,
		Expires:  expires,
		issueURL: ti.loadTokenURL(),
		ClientID: ti.clientID,
	}, nil
}

// ProviderOpts represents options for creating a new MultiSourceProvider
type ProviderOpts struct {
	// Logger is a logger for MultiSourceProvider.
	Logger log.FieldLogger

	// HTTPClient is an HTTP client for MultiSourceProvider.
	HTTPClient *http.Client

	// MinRefreshPeriod is a minimal possible refresh interval for MultiSourceProvider's token cache.
	MinRefreshPeriod time.Duration

	// CustomHeaders is a map of custom headers to be used in all HTTP requests.
	CustomHeaders map[string]string

	// CustomCacheInstance is a custom token cache instance to be used in MultiSourceProvider.
	CustomCacheInstance TokenCache

	// PrometheusLibInstanceLabel is a label for Prometheus metrics.
	// It allows distinguishing metrics from different instances of the same service.
	PrometheusLibInstanceLabel string
}

func uniqAndSort(s []string) []string {
	uniq := make(map[string]struct{})
	for ix := range s {
		uniq[s[ix]] = struct{}{}
	}
	result := make([]string, 0, len(uniq))
	for k := range uniq {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func keyForCache(clientID, sourceURL string, scope []string) string {
	return clientID + ":" + sourceURL + ":" + strings.Join(scope, ",")
}

func keyForIssuer(clientID, sourceURL string) string {
	return sourceURL + ":" + clientID
}

type tokenResponseBody struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope,omitempty"`
	// not empty if token scope is different
	// from the requested scope. Is equal to
	// serialized token scope claim. Returned
	// explicitly so client can know token
	// scope w/o token parsing. Useful for
	// middleware token response processing
	ExpiresIn int `json:"expires_in"`

	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
