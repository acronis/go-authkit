/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/acronis/go-appkit/lrucache"
)

const DefaultCacheUpdateMinInterval = time.Minute * 1

// DefaultCacheTTL is the default time-to-live for cached JWKS entries.
// After this duration, cached entries are considered expired and will be refreshed.
// This prevents revoked keys from remaining in cache indefinitely.
const DefaultCacheTTL = time.Hour * 1

// CachingClientOpts contains options for CachingClient.
type CachingClientOpts struct {
	ClientOpts

	// CacheUpdateMinInterval is a minimal interval between cache updates for the same issuer.
	CacheUpdateMinInterval time.Duration

	// CacheTTL is the time-to-live for cached JWKS entries.
	// After this duration, cached entries expire and will be refreshed on next access.
	// This prevents revoked keys from remaining in cache indefinitely.
	// Default: DefaultCacheTTL (1 hour).
	CacheTTL time.Duration
}

// CachingClient is a Client for getting keys from remote JWKS with a caching mechanism.
type CachingClient struct {
	mu                     sync.RWMutex
	rawClient              *Client
	issuerCache            map[string]issuerCacheEntry
	cacheUpdateMinInterval time.Duration
	cacheTTL               time.Duration
}

const missingKeysCacheSize = 100

type issuerCacheEntry struct {
	updatedAt   time.Time
	expiresAt   time.Time
	keys        map[string]interface{}
	missingKeys *lrucache.LRUCache[string, time.Time]
}

func (ice *issuerCacheEntry) isExpired() bool {
	return time.Now().After(ice.expiresAt)
}

// NewCachingClient returns a new Client that can cache fetched data.
func NewCachingClient() *CachingClient {
	return NewCachingClientWithOpts(CachingClientOpts{})
}

// NewCachingClientWithOpts returns a new Client that can cache fetched data with options.
func NewCachingClientWithOpts(opts CachingClientOpts) *CachingClient {
	if opts.CacheUpdateMinInterval <= 0 {
		opts.CacheUpdateMinInterval = DefaultCacheUpdateMinInterval
	}
	if opts.CacheTTL <= 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	return &CachingClient{
		rawClient:              NewClientWithOpts(opts.ClientOpts),
		issuerCache:            make(map[string]issuerCacheEntry),
		cacheUpdateMinInterval: opts.CacheUpdateMinInterval,
		cacheTTL:               opts.CacheTTL,
	}
}

// GetRSAPublicKey searches JWK with passed key ID in JWKS and returns decoded RSA public key for it.
// The last one can be used for verifying JWT signature. Obtained JWKS is cached.
// If passed issuer URL or key ID is not found in the cache, JWKS will be fetched again,
// but not more than once in a some (configurable) period of time.
func (cc *CachingClient) GetRSAPublicKey(ctx context.Context, issuerURL, keyID string) (interface{}, error) {
	pubKey, found, needInvalidate := cc.getPubKeyFromCache(issuerURL, keyID)
	if found {
		return pubKey, nil
	}
	if needInvalidate {
		var err error
		if pubKey, found, err = cc.getPubKeyFromCacheAndInvalidate(ctx, issuerURL, keyID); err != nil || found {
			return pubKey, err
		}
	}
	return nil, &JWKNotFoundError{IssuerURL: issuerURL, KeyID: keyID}
}

// InvalidateCacheIfPossible does cache invalidation for specific issuer URL if possible.
// It returns true if the cache was invalidated, false if invalidation was skipped due to rate limiting.
func (cc *CachingClient) InvalidateCacheIfPossible(ctx context.Context, issuerURL string) (invalidated bool, err error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	var missingKeys *lrucache.LRUCache[string, time.Time]
	issCache, found := cc.issuerCache[issuerURL]
	if found {
		if time.Since(issCache.updatedAt) < cc.cacheUpdateMinInterval {
			return false, nil
		}
		missingKeys = issCache.missingKeys
	} else {
		var err error
		if missingKeys, err = lrucache.New[string, time.Time](missingKeysCacheSize, nil); err != nil {
			return false, fmt.Errorf("new lru cache for missing keys: %w", err)
		}
	}

	pubKeys, err := cc.rawClient.getRSAPubKeysForIssuer(ctx, issuerURL)
	if err != nil {
		return false, fmt.Errorf("get rsa public keys for issuer %q: %w", issuerURL, err)
	}
	now := time.Now()
	cc.issuerCache[issuerURL] = issuerCacheEntry{
		updatedAt:   now,
		expiresAt:   now.Add(cc.cacheTTL),
		keys:        pubKeys,
		missingKeys: missingKeys,
	}
	return true, nil
}

func (cc *CachingClient) getPubKeyFromCache(
	issuerURL, keyID string,
) (pubKey interface{}, found bool, needInvalidate bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	issCache, issFound := cc.issuerCache[issuerURL]
	if !issFound {
		return nil, false, true
	}

	// Check if cache entry has expired based on TTL (if TTL is configured)
	if issCache.isExpired() {
		return nil, false, true
	}

	if pubKey, found = issCache.keys[keyID]; found {
		return
	}
	missedAt, miss := issCache.missingKeys.Get(keyID)
	if !miss || time.Since(missedAt) > cc.cacheUpdateMinInterval {
		return nil, false, true
	}
	return nil, false, false
}

func (cc *CachingClient) getPubKeyFromCacheAndInvalidate(
	ctx context.Context, issuerURL, keyID string,
) (pubKey interface{}, found bool, err error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	var missingKeys *lrucache.LRUCache[string, time.Time]
	if issCache, issFound := cc.issuerCache[issuerURL]; issFound {
		if !issCache.isExpired() {
			if pubKey, found = issCache.keys[keyID]; found {
				return pubKey, true, nil
			}
			missedAt, miss := issCache.missingKeys.Get(keyID)
			if miss && time.Since(missedAt) < cc.cacheUpdateMinInterval {
				return nil, false, nil
			}
		}
		missingKeys = issCache.missingKeys
	} else {
		missingKeys, err = lrucache.New[string, time.Time](missingKeysCacheSize, nil)
		if err != nil {
			return nil, false, fmt.Errorf("new lru cache for missing keys: %w", err)
		}
	}

	pubKeys, err := cc.rawClient.getRSAPubKeysForIssuer(ctx, issuerURL)
	if err != nil {
		return nil, false, fmt.Errorf("get rsa public keys for issuer %q: %w", issuerURL, err)
	}
	pubKey, found = pubKeys[keyID]
	if !found {
		missingKeys.Add(keyID, time.Now())
	}
	now := time.Now()
	cc.issuerCache[issuerURL] = issuerCacheEntry{
		updatedAt:   now,
		expiresAt:   now.Add(cc.cacheTTL),
		keys:        pubKeys,
		missingKeys: missingKeys,
	}
	return pubKey, found, nil
}
