/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
	"unsafe"

	"github.com/acronis/go-appkit/lrucache"

	"github.com/acronis/go-authkit/jwt"
)

const (
	DefaultIntrospectionClaimsCacheMaxEntries   = 1000
	DefaultIntrospectionClaimsCacheTTL          = 1 * time.Minute
	DefaultIntrospectionNegativeCacheMaxEntries = 1000
	DefaultIntrospectionNegativeCacheTTL        = 10 * time.Minute
)

type IntrospectionClaimsCacheItem struct {
	Claims    *jwt.Claims
	TokenType string
	CreatedAt time.Time
}

type IntrospectionClaimsCache interface {
	Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionClaimsCacheItem, bool)
	Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionClaimsCacheItem)
	Purge(ctx context.Context)
	Len(ctx context.Context) int
}

type IntrospectionNegativeCacheItem struct {
	CreatedAt time.Time
}

type IntrospectionNegativeCache interface {
	Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionNegativeCacheItem, bool)
	Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionNegativeCacheItem)
	Purge(ctx context.Context)
	Len(ctx context.Context) int
}

type CachingIntrospectorOpts struct {
	IntrospectorOpts
	ClaimsCache   CachingIntrospectorCacheOpts
	NegativeCache CachingIntrospectorCacheOpts
}

type CachingIntrospectorCacheOpts struct {
	Enabled    bool
	MaxEntries int
	TTL        time.Duration
}

type CachingIntrospector struct {
	*Introspector
	ClaimsCache      IntrospectionClaimsCache
	NegativeCache    IntrospectionNegativeCache
	claimsCacheTTL   time.Duration
	negativeCacheTTL time.Duration
}

func NewCachingIntrospector(tokenProvider IntrospectionTokenProvider) (*CachingIntrospector, error) {
	return NewCachingIntrospectorWithOpts(tokenProvider, CachingIntrospectorOpts{})
}

func NewCachingIntrospectorWithOpts(
	tokenProvider IntrospectionTokenProvider, opts CachingIntrospectorOpts,
) (*CachingIntrospector, error) {
	if !opts.ClaimsCache.Enabled && !opts.NegativeCache.Enabled {
		return nil, fmt.Errorf("at least one of claims or negative cache must be enabled")
	}

	introspector := NewIntrospectorWithOpts(tokenProvider, opts.IntrospectorOpts)

	// Building claims cache if needed.
	var claimsCache IntrospectionClaimsCache = &disabledIntrospectionClaimsCache{}
	if opts.ClaimsCache.Enabled {
		if opts.ClaimsCache.TTL == 0 {
			opts.ClaimsCache.TTL = DefaultIntrospectionClaimsCacheTTL
		}
		if opts.ClaimsCache.MaxEntries == 0 {
			opts.ClaimsCache.MaxEntries = DefaultIntrospectionClaimsCacheMaxEntries
		}
		cache, err := lrucache.New[[sha256.Size]byte, IntrospectionClaimsCacheItem](
			opts.ClaimsCache.MaxEntries, introspector.promMetrics.TokenClaimsCache)
		if err != nil {
			return nil, err
		}
		claimsCache = &introspectionCacheLRUAdapter[[sha256.Size]byte, IntrospectionClaimsCacheItem]{cache}
	}

	// Building negative cache if needed.
	var negativeCache IntrospectionNegativeCache = &disabledIntrospectionNegativeCache{}
	if opts.NegativeCache.Enabled {
		if opts.NegativeCache.TTL == 0 {
			opts.NegativeCache.TTL = DefaultIntrospectionNegativeCacheTTL
		}
		if opts.NegativeCache.MaxEntries == 0 {
			opts.NegativeCache.MaxEntries = DefaultIntrospectionNegativeCacheMaxEntries
		}
		cache, err := lrucache.New[[sha256.Size]byte, IntrospectionNegativeCacheItem](
			opts.NegativeCache.MaxEntries, introspector.promMetrics.TokenNegativeCache)
		if err != nil {
			return nil, err
		}
		negativeCache = &introspectionCacheLRUAdapter[[sha256.Size]byte, IntrospectionNegativeCacheItem]{cache}
	}

	return &CachingIntrospector{
		Introspector:     introspector,
		ClaimsCache:      claimsCache,
		NegativeCache:    negativeCache,
		claimsCacheTTL:   opts.ClaimsCache.TTL,
		negativeCacheTTL: opts.NegativeCache.TTL,
	}, nil
}

func (i *CachingIntrospector) IntrospectToken(ctx context.Context, token string) (IntrospectionResult, error) {
	cacheKey := sha256.Sum256(
		unsafe.Slice(unsafe.StringData(token), len(token))) // nolint:gosec // prevent redundant slice copying

	if c, ok := i.ClaimsCache.Get(ctx, cacheKey); ok && c.CreatedAt.Add(i.claimsCacheTTL).After(time.Now()) {
		return IntrospectionResult{Active: true, TokenType: c.TokenType, Claims: *c.Claims}, nil
	}
	if c, ok := i.NegativeCache.Get(ctx, cacheKey); ok && c.CreatedAt.Add(i.negativeCacheTTL).After(time.Now()) {
		return IntrospectionResult{Active: false}, nil
	}

	introspectionResult, err := i.Introspector.IntrospectToken(ctx, token)
	if err != nil {
		return IntrospectionResult{}, err
	}
	if introspectionResult.Active {
		i.ClaimsCache.Add(ctx, cacheKey, IntrospectionClaimsCacheItem{
			Claims:    &introspectionResult.Claims,
			TokenType: introspectionResult.TokenType,
			CreatedAt: time.Now(),
		})
	} else {
		i.NegativeCache.Add(ctx, cacheKey, IntrospectionNegativeCacheItem{CreatedAt: time.Now()})
	}

	return introspectionResult, nil
}

type introspectionCacheLRUAdapter[K comparable, V any] struct {
	cache *lrucache.LRUCache[K, V]
}

func (a *introspectionCacheLRUAdapter[K, V]) Get(_ context.Context, key K) (V, bool) {
	return a.cache.Get(key)
}

func (a *introspectionCacheLRUAdapter[K, V]) Add(_ context.Context, key K, val V) {
	a.cache.Add(key, val)
}

func (a *introspectionCacheLRUAdapter[K, V]) Purge(ctx context.Context) {
	a.cache.Purge()
}

func (a *introspectionCacheLRUAdapter[K, V]) Len(ctx context.Context) int {
	return a.cache.Len()
}

type disabledIntrospectionClaimsCache struct{}

func (c *disabledIntrospectionClaimsCache) Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionClaimsCacheItem, bool) {
	return IntrospectionClaimsCacheItem{}, false
}
func (c *disabledIntrospectionClaimsCache) Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionClaimsCacheItem) {
}
func (c *disabledIntrospectionClaimsCache) Purge(ctx context.Context)   {}
func (c *disabledIntrospectionClaimsCache) Len(ctx context.Context) int { return 0 }

type disabledIntrospectionNegativeCache struct{}

func (c *disabledIntrospectionNegativeCache) Get(ctx context.Context, key [sha256.Size]byte) (IntrospectionNegativeCacheItem, bool) {
	return IntrospectionNegativeCacheItem{}, false
}
func (c *disabledIntrospectionNegativeCache) Add(ctx context.Context, key [sha256.Size]byte, value IntrospectionNegativeCacheItem) {
}
func (c *disabledIntrospectionNegativeCache) Purge(ctx context.Context)   {}
func (c *disabledIntrospectionNegativeCache) Len(ctx context.Context) int { return 0 }
