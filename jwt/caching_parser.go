/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt

import (
	"context"
	"crypto/sha256"
	"fmt"
	"unsafe"

	"github.com/acronis/go-appkit/lrucache"
	jwtgo "github.com/golang-jwt/jwt/v5"

	"github.com/acronis/go-authkit/internal/metrics"
)

const DefaultClaimsCacheMaxEntries = 1000

type CachingParserOpts struct {
	ParserOpts
	CacheMaxEntries              int
	CachePrometheusInstanceLabel string
}

// ClaimsCache is an interface that must be implemented by used cache implementations.
type ClaimsCache interface {
	Get(key [sha256.Size]byte) (Claims, bool)
	Add(key [sha256.Size]byte, claims Claims)
	Purge()
	Len() int
}

// CachingParser uses the functionality of Parser to parse JWT, but stores resulted Claims objects in the cache.
type CachingParser struct {
	*Parser
	ClaimsCache     ClaimsCache
	claimsValidator *jwtgo.Validator
}

func NewCachingParser(keysProvider KeysProvider) (*CachingParser, error) {
	return NewCachingParserWithOpts(keysProvider, CachingParserOpts{})
}

func NewCachingParserWithOpts(
	keysProvider KeysProvider, opts CachingParserOpts,
) (*CachingParser, error) {
	promMetrics := metrics.GetPrometheusMetrics(opts.CachePrometheusInstanceLabel, metrics.SourceJWTParser)
	if opts.CacheMaxEntries == 0 {
		opts.CacheMaxEntries = DefaultClaimsCacheMaxEntries
	}
	cache, err := lrucache.New[[sha256.Size]byte, Claims](opts.CacheMaxEntries, promMetrics.TokenClaimsCache)
	if err != nil {
		return nil, err
	}
	return &CachingParser{
		Parser:          NewParserWithOpts(keysProvider, opts.ParserOpts),
		ClaimsCache:     cache,
		claimsValidator: jwtgo.NewValidator(jwtgo.WithExpirationRequired()),
	}, nil
}

// getTokenHash converts an access token to a string hash that is used as a cache key.
func getTokenHash(token []byte) [sha256.Size]byte {
	return sha256.Sum256(token)
}

// stringToBytesUnsafe converts string to byte slice without memory allocation. (both heap and stack)
func stringToBytesUnsafe(s string) []byte {
	// nolint: gosec // memory optimization to prevent redundant slice copying
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// Parse calls Parse method of embedded original Parser but stores result into cache.
func (cp *CachingParser) Parse(ctx context.Context, token string) (Claims, error) {
	key := getTokenHash(stringToBytesUnsafe(token))
	cachedClaims, foundInCache, validationErr := cp.getFromCacheAndValidateIfNeeded(key)
	if foundInCache {
		if validationErr != nil {
			return nil, validationErr
		}
		return cachedClaims, nil
	}
	claims, err := cp.Parser.Parse(ctx, token)
	if err != nil {
		return nil, err
	}
	cp.ClaimsCache.Add(key, claims)
	return claims, nil
}

func (cp *CachingParser) getFromCacheAndValidateIfNeeded(key [sha256.Size]byte) (claims Claims, found bool, err error) {
	cachedClaims, found := cp.ClaimsCache.Get(key)
	if !found {
		return nil, false, nil
	}
	if !cp.Parser.skipClaimsValidation {
		if err = cp.claimsValidator.Validate(cachedClaims); err != nil {
			return nil, true, fmt.Errorf("%w: %w", jwtgo.ErrTokenInvalidClaims, err)
		}
		if err = cp.Parser.customValidator(cachedClaims); err != nil {
			return nil, true, fmt.Errorf("%w: %w", jwtgo.ErrTokenInvalidClaims, err)
		}
	}
	return cachedClaims, true, nil
}

// InvalidateClaimsCache removes all preserved parsed Claims objects from cache.
func (cp *CachingParser) InvalidateClaimsCache() {
	cp.ClaimsCache.Purge()
}
