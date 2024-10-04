/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt

import (
	"context"
	"errors"
	"fmt"

	"github.com/acronis/go-appkit/log"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/vasayxtx/go-glob"

	"github.com/acronis/go-authkit/internal/idputil"
)

// KeysProvider is an interface for providing keys for verifying JWT.
type KeysProvider interface {
	GetRSAPublicKey(ctx context.Context, issuer, keyID string) (interface{}, error)
}

// CachingKeysProvider is an interface for providing keys for verifying JWT.
// Unlike KeysProvider, it supports caching of obtained keys.
type CachingKeysProvider interface {
	KeysProvider
	InvalidateCacheIfNeeded(ctx context.Context, issuer string) error
}

// ParserOpts additional options for parser.
type ParserOpts struct {
	SkipClaimsValidation          bool
	RequireAudience               bool
	ExpectedAudience              []string
	TrustedIssuerNotFoundFallback TrustedIssNotFoundFallback
}

type audienceMatcher func(aud string) bool

// TrustedIssNotFoundFallback is a function called when given issuer is not found in the list of trusted ones.
// For example, it could be analyzed and then added to the list by calling AddTrustedIssuerURL method.
type TrustedIssNotFoundFallback func(ctx context.Context, p *Parser, iss string) (issURL string, issFound bool)

// Parser is an object for parsing, validation and verification JWT.
type Parser struct {
	parser               *jwtgo.Parser
	claimsValidator      *jwtgo.Validator
	customValidator      func(claims *Claims) error
	skipClaimsValidation bool
	keysProvider         KeysProvider

	trustedIssuerStore            *idputil.TrustedIssuerStore
	trustedIssuerNotFoundFallback TrustedIssNotFoundFallback

	logger log.FieldLogger
}

// NewParser creates new JWT parser with specified keys provider.
func NewParser(keysProvider KeysProvider, logger log.FieldLogger) *Parser {
	return NewParserWithOpts(keysProvider, logger, ParserOpts{})
}

// NewParserWithOpts creates new JWT parser with specified keys provider and additional options.
func NewParserWithOpts(keysProvider KeysProvider, logger log.FieldLogger, opts ParserOpts) *Parser {
	var audienceMatchers []audienceMatcher
	for _, audPattern := range opts.ExpectedAudience {
		audienceMatchers = append(audienceMatchers, glob.Compile(audPattern))
	}
	return &Parser{
		parser:                        jwtgo.NewParser(jwtgo.WithExpirationRequired()),
		claimsValidator:               jwtgo.NewValidator(jwtgo.WithExpirationRequired()),
		customValidator:               makeCustomAudienceValidator(opts.RequireAudience, audienceMatchers),
		skipClaimsValidation:          opts.SkipClaimsValidation,
		keysProvider:                  keysProvider,
		trustedIssuerStore:            idputil.NewTrustedIssuerStore(),
		trustedIssuerNotFoundFallback: opts.TrustedIssuerNotFoundFallback,
		logger:                        logger,
	}
}

// AddTrustedIssuer adds trusted issuer with specified name and URL.
func (p *Parser) AddTrustedIssuer(issName, issURL string) {
	p.trustedIssuerStore.AddTrustedIssuer(issName, issURL)
}

// AddTrustedIssuerURL adds trusted issuer URL.
func (p *Parser) AddTrustedIssuerURL(issURL string) error {
	return p.trustedIssuerStore.AddTrustedIssuerURL(issURL)
}

// GetURLForIssuer returns URL for issuer if it is trusted.
func (p *Parser) GetURLForIssuer(issuer string) (string, bool) {
	return p.trustedIssuerStore.GetURLForIssuer(issuer)
}

// Parse parses, validates and verifies passed token (it's string representation). Parsed claims is returned.
func (p *Parser) Parse(ctx context.Context, token string) (*Claims, error) {
	keyFunc := p.getKeyFunc(ctx)
	claims := validatableClaims{customValidator: p.customValidator}
	if _, err := p.parser.ParseWithClaims(token, &claims, keyFunc); err != nil {
		if !errors.Is(err, jwtgo.ErrTokenSignatureInvalid) {
			return nil, err
		}

		// If keys provider supports caching, we may try to invalidate it and try parsing JWT again.
		cachingKeysProvider, ok := p.keysProvider.(CachingKeysProvider)
		if !ok {
			return nil, err
		}

		issuerURL, issuerURLFound := p.getURLForIssuerWithCallback(ctx, claims.Issuer)
		if !issuerURLFound {
			return nil, err
		}
		if err = cachingKeysProvider.InvalidateCacheIfNeeded(ctx, issuerURL); err != nil {
			p.logger.Error(fmt.Sprintf("keys provider invalidating cache error for issuer %q", issuerURL),
				log.Error(err))
			return nil, err
		}

		if _, err = p.parser.ParseWithClaims(token, &claims, keyFunc); err != nil {
			return nil, err
		}
	}

	return &claims.Claims, nil
}

func (p *Parser) getKeyFunc(ctx context.Context) func(token *jwtgo.Token) (interface{}, error) {
	return func(token *jwtgo.Token) (i interface{}, err error) {
		switch signAlg := token.Method.Alg(); signAlg {
		case "none": //nolint:goconst
			return nil, jwtgo.NoneSignatureTypeDisallowedError

		case "RS256", "RS384", "RS512":
			// Empty kid is LEGAL, not all IDP impl support kid.
			kidStr := ""
			if kid, found := token.Header["kid"]; found {
				kidStr = kid.(string)
			}
			claims := token.Claims.(*validatableClaims)
			if claims.Issuer == "" {
				return nil, &IssuerMissingError{&claims.Claims}
			}
			issuerURL, issuerURLFound := p.getURLForIssuerWithCallback(ctx, claims.Issuer)
			if !issuerURLFound {
				return nil, &IssuerUntrustedError{&claims.Claims}
			}
			return p.keysProvider.GetRSAPublicKey(ctx, issuerURL, kidStr)

		default:
			return nil, &SignAlgUnknownError{signAlg}
		}
	}
}

func (p *Parser) getURLForIssuerWithCallback(ctx context.Context, issuer string) (string, bool) {
	issURL, issFound := p.GetURLForIssuer(issuer)
	if issFound {
		return issURL, true
	}
	if p.trustedIssuerNotFoundFallback == nil {
		return "", false
	}
	return p.trustedIssuerNotFoundFallback(ctx, p, issuer)
}

// Claims represents an extended version of JWT claims.
type Claims struct {
	jwtgo.RegisteredClaims
	Scope           []AccessPolicy `json:"scope,omitempty"`
	Version         int            `json:"ver,omitempty"`
	UserID          string         `json:"uid,omitempty"`
	OriginID        string         `json:"origin,omitempty"`
	ClientID        string         `json:"client_id,omitempty"`
	TOTPTime        int64          `json:"totp_time,omitempty"`
	SubType         string         `json:"sub_type,omitempty"`
	OwnerTenantUUID string         `json:"owner_tuid,omitempty"`
}

// AccessPolicy represents a single access policy which specifies access rights to a tenant or resource
// in the scope of a resource server.
type AccessPolicy struct {
	// TenantID is a unique identifier of tenant for which access is granted (if resource is not specified)
	// or which the resource is owned by (if resource is specified).
	TenantID string `json:"tid,omitempty"`

	// TenantUUID is a UUID of tenant for which access is granted (if the resource is not specified)
	// or which the resource is owned by (if the resource is specified).
	TenantUUID string `json:"tuid,omitempty"`

	// ResourceServerID is a unique resource server instance or cluster ID.
	ResourceServerID string `json:"rs,omitempty"`

	// ResourceNamespace is a namespace to which resource belongs within resource server.
	// E.g.: account-server, storage-manager, task-manager, alert-manager, etc.
	ResourceNamespace string `json:"rn,omitempty"`

	// ResourcePath is a unique identifier of or path to a single resource or resource collection
	// in the scope of the resource server and namespace.
	ResourcePath string `json:"rp,omitempty"`

	// Role determines what actions are allowed to be performed on the specified tenant or resource.
	Role string `json:"role,omitempty"`
}

type validatableClaims struct {
	Claims
	customValidator func(c *Claims) error
}

func (v *validatableClaims) Validate() error {
	if v.customValidator != nil {
		return v.customValidator(&v.Claims)
	}
	return nil
}

func makeCustomAudienceValidator(requireAudience bool, audienceMatchers []audienceMatcher) func(c *Claims) error {
	return func(c *Claims) error {
		if len(c.Audience) == 0 {
			if requireAudience {
				return fmt.Errorf("%w: %w", jwtgo.ErrTokenRequiredClaimMissing, &AudienceMissingError{c})
			}
			return nil
		}

		if len(audienceMatchers) == 0 {
			return nil
		}
		for i := range audienceMatchers {
			for j := range c.Audience {
				if audienceMatchers[i](c.Audience[j]) {
					return nil
				}
			}
		}
		return fmt.Errorf("%w: %w", jwtgo.ErrTokenInvalidAudience, &AudienceNotExpectedError{c})
	}
}
