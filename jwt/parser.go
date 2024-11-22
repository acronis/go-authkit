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
	LoggerProvider                func(ctx context.Context) log.FieldLogger
	ClaimsTemplate                Claims
}

type audienceMatcher func(aud string) bool

// TrustedIssNotFoundFallback is a function called when given issuer is not found in the list of trusted ones.
// For example, it could be analyzed and then added to the list by calling AddTrustedIssuerURL method.
type TrustedIssNotFoundFallback func(ctx context.Context, p *Parser, iss string) (issURL string, issFound bool)

// Parser is an object for parsing, validation and verification JWT.
type Parser struct {
	parser               *jwtgo.Parser
	claimsTemplate       Claims
	customValidator      func(claims Claims) error
	skipClaimsValidation bool
	keysProvider         KeysProvider

	trustedIssuerStore            *idputil.TrustedIssuerStore
	trustedIssuerNotFoundFallback TrustedIssNotFoundFallback

	loggerProvider func(ctx context.Context) log.FieldLogger
}

// NewParser creates new JWT parser with specified keys provider.
func NewParser(keysProvider KeysProvider) *Parser {
	return NewParserWithOpts(keysProvider, ParserOpts{})
}

// NewParserWithOpts creates new JWT parser with specified keys provider and additional options.
func NewParserWithOpts(keysProvider KeysProvider, opts ParserOpts) *Parser {
	var audienceMatchers []audienceMatcher
	for _, audPattern := range opts.ExpectedAudience {
		audienceMatchers = append(audienceMatchers, glob.Compile(audPattern))
	}
	parserOpts := []jwtgo.ParserOption{jwtgo.WithExpirationRequired()}
	if opts.SkipClaimsValidation {
		parserOpts = append(parserOpts, jwtgo.WithoutClaimsValidation())
	}
	var claimsTemplate Claims = &DefaultClaims{}
	if opts.ClaimsTemplate != nil {
		claimsTemplate = opts.ClaimsTemplate
	}
	return &Parser{
		parser:                        jwtgo.NewParser(parserOpts...),
		customValidator:               makeCustomAudienceValidator(opts.RequireAudience, audienceMatchers),
		skipClaimsValidation:          opts.SkipClaimsValidation,
		keysProvider:                  keysProvider,
		trustedIssuerStore:            idputil.NewTrustedIssuerStore(),
		trustedIssuerNotFoundFallback: opts.TrustedIssuerNotFoundFallback,
		loggerProvider:                opts.LoggerProvider,
		claimsTemplate:                claimsTemplate,
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
func (p *Parser) Parse(ctx context.Context, token string) (Claims, error) {
	keyFunc := p.getKeyFunc(ctx)
	claims := p.claimsTemplate.Clone()
	if _, err := p.parser.ParseWithClaims(token, claims, keyFunc); err != nil {
		if !errors.Is(err, jwtgo.ErrTokenSignatureInvalid) {
			return nil, err
		}

		// If keys provider supports caching, we may try to invalidate it and try parsing JWT again.
		cachingKeysProvider, ok := p.keysProvider.(CachingKeysProvider)
		if !ok {
			return nil, err
		}

		issuer, issuerErr := claims.GetIssuer()
		if issuerErr != nil {
			return nil, err // original error is more important
		}

		issuerURL, issuerURLFound := p.getURLForIssuerWithCallback(ctx, issuer)
		if !issuerURLFound {
			return nil, err
		}
		if err = cachingKeysProvider.InvalidateCacheIfNeeded(ctx, issuerURL); err != nil {
			idputil.GetLoggerFromProvider(ctx, p.loggerProvider).Error(
				fmt.Sprintf("keys provider invalidating cache error for issuer %q", issuerURL),
				log.Error(err))
			return nil, err
		}

		if _, err = p.parser.ParseWithClaims(token, claims, keyFunc); err != nil {
			return nil, err
		}
	}

	if !p.skipClaimsValidation {
		if err := p.customValidator(claims); err != nil {
			return nil, fmt.Errorf("%w: %w", jwtgo.ErrTokenInvalidClaims, err)
		}
	}

	return claims, nil
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
			claims, ok := token.Claims.(Claims)
			if !ok {
				return nil, fmt.Errorf("claims type %T does not implement Claims interface", token.Claims)
			}
			issuer, issuerErr := claims.GetIssuer()
			if issuerErr != nil {
				return nil, issuerErr
			}
			if issuer == "" {
				return nil, &IssuerMissingError{claims}
			}
			issuerURL, issuerURLFound := p.getURLForIssuerWithCallback(ctx, issuer)
			if !issuerURLFound {
				return nil, &IssuerUntrustedError{claims, issuer}
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

func makeCustomAudienceValidator(requireAudience bool, audienceMatchers []audienceMatcher) func(c Claims) error {
	return func(c Claims) error {
		audience, err := c.GetAudience()
		if err != nil {
			return err
		}
		if len(audience) == 0 {
			if requireAudience {
				return fmt.Errorf("%w: %w", jwtgo.ErrTokenRequiredClaimMissing, &AudienceMissingError{c})
			}
			return nil
		}

		if len(audienceMatchers) == 0 {
			return nil
		}
		for i := range audienceMatchers {
			for j := range audience {
				if audienceMatchers[i](audience[j]) {
					return nil
				}
			}
		}
		return fmt.Errorf("%w: %w", jwtgo.ErrTokenInvalidAudience, &AudienceNotExpectedError{c, audience})
	}
}
