/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt

import (
	"fmt"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/vasayxtx/go-glob"
)

// AudienceValidator is a validator that checks if the audience claim ("aud") of the token is expected.
// It validates that the audience claim is presented and/or matches one of the expected glob patterns (e.g. "*.my-service.com").
type AudienceValidator struct {
	requireAudience  bool
	audienceMatchers []func(aud string) bool
}

// NewAudienceValidator creates a new AudienceValidator.
// If requireAudience is true, the audience claim must be presented in the token.
// If audiencePatterns is not empty, the audience claim must match at least one of the patterns.
func NewAudienceValidator(requireAudience bool, audiencePatterns []string) *AudienceValidator {
	var audienceMatchers []func(aud string) bool
	for i := range audiencePatterns {
		audienceMatchers = append(audienceMatchers, glob.Compile(audiencePatterns[i]))
	}
	return &AudienceValidator{requireAudience: requireAudience, audienceMatchers: audienceMatchers}
}

// Validate checks if the audience claim of the token is expected.
func (av *AudienceValidator) Validate(claims Claims) error {
	audience, err := claims.GetAudience()
	if err != nil {
		return err
	}
	if len(audience) == 0 {
		if av.requireAudience {
			return fmt.Errorf("%w: %w", jwtgo.ErrTokenRequiredClaimMissing, &AudienceMissingError{claims})
		}
		return nil
	}

	if len(av.audienceMatchers) == 0 {
		return nil
	}
	for i := range av.audienceMatchers {
		for j := range audience {
			if av.audienceMatchers[i](audience[j]) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: %w", jwtgo.ErrTokenInvalidAudience, &AudienceNotExpectedError{claims, audience})
}
