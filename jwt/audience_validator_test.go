/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwt

import (
	"testing"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestAudienceValidator_Validate(t *testing.T) {
	tests := []struct {
		name             string
		requireAudience  bool
		audiencePatterns []string
		claims           Claims
		checkError       func(t *testing.T, err error, claims Claims)
	}{
		{
			name:             "no audience required, no audience in claims",
			requireAudience:  false,
			audiencePatterns: nil,
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: nil}},
		},
		{
			name:             "audience required, no audience in claims",
			requireAudience:  true,
			audiencePatterns: nil,
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: nil}},
			checkError: func(t *testing.T, err error, claims Claims) {
				require.ErrorIs(t, err, jwtgo.ErrTokenRequiredClaimMissing)
				var audMissingErr *AudienceMissingError
				require.ErrorAs(t, err, &audMissingErr)
				require.Equal(t, claims, audMissingErr.Claims)
			},
		},
		{
			name:             "audience not required, audience in claims",
			requireAudience:  false,
			audiencePatterns: nil,
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: jwtgo.ClaimStrings{"rs.example.com"}}},
		},
		{
			name:             "audience required, audience in claims",
			requireAudience:  true,
			audiencePatterns: nil,
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: jwtgo.ClaimStrings{"rs.example.com"}}},
		},
		{
			name:             "audience matches pattern with wildcard in the beginning",
			requireAudience:  false,
			audiencePatterns: []string{"*.example.com"},
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: jwtgo.ClaimStrings{"rs.example.com"}}},
		},
		{
			name:             "audience matches pattern with wildcard in the end",
			requireAudience:  false,
			audiencePatterns: []string{"rs-*"},
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: jwtgo.ClaimStrings{"rs-2ae8e60e-abf9-41d7-a9cb-e083a1814518"}}},
		},
		{
			name:             "audience matches pattern with wildcard in the middle",
			requireAudience:  false,
			audiencePatterns: []string{"https://*.example.com"},
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: jwtgo.ClaimStrings{"https://rs.example.com"}}},
		},
		{
			name:             "audience matches pattern without wildcard, multiple patterns",
			requireAudience:  false,
			audiencePatterns: []string{"rs1.example.com", "rs2.example.com", "rs3.example.com"},
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: jwtgo.ClaimStrings{"rs2.example.com"}}},
		},
		{
			name:             "audience does not match pattern",
			requireAudience:  false,
			audiencePatterns: []string{"*.example.com"},
			claims:           &DefaultClaims{RegisteredClaims: jwtgo.RegisteredClaims{Audience: jwtgo.ClaimStrings{"service.other.com"}}},
			checkError: func(t *testing.T, err error, claims Claims) {
				require.ErrorIs(t, err, jwtgo.ErrTokenInvalidAudience)
				var audNotExpectedErr *AudienceNotExpectedError
				require.ErrorAs(t, err, &audNotExpectedErr)
				require.Equal(t, claims, audNotExpectedErr.Claims)
				require.Equal(t, jwtgo.ClaimStrings{"service.other.com"}, audNotExpectedErr.Audience)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewAudienceValidator(tt.requireAudience, tt.audiencePatterns).Validate(tt.claims)
			if tt.checkError != nil {
				tt.checkError(t, err, tt.claims)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
