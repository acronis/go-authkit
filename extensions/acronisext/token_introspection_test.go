/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package acronisext

import (
	"encoding/json"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/jwt"
)

func TestTokenIntrospectionResult(t *testing.T) {
	now := time.Now()
	expiry := now.Add(time.Hour)

	result := TokenIntrospectionResult{
		Active:    true,
		TokenType: "bearer",
		JWTClaims: JWTClaims{
			DefaultClaims: jwt.DefaultClaims{
				RegisteredClaims: jwtgo.RegisteredClaims{
					Issuer:    "https://eu8-cloud.acronis.com",
					Subject:   "d6071d31-a6e8-4f44-bce5-a6123e9002b8",
					Audience:  []string{"eu8-cloud.acronis.com"},
					ExpiresAt: jwtgo.NewNumericDate(expiry),
					IssuedAt:  jwtgo.NewNumericDate(now),
					ID:        "a2bdb29a-afd1-45a2-abfa-fa8e30b678ae",
				},
				Scope: []jwt.AccessPolicy{
					{
						TenantID:          "42",
						TenantUUID:        "f7d9bf6e-c718-4a8c-9ef1-bfab550921cb",
						ResourceNamespace: "cyber-backup-service",
						ResourcePath:      "/backups",
						Role:              "reader",
					},
					{
						TenantID:          "42",
						TenantUUID:        "f7d9bf6e-c718-4a8c-9ef1-bfab550921cb",
						ResourceNamespace: "cyber-protect-service",
						Role:              "auditor",
					},
				},
			},
			Version:         2,
			OriginID:        "app.code",
			TOTPTime:        now.Unix() - 300,
			LoginTOTPTime:   now.Unix() - 600,
			SubType:         "user",
			ClientID:        "d6071d31-a6e8-4f44-bce5-a6123e9002b8",
			OwnerTenantUUID: "2e2936fe-8a20-4e69-88cf-af566897cad8",
			Narrowing: [][]string{
				{"urn:acronis.com:tenant-id:f7d9bf6e-c718-4a8c-9ef1-bfab550921cb"},
				{"urn:acronis.com:agent-unit:cyber-backup-service", "urn:acronis.com:agent-unit:cyber-protect-service"},
			},
		},
	}

	checkIntrospectionResult := func(t *testing.T, r *TokenIntrospectionResult) {
		t.Helper()
		assert.Equal(t, result.Active, r.Active)
		assert.Equal(t, result.TokenType, r.TokenType)
		assert.Equal(t, result.JWTClaims, r.JWTClaims)
	}

	// Test JSON marshaling/unmarshaling
	jsonData, err := json.Marshal(result)
	require.NoError(t, err)
	var unmarshaledResult TokenIntrospectionResult
	err = json.Unmarshal(jsonData, &unmarshaledResult)
	require.NoError(t, err)
	checkIntrospectionResult(t, &unmarshaledResult)

	// Test Clone
	clonedResult := result.Clone().(*TokenIntrospectionResult)
	checkIntrospectionResult(t, clonedResult)
}
