/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package acronisext

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/jwt"
)

func TestJWTClaims(t *testing.T) {
	now := time.Now()
	expiry := now.Add(time.Hour)
	claims := &JWTClaims{
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
	}

	checkClaims := func(t *testing.T, c *JWTClaims) {
		t.Helper()
		assert.Equal(t, claims.DefaultClaims, c.DefaultClaims)
		assert.Equal(t, claims.Version, c.Version)
		assert.Equal(t, claims.UserID, c.UserID)
		assert.Equal(t, claims.OriginID, c.OriginID)
		assert.Equal(t, claims.TOTPTime, c.TOTPTime)
		assert.Equal(t, claims.LoginTOTPTime, c.LoginTOTPTime)
		assert.Equal(t, claims.SubType, c.SubType)
		assert.Equal(t, claims.ClientID, c.ClientID)
		assert.Equal(t, claims.OwnerTenantUUID, c.OwnerTenantUUID)
		assert.Equal(t, claims.Narrowing, c.Narrowing)
	}

	// Test JSON marshaling/unmarshaling
	jsonData, err := json.Marshal(claims)
	require.NoError(t, err)
	var unmarshaledClaims JWTClaims
	err = json.Unmarshal(jsonData, &unmarshaledClaims)
	require.NoError(t, err)
	checkClaims(t, &unmarshaledClaims)

	// Test Clone method
	clonedClaims := claims.Clone().(*JWTClaims)
	require.NotNil(t, clonedClaims)
	checkClaims(t, clonedClaims)
	// Verify deep clone by modifying original
	claims.UserID = "changed"
	claims.Narrowing[0][0] = "changed"
	assert.NotEqual(t, claims.UserID, clonedClaims.UserID)
	assert.NotEqual(t, claims.Narrowing[0][0], clonedClaims.Narrowing[0][0])
}

func TestScopeDecoder(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    jwt.Scope
		expectError bool
	}{
		{
			name:  "array of URN strings",
			input: `["urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111:admin"]`,
			expected: jwt.Scope{
				{
					TenantUUID:        "11111111-1111-1111-1111-111111111111",
					ResourceServerID:  "identity",
					ResourceNamespace: "tenant",
					Role:              "admin",
				},
			},
		},
		{
			name:  "single space-delimited string",
			input: `"urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111:admin urn:acronis:backup:tenant:22222222-2222-2222-2222-222222222222:backup_admin"`,
			expected: jwt.Scope{
				{
					TenantUUID:        "11111111-1111-1111-1111-111111111111",
					ResourceServerID:  "identity",
					ResourceNamespace: "tenant",
					Role:              "admin",
				},
				{
					TenantUUID:        "22222222-2222-2222-2222-222222222222",
					ResourceServerID:  "backup",
					ResourceNamespace: "tenant",
					Role:              "backup_admin",
				},
			},
		},
		{
			name:  "URN with resource path",
			input: `["urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111|/resource/path:admin"]`,
			expected: jwt.Scope{
				{
					TenantUUID:        "11111111-1111-1111-1111-111111111111",
					ResourceServerID:  "identity",
					ResourceNamespace: "tenant",
					ResourcePath:      "/resource/path",
					Role:              "admin",
				},
			},
		},
		{
			name:        "empty JSON",
			input:       ``,
			expectError: true,
		},
		{
			name:        "invalid JSON type",
			input:       `123`,
			expectError: true,
		},
		{
			name:        "malformed JSON",
			input:       `[invalid`,
			expectError: true,
		},
		{
			name:        "invalid URN in array",
			input:       `["invalid:urn:format"]`,
			expectError: true,
		},
		{
			name:        "invalid URN in string",
			input:       `"invalid:urn:format"`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ScopeDecoder(json.RawMessage(tt.input))
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseAccessPolicyURN(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    jwt.AccessPolicy
		expectError bool
	}{
		{
			name:  "valid URN",
			input: "urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111:admin",
			expected: jwt.AccessPolicy{
				TenantUUID:        "11111111-1111-1111-1111-111111111111",
				ResourceServerID:  "identity",
				ResourceNamespace: "tenant",
				Role:              "admin",
			},
		},
		{
			name:  "URN with resource path",
			input: "urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111|/resource/path:admin",
			expected: jwt.AccessPolicy{
				TenantUUID:        "11111111-1111-1111-1111-111111111111",
				ResourceServerID:  "identity",
				ResourceNamespace: "tenant",
				ResourcePath:      "/resource/path",
				Role:              "admin",
			},
		},
		{
			name:        "not an Acronis URN",
			input:       "urn:other:identity:tenant:11111111-1111-1111-1111-111111111111:admin",
			expectError: true,
		},
		{
			name:        "missing resource server",
			input:       "urn:acronis:",
			expectError: true,
		},
		{
			name:        "missing resource namespace",
			input:       "urn:acronis:identity",
			expectError: true,
		},
		{
			name:        "missing tenant ID",
			input:       "urn:acronis:identity:tenant",
			expectError: true,
		},
		{
			name:        "missing role",
			input:       "urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111",
			expectError: true,
		},
		{
			name:        "trailing data",
			input:       "urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111:admin:extra",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseAccessPolicyURN(tt.input)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestScopeUnmarshalJSON(t *testing.T) {
	// Register the scope decoder for this test
	RegisterScopeDecoder()

	tests := []struct {
		name        string
		input       string
		expected    jwt.Scope
		expectError bool
	}{
		{
			name:  "standard JSON array",
			input: `[{"tid":"tenant1","rs":"server1","rn":"namespace1","role":"admin"}]`,
			expected: jwt.Scope{
				{
					TenantID:          "tenant1",
					ResourceServerID:  "server1",
					ResourceNamespace: "namespace1",
					Role:              "admin",
				},
			},
		},
		{
			name:  "Acronis URN format via custom decoder",
			input: `["urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111:admin"]`,
			expected: jwt.Scope{
				{
					TenantUUID:        "11111111-1111-1111-1111-111111111111",
					ResourceServerID:  "identity",
					ResourceNamespace: "tenant",
					Role:              "admin",
				},
			},
		},
		{
			name:        "invalid JSON",
			input:       `invalid`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scope jwt.Scope
			err := json.Unmarshal([]byte(tt.input), &scope)
			if tt.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, scope)
		})
	}
}

func TestRegisterScopeDecoder_Idempotent(t *testing.T) {
	// Test that multiple calls are safe
	RegisterScopeDecoder()
	RegisterScopeDecoder()
	RegisterScopeDecoder()

	// Test concurrent calls
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			RegisterScopeDecoder()
		}()
	}
	wg.Wait()

	// Verify the decoder still works correctly
	input := `["urn:acronis:identity:tenant:11111111-1111-1111-1111-111111111111:admin"]`
	var scope jwt.Scope
	err := json.Unmarshal([]byte(input), &scope)
	require.NoError(t, err)

	expected := jwt.Scope{
		{
			TenantUUID:        "11111111-1111-1111-1111-111111111111",
			ResourceServerID:  "identity",
			ResourceNamespace: "tenant",
			Role:              "admin",
		},
	}
	assert.Equal(t, expected, scope)
}
