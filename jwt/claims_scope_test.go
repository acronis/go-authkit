package jwt_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/jwt"
)

func TestScope_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    jwt.Scope
		expectError bool
	}{
		{
			name:     "empty array",
			input:    `[]`,
			expected: jwt.Scope{},
		},
		{
			name:  "single access policy",
			input: `[{"tid":"tenant1","tuid":"uuid1","rs":"server1","rn":"namespace1","rp":"path1","role":"admin"}]`,
			expected: jwt.Scope{
				{
					TenantID:          "tenant1",
					TenantUUID:        "uuid1",
					ResourceServerID:  "server1",
					ResourceNamespace: "namespace1",
					ResourcePath:      "path1",
					Role:              "admin",
				},
			},
		},
		{
			name:  "multiple access policies",
			input: `[{"tid":"tenant1","rs":"server1","rn":"namespace1","role":"admin"},{"tid":"tenant2","rs":"server2","rn":"namespace2","role":"user"}]`,
			expected: jwt.Scope{
				{
					TenantID:          "tenant1",
					ResourceServerID:  "server1",
					ResourceNamespace: "namespace1",
					Role:              "admin",
				},
				{
					TenantID:          "tenant2",
					ResourceServerID:  "server2",
					ResourceNamespace: "namespace2",
					Role:              "user",
				},
			},
		},
		{
			name:  "policy with minimal fields",
			input: `[{"role":"guest"}]`,
			expected: jwt.Scope{
				{
					Role: "guest",
				},
			},
		},
		{
			name:  "policy with all fields",
			input: `[{"tid":"tenant1","tuid":"11111111-1111-1111-1111-111111111111","rs":"server1","rn":"namespace1","rp":"/resource/path","role":"admin"}]`,
			expected: jwt.Scope{
				{
					TenantID:          "tenant1",
					TenantUUID:        "11111111-1111-1111-1111-111111111111",
					ResourceServerID:  "server1",
					ResourceNamespace: "namespace1",
					ResourcePath:      "/resource/path",
					Role:              "admin",
				},
			},
		},
		{
			name:        "invalid JSON",
			input:       `[invalid json}`,
			expectError: true,
		},
		{
			name:     "null input",
			input:    `null`,
			expected: jwt.Scope(nil),
		},
		{
			name:        "wrong type - string",
			input:       `"not an array"`,
			expectError: true,
		},
		{
			name:        "wrong type - number",
			input:       `123`,
			expectError: true,
		},
		{
			name:        "array with invalid object",
			input:       `[{"role":123}]`,
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

func TestScopeDecodeError(t *testing.T) {
	t.Run("error formatting", func(t *testing.T) {
		err := &jwt.ScopeDecodeError{
			DecodedErrors: []error{
				fmt.Errorf("decoder 1 error"),
				fmt.Errorf("decoder 2 error"),
			},
			UnmarshalError: fmt.Errorf("fallback JSON error"),
		}

		expected := "all scope decoders failed: [decoder 1 error; decoder 2 error]; fallback error: fallback JSON error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("only decoder errors", func(t *testing.T) {
		err := &jwt.ScopeDecodeError{
			DecodedErrors: []error{
				fmt.Errorf("decoder error"),
			},
		}

		expected := "all scope decoders failed: [decoder error]"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("only unmarshal error", func(t *testing.T) {
		err := &jwt.ScopeDecodeError{
			UnmarshalError: fmt.Errorf("unmarshal error"),
		}

		expected := "fallback error: unmarshal error"
		assert.Equal(t, expected, err.Error())
	})

	t.Run("unwrap unmarshal error", func(t *testing.T) {
		unmarshalErr := fmt.Errorf("unmarshal error")
		err := &jwt.ScopeDecodeError{
			UnmarshalError: unmarshalErr,
		}

		assert.Equal(t, unmarshalErr, err.Unwrap())
	})
}
