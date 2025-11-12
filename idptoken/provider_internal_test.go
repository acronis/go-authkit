/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package idptoken

import (
	"reflect"
	"testing"
)

func TestUniqAndSort(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single element",
			input:    []string{"a"},
			expected: []string{"a"},
		},
		{
			name:     "no duplicates",
			input:    []string{"c", "a", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"b", "a", "b", "c", "a"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all same",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
		{
			name:     "already sorted unique",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "already sorted with duplicates",
			input:    []string{"a", "a", "b", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "reverse order",
			input:    []string{"c", "b", "a"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "multiple duplicates",
			input:    []string{"d", "b", "a", "c", "b", "d", "a"},
			expected: []string{"a", "b", "c", "d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make a copy since the function modifies in-place
			inputCopy := make([]string, len(tt.input))
			copy(inputCopy, tt.input)

			result := uniqAndSort(inputCopy)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("uniqAndSort(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}
