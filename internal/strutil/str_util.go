/*
Copyright © 2025 Acronis International GmbH.

Released under MIT license.
*/

package strutil

import "unsafe"

// StringToBytesUnsafe converts string to byte slice without memory allocation.
func StringToBytesUnsafe(s string) []byte {
	// nolint: gosec // memory optimization to prevent redundant slice copying
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
