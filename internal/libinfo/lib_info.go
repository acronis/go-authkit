/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package libinfo

import (
	"fmt"
)

const libName = "go-authkit"

const libPath = "github.com/acronis/" + libName

func MakeUserAgent(prependedUserAgent string) string {
	if prependedUserAgent != "" {
		prependedUserAgent += " "
	}
	return prependedUserAgent + " " + libName + "/" + GetLibVersion()
}

func GetLogPrefix() string {
	return fmt.Sprintf("[%s/%s]", libName, GetLibVersion())
}
