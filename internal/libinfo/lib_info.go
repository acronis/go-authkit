/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package libinfo

func UserAgent() string {
	return libShortName + "/" + GetLibVersion()
}

func LogPrefix() string {
	return "[" + libShortName + "/" + GetLibVersion() + "] "
}
