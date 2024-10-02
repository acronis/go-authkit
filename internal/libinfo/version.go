/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package libinfo

import (
	"sync"

	"runtime/debug"
)

var libVersion string
var libVersionOnce sync.Once

func initLibVersion() {
	if buildInfo, ok := debug.ReadBuildInfo(); ok && buildInfo != nil {
		for _, dep := range buildInfo.Deps {
			if dep.Path == libPath {
				libVersion = dep.Version
				return
			}
		}
	}
	libVersion = "v0.0.0"
}

func GetLibVersion() string {
	libVersionOnce.Do(initLibVersion)
	return libVersion
}
