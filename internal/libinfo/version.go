/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package libinfo

import (
	"debug/buildinfo"
	"regexp"
	"sync"

	"runtime/debug"
)

const libShortName = "go-authkit"

const moduleName = "github.com/acronis/" + libShortName

var libVersion string
var libVersionOnce sync.Once

func GetLibVersion() string {
	libVersionOnce.Do(initLibVersion)
	return libVersion
}

func initLibVersion() {
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		libVersion = extractLibVersion(buildInfo, moduleName)
	}
	if libVersion == "" {
		libVersion = "v0.0.0"
	}
}

func extractLibVersion(buildInfo *buildinfo.BuildInfo, modName string) string {
	if buildInfo == nil {
		return ""
	}
	re, err := regexp.Compile(`^` + regexp.QuoteMeta(modName) + `(/v[0-9]+)?$`)
	if err != nil {
		return "" // should never happen
	}
	for _, dep := range buildInfo.Deps {
		if re.MatchString(dep.Path) {
			return dep.Version
		}
	}
	return ""
}
