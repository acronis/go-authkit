/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package libinfo

import (
	"debug/buildinfo"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractLibVersion(t *testing.T) {
	tests := []struct {
		name        string
		buildInfo   *buildinfo.BuildInfo
		moduleName  string
		expectedVer string
	}{
		{
			name: "module found",
			buildInfo: &buildinfo.BuildInfo{
				Deps: []*debug.Module{
					{Path: "github.com/acronis/go-authkit", Version: "v1.2.3"},
				},
			},
			moduleName:  "github.com/acronis/go-authkit",
			expectedVer: "v1.2.3",
		},
		{
			name: "module found, v2",
			buildInfo: &buildinfo.BuildInfo{
				Deps: []*debug.Module{
					{Path: "github.com/acronis/go-authkit/v2", Version: "v2.0.0"},
				},
			},
			moduleName:  "github.com/acronis/go-authkit",
			expectedVer: "v2.0.0",
		},
		{
			name: "module not found",
			buildInfo: &buildinfo.BuildInfo{
				Deps: []*debug.Module{
					{Path: "github.com/other/module", Version: "v1.0.0"},
				},
			},
			moduleName:  "github.com/acronis/go-authkit",
			expectedVer: "",
		},
		{
			name: "empty deps",
			buildInfo: &buildinfo.BuildInfo{
				Deps: []*debug.Module{},
			},
			moduleName:  "github.com/acronis/go-authkit",
			expectedVer: "",
		},
		{
			name:        "nil build info",
			buildInfo:   nil,
			moduleName:  "github.com/acronis/go-authkit",
			expectedVer: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLibVersion(tt.buildInfo, tt.moduleName)
			require.Equal(t, tt.expectedVer, got)
		})
	}
}
