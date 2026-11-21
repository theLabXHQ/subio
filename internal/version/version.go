// Package version holds build metadata.
package version

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// Version is set at link time by release builds (-ldflags "-X
// github.com/theLabXHQ/subio/internal/version.Version=1.2.3").
var Version = ""

// Release is the version this source tree is.
const Release = "0.1.0"

// SchemaVersion identifies the JSONL ledger schema.
const SchemaVersion = "subio.v2"

func init() {
	if Version == "" {
		Version = fromBuildInfo(debug.ReadBuildInfo())
	}
}

// fromBuildInfo returns the main module's version without the leading "v"
// when it is a release tag, and Release for anything else: a local build, or
// a pseudo-version Go derived from a commit.
func fromBuildInfo(bi *debug.BuildInfo, ok bool) string {
	if !ok || bi.Main.Version == "" || bi.Main.Version == "(devel)" {
		return Release
	}
	v := strings.TrimPrefix(bi.Main.Version, "v")

	if strings.Contains(v, "+") || pseudo.MatchString(v) {
		return Release
	}
	return v
}

var pseudo = regexp.MustCompile(`-(0\.)?\d{14}-[0-9a-f]{12}`)
