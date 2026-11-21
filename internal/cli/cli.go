// Package cli is subio's command-line interface.
package cli

import (
	"fmt"
	"io"

	"github.com/theLabXHQ/subio/internal/version"
)

// Exit codes.
const (
	exitOK = 0
	// exitFatal is an unexpected failure.
	exitFatal = 1
	// exitConfig is a usage or configuration error; nothing was queried.
	exitConfig = 2
	// exitEmpty means the run completed and found nothing.
	exitEmpty = 3

	// exitPartial means at least one source's result set is incomplete
	// (truncated, throttled, failed, missing a credential, terms-blocked).
	exitPartial = 4
)

// Main dispatches a command and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {

		banner(stderr, false, false)
		helpRoot(stderr, version.Version)
		return exitConfig
	}
	switch args[0] {
	case "discover", "d":
		return runDiscover(args[1:], stdout, stderr)
	case "all", "a":
		return runAll(args[1:], stdout, stderr)
	case "sources", "s":
		return runSources(args[1:], stdout, stderr)
	case "resolve", "r":
		return runResolve(args[1:], stdout, stderr)
	case "history", "h":
		return runHistory(args[1:], stdout, stderr)
	case "cttail", "ct":
		return runCTTail(args[1:], stdout, stderr)
	case "relate":
		return runRelate(args[1:], stdout, stderr)
	case "nsec3":
		return runNSEC3(args[1:], stdout, stderr)
	case "cdn":
		return runCDN(args[1:], stdout, stderr)
	case "asn":
		return runASN(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "subio %s\n", version.Version)
		return exitOK
	case "help", "-h", "--help", "-help":
		banner(stderr, false, false)
		helpRoot(stdout, version.Version)
		return exitOK
	default:
		fmt.Fprintf(stderr, "subio: unknown command %q\n", args[0])
		helpRoot(stderr, version.Version)
		return exitConfig
	}
}
