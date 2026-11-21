// Command subio discovers subdomains from passive sources and, on explicit
// opt-in, observes their DNS state.
package main

import (
	"os"

	"github.com/theLabXHQ/subio/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
