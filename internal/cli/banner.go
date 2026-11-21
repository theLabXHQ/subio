package cli

import (
	"io"
	"strings"
	"unicode/utf8"
)

// The wordmark: the word subio rendered in the FIGlet slant font, the same
// font Pulse uses for its own, because the two are one family and a user who
// runs both should not have to wonder.
const logo = `               __    _
   _______  __/ /_  (_)___
  / ___/ / / / __ \/ / __ \
 (__  ) /_/ / /_/ / / /_/ /
/____/\__,_/_.___/_/\____/
`

// printBanner writes the startup banner.
func printBanner(w io.Writer, color bool) {
	bold, dim, reset := "\x1b[1;97m", "\x1b[2m", "\x1b[0m"
	if !color {
		bold, dim, reset = "", "", ""
	}
	lines := strings.Split(strings.TrimSuffix(logo, "\n"), "\n")
	width := 0
	for _, l := range lines {
		width = max(width, utf8.RuneCountInString(l))
	}
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(bold + l + reset + "\n")
	}
	// The footer ends where the logo's widest line ends (spaces, not tabs: tab
	// stops differ between terminals).
	const footer = "thelabx.io"
	pad := max(0, width-utf8.RuneCountInString(footer))
	b.WriteString("\n" + strings.Repeat(" ", pad) + dim + footer + reset + "\n\n")
	_, _ = io.WriteString(w, b.String())
}

// banner prints the startup banner for a command, under the one condition
// that makes it safe: a human is watching stderr and did not ask for silence.
func banner(stderr io.Writer, silent, noColor bool) {
	if silent || !isWriterTerminal(stderr) {
		return
	}
	printBanner(stderr, !noColor)
}
