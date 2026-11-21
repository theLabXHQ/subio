package cli

import (
	"fmt"
	"io"
	"strings"
)

// render writes the grouped flag help.
func (r *registry) render(w io.Writer) {
	width := 0
	for _, g := range r.groups {
		for _, f := range g.flags {
			if n := len(f.names) + len(f.typ) + 1; n > width {
				width = n
			}
		}
	}
	if width > 34 {
		width = 34
	}
	for _, g := range r.groups {
		if len(g.flags) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s:\n", strings.ToUpper(g.title))
		for _, f := range g.flags {
			left := f.names
			if f.typ != "" {
				left += " " + f.typ
			}
			usage := f.usage
			if f.def != "" && f.def != "0" && f.def != "false" {
				usage += " (default " + f.def + ")"
			}
			if len(left) > width {
				fmt.Fprintf(w, "   %s\n   %*s  %s\n", left, width, "", usage)
				continue
			}
			fmt.Fprintf(w, "   %-*s  %s\n", width, left, usage)
		}
	}
}

// helpDiscover prints the discover usage followed by the grouped flags.
func helpDiscover(w io.Writer, r *registry) {
	fmt.Fprint(w, `subio discover - collect subdomains from passive sources

USAGE
   subio discover example.com [more.com ...] [flags]
   subio discover -l roots.txt -j -o findings.jsonl

Passive collection sends requests to third-party providers, which discloses
the names you are researching to them. -resolve additionally queries the
target's nameservers, which is active: use it only where you are authorized.

Names are reported as evidence. subio never claims a name is live, owned or
reachable, and an incomplete source run is reported as incomplete rather than
rendered as "these names are gone".
`)
	r.render(w)
	fmt.Fprint(w, `
EXIT CODES
   0  success
   1  fatal error
   2  configuration error (nothing was queried)
   3  completed, found nothing
   4  completed, but a source's results are incomplete or a DNS query went unanswered

EXAMPLES
   subio discover example.com
   subio discover example.com -src -ec
   subio discover example.com -s crtsh,wayback -j -o run.jsonl -ledger run.ledger.jsonl
   subio discover example.com -r -ty A,AAAA,CNAME -qps 5000 -dns -st
   subio discover -l roots.txt -m run.manifest.json -of csv -o findings.csv
   subio discover example.com -active -auth auth.json -brute -permute -mine
`)
}

// helpRoot prints the top-level usage.
func helpRoot(w io.Writer, ver string) {
	fmt.Fprintf(w, `subio %s - subdomain discovery with an evidence ledger

USAGE
   subio <command> [flags]

COMMANDS
   discover   collect subdomains from passive sources
   all        every discovery method the authorization allows
   resolve    observe DNS for a list of names (active)
   relate     suggest related root domains, with the evidence for each
   cttail     monitor certificate transparency logs, tiled or RFC 6962
   nsec3      report a zone's NSEC3 posture before walking it
   cdn        say which hosts sit behind a CDN, WAF or cloud provider
   asn        map an organisation, AS, address or domain to its address space
   sources    list adapters, credential state and terms state (offline)
   history    inspect and maintain a run history
   version    print the version

Run "subio <command> -h" for a command's flags.
`, ver)
}
