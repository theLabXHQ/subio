package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/theLabXHQ/subio/internal/authz"
)

// runAll turns on every discovery method subio has, and no more than the
// operator is authorized to use.
func runAll(args []string, stdout, stderr io.Writer) int {
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "-help" {
			helpAll(stdout)
			return exitOK
		}
	}

	preset := []string{"-r", "-ty", "A,AAAA,CNAME"}
	authFile := authFileFrom(args)
	if authFile != "" {
		auth, err := authz.LoadAuthorization(authFile)
		if err != nil {
			fmt.Fprintf(stderr, "subio all: %v\n", err)
			return exitConfig
		}
		var on []string
		if auth.Allows(authz.MethodActiveDNS) {

			preset = []string{"-r", "-ty", "A,AAAA,CNAME,MX,TXT,NS", "-active", "-active-all"}
			on = append(on, "brute, permute, mine, nsec, ptr, axfr")
		}
		if auth.Allows(authz.MethodActiveTLS) {
			preset = append(preset, "-tls")
			on = append(on, "tls")
		}
		if auth.Allows(authz.MethodActiveHTTP) {
			preset = append(preset, "-web", "-vhost")
			on = append(on, "web, vhost")
		}
		if len(on) == 0 {

			fmt.Fprintf(stderr, "[WRN] %s grants no active method, so this run stays passive; "+
				"add active-dns to allowed_methods to enable the rest\n", authFile)
			preset = []string{"-r", "-ty", "A,AAAA,CNAME"}
			args = withoutAuth(args)
		} else {
			fmt.Fprintf(stderr, "[INF] %s authorizes: %s\n", authFile, strings.Join(on, "; "))
		}
	}
	return runDiscover(append(preset, args...), stdout, stderr)
}

// authFileFrom finds -auth in the operator's arguments without parsing them,
// so that the preset can be decided before discover's flag set is built.
func authFileFrom(args []string) string {
	for i, a := range args {
		for _, name := range []string{"-auth", "--auth"} {
			if a == name && i+1 < len(args) {
				return args[i+1]
			}
			if v, ok := strings.CutPrefix(a, name+"="); ok {
				return v
			}
		}
	}
	return ""
}

// withoutAuth drops -auth and its value, for the one case where the record
// was read and granted nothing active: discover refuses -auth without
// -active, and that refusal would stop a run this command has just established is allowed.
func withoutAuth(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-auth" || a == "--auth" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-auth=") || strings.HasPrefix(a, "--auth=") {
			continue
		}
		out = append(out, a)
	}
	return out
}

func helpAll(w io.Writer) {
	fmt.Fprint(w, `subio all - every discovery method the authorization allows

USAGE
   subio all example.com
   subio all example.com -auth auth.json
   subio all example.com -auth auth.json -ledger run.jsonl -a

This is a preset over "discover", so every discover flag works here and
anything you pass explicitly wins over the preset. Run "subio discover -h" for
the full flag list.

WITHOUT -auth, the fullest run that needs nobody's permission:

   every enabled passive adapter, then DNS observation of what they reported
   (-r -ty A,AAAA,CNAME)

Passive collection discloses the names you are researching to each provider.
DNS observation reads public DNS through a recursive resolver.

WITH -auth, the record's allowed_methods list decides - not this flag:

   active-dns    -active -active-all: brute, permute, mine, nsec, ptr and
                 axfr, and more record types, because -mine reads names out
                 of the answers.
   active-tls    -tls: read certificate names from found hosts on port 443
   active-http   -web and -vhost: read hostnames the found hosts' pages and
                 headers reference, and probe addresses for virtual hosts

A method the record does not grant is never requested, so this command cannot
be the reason a run reached further than its paperwork. A record that grants
nothing active is reported and the run stays passive.

It does not change how results print or write any file. Add -a for every
display field, -ledger for the evidence trail, -m for a run manifest.

It also does not turn on -authoritative, which asks each root's own
nameservers instead of a recursive resolver. That is a sound thing to do with
a record in hand, but it fails the whole run when a root publishes no NS
record subio can read rather than falling back quietly, which is right for a
flag you typed and wrong for one a preset chose. Add it yourself when you want
it. How DNS is asked stays your choice; this command decides what is asked.
`)
}
