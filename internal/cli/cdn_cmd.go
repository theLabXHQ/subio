package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/theLabXHQ/subio/internal/asn"
	"github.com/theLabXHQ/subio/internal/cdn"
	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/scope"
)

// cdnResult is what subio learned about one input.
type cdnResult struct {
	Input     string    `json:"input"`
	Addresses []string  `json:"addresses,omitempty"`
	CNAME     []string  `json:"cname,omitempty"`
	Edge      *cdn.Edge `json:"edge,omitempty"`

	// Status is identified, not_identified, unresolved or error.
	Status string `json:"status"`
}

const (
	cdnIdentified    = "identified"
	cdnNotIdentified = "not_identified"
	cdnUnresolved    = "unresolved"
	cdnError         = "error"
)

// runCDN says which inputs sit behind a CDN, a WAF or a cloud provider.
func runCDN(args []string, stdout, stderr io.Writer) int {
	var (
		inputs       []string
		listPath     string
		resolversRaw string
		exclude      bool
		asJSON       bool
		silent       bool
		noColor      bool
		timeout      = 2 * time.Minute
	)
	fs := flag.NewFlagSet("cdn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("input")
	r.listVar(g, &inputs, true, "string", "names or addresses; repeatable and comma separated", "i", "input")
	r.stringVar(g, &listPath, "file of names or addresses, one per line; - for stdin", "l", "list")

	g = r.group("options")
	r.stringVar(g, &resolversRaw, "resolvers, comma separated or @file", "rs", "resolvers")
	r.durationVar(g, &timeout, "overall deadline", "t", "timeout")

	g = r.group("output")
	r.boolVar(g, &exclude, "print only inputs not behind a CDN or WAF, one per line; a cloud host stays, since the machine may be the target's own", "e", "exclude")
	r.boolVar(g, &asJSON, "emit one JSON object per input", "j", "jsonl")
	r.boolVar(g, &silent, "only results on stdout", "silent")
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")

	if err := fs.Parse(args); err != nil {
		w := stderr
		if err == flag.ErrHelp {
			w = stdout
		} else {
			fmt.Fprintf(stderr, "subio: %v\n", err)
		}
		fmt.Fprintf(w, `subio cdn - say which hosts sit behind a CDN, WAF or cloud provider

A name whose address is a CDN edge says nothing about the machine serving it:
scanning that address scans the CDN, and a hundred names sharing it are one
vendor, not a hundred hosts. This reads two signals:

  cname  the name aliases to a provider's domain (*.cloudfront.net, ...)
  asn    the address is announced by a provider's autonomous system

A host matching neither is "not identified", which is not proof of an origin:
a provider announcing from an AS not listed here goes unseen.

This is ACTIVE for names: it resolves them. Addresses need only Cymru's
origin record, one DNS query each.

USAGE
   subio cdn -i 104.16.0.1,www.example.com
   subio discover example.com -silent | subio cdn -l - -e | subio resolve -l -

Providers: %s

EXIT CODES
   0  every input was looked up
   2  configuration error
   4  at least one lookup failed; that input's answer is missing, not negative
`, strings.Join(cdn.Providers(), ", "))
		r.render(w)
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitConfig
	}
	if rejectBareArgs(fs, stderr) {
		return exitConfig
	}

	log := logx.New(stderr)
	log.Silent = silent || exclude
	log.Color = !noColor && isWriterTerminal(stderr)
	banner(stderr, silent || exclude, noColor)

	if listPath != "" {
		lines, err := readTokens(listPath)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		inputs = append(inputs, lines...)
	}
	names, addrs, bad := splitInputs(inputs)
	for _, b := range bad {
		log.Logf("warn", "skipping %q: neither a hostname nor an address", b)
	}
	if len(names)+len(addrs) == 0 {
		log.Logf("error", "give names or addresses with -i or -l")
		return exitConfig
	}

	servers, public, err := parseResolvers(resolversRaw)
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	res, err := resolver.New(resolver.Config{
		Servers: servers, Workers: 4, Window: 64,
		Timeout: 3 * time.Second, Retries: 1,
	})
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	if public {
		log.Logf("warn", "using public resolvers; their operators see every name and address asked about")
	}

	ctx, cancel := interruptible(timeout, log)
	defer cancel()
	results := classifyHosts(ctx, res, names, addrs, log)

	failed := 0
	counts := map[string]int{}
	for _, cr := range results {
		if cr.Status == cdnError {
			failed++
		}
		if cr.Edge != nil {
			counts[string(cr.Edge.Kind)]++
		}
	}
	switch {
	case exclude:
		for _, cr := range results {

			if cr.Status == cdnError || cr.Status == cdnUnresolved {
				continue
			}
			if cr.Edge == nil || cr.Edge.Kind == cdn.KindCloud {
				fmt.Fprintln(stdout, cr.Input)
			}
		}
	case asJSON:
		enc := json.NewEncoder(stdout)
		for _, cr := range results {
			if err := enc.Encode(cr); err != nil {
				log.Logf("error", "%v", err)
				return exitFatal
			}
		}
	default:
		tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "INPUT\tKIND\tPROVIDER\tVIA")
		for _, cr := range results {
			kind, prov, via := "-", "-", cr.Status
			if cr.Edge != nil {
				kind, prov = string(cr.Edge.Kind), cr.Edge.Provider
				via = cr.Edge.Signal + " " + cr.Edge.Evidence
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", cr.Input, kind, prov, via)
		}
		_ = tw.Flush()
	}
	log.Printf("\n%d input(s): %d cdn, %d waf, %d cloud, %d failed.\n",
		len(results), counts["cdn"], counts["waf"], counts["cloud"], failed)
	if failed > 0 {
		log.Logf("warn", "%d lookup(s) failed; those inputs are neither edge nor origin, just unknown", failed)
		return exitPartial
	}
	if why := stoppedEarly(ctx); why != "" {
		return exitPartial
	}
	return exitOK
}

// splitInputs sorts inputs into canonical names and addresses, in the order
// given and without repeats.
func splitInputs(in []string) (names []string, addrs []netip.Addr, bad []string) {
	seenN, seenA := map[string]bool{}, map[netip.Addr]bool{}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			a = a.Unmap()
			if !seenA[a] {
				seenA[a] = true
				addrs = append(addrs, a)
			}
			continue
		}
		h, err := scope.Canonical(s)
		if err != nil {
			bad = append(bad, s)
			continue
		}
		if !seenN[h] {
			seenN[h] = true
			names = append(names, h)
		}
	}
	return names, addrs, bad
}

// classifyHosts resolves the names, asks Cymru about every address, and
// picks the strongest identification for each input.
func classifyHosts(ctx context.Context, res *resolver.Resolver, names []string, addrs []netip.Addr, log *logx.Logger) []cdnResult {
	byName := map[string]*cdnResult{}
	var jobs []resolver.Job
	for _, n := range names {
		byName[n] = &cdnResult{Input: n, Status: cdnUnresolved}
		jobs = append(jobs, resolver.Job{Name: n, Type: dnsfast.TypeA}, resolver.Job{Name: n, Type: dnsfast.TypeAAAA})
	}
	nameAddrs := map[string][]netip.Addr{}
	errored := map[string]bool{}
	for _, a := range res.ResolveJobs(ctx, jobs) {
		cr := byName[a.Name]
		if cr == nil {
			continue
		}
		switch a.Outcome {
		case resolver.Resolved:
			for _, rr := range a.Records {
				switch rr.Type {
				case "A", "AAAA":
					if ad, err := netip.ParseAddr(rr.Value); err == nil && !containsAddr(nameAddrs[a.Name], ad) {
						nameAddrs[a.Name] = append(nameAddrs[a.Name], ad)
					}
				case "CNAME":
					if !containsString(cr.CNAME, rr.Value) {
						cr.CNAME = append(cr.CNAME, rr.Value)
					}
				}
			}
		case resolver.NXDomain, resolver.NoData:
		default:
			errored[a.Name] = true
		}
	}

	all := append([]netip.Addr(nil), addrs...)
	for _, n := range names {
		for _, ad := range nameAddrs[n] {
			if !containsAddr(all, ad) {
				all = append(all, ad)
			}
		}
	}
	origin, originFailed := originByAddr(ctx, res, all, log)

	edgesFor := func(cnames []string, as []netip.Addr) []cdn.Edge {
		var out []cdn.Edge
		for _, c := range cnames {
			if e, ok := cdn.ByCNAME(c); ok {
				out = append(out, e)
			}
		}
		for _, ad := range as {
			for _, n := range origin[ad] {
				if e, ok := cdn.ByASN(n); ok {
					out = append(out, e)
				}
			}
		}
		return out
	}

	var out []cdnResult
	for _, n := range names {
		cr := byName[n]
		for _, ad := range nameAddrs[n] {
			cr.Addresses = append(cr.Addresses, ad.String())
		}
		e, ok := cdn.Best(edgesFor(cr.CNAME, nameAddrs[n]))
		switch {
		case ok:
			cr.Edge, cr.Status = &e, cdnIdentified
		case errored[n] || anyAddr(nameAddrs[n], originFailed):

			cr.Status = cdnError
		case len(nameAddrs[n]) > 0 || len(cr.CNAME) > 0:
			cr.Status = cdnNotIdentified
		}
		out = append(out, *cr)
	}
	for _, ad := range addrs {
		cr := cdnResult{Input: ad.String(), Status: cdnNotIdentified}
		if e, ok := cdn.Best(edgesFor(nil, []netip.Addr{ad})); ok {
			cr.Edge, cr.Status = &e, cdnIdentified
		} else if originFailed[ad] {
			cr.Status = cdnError
		}
		out = append(out, cr)
	}
	return out
}

// originByAddr asks Cymru which AS announces each address.
func originByAddr(ctx context.Context, res *resolver.Resolver, addrs []netip.Addr, log *logx.Logger) (map[netip.Addr][]uint32, map[netip.Addr]bool) {
	byQuery := map[string]netip.Addr{}
	var jobs []resolver.Job
	for _, a := range addrs {
		if q := asn.OriginQuery(a); q != "" {
			byQuery[q] = a
			jobs = append(jobs, resolver.Job{Name: q, Type: dnsfast.TypeTXT})
		}
	}
	out := map[netip.Addr][]uint32{}
	failed := map[netip.Addr]bool{}
	for _, ans := range res.ResolveJobs(ctx, jobs) {
		a, ok := byQuery[ans.Name]
		if !ok {
			continue
		}
		switch ans.Outcome {
		case resolver.Resolved:
		case resolver.NXDomain, resolver.NoData:

			continue
		default:
			failed[a] = true
			continue
		}
		for _, rr := range ans.Records {
			if rr.Type != "TXT" {
				continue
			}
			o, err := asn.ParseOrigin(rr.Value)
			if err != nil {
				log.Logf("verbose", "cdn: unreadable origin answer for %s: %v", a, err)
				continue
			}
			for _, n := range o.ASNs {
				if !containsUint(out[a], n) {
					out[a] = append(out[a], n)
				}
			}
		}
		sort.Slice(out[a], func(i, j int) bool { return out[a][i] < out[a][j] })
	}
	return out, failed
}

// readTokens reads one input per line, keeping the first field so another
// tool's output pipes straight in.
func readTokens(path string) ([]string, error) {
	lines, err := readRootFile(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
			out = append(out, f[0])
		}
	}
	return out, nil
}

func containsAddr(list []netip.Addr, a netip.Addr) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

func anyAddr(list []netip.Addr, set map[netip.Addr]bool) bool {
	for _, x := range list {
		if set[x] {
			return true
		}
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func containsUint(list []uint32, n uint32) bool {
	for _, x := range list {
		if x == n {
			return true
		}
	}
	return false
}
