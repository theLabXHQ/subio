package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/asn"
	"github.com/theLabXHQ/subio/internal/cdn"
	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/fetch"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/scope"
	"github.com/theLabXHQ/subio/internal/source"
)

// asnRow is one announced prefix and how subio got to it.
type asnRow struct {
	Input  string `json:"input"`
	ASN    uint32 `json:"asn,omitempty"`
	ASName string `json:"as_name,omitempty"`
	Prefix string `json:"prefix"`
}

// defaultExpandMax bounds -expand.
const defaultExpandMax = 1 << 20

// runASN maps an organisation, an AS, an address, a domain or a range to the
// address space behind it: the asnmap step, with mapcidr's expand, aggregate
// and shuffle on its output.
func runASN(args []string, stdout, stderr io.Writer) int {
	var (
		inputs       []string
		listPath     string
		resolversRaw string
		aggregate    bool
		expand       bool
		wholeAS      bool
		shuffle      bool
		count        bool
		only4, only6 bool
		expandMax    = defaultExpandMax
		asJSON       bool
		silent       bool
		noColor      bool
		timeout      = 2 * time.Minute
	)
	fs := flag.NewFlagSet("asn", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("input")
	r.listVar(g, &inputs, true, "string", "AS numbers, addresses, ranges, domains or organisation names; repeatable and comma separated", "i", "input")
	r.stringVar(g, &listPath, "file of inputs, one per line; - for stdin", "l", "list")

	g = r.group("ranges")
	r.boolVar(g, &wholeAS, "for a domain or address in a CDN or cloud provider's AS, map the provider's whole AS rather than only the range holding the address", "whole-as")
	r.boolVar(g, &aggregate, "merge contained and adjacent ranges into the fewest that cover the same addresses", "agg", "aggregate")
	r.boolVar(g, &only4, "IPv4 only", "4", "v4")
	r.boolVar(g, &only6, "IPv6 only", "6", "v6")

	g = r.group("addresses")
	r.boolVar(g, &expand, "print every address instead of the ranges", "e", "expand")
	r.intVar(g, &expandMax, "with -expand, stop after this many addresses; 0 is no limit", "max")
	r.boolVar(g, &shuffle, "with -expand, print the addresses in random order", "shuffle", "shuffle-ip")
	r.boolVar(g, &count, "print only how many addresses the ranges hold", "c", "count")

	g = r.group("options")
	r.stringVar(g, &resolversRaw, "resolvers, comma separated or @file", "rs", "resolvers")
	r.durationVar(g, &timeout, "overall deadline", "t", "timeout")

	g = r.group("output")
	r.boolVar(g, &asJSON, "emit one JSON object per range, with the AS it came from", "j", "jsonl")
	r.boolVar(g, &silent, "only results on stdout", "silent")
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")

	if err := fs.Parse(args); err != nil {
		w := stderr
		if err == flag.ErrHelp {
			w = stdout
		} else {
			fmt.Fprintf(stderr, "subio: %v\n", err)
		}
		fmt.Fprint(w, `subio asn - map an organisation, AS, address or domain to its address space

Each input is read as what it looks like:

  AS13335, 13335     the prefixes that AS announces
  192.0.2.1          the AS announcing it, then that AS's prefixes
  192.0.2.0/24       the range itself, for -aggregate, -expand or -count
  example.com        its addresses, then as for an address
  "Example Corp"     ASes whose registry holder name matches, then theirs

A name search matches the text a registry was given, not ownership: check
each AS it prints before using its ranges. Announced prefixes are what the
routing table showed at RIPEstat's last collection.

This lists address space and connects to none of it. Domains are resolved and
each address costs one DNS query to Team Cymru; AS prefixes and name searches
are asked of RIPEstat.

USAGE
   subio asn -i AS13335
   subio asn -i example.com -agg
   subio asn -i "Example Corp" -4 -j
   subio asn -i 192.0.2.0/24 -e -shuffle

EXIT CODES
   0  every input was mapped
   2  configuration error
   3  every lookup completed and no address space was found
   4  a lookup failed or -max cut the output short; what is printed is partial
`)
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
	log.Silent = silent
	log.Color = !noColor && isWriterTerminal(stderr)
	banner(stderr, silent, noColor)

	if listPath != "" {
		lines, err := readRootFile(listPath)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		inputs = append(inputs, lines...)
	}
	if len(inputs) == 0 {
		log.Logf("error", "give at least one input with -i or -l")
		return exitConfig
	}
	if only4 && only6 {
		log.Logf("error", "-4 and -6 together select nothing")
		return exitConfig
	}
	if expandMax < 0 {
		log.Logf("error", "-max must be 0 or more")
		return exitConfig
	}
	if (shuffle && !expand) || (count && expand) {
		log.Logf("error", "-shuffle needs -expand, and -count replaces it")
		return exitConfig
	}

	plan := classifyASNInputs(inputs)
	for _, b := range plan.bad {
		log.Logf("warn", "skipping %q: not an AS number, address, range, domain or name", b)
	}

	scheduler := sched.New(sched.Config{GlobalConcurrency: 4, PerSourceConcurrency: 2})
	client := fetch.New(fetch.Config{Scheduler: scheduler, MaxAttempts: 3})
	client.Register(source.Metadata{ID: asn.SourceID, Limits: ripeStatLimits})

	// The resolver also names each AS, through Cymru, so an AS number alone
	// needs it too.
	var res *resolver.Resolver
	if len(plan.names)+len(plan.addrs)+len(plan.asns)+len(plan.orgs) > 0 {
		servers, public, err := parseResolvers(resolversRaw)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		res, err = resolver.New(resolver.Config{
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
	}

	ctx, cancel := interruptible(timeout, log)
	defer cancel()
	rows, partial := mapASNs(ctx, plan, res, client, log, wholeAS)

	var prefixes []netip.Prefix
	keep := func(p netip.Prefix) bool { return !(only4 && !p.Addr().Is4()) && !(only6 && !p.Addr().Is6()) }
	var kept []asnRow
	for _, row := range rows {
		p, err := netip.ParsePrefix(row.Prefix)
		if err != nil || !keep(p) {
			continue
		}
		prefixes = append(prefixes, p)
		kept = append(kept, row)
	}
	if aggregate {
		prefixes = asn.Aggregate(prefixes)
	} else {
		prefixes = uniquePrefixes(prefixes)
	}

	total := new(big.Int)
	for _, p := range asn.Aggregate(prefixes) {
		total.Add(total, asn.Size(p))
	}
	switch {
	case count:
		fmt.Fprintln(stdout, total.String())
	case expand:
		if !expandAddrs(stdout, prefixes, uint64(expandMax), shuffle, total, log) {
			partial = true
		}
	case asJSON && !aggregate:
		enc := json.NewEncoder(stdout)
		for _, row := range kept {
			if err := enc.Encode(row); err != nil {
				log.Logf("error", "%v", err)
				return exitFatal
			}
		}
	case asJSON:

		enc := json.NewEncoder(stdout)
		for _, p := range prefixes {
			if err := enc.Encode(asnRow{Prefix: p.String()}); err != nil {
				log.Logf("error", "%v", err)
				return exitFatal
			}
		}
	default:
		for _, p := range prefixes {
			fmt.Fprintln(stdout, p.String())
		}
	}

	log.Printf("\n%d range(s), %s address(es).\n", len(prefixes), total.String())
	if partial || stoppedEarly(ctx) != "" {
		log.Logf("warn", "the output is partial: see the warnings above")
		return exitPartial
	}
	if len(prefixes) == 0 {
		return exitEmpty
	}
	return exitOK
}

// asnPlan sorts inputs by what they look like.
type asnPlan struct {
	asns     []uint32
	prefixes []netip.Prefix
	addrs    []netip.Addr
	names    []string
	orgs     []string
	bad      []string
	// from remembers which input led to each AS, for the rows' input field.
	from map[uint32]string
}

func classifyASNInputs(in []string) asnPlan {
	p := asnPlan{from: map[uint32]string{}}
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		switch {
		case s == "":
		case isASNInput(s):
			n, _ := asn.ParseASN(s)
			if _, ok := p.from[n]; !ok {
				p.from[n] = s
				p.asns = append(p.asns, n)
			}
		case strings.Contains(s, "/"):
			if pf, err := netip.ParsePrefix(s); err == nil {
				p.prefixes = append(p.prefixes, pf.Masked())
			} else {
				p.bad = append(p.bad, s)
			}
		default:
			if a, err := netip.ParseAddr(s); err == nil {
				p.addrs = append(p.addrs, a.Unmap())
			} else if h, err := scope.Canonical(s); err == nil && strings.Contains(h, ".") {
				p.names = append(p.names, h)
			} else if strings.ContainsAny(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				p.orgs = append(p.orgs, s)
			} else {
				p.bad = append(p.bad, s)
			}
		}
	}
	return p
}

// isASNInput is true for "AS123" and for a bare number, but not for a bare
// number that is also an address (an integer is never parsed as one here).
func isASNInput(s string) bool {
	_, ok := asn.ParseASN(s)
	return ok
}

// mapASNs turns the plan into announced prefixes.
func mapASNs(ctx context.Context, plan asnPlan, res *resolver.Resolver, http *fetch.Client, log *logx.Logger, wholeAS bool) (rows []asnRow, partial bool) {
	for _, pf := range plan.prefixes {
		rows = append(rows, asnRow{Input: pf.String(), Prefix: pf.String()})
	}
	names := map[uint32]string{}

	addrFrom := map[netip.Addr]string{}
	addrs := append([]netip.Addr(nil), plan.addrs...)
	for _, a := range plan.addrs {
		addrFrom[a] = a.String()
	}
	if len(plan.names) > 0 {
		var jobs []resolver.Job
		for _, n := range plan.names {
			jobs = append(jobs, resolver.Job{Name: n, Type: dnsfast.TypeA}, resolver.Job{Name: n, Type: dnsfast.TypeAAAA})
		}
		answered := map[string]bool{}
		failed := map[string]bool{}
		for _, a := range res.ResolveJobs(ctx, jobs) {
			switch a.Outcome {
			case resolver.Resolved:
				answered[a.Name] = true
				for _, rr := range a.Records {
					if rr.Type != "A" && rr.Type != "AAAA" {
						continue
					}
					if ad, err := netip.ParseAddr(rr.Value); err == nil {
						if _, seen := addrFrom[ad]; !seen {
							addrFrom[ad] = a.Name
							addrs = append(addrs, ad)
						}
					}
				}
			case resolver.NXDomain, resolver.NoData:
				answered[a.Name] = true
			default:
				failed[a.Name] = true
			}
		}
		for _, n := range plan.names {
			if failed[n] && !answered[n] {
				log.Logf("warn", "%s: the resolver gave no answer, so its address space is missing, not empty", n)
				partial = true
			}
		}
	}

	asns := append([]uint32(nil), plan.asns...)
	from := map[uint32]string{}
	for n, s := range plan.from {
		from[n] = s
	}
	covering := map[uint32][]netip.Prefix{}

	viaAddress := map[uint32]bool{}
	if len(addrs) > 0 {
		origins, failed := originDetail(ctx, res, addrs, log)
		for _, a := range addrs {
			if failed[a] {
				log.Logf("warn", "%s: Cymru gave no answer for its origin", a)
				partial = true
				continue
			}
			o, ok := origins[a]
			if !ok {
				log.Logf("info", "%s: no route announces it", a)
				continue
			}
			for _, n := range o.ASNs {
				if _, ok := from[n]; !ok {
					from[n] = addrFrom[a]
					asns = append(asns, n)
					viaAddress[n] = true
				}
				if o.Prefix.IsValid() {
					covering[n] = append(covering[n], o.Prefix)
				}
			}
		}
	}

	for _, q := range plan.orgs {
		found, err := asn.Search(ctx, http, "", q)
		if err != nil {
			log.Logf("warn", "%v", err)
			partial = true
			continue
		}
		if len(found) == 0 {
			log.Logf("info", "%q: no AS holder name matches", q)
		}
		for _, info := range found {
			log.Logf("info", "%q matched AS%d %s", q, info.Number, info.Name)
			names[info.Number] = info.Name
			if _, ok := from[info.Number]; !ok {
				from[info.Number] = q
				asns = append(asns, info.Number)
			}
		}
	}

	if res != nil {
		var missing []uint32
		for _, n := range asns {
			if names[n] == "" {
				missing = append(missing, n)
			}
		}
		for n, name := range asNames(ctx, res, missing) {
			names[n] = name
		}
	}

	sort.SliceStable(asns, func(i, j int) bool { return asns[i] < asns[j] })
	for _, n := range asns {
		label := asLabel(n, names[n])

		if edge, isProvider := cdn.ByASN(n); isProvider && viaAddress[n] && !wholeAS && len(covering[n]) > 0 {
			ps := asn.Aggregate(covering[n])
			log.Logf("warn", "%s belongs to %s (%s), not to %s: printing only the %d range(s) holding its address(es); -whole-as maps the provider's whole AS",
				label, edge.Provider, edge.Kind, from[n], len(ps))
			for _, p := range ps {
				rows = append(rows, asnRow{Input: from[n], ASN: n, ASName: names[n], Prefix: p.String()})
			}
			continue
		}
		ps, err := asn.Prefixes(ctx, http, "", n)
		if err != nil {
			if len(covering[n]) == 0 {
				log.Logf("warn", "%s: announced prefixes unavailable (%v)", label, err)
				partial = true
				continue
			}
			log.Logf("warn", "%s: announced prefixes unavailable (%v); using only the %d prefix(es) Cymru named", label, err, len(covering[n]))
			ps = covering[n]
			partial = true
		}
		log.Logf("info", "%s: %d prefix(es), from %s", label, len(ps), from[n])
		for _, p := range ps {
			rows = append(rows, asnRow{Input: from[n], ASN: n, ASName: names[n], Prefix: p.String()})
		}
	}
	return rows, partial
}

// originDetail is originByAddr with the covering prefix kept.
func originDetail(ctx context.Context, res *resolver.Resolver, addrs []netip.Addr, log *logx.Logger) (map[netip.Addr]asn.Origin, map[netip.Addr]bool) {
	byQuery := map[string]netip.Addr{}
	var jobs []resolver.Job
	for _, a := range addrs {
		if q := asn.OriginQuery(a); q != "" {
			byQuery[q] = a
			jobs = append(jobs, resolver.Job{Name: q, Type: dnsfast.TypeTXT})
		}
	}
	out := map[netip.Addr]asn.Origin{}
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
				log.Logf("verbose", "unreadable origin answer for %s: %v", a, err)
				continue
			}
			prev := out[a]
			for _, n := range o.ASNs {
				if !containsUint(prev.ASNs, n) {
					prev.ASNs = append(prev.ASNs, n)
				}
			}
			if !prev.Prefix.IsValid() || (o.Prefix.IsValid() && o.Prefix.Bits() > prev.Prefix.Bits()) {
				prev.Prefix = o.Prefix
			}
			out[a] = prev
		}
	}
	return out, failed
}

func uniquePrefixes(ps []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	out := ps[:0:0]
	for _, p := range ps {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	asn.SortPrefixes(out)
	return out
}

// expandAddrs prints the addresses, up to max.
func expandAddrs(w io.Writer, prefixes []netip.Prefix, max uint64, shuffle bool, total *big.Int, log *logx.Logger) bool {
	limit := max
	truncated := max > 0 && total.Cmp(new(big.Int).SetUint64(max)) > 0
	if shuffle {
		var all []netip.Addr
		asn.Expand(prefixes, limit, func(a netip.Addr) bool { all = append(all, a); return true })
		rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
		for _, a := range all {
			fmt.Fprintln(w, a.String())
		}
	} else {
		asn.Expand(prefixes, limit, func(a netip.Addr) bool { fmt.Fprintln(w, a.String()); return true })
	}
	if truncated {
		what := "the first"
		if shuffle {
			what = "a shuffle of the first"
		}
		log.Logf("warn", "-expand printed %s %d of %s addresses; -max raises the limit", what, max, total.String())
		return false
	}
	return true
}
