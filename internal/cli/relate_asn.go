package cli

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/theLabXHQ/subio/internal/asn"
	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/fetch"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
)

// asnSweep is the operator's bounds on the ASN signal.
type asnSweep struct {

	// MaxAddresses is the largest announced address space whose neighbours are
	// still treated as a signal.
	MaxAddresses uint64
	// PTRBudget caps how many reverse lookups one run will send.
	PTRBudget int
	// RIPEStatURL overrides the announced-prefixes endpoint, for tests.
	RIPEStatURL string
}

// asnRelated runs the signal end to end and returns the evidence it found.
func asnRelated(ctx context.Context, res *resolver.Resolver, http *fetch.Client, roots []string, opt asnSweep, log *logx.Logger) []seenName {
	addrs := rootAddresses(ctx, res, roots)
	if len(addrs) == 0 {
		log.Logf("warn", "-asn: no address resolved for any root, so there is no autonomous system to look in")
		return nil
	}

	origins, prefixByAS := originsOf(ctx, res, addrs, log)
	if len(origins) == 0 {
		log.Logf("warn", "-asn: Cymru's origin zone answered for none of %d address(es); the signal is missing, not empty", len(addrs))
		return nil
	}
	names := asNames(ctx, res, origins)

	var out []seenName
	for _, n := range origins {
		label := asLabel(n, names[n])
		prefixes, err := asn.Prefixes(ctx, http, opt.RIPEStatURL, n)
		if err != nil {

			log.Logf("warn", "-asn: %s announced-prefix list unavailable (%v); using only the prefix the target sits in", label, err)
			prefixes = prefixByAS[n]
		}
		if len(prefixes) == 0 {
			log.Logf("warn", "-asn: %s has no usable prefix", label)
			continue
		}
		total := asn.AddressCount(prefixes)
		if opt.MaxAddresses > 0 && asn.SharedInfrastructure(prefixes, opt.MaxAddresses) {
			log.Logf("warn", "-asn: %s announces %d addresses in %d prefix(es), over the %d ceiling: not swept, because at that size the neighbours are a hosting provider's other customers, not the target's siblings. -asn-max-addresses raises or (as 0) removes the ceiling.",
				label, total, len(prefixes), opt.MaxAddresses)
			continue
		}
		plan, skipped := asn.Sweep(prefixes, opt.PTRBudget)
		if len(plan) == 0 {
			log.Logf("warn", "-asn: %s has nothing sweepable (IPv6-only prefixes cannot be enumerated)", label)
			continue
		}
		log.Logf("info", "-asn: %s: reverse DNS over %d of %d address(es) in %d prefix(es)", label, len(plan), total, len(prefixes))
		if skipped > 0 {
			log.Logf("warn", "-asn: %s: %d address(es) left unqueried by the -asn-max-ptr budget, so these neighbours are partial", label, skipped)
		}
		out = append(out, sweepPTR(ctx, res, plan, label)...)
	}
	return out
}

// rootAddresses resolves each root's own A and AAAA records.
func rootAddresses(ctx context.Context, res *resolver.Resolver, roots []string) []netip.Addr {
	var jobs []resolver.Job
	for _, r := range roots {
		jobs = append(jobs,
			resolver.Job{Name: r, Type: dnsfast.TypeA},
			resolver.Job{Name: r, Type: dnsfast.TypeAAAA},
		)
	}
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range res.ResolveJobs(ctx, jobs) {
		if a.Outcome != resolver.Resolved {
			continue
		}
		for _, rr := range a.Records {
			if rr.Type != "A" && rr.Type != "AAAA" {
				continue
			}
			addr, err := netip.ParseAddr(rr.Value)
			if err != nil || seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, addr)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// originsOf asks Cymru which AS announces each address, and keeps the prefix
// it named as a fallback for when RIPEstat cannot be reached.
func originsOf(ctx context.Context, res *resolver.Resolver, addrs []netip.Addr, log *logx.Logger) ([]uint32, map[uint32][]netip.Prefix) {
	var jobs []resolver.Job
	for _, a := range addrs {
		if q := asn.OriginQuery(a); q != "" {
			jobs = append(jobs, resolver.Job{Name: q, Type: dnsfast.TypeTXT})
		}
	}
	seen := map[uint32]bool{}
	var order []uint32
	byAS := map[uint32][]netip.Prefix{}
	for _, ans := range res.ResolveJobs(ctx, jobs) {
		if ans.Outcome != resolver.Resolved {
			continue
		}
		for _, rr := range ans.Records {
			if rr.Type != "TXT" {
				continue
			}
			o, err := asn.ParseOrigin(rr.Value)
			if err != nil {
				log.Logf("verbose", "-asn: unreadable origin answer: %v", err)
				continue
			}
			for _, n := range o.ASNs {
				if !seen[n] {
					seen[n] = true
					order = append(order, n)
				}
				if o.Prefix.IsValid() && !hasPrefix(byAS[n], o.Prefix) {
					byAS[n] = append(byAS[n], o.Prefix)
				}
			}
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	return order, byAS
}

func hasPrefix(list []netip.Prefix, p netip.Prefix) bool {
	for _, e := range list {
		if e == p {
			return true
		}
	}
	return false
}

// asNames reads each AS's name from Cymru.
func asNames(ctx context.Context, res *resolver.Resolver, asns []uint32) map[uint32]string {
	var jobs []resolver.Job
	for _, n := range asns {
		jobs = append(jobs, resolver.Job{Name: asn.ASQuery(n), Type: dnsfast.TypeTXT})
	}
	out := map[uint32]string{}
	for _, ans := range res.ResolveJobs(ctx, jobs) {
		if ans.Outcome != resolver.Resolved {
			continue
		}
		for _, rr := range ans.Records {
			if rr.Type != "TXT" {
				continue
			}
			if info, err := asn.ParseAS(rr.Value); err == nil && info.Name != "" {
				out[info.Number] = info.Name
			}
		}
	}
	return out
}

func asLabel(n uint32, name string) string {
	if name == "" {
		return fmt.Sprintf("AS%d", n)
	}
	return fmt.Sprintf("AS%d %s", n, name)
}

// sweepPTR sends the planned reverse lookups and returns each PTR name as
// ASN evidence.
func sweepPTR(ctx context.Context, res *resolver.Resolver, addrs []netip.Addr, label string) []seenName {
	var jobs []resolver.Job
	for _, a := range addrs {
		if n := reverseName(a); n != "" {
			jobs = append(jobs, resolver.Job{Name: n, Type: dnsfast.TypePTR})
		}
	}
	var out []seenName
	for _, ans := range res.ResolveJobs(ctx, jobs) {
		if ans.Outcome != resolver.Resolved {
			continue
		}
		for _, rr := range ans.Records {
			if rr.Type != "PTR" {
				continue
			}
			host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(rr.Value)), ".")
			if host == "" {
				continue
			}
			out = append(out, seenName{host: host, source: "asn", kind: viaASN, detail: label})
		}
	}
	return out
}
