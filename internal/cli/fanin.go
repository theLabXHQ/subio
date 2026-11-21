package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/logx"
)

const (

	// fanInMinNames is the smallest group worth a line.
	fanInMinNames = 8
	// fanInTopN bounds the list so a wide result set does not bury the rest of
	// the report under addresses.
	fanInTopN = 5
)

// addressGroup is one address and the names observed on it.
type addressGroup struct {
	addr  string
	names []string
}

// groupByAddress buckets resolved names by the addresses they answered with.
func groupByAddress(led *ledger.Ledger) []addressGroup {
	byAddr := map[string]map[string]struct{}{}
	for _, f := range led.Findings() {

		if f.WildcardSuspected {
			continue
		}
		for _, obs := range led.DNSFor(f.RootDomain, f.FQDN) {
			for _, r := range obs.Records {
				if r.Type != "A" && r.Type != "AAAA" {
					continue
				}
				if byAddr[r.Value] == nil {
					byAddr[r.Value] = map[string]struct{}{}
				}
				byAddr[r.Value][f.FQDN] = struct{}{}
			}
		}
	}
	out := make([]addressGroup, 0, len(byAddr))
	for addr, set := range byAddr {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		out = append(out, addressGroup{addr: addr, names: names})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].names) != len(out[j].names) {
			return len(out[i].names) > len(out[j].names)
		}
		return out[i].addr < out[j].addr
	})
	return out
}

// printFanIn reports the addresses that many names share.
func printFanIn(log *logx.Logger, led *ledger.Ledger) {
	groups := groupByAddress(led)
	if len(groups) == 0 {
		return
	}
	var shown []addressGroup
	for _, g := range groups {
		if len(g.names) < fanInMinNames {
			break
		}
		shown = append(shown, g)
		if len(shown) == fanInTopN {
			break
		}
	}
	if len(shown) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("\nNames per address, where many share one:\n")
	for _, g := range shown {
		sample := g.names
		if len(sample) > 3 {
			sample = sample[:3]
		}
		fmt.Fprintf(&b, "  %-39s %4d names  e.g. %s\n",
			g.addr, len(g.names), strings.Join(sample, ", "))
	}
	b.WriteString("An address many names answer with is usually one load balancer, " +
		"shared host or CDN edge rather than that many machines. The names are real; " +
		"the count of things to look at is smaller than the count of names.\n")
	log.Printf("%s", b.String())
}
