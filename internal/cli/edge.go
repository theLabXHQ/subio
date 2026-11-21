package cli

import (
	"context"
	"net/netip"
	"time"

	"github.com/theLabXHQ/subio/internal/cdn"
	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/output"
	"github.com/theLabXHQ/subio/internal/resolver"
)

// edgeIndex is the origin AS of every address a run resolved, read once
// after the DNS stage so each record can say what is in front of it.
type edgeIndex map[netip.Addr][]uint32

// buildEdgeIndex asks Cymru about every distinct address in the ledger's DNS
// observations.
func buildEdgeIndex(ctx context.Context, servers []netip.AddrPort, led *ledger.Ledger, log *logx.Logger) edgeIndex {
	seen := map[netip.Addr]bool{}
	var addrs []netip.Addr
	_ = led.EachFinding(func(f ledger.Finding) error {
		for _, o := range led.DNSFor(f.RootDomain, f.FQDN) {
			for _, r := range o.Records {
				if r.Type != "A" && r.Type != "AAAA" {
					continue
				}
				if a, err := netip.ParseAddr(r.Value); err == nil && !seen[a] {
					seen[a] = true
					addrs = append(addrs, a)
				}
			}
		}
		return nil
	})
	ix := edgeIndex{}
	if len(addrs) == 0 {
		return ix
	}
	res, err := resolver.New(resolver.Config{
		Servers: servers, Workers: 4, Window: 128,
		Timeout: 3 * time.Second, Retries: 1,
	})
	if err != nil {
		log.Logf("warn", "-cdn: %v; edges are marked from CNAME chains only", err)
		return ix
	}
	log.Logf("info", "-cdn: asking Team Cymru for the origin AS of %d address(es)", len(addrs))
	origin, failed := originByAddr(ctx, res, addrs, log)
	for a, asns := range origin {
		ix[a] = asns
	}
	if len(failed) > 0 {
		log.Logf("warn", "-cdn: no origin answer for %d of %d address(es); a name on one of those is unmarked, which is not the same as being an origin", len(failed), len(addrs))
	}
	return ix
}

// edgeFor picks what is in front of one name: its CNAME chain first, then
// the AS routing each of its addresses.
func (ix edgeIndex) edgeFor(cnames []string, records []output.RR) *cdn.Edge {
	var edges []cdn.Edge
	for _, c := range cnames {
		if e, ok := cdn.ByCNAME(c); ok {
			edges = append(edges, e)
		}
	}
	for _, r := range records {
		if r.Type == "CNAME" {
			if e, ok := cdn.ByCNAME(r.Value); ok {
				edges = append(edges, e)
			}
			continue
		}
		if ix == nil || (r.Type != "A" && r.Type != "AAAA") {
			continue
		}
		a, err := netip.ParseAddr(r.Value)
		if err != nil {
			continue
		}
		for _, n := range ix[a] {
			if e, ok := cdn.ByASN(n); ok {
				edges = append(edges, e)
			}
		}
	}
	e, ok := cdn.Best(edges)
	if !ok {
		return nil
	}
	return &e
}
