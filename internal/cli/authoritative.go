package cli

import (
	"context"
	"net/netip"
	"sort"

	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
)

// authoritativeServers finds the IP addresses of the nameservers for every
// root and returns them as a resolver set.
func authoritativeServers(ctx context.Context, boot *resolver.Resolver, roots []string, log *logx.Logger) []netip.AddrPort {
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	for _, root := range roots {
		var nsNames []string
		for _, a := range boot.ResolveAll(ctx, []string{root}, []dnsfast.Type{dnsfast.TypeNS}) {
			for _, rr := range a.Records {
				if rr.Type == "NS" {
					nsNames = append(nsNames, rr.Value)
				}
			}
		}
		if len(nsNames) == 0 {
			log.Logf("warn", "authoritative: %s publishes no NS record subio could read", root)
			continue
		}
		for _, a := range boot.ResolveAll(ctx, nsNames, []dnsfast.Type{dnsfast.TypeA, dnsfast.TypeAAAA}) {
			for _, rr := range a.Records {
				if rr.Type != "A" && rr.Type != "AAAA" {
					continue
				}
				ip, err := netip.ParseAddr(rr.Value)
				if err != nil {
					continue
				}
				ap := netip.AddrPortFrom(ip, 53)
				if !seen[ap] {
					seen[ap] = true
					out = append(out, ap)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
