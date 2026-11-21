package cli

import (
	"context"

	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/resolver"
)

// zoneTransfers asks each root's nameservers for the whole zone.
func (d *dnsStage) zoneTransfers(ctx context.Context) {
	var found []string
	for _, root := range d.o.RootList {
		answers := d.res.ResolveAll(ctx, []string{root}, []dnsfast.Type{dnsfast.TypeNS})
		var servers []string
		for _, a := range answers {
			if a.Outcome != resolver.Resolved {
				continue
			}
			for _, r := range a.Records {
				if r.Type == "NS" {
					servers = append(servers, r.Value)
				}
			}
		}
		for _, ns := range servers {
			names, err := d.res.Transfer(ctx, root, ns)
			d.records.queries++
			if err != nil {
				continue
			}
			for _, n := range names {
				a := resolver.Answer{Name: ns, Records: []resolver.Record{{Type: "AXFR", Value: n}}}
				found = append(found, d.harvest(a)...)
			}
		}
	}
	d.followRecords(ctx, found)
}
