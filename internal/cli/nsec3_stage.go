package cli

import (
	"context"

	"github.com/theLabXHQ/subio/internal/gen"
	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/source"
)

const sourceNSEC3 = "nsec3"

// nsec3Walk maps a root's NSEC3 chain, if it has one, and remembers it so
// the generators can settle their guesses against it offline.
func (d *dnsStage) nsec3Walk(ctx context.Context, root string) *resolver.NSEC3Chain {
	chain, err := d.res.WalkNSEC3(ctx, root, 0)
	if chain != nil {
		d.nsec3st.walkQueries += chain.Queries
	}
	if err != nil {
		d.log.Logf("verbose", "nsec3 walk of %s stopped: %v", root, err)
	}
	if chain == nil || !chain.Supported {
		if chain != nil && !chain.Supported {
			d.nsec3st.unsupported++
			d.log.Logf("verbose", "nsec3: %s uses a hash algorithm subio cannot reproduce; not matching offline", root)
		}
		return nil
	}
	if !chain.Mapped() {
		return nil
	}
	d.nsec3[root] = chain
	d.nsec3st.zones++
	d.nsec3st.hashedOwners += chain.HashedOwners()
	d.log.Logf("verbose", "nsec3: %s mapped, %d hashed owners from %d queries",
		root, chain.HashedOwners(), chain.Queries)
	return chain
}

// nsec3Surface reverses the chain with a candidate list: it hashes the
// built-in words and the labels of known names, keeps the ones whose hash is
// a zone name, and queries only those to confirm them and read their
// records.
func (d *dnsStage) nsec3Surface(ctx context.Context, root string, chain *resolver.NSEC3Chain) {
	labels := d.nsec3Candidates(root)
	var present []string
	seen := map[string]bool{}
	for _, label := range labels {
		name := label + "." + root
		if len(name) > 253 {
			continue
		}
		host, _, err := d.o.Roots.Admit(name)
		if err != nil || seen[host] || d.led.Has(root, host) {
			continue
		}
		st, err := chain.Match(host)
		if err != nil {
			continue
		}
		if st == resolver.NSEC3Present {
			seen[host] = true
			present = append(present, host)
		}
	}
	d.nsec3st.present += len(present)
	if len(present) == 0 {
		return
	}

	res := &generatorResult{}
	d.nsec3st.confirmed += len(d.accept(ctx, sourceNSEC3, "nsec3-hash-match", res, d.resolveFor(ctx, present)))
	d.nsec3st.errors += res.errors
}

// resolveFor queries a set of known names and returns the answers that
// resolved, so accept can turn them into findings with their records.
func (d *dnsStage) resolveFor(ctx context.Context, names []string) []resolver.Answer {
	jobs := make(chan resolver.Job, 1024)
	answers := make(chan resolver.Answer, 1024)
	go func() {
		defer close(jobs)
		for _, n := range names {
			for _, t := range d.o.Types {
				select {
				case jobs <- resolver.Job{Name: n, Type: t}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go d.res.Stream(ctx, jobs, answers)

	var hits []resolver.Answer
	for a := range answers {
		if a.Outcome == resolver.Resolved {
			hits = append(hits, a)
		}
	}
	return hits
}

// nsec3Candidates is the word list the surface step reverses the chain with:
// the operator's lists if any, the built-in list, and the labels of names
// already known - under this root first, then under every other root in the
// run.
func (d *dnsStage) nsec3Candidates(root string) []string {
	lists := d.o.Wordlists
	if len(lists) == 0 {
		lists = []*gen.Wordlist{gen.Builtin()}
	}
	labels := gen.Merge(lists...)
	known := &gen.Wordlist{Labels: gen.Labels(d.knownNames(root), root)}

	// Labels from the other roots, deduplicated by Merge.
	var elsewhere []string
	for _, other := range d.o.RootList {
		if other == root {
			continue
		}
		elsewhere = append(elsewhere, gen.Labels(d.knownNames(other), other)...)
	}
	return gen.Merge(known, &gen.Wordlist{Labels: elsewhere}, &gen.Wordlist{Labels: labels})
}

// addNSEC3Run records what offline NSEC3 discovery did, as one source row,
// so the report shows the zone's name count, how many names were surfaced,
// and how many guesses the chain settled without a query.
func (d *dnsStage) addNSEC3Run() {
	s := d.nsec3st
	if s.zones == 0 && s.unsupported == 0 {
		return
	}
	status := source.StatusComplete
	switch {
	case s.errors > 0:
		status = source.StatusPartial
	case s.confirmed == 0:
		status = source.StatusEmpty
	}
	d.led.AddSourceRun(ledger.SourceRun{
		SourceID: sourceNSEC3, Family: string(source.FamilyActiveDNS), Status: string(status),
		TermsState: termsNotApplicable, Requests: s.walkQueries + s.present,
		RawObservation: s.confirmed, InScope: s.confirmed, UniqueNames: s.confirmed,
		MarginalNames: s.confirmed, QuotaRemaining: -1, DNSErrors: s.errors,
	})
	if s.hashedOwners > 0 {
		d.log.Logf("info", "nsec3: %d zone(s), %d hashed owners, %d name(s) surfaced, %d guess(es) proven absent offline",
			s.zones, s.hashedOwners, s.confirmed, s.pruned)
	}
}
