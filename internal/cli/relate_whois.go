package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/rdap"
)

// whoisOptions bounds the registrant signal.
type whoisOptions struct {
	// MaxLookups caps how many candidate apexes are looked up, strongest
	// evidence first.
	MaxLookups int
	// BootstrapURL overrides IANA's RDAP bootstrap, for tests.
	BootstrapURL string

	// FollowReferral allows one hop to the registrar's RDAP server.
	FollowReferral bool
	// Search runs the nameserver search as well as the confirmations.
	Search bool
}

// whoisRelated looks the target's registrant up, optionally asks the
// registry which other domains use the target's own nameservers, and
// confirms candidate apexes against the target's registrant.
func whoisRelated(ctx context.Context, cl *rdap.Client, roots []string, targetApexes map[string]bool,
	candidates []relatedRoot, opt whoisOptions, log *logx.Logger) []seenName {

	keys, nsByBase, ok := targetIdentity(ctx, cl, roots, log)
	var out []seenName

	if opt.Search {
		out = append(out, nameserverSearch(ctx, cl, nsByBase, targetApexes, log)...)
	}

	if !ok {
		log.Logf("warn", "-whois: no root published a usable registrant, so there is nothing to compare a candidate against. "+
			"Post-GDPR gTLD registries redact it by default; this is a missing signal, not an absence of relatives.")
		return out
	}

	n, matched, redacted, failed := 0, 0, 0, 0
	for _, c := range candidates {
		if n >= opt.MaxLookups {
			log.Logf("warn", "-whois: stopped after %d candidate lookups (-whois-max); apexes ranked below that were not checked", opt.MaxLookups)
			break
		}
		n++
		d, err := cl.Lookup(ctx, c.Apex)
		if err != nil {
			if errors.Is(err, rdap.ErrNoServer) {
				log.Logf("verbose", "-whois: %s: its TLD has no RDAP server", c.Apex)
			} else {
				log.Logf("verbose", "-whois: %s: %v", c.Apex, err)
			}
			failed++
			continue
		}
		candidateKeys, usable := d.Registrant.MatchKeys()
		if !usable {
			redacted++
			continue
		}

		for _, k := range candidateKeys {
			who, hit := keys[k]
			if !hit {
				continue
			}
			matched++
			out = append(out, seenName{
				host: c.Apex, source: "rdap", kind: viaRegistrant,
				detail: "registrant " + who,
			})
			break
		}
	}
	log.Logf("info", "-whois: %d candidate(s) looked up, %d registrant match(es), %d withheld their registrant, %d could not be read",
		n, matched, redacted, failed)
	return out
}

// targetIdentity looks up every root and returns the registrant keys to
// compare against, the target's own nameservers grouped by the RDAP server
// that would answer a search, and whether any usable registrant was found at all.
func targetIdentity(ctx context.Context, cl *rdap.Client, roots []string, log *logx.Logger) (map[string]string, map[string][]string, bool) {
	keys := map[string]string{}
	nsByBase := map[string][]string{}
	for _, r := range roots {
		d, err := cl.Lookup(ctx, r)
		if err != nil {
			log.Logf("warn", "-whois: %s could not be looked up: %v", r, err)
			continue
		}
		base := d.Server
		nsByBase[base] = append(nsByBase[base], d.Nameservers...)
		rootKeys, usable := d.Registrant.MatchKeys()
		if !usable {
			what := "it was withheld"
			if d.Registrant.PrivacyService != "" {
				what = "a privacy service stands in its place"
			}
			log.Logf("warn", "-whois: %s publishes no comparable registrant: %s", r, what)
			continue
		}
		who := describeIdentity(d.Registrant)
		for _, k := range rootKeys {
			keys[k] = who
		}
		via := ""
		if d.Referred {
			via = " (via its registrar's RDAP server)"
		}
		log.Logf("info", "-whois: %s registrant: %s%s", r, who, via)
	}
	return keys, nsByBase, len(keys) > 0
}

func describeIdentity(id rdap.Identity) string {
	parts := []string{}
	if id.Org != "" {
		parts = append(parts, id.Org)
	} else if id.Name != "" {
		parts = append(parts, id.Name)
	} else if id.Email != "" {
		parts = append(parts, id.Email)
	}
	if id.Country != "" {
		parts = append(parts, id.Country)
	}
	if len(parts) == 0 {
		return "(unnamed)"
	}
	return strings.Join(parts, ", ")
}

// nameserverSearch asks each registry that answered for a root which other
// domains are delegated to that root's nameservers.
func nameserverSearch(ctx context.Context, cl *rdap.Client, nsByBase map[string][]string,
	targetApexes map[string]bool, log *logx.Logger) []seenName {

	bases := make([]string, 0, len(nsByBase))
	for b := range nsByBase {
		bases = append(bases, b)
	}
	sort.Strings(bases)

	var out []seenName
	asked, thirdParty := 0, 0
	for _, base := range bases {
		seenNS := map[string]bool{}
		for _, ns := range nsByBase[base] {
			if seenNS[ns] {
				continue
			}
			seenNS[ns] = true
			if !targetApexes[apexOf(ns)] {
				thirdParty++
				continue
			}
			asked++
			names, err := cl.SearchByNameserver(ctx, base, ns)
			if err != nil {
				if errors.Is(err, rdap.ErrUnsupported) {
					log.Logf("info", "-whois: %s does not implement RDAP domain search, so no sibling can be read from it; this is unsupported, not empty", base)
				} else {
					log.Logf("warn", "-whois: search on %s failed: %v", base, err)
				}

				break
			}
			for _, n := range names {
				out = append(out, seenName{
					host: n, source: "rdap", kind: viaNameserverSearch,
					detail: fmt.Sprintf("delegated to %s, per %s", ns, shortHost(base)),
				})
			}
			log.Logf("info", "-whois: %s returned %d domain(s) delegated to %s", shortHost(base), len(names), ns)
		}
	}
	if thirdParty > 0 && asked == 0 {
		log.Logf("warn", "-whois: every nameserver the roots use belongs to a third party, so the registry search was skipped: "+
			"its answer would be that provider's other customers, not the target's domains")
	}
	return out
}

func shortHost(raw string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
	if i := strings.Index(s, "/"); i > 0 {
		s = s[:i]
	}
	return s
}
