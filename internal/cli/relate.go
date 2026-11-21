package cli

import (
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/theLabXHQ/subio/internal/source"
)

// Evidence kinds, and the tier each one carries.
const (
	// viaRegistrant: the registry says the same registrant registered both
	// domains.
	viaRegistrant = "registrant"

	// viaCertificate: one certificate covers the target and this apex.
	viaCertificate = "shared-certificate"

	// viaNameserverSearch: the registry's own domain search returned this apex
	// for a nameserver the target uses.
	viaNameserverSearch = "nameserver-search"

	// viaASN: a reverse-DNS name in the target's autonomous system.
	viaASN = "asn-neighbour"
)

// evidenceTier ranks a kind.
func evidenceTier(kind string) int {
	switch kind {
	case viaRegistrant:
		return 3
	case viaCertificate:
		return 2
	case viaNameserverSearch:
		return 1
	default:
		return 0
	}
}

// confidenceOf names a tier for output.
func confidenceOf(tier int) string {
	switch tier {
	case 3:
		return "owner"
	case 2:
		return "strong"
	case 1:
		return "medium"
	default:
		return "weak"
	}
}

// relatedRoot is one suggested root and the evidence for it.
type relatedRoot struct {
	Apex string `json:"apex"`
	// Certs is how many distinct certificates listed this apex alongside the
	// target.
	Certs int `json:"shared_certificates"`
	// Names is how many distinct hostnames under the apex were seen.
	Names int `json:"names_seen"`
	// Via lists the kinds of evidence, sorted.
	Via []string `json:"via"`
	// Confidence names the strongest tier of evidence present: owner, strong,
	// medium or weak.
	Confidence string `json:"confidence"`
	// Detail is the strongest evidence in words — the matched registrant, the
	// AS, the nameserver — so the operator can judge it without a second query.
	Detail string `json:"detail,omitempty"`
	// Example is one hostname under the apex, so the operator can recognise it.
	Example string `json:"example"`
	// Sources are the sources (a CT adapter, "dns", "rdap", "asn") that saw it.
	Sources []string `json:"sources"`

	// tier is the numeric form of Confidence, kept for ranking and filtering.
	tier int
}

// apexOf returns the registrable domain (eTLD+1) of a hostname, or "" when
// it has none.
func apexOf(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if !plausibleHostname(host) {
		return ""
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return apex
}

// plausibleHostname rejects a value that cannot be a DNS name at all.
func plausibleHostname(host string) bool {
	if host == "" || len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			case r >= 0x80:
			default:
				return false
			}
		}
	}
	return true
}

// seenName is one observation relate works from: a hostname, the certificate
// it came from, the source that reported it, the kind of evidence it is, and
// a short human detail for the kinds where the evidence is a fact rather
// than a count.
type seenName struct {
	host     string
	recordID string
	source   string
	// kind is one of the via* constants, or a DNS record type ("mx", "ns",
	// "soa", "txt") for a name a record pointed at.
	kind string
	// detail is evidence in words: the matched registrant, "AS15169 GOOGLE", the
	// nameserver that returned the apex.
	detail string
}

// tallyRelated groups observations by the foreign registrable apex they
// belong to — any apex other than the target's own — and ranks them by
// what the evidence establishes, then by how much of it there is.
func tallyRelated(targetApexes map[string]bool, seen []seenName) []relatedRoot {
	type acc struct {
		certs      map[string]bool
		names      map[string]bool
		sources    map[string]bool
		via        map[string]bool
		example    string
		tier       int
		bestDetail string
	}
	by := map[string]*acc{}
	for _, s := range seen {
		apex := apexOf(s.host)
		if apex == "" || targetApexes[apex] {
			continue
		}
		if isInfrastructureApex(apex) {
			continue
		}
		a := by[apex]
		if a == nil {
			a = &acc{certs: map[string]bool{}, names: map[string]bool{}, sources: map[string]bool{}, via: map[string]bool{}, example: s.host, tier: -1}
			by[apex] = a
		}
		kind := s.kind
		if kind == "" {
			kind = viaCertificate
		}
		if kind == viaCertificate && s.recordID != "" {
			a.certs[s.recordID] = true
		}
		a.names[s.host] = true
		if s.source != "" {
			a.sources[s.source] = true
		}
		a.via[kind] = true

		if t := evidenceTier(kind); t > a.tier {
			a.tier = t
			a.bestDetail = s.detail
		} else if t == a.tier && a.bestDetail == "" {
			a.bestDetail = s.detail
		}
	}

	out := make([]relatedRoot, 0, len(by))
	for apex, a := range by {
		tier := a.tier
		if tier < 0 {
			tier = 0
		}
		out = append(out, relatedRoot{
			Apex: apex, Certs: len(a.certs), Names: len(a.names),
			Via: sortedKeysOf(a.via), Confidence: confidenceOf(tier), Detail: a.bestDetail,
			Example: a.example, Sources: sortedKeysOf(a.sources), tier: tier,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].tier != out[j].tier {
			return out[i].tier > out[j].tier
		}
		if out[i].Certs != out[j].Certs {
			return out[i].Certs > out[j].Certs
		}
		if out[i].Names != out[j].Names {
			return out[i].Names > out[j].Names
		}
		return out[i].Apex < out[j].Apex
	})
	return out
}

// collectObservations runs a provider and returns every hostname it
// observed, with no scope filtering: relate needs the names that fall
// outside the root, which the engine would drop.
func collectObservations(obs []source.Observation, sourceID string) []seenName {
	out := make([]seenName, 0, len(obs))
	for _, o := range obs {
		host := strings.TrimPrefix(strings.TrimSpace(o.Hostname), "*.")
		if host == "" {
			continue
		}
		out = append(out, seenName{host: host, recordID: o.RecordID, source: sourceID, kind: viaCertificate})
	}
	return out
}

// sortedKeysOf returns the keys of a set, sorted.
func sortedKeysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// isInfrastructureApex rejects an apex nobody can own as a root domain.
func isInfrastructureApex(apex string) bool {
	return apex == "arpa" || strings.HasSuffix(apex, ".arpa")
}

// hasNonCertificateEvidence reports whether any of an apex's evidence is
// something other than a shared certificate.
func hasNonCertificateEvidence(via []string) bool {
	for _, v := range via {
		if v != viaCertificate {
			return true
		}
	}
	return false
}
