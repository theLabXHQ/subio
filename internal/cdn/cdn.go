// Package cdn says whether an address or a name sits behind a CDN, a WAF or
// a cloud provider rather than being the origin itself.
package cdn

import (
	"sort"
	"strings"
)

// Kind is what a provider in front of a host does.
type Kind string

const (
	// KindCDN caches and serves on the origin's behalf from its own edges.
	KindCDN Kind = "cdn"
	// KindWAF filters traffic before passing it to the origin.
	KindWAF Kind = "waf"
	// KindCloud hosts the machine itself: the address is the provider's, but the
	// machine behind it may well be the target's own.
	KindCloud Kind = "cloud"
)

// Edge is one identification and the evidence for it.
type Edge struct {
	Provider string `json:"provider"`
	Kind     Kind   `json:"kind"`
	// Signal is "cname" or "asn", the kind of evidence.
	Signal string `json:"signal"`
	// Evidence is the CNAME target or the AS number that matched.
	Evidence string `json:"evidence"`
}

type provider struct {
	name string
	kind Kind
}

// byASN lists autonomous systems that announce a provider's own address
// space.
var byASN = map[uint32]provider{
	13335: {"cloudflare", KindCDN}, 14789: {"cloudflare", KindCDN}, 209242: {"cloudflare", KindCDN},
	20940: {"akamai", KindCDN}, 16625: {"akamai", KindCDN}, 12222: {"akamai", KindCDN},
	21342: {"akamai", KindCDN}, 33905: {"akamai", KindCDN}, 35994: {"akamai", KindCDN},
	32787: {"akamai-prolexic", KindWAF},
	54113: {"fastly", KindCDN},
	15133: {"edgecast", KindCDN},
	22822: {"limelight", KindCDN},
	20446: {"stackpath", KindCDN}, 12989: {"stackpath", KindCDN}, 33438: {"stackpath", KindCDN},
	60068:  {"cdn77", KindCDN},
	200325: {"bunnycdn", KindCDN},
	19551:  {"imperva", KindWAF},
	30148:  {"sucuri", KindWAF},
	16509:  {"amazon", KindCloud}, 14618: {"amazon", KindCloud}, 8987: {"amazon", KindCloud},
	15169: {"google", KindCloud}, 396982: {"google", KindCloud}, 19527: {"google", KindCloud},
	36040: {"google", KindCloud},
	8075:  {"microsoft", KindCloud}, 8068: {"microsoft", KindCloud}, 8069: {"microsoft", KindCloud},
	31898: {"oracle", KindCloud},
	14061: {"digitalocean", KindCloud},
	63949: {"linode", KindCloud},
	24940: {"hetzner", KindCloud},
	16276: {"ovh", KindCloud},
	45102: {"alibaba", KindCloud}, 37963: {"alibaba", KindCloud},
	132203: {"tencent", KindCloud}, 45090: {"tencent", KindCloud},
}

// bySuffix lists CNAME targets that only a provider's customers alias to.
var bySuffix = map[string]provider{
	"cloudfront.net":       {"amazon-cloudfront", KindCDN},
	"akamaiedge.net":       {"akamai", KindCDN},
	"akamai.net":           {"akamai", KindCDN},
	"akamaized.net":        {"akamai", KindCDN},
	"edgekey.net":          {"akamai", KindCDN},
	"edgesuite.net":        {"akamai", KindCDN},
	"fastly.net":           {"fastly", KindCDN},
	"fastlylb.net":         {"fastly", KindCDN},
	"cdn.cloudflare.net":   {"cloudflare", KindCDN},
	"azureedge.net":        {"azure-cdn", KindCDN},
	"azurefd.net":          {"azure-frontdoor", KindCDN},
	"edgecastcdn.net":      {"edgecast", KindCDN},
	"llnwd.net":            {"limelight", KindCDN},
	"hwcdn.net":            {"stackpath", KindCDN},
	"stackpathdns.com":     {"stackpath", KindCDN},
	"b-cdn.net":            {"bunnycdn", KindCDN},
	"cdn77.org":            {"cdn77", KindCDN},
	"incapdns.net":         {"imperva", KindWAF},
	"sucuridns.com":        {"sucuri", KindWAF},
	"elb.amazonaws.com":    {"amazon-elb", KindCloud},
	"amazonaws.com":        {"amazon", KindCloud},
	"azurewebsites.net":    {"azure-appservice", KindCloud},
	"cloudapp.net":         {"azure", KindCloud},
	"cloudapp.azure.com":   {"azure", KindCloud},
	"trafficmanager.net":   {"azure-trafficmanager", KindCloud},
	"appspot.com":          {"google-appengine", KindCloud},
	"ghs.googlehosted.com": {"google", KindCloud},
	"herokudns.com":        {"heroku", KindCloud},
	"herokuapp.com":        {"heroku", KindCloud},
	"vercel-dns.com":       {"vercel", KindCDN},
	"netlify.app":          {"netlify", KindCDN},
	"github.io":            {"github-pages", KindCloud},
}

// ByCNAME identifies the provider a CNAME target belongs to.
func ByCNAME(target string) (Edge, bool) {
	t := strings.TrimSuffix(strings.ToLower(target), ".")
	best := ""
	for suf := range bySuffix {
		if (t == suf || strings.HasSuffix(t, "."+suf)) && len(suf) > len(best) {
			best = suf
		}
	}
	if best == "" {
		return Edge{}, false
	}
	p := bySuffix[best]
	return Edge{Provider: p.name, Kind: p.kind, Signal: "cname", Evidence: t}, true
}

// ByASN identifies the provider that operates an autonomous system.
func ByASN(n uint32) (Edge, bool) {
	p, ok := byASN[n]
	if !ok {
		return Edge{}, false
	}
	return Edge{Provider: p.name, Kind: p.kind, Signal: "asn", Evidence: asText(n)}, true
}

// Best picks the strongest of several identifications for one host: a CNAME
// over an AS, then a CDN or WAF over a cloud, since the edge is what traffic
// reaches first.
func Best(edges []Edge) (Edge, bool) {
	if len(edges) == 0 {
		return Edge{}, false
	}
	rank := func(e Edge) int {
		r := 0
		if e.Signal == "cname" {
			r += 2
		}
		if e.Kind != KindCloud {
			r++
		}
		return r
	}
	sorted := append([]Edge(nil), edges...)
	sort.SliceStable(sorted, func(i, j int) bool { return rank(sorted[i]) > rank(sorted[j]) })
	return sorted[0], true
}

// Providers lists every provider this package can name, for help text and a
// test that the tables stay consistent.
func Providers() []string {
	seen := map[string]bool{}
	for _, p := range byASN {
		seen[p.name] = true
	}
	for _, p := range bySuffix {
		seen[p.name] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func asText(n uint32) string {
	const digits = "0123456789"
	if n == 0 {
		return "AS0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	return "AS" + string(b[i:])
}
