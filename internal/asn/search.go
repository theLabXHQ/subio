package asn

import (
	"context"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// DefaultSearchURL is RIPEstat's search-completion endpoint, which matches a
// string against the registries' AS holder names.
const DefaultSearchURL = "https://stat.ripe.net/data/searchcomplete/data.json"

type searchDoc struct {
	Data struct {
		Categories []struct {
			Category    string `json:"category"`
			Suggestions []struct {
				Value       string `json:"value"`
				Description string `json:"description"`
			} `json:"suggestions"`
		} `json:"categories"`
	} `json:"data"`
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
}

// Search finds autonomous systems whose registry holder name matches query.
func Search(ctx context.Context, http Doer, baseURL, query string) ([]Info, error) {
	if baseURL == "" {
		baseURL = DefaultSearchURL
	}
	q := strings.TrimSpace(query)
	if q == "" {
		return nil, fmt.Errorf("asn: empty search")
	}
	var doc searchDoc
	if _, _, err := http.GetJSON(ctx, SourceID, baseURL+"?resource="+url.QueryEscape(q), nil, &doc); err != nil {
		return nil, fmt.Errorf("asn: search for %q: %w", q, err)
	}
	if doc.Status != "" && doc.Status != "ok" {
		return nil, fmt.Errorf("asn: RIPEstat answered %q for search %q: %s", doc.Status, q, clip(doc.StatusMessage))
	}
	seen := map[uint32]bool{}
	var out []Info
	for _, c := range doc.Data.Categories {
		if c.Category != "ASNs" {
			continue
		}
		for _, s := range c.Suggestions {
			n, ok := ParseASN(s.Value)
			if !ok || seen[n] {
				continue
			}
			seen[n] = true
			out = append(out, Info{Number: n, Name: clip(s.Description)})
		}
	}
	return out, nil
}

// ParseASN reads "AS13335", "as13335" or "13335".
func ParseASN(s string) (uint32, bool) {
	t := strings.TrimSpace(s)
	if len(t) > 2 && (t[:2] == "AS" || t[:2] == "as" || t[:2] == "As" || t[:2] == "aS") {
		t = t[2:]
	}
	if t == "" || t[0] == '+' || t[0] == '-' {
		return 0, false
	}
	n, err := strconv.ParseUint(t, 10, 32)
	if err != nil || n == 0 || n == 1<<32-1 {
		return 0, false
	}
	return uint32(n), true
}

// Aggregate is the smallest prefix list covering exactly the same addresses:
// contained prefixes are dropped and adjacent siblings merged into their
// parent, repeatedly, so 10.0.0.0/25 and 10.0.0.128/25 become 10.0.0.0/24.
func Aggregate(prefixes []netip.Prefix) []netip.Prefix {
	cur := normalize(prefixes)
	for {
		merged := false
		next := make([]netip.Prefix, 0, len(cur))
		for i := 0; i < len(cur); i++ {
			p := cur[i]
			if i+1 < len(cur) && p.Bits() > 0 && p.Bits() == cur[i+1].Bits() {
				parent, err := p.Addr().Prefix(p.Bits() - 1)
				if err == nil && parent.Addr() == p.Addr() && parent.Contains(cur[i+1].Addr()) {
					next = append(next, parent)
					i++
					merged = true
					continue
				}
			}
			next = append(next, p)
		}
		cur = normalize(next)
		if !merged {
			return cur
		}
	}
}

// Size is how many addresses a prefix holds, for either family.
func Size(p netip.Prefix) *big.Int {
	total := 32
	if p.Addr().Is6() {
		total = 128
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(total-p.Bits()))
}

// Expand yields every address in the prefixes, in order, until yield returns
// false or limit addresses have been yielded.
func Expand(prefixes []netip.Prefix, limit uint64, yield func(netip.Addr) bool) bool {
	var n uint64
	for _, p := range normalize(prefixes) {
		a := p.Addr()
		for p.Contains(a) {
			if limit > 0 && n >= limit {
				return false
			}
			if !yield(a) {
				return false
			}
			n++
			nx := a.Next()
			if !nx.IsValid() {
				break
			}
			a = nx
		}
	}
	return true
}

// SortPrefixes orders prefixes by address, then by length.
func SortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Addr() != ps[j].Addr() {
			return ps[i].Addr().Less(ps[j].Addr())
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}
