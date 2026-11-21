// Package asn maps an address to the autonomous system that announces it,
// and an autonomous system to the prefixes it announces.
package asn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/theLabXHQ/subio/internal/source"
)

// SourceID is the scheduler key RIPEstat requests are charged to.
const SourceID = "ripestat"

// DefaultRIPEStatURL is the announced-prefixes endpoint.
const DefaultRIPEStatURL = "https://stat.ripe.net/data/announced-prefixes/data.json"

// CymruZone and CymruZone6 are Team Cymru's origin-lookup zones.
const (
	CymruZone   = "origin.asn.cymru.com"
	CymruZone6  = "origin6.asn.cymru.com"
	CymruASZone = "asn.cymru.com"
)

// Doer is the HTTP surface this package needs; internal/fetch.Client
// satisfies it.
type Doer interface {
	GetJSON(ctx context.Context, sourceID, rawURL string, hdr map[string]string, out any) (*source.HTTPMeta, source.ErrorClass, error)
}

// Origin is one answer from Cymru's origin zone: which AS announces an
// address, and in which prefix.
type Origin struct {

	// ASNs holds every AS in the answer.
	ASNs      []uint32     `json:"asns"`
	Prefix    netip.Prefix `json:"prefix"`
	Country   string       `json:"country,omitempty"`
	Registry  string       `json:"registry,omitempty"`
	Allocated string       `json:"allocated,omitempty"`
}

// Info describes one autonomous system.
type Info struct {
	Number   uint32 `json:"number"`
	Name     string `json:"name,omitempty"`
	Country  string `json:"country,omitempty"`
	Registry string `json:"registry,omitempty"`
}

// ErrNoAnswer means the service returned nothing usable for that query.
var ErrNoAnswer = errors.New("asn: no usable answer")

// OriginQuery is the Cymru DNS name whose TXT record gives an address's
// origin.
func OriginQuery(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case a.Is4():
		b := a.As4()
		return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
			strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + "." + CymruZone
	case a.Is6():
		const hex = "0123456789abcdef"
		b := a.As16()
		var sb strings.Builder
		for i := len(b) - 1; i >= 0; i-- {
			sb.WriteByte(hex[b[i]&0x0f])
			sb.WriteByte('.')
			sb.WriteByte(hex[b[i]>>4])
			sb.WriteByte('.')
		}
		sb.WriteString(CymruZone6)
		return sb.String()
	}
	return ""
}

// ASQuery is the Cymru DNS name whose TXT record names an AS.
func ASQuery(n uint32) string {
	return "AS" + strconv.FormatUint(uint64(n), 10) + "." + CymruASZone
}

// ParseOrigin reads Cymru's origin TXT value, which is pipe separated:
func ParseOrigin(txt string) (Origin, error) {
	f := splitPipe(txt)
	if len(f) < 2 {
		return Origin{}, fmt.Errorf("%w: origin answer %q", ErrNoAnswer, clip(txt))
	}
	var o Origin
	for _, part := range strings.Fields(f[0]) {
		if n, err := strconv.ParseUint(part, 10, 32); err == nil && n != 0 {
			o.ASNs = append(o.ASNs, uint32(n))
		}
	}
	p, err := netip.ParsePrefix(f[1])
	if err != nil {
		return Origin{}, fmt.Errorf("%w: prefix %q", ErrNoAnswer, clip(f[1]))
	}
	o.Prefix = p.Masked()
	if len(f) > 2 {
		o.Country = strings.ToUpper(f[2])
	}
	if len(f) > 3 {
		o.Registry = f[3]
	}
	if len(f) > 4 {
		o.Allocated = f[4]
	}
	if len(o.ASNs) == 0 {
		return Origin{}, fmt.Errorf("%w: no AS number in %q", ErrNoAnswer, clip(txt))
	}
	return o, nil
}

// ParseAS reads Cymru's AS TXT value, where the name is last:
func ParseAS(txt string) (Info, error) {
	f := splitPipe(txt)
	if len(f) < 1 {
		return Info{}, fmt.Errorf("%w: AS answer %q", ErrNoAnswer, clip(txt))
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(f[0]), "AS"), 10, 32)
	if err != nil {
		return Info{}, fmt.Errorf("%w: AS number %q", ErrNoAnswer, clip(f[0]))
	}
	if n == 0 {

		return Info{}, fmt.Errorf("%w: AS0 is reserved", ErrNoAnswer)
	}
	in := Info{Number: uint32(n)}
	if len(f) > 1 {
		in.Country = strings.ToUpper(f[1])
	}
	if len(f) > 2 {
		in.Registry = f[2]
	}
	if len(f) > 4 {
		in.Name = f[4]
	}
	return in, nil
}

func splitPipe(txt string) []string {
	parts := strings.Split(strings.TrimSpace(txt), "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	if len(out) == 1 && out[0] == "" {
		return nil
	}
	return out
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

type ripeDoc struct {
	Data struct {
		Resource string `json:"resource"`
		Prefixes []struct {
			Prefix string `json:"prefix"`
		} `json:"prefixes"`
	} `json:"data"`
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
}

// Prefixes asks RIPEstat which prefixes an AS announces.
func Prefixes(ctx context.Context, http Doer, baseURL string, n uint32) ([]netip.Prefix, error) {
	if baseURL == "" {
		baseURL = DefaultRIPEStatURL
	}
	u := baseURL + "?resource=AS" + strconv.FormatUint(uint64(n), 10)
	var doc ripeDoc
	if _, _, err := http.GetJSON(ctx, SourceID, u, nil, &doc); err != nil {
		return nil, fmt.Errorf("asn: announced prefixes for AS%d: %w", n, err)
	}
	if doc.Status != "" && doc.Status != "ok" {
		return nil, fmt.Errorf("asn: RIPEstat answered %q for AS%d: %s", doc.Status, n, clip(doc.StatusMessage))
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, p := range doc.Data.Prefixes {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(p.Prefix))
		if err != nil {
			continue
		}
		pfx = pfx.Masked()
		if !seen[pfx] {
			seen[pfx] = true
			out = append(out, pfx)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out, nil
}

// normalize masks every prefix, drops duplicates, and drops any prefix that
// another one already contains.
func normalize(prefixes []netip.Prefix) []netip.Prefix {
	seen := map[netip.Prefix]bool{}
	masked := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		m := p.Masked()
		if !seen[m] {
			seen[m] = true
			masked = append(masked, m)
		}
	}

	sort.Slice(masked, func(i, j int) bool {
		if masked[i].Bits() != masked[j].Bits() {
			return masked[i].Bits() < masked[j].Bits()
		}
		return masked[i].Addr().Less(masked[j].Addr())
	})
	out := make([]netip.Prefix, 0, len(masked))
	for _, p := range masked {
		covered := false
		for _, kept := range out {
			if kept.Addr().Is4() == p.Addr().Is4() && kept.Bits() <= p.Bits() && kept.Contains(p.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

// AddressCount is how many distinct IPv4 addresses a prefix list covers.
func AddressCount(prefixes []netip.Prefix) uint64 {
	var total uint64
	for _, p := range normalize(prefixes) {
		if !p.Addr().Is4() || p.Bits() < 0 || p.Bits() > 32 {
			continue
		}
		total += uint64(1) << uint(32-p.Bits())
	}
	return total
}

// SharedInfrastructure reports whether an AS is too large for its neighbours
// to mean common ownership, given the operator's ceiling in addresses.
func SharedInfrastructure(prefixes []netip.Prefix, maxAddresses uint64) bool {
	return AddressCount(prefixes) > maxAddresses
}

// Sweep plans the reverse-DNS sweep: up to budget addresses, taken round
// robin across the prefixes so every prefix contributes rather than the
// first one consuming the whole budget.
func Sweep(prefixes []netip.Prefix, budget int) (addrs []netip.Addr, skipped uint64) {
	if budget <= 0 {
		return nil, AddressCount(prefixes)
	}
	// normalize below also decides what "every address" means here, so the
	// skipped count and the plan agree about the same set.
	type cursor struct {
		next netip.Addr
		left uint64
	}
	var cs []*cursor
	for _, p := range normalize(prefixes) {
		if !p.Addr().Is4() || p.Bits() < 0 || p.Bits() > 32 {
			skipped += AddressCount([]netip.Prefix{p})
			continue
		}
		cs = append(cs, &cursor{next: p.Addr(), left: uint64(1) << uint(32-p.Bits())})
	}
	for len(addrs) < budget {
		progressed := false
		for _, c := range cs {
			if c.left == 0 {
				continue
			}
			if len(addrs) >= budget {
				break
			}
			addrs = append(addrs, c.next)
			c.next = c.next.Next()
			c.left--
			progressed = true
		}
		if !progressed {
			break
		}
	}
	for _, c := range cs {
		skipped += c.left
	}
	return addrs, skipped
}
