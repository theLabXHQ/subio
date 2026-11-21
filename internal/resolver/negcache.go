package resolver

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/theLabXHQ/subio/internal/dnsfast"
)

// negCacheChecks is how many inferences a zone has to confirm on the wire
// before its answers are inferred rather than asked.
const negCacheChecks = 2

// negCacheSample is how often a trusted zone is still checked: one inferable
// query in this many is sent anyway.
const negCacheSample = 16

// negCacheMaxTTL bounds how long one negative answer is believed, whatever
// the SOA says: a run is not a resolver, and a zone can change under a long
// run.
const negCacheMaxTTL = time.Hour

type negEntry struct {
	zone     string
	until    time.Time
	resolver string
}

type negZone struct {
	confirmed int
	inferred  int
	broken    bool
}

type negCache struct {
	mu    sync.Mutex
	names map[string]negEntry
	zones map[string]*negZone
	now   func() time.Time

	inferred    atomic.Int64
	checks      atomic.Int64
	contradicts atomic.Int64
}

func newNegCache() *negCache {
	return &negCache{names: map[string]negEntry{}, zones: map[string]*negZone{}, now: time.Now}
}

// negDecision is what the cache says about one query before it is sent.
type negDecision int

const (
	negAsk negDecision = iota
	negCheck
	negInfer
)

// decide looks the name and each of its ancestors up.
func (c *negCache) decide(name string) (negDecision, string, negEntry) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.names) == 0 {
		return negAsk, "", negEntry{}
	}
	for cur := n; cur != ""; {
		if e, ok := c.names[cur]; ok && now.Before(e.until) {
			z := c.zones[e.zone]
			switch {
			case z == nil || z.broken:
				return negAsk, "", negEntry{}
			case z.confirmed >= negCacheChecks:
				z.inferred++
				if z.inferred%negCacheSample == 0 {
					return negCheck, cur, e
				}
				return negInfer, cur, e
			default:
				return negCheck, cur, e
			}
		}
		i := strings.IndexByte(cur, '.')
		if i < 0 {
			break
		}
		cur = cur[i+1:]
	}
	return negAsk, "", negEntry{}
}

// learn records an NXDOMAIN response.
func (c *negCache) learn(msg []byte, qname, resolver string) {
	h, err := dnsfast.ParseHeader(msg)
	if err != nil || h.RCode != dnsfast.RCodeNXDomain || h.ANCount != 0 || h.NSCount == 0 {
		return
	}
	n := strings.ToLower(strings.TrimSuffix(qname, "."))
	var zone string
	var ttl uint32
	_, _ = dnsfast.ForEachAuthority(msg, func(rr dnsfast.RR) error {
		if rr.Type != dnsfast.TypeSOA || zone != "" {
			return nil
		}
		owner, err := rr.NameString(msg)
		if err != nil {
			return nil
		}
		owner = strings.ToLower(strings.TrimSuffix(owner, "."))

		if owner != "" && owner != n && !strings.HasSuffix(n, "."+owner) {
			return nil
		}
		soa, err := rr.SOA(msg)
		if err != nil {
			return nil
		}
		zone, ttl = owner, min(rr.TTL, soa.MinTTL)
		if zone == "" {
			zone = "."
		}
		return nil
	})
	if zone == "" || ttl == 0 || zone == n {

		return
	}
	d := min(time.Duration(ttl)*time.Second, negCacheMaxTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.names[n] = negEntry{zone: zone, until: c.now().Add(d), resolver: resolver}
	if c.zones[zone] == nil {
		c.zones[zone] = &negZone{}
	}
}

// verdict records how a check query came back.
func (c *negCache) verdict(zone string, a Answer) {
	if a.Outcome != NXDomain && a.Outcome != Resolved && a.Outcome != NoData {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	z := c.zones[zone]
	if z == nil {
		return
	}
	if a.Outcome == NXDomain {
		z.confirmed++
		return
	}
	if !z.broken {
		z.broken = true
		c.contradicts.Add(1)
	}
}

// NegativeCacheStats says what the negative cache saved and what it refused
// to trust.
type NegativeCacheStats struct {
	// Inferred is how many queries were answered NXDOMAIN without being sent,
	// because the name or one of its ancestors had just been answered so.
	Inferred int64 `json:"inferred"`
	// Checks is how many inferable queries were sent anyway, to see whether the
	// zone keeps the rule.
	Checks int64 `json:"checks"`
	// Contradicted is how many zones answered a check with a name that exists
	// beneath an NXDOMAIN, and so were never inferred from again.
	Contradicted int64 `json:"contradicted_zones"`
}

// NegativeCacheStats reports the cache's effect on this run.
func (r *Resolver) NegativeCacheStats() NegativeCacheStats {
	if r.neg == nil {
		return NegativeCacheStats{}
	}
	return NegativeCacheStats{
		Inferred: r.neg.inferred.Load(), Checks: r.neg.checks.Load(), Contradicted: r.neg.contradicts.Load(),
	}
}
