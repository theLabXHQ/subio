package resolver

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/dnsfast"
)

// NSEC3Status is the offline verdict for one candidate name against a mapped
// NSEC3 chain.
type NSEC3Status uint8

const (

	// NSEC3Unknown means the chain does not cover this name's hash, so a live
	// query is still needed.
	NSEC3Unknown NSEC3Status = iota

	// NSEC3Present means the name's hash equals a hash that exists in the zone,
	// so the name exists.
	NSEC3Present
	// NSEC3Absent means the name's hash falls strictly inside a proven gap, so
	// the name does not exist and no query need be sent for it.
	NSEC3Absent
)

// nsec3gap is one proven interval of the hash ring: no name hashes strictly
// between start and end.
type nsec3gap struct {
	start  []byte
	end    []byte
	optOut bool
}

// covers reports whether h lies strictly inside the gap.
func (g nsec3gap) covers(h []byte) bool {
	if bytes.Compare(g.start, g.end) < 0 {
		return bytes.Compare(g.start, h) < 0 && bytes.Compare(h, g.end) < 0
	}

	return bytes.Compare(g.start, h) < 0 || bytes.Compare(h, g.end) < 0
}

// NSEC3Chain is a zone's NSEC3 denial structure, mapped from the records a
// walk collected.
type NSEC3Chain struct {
	Salt       []byte
	Iterations uint16

	// HashAlg is the hash algorithm the zone's records declare.
	HashAlg uint8
	// Supported is false when the zone uses a hash algorithm subio cannot
	// reproduce, so nothing can be matched offline and every guess must query.
	Supported bool
	// Queries is how many packets the walk sent to map this chain, so the cost
	// of mapping can be weighed against the guesses it later saves.
	Queries int

	// owners holds the hex of every owner and next-owner hash seen: each one is
	// the hash of a name that exists in the zone.
	owners map[string]struct{}
	// gaps is keyed by hex(start) while collecting, then sorted for matching.
	gapByStart map[string]nsec3gap
	sorted     []nsec3gap
	paramsSet  bool
	// hasOptOut records that at least one gap can span an unsigned delegation,
	// so the ring can never be treated as a complete absence proof.
	hasOptOut bool

	// sawNSEC records that the answers carried plain NSEC records instead.
	sawNSEC bool

	// synthesized records that an NSEC record echoed the random label that was
	// just invented to ask for it.
	synthesized bool
	// answered records that at least one query got a well-formed response, so a
	// zone that said nothing is not reported as a zone that said no.
	answered bool
}

func newNSEC3Chain() *NSEC3Chain {
	return &NSEC3Chain{
		Supported:  true,
		owners:     map[string]struct{}{},
		gapByStart: map[string]nsec3gap{},
	}
}

// ErrNSEC3Params reports an NSEC3 record whose parameters disagree with the
// rest of the chain, which a correct zone never produces mid-walk.
var ErrNSEC3Params = errors.New("resolver: NSEC3 records disagree on salt or iterations")

// addRecord folds one NSEC3 record, identified by its base32hex owner label,
// into the chain.
func (c *NSEC3Chain) addRecord(ownerLabel string, rec dnsfast.NSEC3Record) (bool, error) {
	if c.HashAlg == 0 {
		c.HashAlg = rec.HashAlg
	}
	if !rec.SupportedHash() {
		c.Supported = false
		return false, nil
	}
	if !c.paramsSet {
		c.Salt = append([]byte(nil), rec.Salt...)
		c.Iterations = rec.Iterations
		c.paramsSet = true
	} else if c.Iterations != rec.Iterations || !bytes.Equal(c.Salt, rec.Salt) {
		return false, ErrNSEC3Params
	}

	start, err := dnsfast.DecodeNSEC3Label(ownerLabel)
	if err != nil {
		return false, err
	}
	end := rec.NextHashedOwner
	c.owners[hex.EncodeToString(start)] = struct{}{}
	c.owners[hex.EncodeToString(end)] = struct{}{}

	if rec.OptOut() {
		c.hasOptOut = true
	}
	key := hex.EncodeToString(start)
	if _, seen := c.gapByStart[key]; seen {
		return false, nil
	}
	c.gapByStart[key] = nsec3gap{start: start, end: append([]byte(nil), end...), optOut: rec.OptOut()}
	return true, nil
}

// echoesAskedLabel reports whether a denial record mentions the label that
// was invented a moment ago to ask for it.
func echoesAskedLabel(owner, next, askedLabel string) bool {
	if askedLabel == "" {
		return false
	}
	l := strings.ToLower(askedLabel)
	return strings.Contains(strings.ToLower(owner), l) ||
		strings.Contains(strings.ToLower(next), l)
}

// NSEC reports that the answers carried plain NSEC records rather than
// NSEC3.
func (c *NSEC3Chain) NSEC() bool { return c.sawNSEC }

// Synthesized reports that a denial record was generated for the query
// rather than taken from the zone, so walking it cannot reach any real name.
func (c *NSEC3Chain) Synthesized() bool { return c.synthesized }

// Answered reports that at least one query produced a well-formed response,
// so a caller can tell a zone that denied DNSSEC from one that did not reply at all.
func (c *NSEC3Chain) Answered() bool { return c.answered }

// OptOut reports that at least one gap seen may span an unsigned delegation.
func (c *NSEC3Chain) OptOut() bool { return c.hasOptOut }

// Params reports whether any NSEC3 record was read at all, which separates
// "this zone is not NSEC3" from "the query failed".
func (c *NSEC3Chain) Params() bool { return c.paramsSet }

// finalize sorts the gaps so Match can binary-search them.
func (c *NSEC3Chain) finalize() {
	c.sorted = make([]nsec3gap, 0, len(c.gapByStart))
	for _, g := range c.gapByStart {
		c.sorted = append(c.sorted, g)
	}
	sort.Slice(c.sorted, func(i, j int) bool {
		return bytes.Compare(c.sorted[i].start, c.sorted[j].start) < 0
	})
}

// Match classifies a candidate name against the chain, offline.
func (c *NSEC3Chain) Match(name string) (NSEC3Status, error) {
	if !c.Supported || !c.paramsSet {
		return NSEC3Unknown, nil
	}
	h, err := dnsfast.NSEC3Hash(name, c.Salt, c.Iterations)
	if err != nil {
		return NSEC3Unknown, err
	}
	if _, ok := c.owners[hex.EncodeToString(h)]; ok {
		return NSEC3Present, nil
	}
	if g, ok := c.coveringGap(h); ok {
		if g.optOut {

			return NSEC3Unknown, nil
		}
		return NSEC3Absent, nil
	}
	return NSEC3Unknown, nil
}

// coveringGap finds the gap whose start is the greatest start not above h,
// which is the only non-wrap gap that can cover h, plus the wrap gap as a fallback.
func (c *NSEC3Chain) coveringGap(h []byte) (nsec3gap, bool) {
	if len(c.sorted) == 0 {
		return nsec3gap{}, false
	}
	i := sort.Search(len(c.sorted), func(i int) bool {
		return bytes.Compare(c.sorted[i].start, h) >= 0
	})

	if i > 0 && c.sorted[i-1].covers(h) {
		return c.sorted[i-1], true
	}

	last := c.sorted[len(c.sorted)-1]
	if bytes.Compare(last.start, last.end) >= 0 && last.covers(h) {
		return last, true
	}
	return nsec3gap{}, false
}

// HashedOwners is how many distinct zone-name hashes the walk has seen.
func (c *NSEC3Chain) HashedOwners() int { return len(c.owners) }

// Gaps is how many distinct gaps of the ring have been mapped.
func (c *NSEC3Chain) Gaps() int { return len(c.gapByStart) }

// Closed reports whether the collected gaps form one cycle covering every
// owner, i.e.
func (c *NSEC3Chain) Closed() bool {
	if len(c.gapByStart) == 0 {
		return false
	}
	next := make(map[string]string, len(c.gapByStart))
	for k, g := range c.gapByStart {
		if g.optOut {

			return false
		}
		next[k] = hex.EncodeToString(g.end)
	}

	for _, end := range next {
		if _, ok := next[end]; !ok {
			return false
		}
	}
	// Follow the cycle from any start; it is closed only if one loop visits
	// every owner exactly once.
	var start string
	for k := range next {
		start = k
		break
	}
	cur, steps := start, 0
	for {
		cur = next[cur]
		steps++
		if cur == start {
			return steps == len(next)
		}
		if steps > len(next) {
			return false
		}
	}
}

// Mapped reports whether the walk collected a usable chain.
func (c *NSEC3Chain) Mapped() bool { return c.Supported && c.paramsSet && len(c.sorted) > 0 }

const (
	// nsec3StopAfter is how many consecutive queries may reveal no new gap
	// before an opt-out walk, which can never close, gives up.
	nsec3StopAfter = 40

	// maxNSEC3Queries caps a walk so a huge or deliberately padded zone cannot
	// spend the whole run.
	maxNSEC3Queries = 4000
)

// WalkNSEC3 maps a zone's NSEC3 chain by asking for names that cannot exist
// and collecting the NSEC3 records that prove their absence.
func (r *Resolver) WalkNSEC3(ctx context.Context, zone string, maxQueries int) (*NSEC3Chain, error) {
	zone = strings.TrimSuffix(strings.ToLower(zone), ".")
	if maxQueries <= 0 || maxQueries > maxNSEC3Queries {
		maxQueries = maxNSEC3Queries
	}
	conn, err := net.Dial("udp", r.server().text)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	chain := newNSEC3Chain()
	buf := make([]byte, 4096)
	noNew := 0
	for q := 0; q < maxQueries; q++ {
		if err := ctx.Err(); err != nil {
			chain.finalize()
			return chain, err
		}
		if r.lim != nil {
			if err := r.lim.Wait(ctx); err != nil {
				chain.finalize()
				return chain, err
			}
		}

		label := randomLabel()
		name := label + "." + zone
		chain.Queries++
		added, err := r.collectNSEC3(conn, buf, zone, name, chain, label)
		if err != nil {
			noNew++
		} else if !chain.Supported {
			chain.finalize()
			return chain, nil
		} else if added {
			noNew = 0
		} else {
			noNew++
		}

		if chain.Closed() {
			break
		}

		if chain.hasOptOut && noNew >= nsec3StopAfter {
			break
		}
	}
	chain.finalize()
	return chain, nil
}

// collectNSEC3 sends one query and folds its authority NSEC3 records into
// the chain, reporting whether any were new.
func (r *Resolver) collectNSEC3(conn net.Conn, buf []byte, zone, name string, chain *NSEC3Chain, askedLabel string) (bool, error) {
	id := uint16(time.Now().UnixNano())
	query, err := dnsfast.AppendQueryDNSSEC(nil, id, name, dnsfast.TypeA, dnsfast.DefaultEDNSPayload)
	if err != nil {
		return false, err
	}
	_ = conn.SetDeadline(time.Now().Add(r.cfg.Timeout))
	if _, err := conn.Write(query); err != nil {
		return false, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return false, err
	}
	msg := append([]byte(nil), buf[:n]...)
	h, err := dnsfast.ParseHeader(msg)
	if err != nil {
		return false, err
	}
	if !h.Response || h.ID != id {
		return false, errors.New("resolver: NSEC3 answer does not match the query")
	}

	chain.answered = true
	suffix := "." + zone
	added := false
	_, err = dnsfast.ForEachAuthority(msg, func(rr dnsfast.RR) error {
		if rr.Type == dnsfast.TypeNSEC {
			chain.sawNSEC = true

			owner, oerr := rr.NameString(msg)
			next, nerr := rr.NSECNext(msg)
			if oerr != nil {
				owner = ""
			}
			if nerr != nil {
				next = ""
			}
			if echoesAskedLabel(owner, next, askedLabel) {
				chain.synthesized = true
			}
			return nil
		}
		if rr.Type != dnsfast.TypeNSEC3 {
			return nil
		}
		owner, nerr := rr.NameString(msg)
		if nerr != nil {
			return nil
		}
		owner = strings.TrimSuffix(strings.ToLower(owner), ".")

		label, ok := strings.CutSuffix(owner, suffix)
		if !ok || strings.Contains(label, ".") {
			return nil
		}
		rec, rerr := rr.NSEC3()
		if rerr != nil {
			return nil
		}
		isNew, aerr := chain.addRecord(label, rec)
		if aerr != nil {
			return nil
		}
		added = added || isNew
		return nil
	})
	return added, err
}
