// Package ledger holds what a run found and, separately, why it believes it.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash/maphash"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// SchemaVersion identifies the record contract.
const SchemaVersion = "subio.ledger.v2"

// NormalizationProfile is recorded on every finding so a consumer can tell
// which canonicalization produced the key.
const NormalizationProfile = "idna2008-uts46"

// Kind discriminates record types on the output stream.
type Kind string

const (
	KindFinding   Kind = "finding"
	KindEvidence  Kind = "evidence"
	KindDNS       Kind = "dns_observation"
	KindSourceRun Kind = "source_run"

	// KindDisagreement records two resolvers answering the same question
	// differently.
	KindDisagreement Kind = "resolver_disagreement"
)

// Verification is the DNS verification state of a finding.
type Verification string

const (
	NotChecked       Verification = "not_checked"
	Resolved         Verification = "resolved"
	NegativeNXDomain Verification = "nxdomain"
	NegativeNoData   Verification = "nodata"
	ResolutionError  Verification = "resolution_error"
)

// Finding is one canonical hostname inside one authorization root.
type Finding struct {
	SchemaVersion string `json:"schema_version"`
	Kind          Kind   `json:"kind"`
	FindingID     string `json:"finding_id"`
	FQDN          string `json:"fqdn"`
	RootDomain    string `json:"root_domain"`
	// Sources lists the distinct source IDs that reported this name.
	Sources []string `json:"sources"`

	// Families lists the distinct evidence families.
	Families []string `json:"families"`
	// FirstSeenAt and LastSeenAt are provider-stated times, or null.
	FirstSeenAt *time.Time `json:"first_seen_at"`
	LastSeenAt  *time.Time `json:"last_seen_at"`
	// EvidenceCount is the number of distinct evidence events retained.
	EvidenceCount int `json:"evidence_count"`
	// Verification is the DNS state.
	Verification Verification `json:"verification_status"`

	// WildcardSuspected is an annotation carried from the DNS stage.
	WildcardSuspected bool `json:"wildcard_suspected"`

	// OriginalValues keeps the distinct raw spellings providers returned.
	OriginalValues       []string `json:"original_values"`
	NormalizationProfile string   `json:"normalization_profile"`
}

// Evidence is one immutable provider assertion.
type Evidence struct {
	SchemaVersion string `json:"schema_version"`
	Kind          Kind   `json:"kind"`
	EvidenceID    string `json:"evidence_id"`
	FindingID     string `json:"finding_id"`
	SourceID      string `json:"source_id"`
	Family        string `json:"family"`
	Method        string `json:"method"`
	// ObservedAt is what the provider said, or null when it said nothing.
	ObservedAt *time.Time `json:"observed_at"`
	// CollectedAt is when subio asked.
	CollectedAt time.Time `json:"collected_at"`
	RecordID    string    `json:"record_id,omitempty"`
	EvidenceRef string    `json:"evidence_ref,omitempty"`
	// OriginalValue is the hostname exactly as the provider returned it.
	OriginalValue string            `json:"original_value"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// DNSRecord is one resource record from an answer.
type DNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl"`
}

// DNSObservation is a resolver answer at a point in time.
type DNSObservation struct {
	SchemaVersion string    `json:"schema_version"`
	Kind          Kind      `json:"kind"`
	FindingID     string    `json:"finding_id"`
	FQDN          string    `json:"fqdn"`
	CheckedAt     time.Time `json:"checked_at"`
	Resolver      string    `json:"resolver"`
	QueryType     string    `json:"query_type"`
	// RCode is absent when no response was read, as with a timeout.
	RCode      string      `json:"rcode,omitempty"`
	Outcome    string      `json:"outcome"`
	Records    []DNSRecord `json:"records,omitempty"`
	CNAMEChain []string    `json:"cname_chain,omitempty"`
	// Truncated marks an answer with TC set whose TCP retry did not happen or
	// failed, so its records may not be all of them.
	Truncated bool `json:"truncated,omitempty"`

	// ExtendedError is the reason the resolver attached to this answer, RFC
	// 8914, rendered for a reader.
	ExtendedError string `json:"extended_error,omitempty"`

	// DenialInferred marks a negative answer the resolver produced from its own
	// cache or synthesis rather than from the zone on this occasion.
	DenialInferred bool `json:"denial_inferred,omitempty"`

	// InferredFrom marks a negative answer subio did not ask for at all: it
	// names the name, this one or an ancestor, a resolver had answered NXDOMAIN
	// for moments earlier, and RFC 8020 says nothing exists beneath a name that
	// does not exist.
	InferredFrom string `json:"inferred_from,omitempty"`
	// WildcardSuspected and WildcardSamples keep the controls behind the
	// classification so an operator can audit it.
	WildcardSuspected bool     `json:"wildcard_suspected"`
	WildcardSamples   []string `json:"wildcard_samples,omitempty"`
	ErrorClass        string   `json:"error_class,omitempty"`
}

// Definitive reports whether this is a whole answer from a resolver: an
// answer set, NXDOMAIN or NODATA.
func (o DNSObservation) Definitive() bool {
	switch o.Outcome {
	case "resolved", "nxdomain", "nodata":
		return !o.Truncated
	}
	return false
}

// SourceRun is the per-source diagnostic record.
type SourceRun struct {
	SchemaVersion string `json:"schema_version"`
	Kind          Kind   `json:"kind"`
	RunID         string `json:"run_id"`
	SourceID      string `json:"source_id"`
	Family        string `json:"family"`
	Status        string `json:"status"`
	ErrorClass    string `json:"error_class,omitempty"`
	// Note is the adapter's sanitized line for the operator, when it left one.
	Note string `json:"note,omitempty"`

	// CapsSilently marks a run whose provider can return a partial answer with
	// nothing in the response to say so.
	CapsSilently   bool    `json:"caps_silently,omitempty"`
	TermsState     string  `json:"terms_state"`
	Requests       int     `json:"requests"`
	Pages          int     `json:"pages"`
	Retries        int     `json:"retries"`
	RateLimitHits  int     `json:"rate_limit_hits"`
	RawObservation int     `json:"raw_observations"`
	InScope        int     `json:"in_scope_observations"`
	OutOfScope     int     `json:"out_of_scope_rejected"`
	Malformed      int     `json:"malformed_rejected"`
	UniqueNames    int     `json:"unique_names"`
	MarginalNames  int     `json:"marginal_names"`
	DurationMS     int64   `json:"duration_ms"`
	QuotaRemaining int     `json:"quota_remaining"`
	ResetAt        *string `json:"reset_at,omitempty"`
	// WildcardExplained counts generated names that resolved only because a
	// wildcard answers everything.
	WildcardExplained int `json:"wildcard_explained,omitempty"`
	// FailedValidation counts generated names a trusted resolver did not confirm.
	FailedValidation int `json:"failed_validation,omitempty"`

	// DNSErrors counts generated names no resolver could answer.
	DNSErrors int `json:"dns_errors,omitempty"`
}

// key is the internal identity of an asset: sha256(root, fqdn) as a value.
type key [32]byte

// verification is the compact form of the exported Verification strings.
type verification uint8

const (
	vNotChecked verification = iota
	vResolved
	vNXDomain
	vNoData
	vError
)

func (v verification) String() Verification {
	switch v {
	case vResolved:
		return Resolved
	case vNXDomain:
		return NegativeNXDomain
	case vNoData:
		return NegativeNoData
	case vError:
		return ResolutionError
	}
	return NotChecked
}

// asset is the stored state of one hostname.
type asset struct {
	fqdn   string
	rootID uint8
	// srcMask and famMask are bitmasks over the interned source and family
	// tables, replacing two string slices per asset.
	srcMask uint64
	famMask uint64
	// firstNS and lastNS are provider-stated times in Unix nanoseconds; zero
	// means no provider stated one, and is serialized as null.
	firstNS int64
	lastNS  int64
	evCount int32
	verif   verification
	// sawCanonical records that a provider returned the name already in its
	// canonical form, so the exported OriginalValues can include it without
	// storing the same string twice.
	sawCanonical bool
	wildcard     bool
	// originals holds only the spellings that differ from fqdn.
	originals []string
}

// ev is one stored evidence record.
type ev struct {
	id         key
	srcID      uint8
	famID      uint8
	methodID   uint8
	observedNS int64
	recordID   string
	ref        string
	// original is empty when the provider returned the canonical spelling.
	original string
	attrs    map[string]string
}

// Ledger accumulates a run.
type Ledger struct {
	mu     sync.Mutex
	assets map[key]*asset
	// evs groups evidence so output stays deterministic.
	evs map[key][]ev

	// evSeen deduplicates by evidence identity, not by hostname, through a
	// 128-bit maphash of the same fields the stable SHA-256 id covers.
	evSeen  map[[2]uint64]struct{}
	evSeedA maphash.Seed
	evSeedB maphash.Seed
	// keyOf caches each name's finding key, so a name observed a million times
	// is hashed once.
	keyOf map[string]keyEntry
	dns   map[key][]DNSObservation
	runs  []SourceRun
	// disagreements are resolver contradictions, kept even for names that were
	// not reported.
	disagreements []Disagreement

	srcs    *interner
	fams    *interner
	methods *interner
	roots   *interner

	collected time.Time
}

// New builds an empty ledger.
func New(collectedAt time.Time) *Ledger {
	return &Ledger{
		assets:    map[key]*asset{},
		evs:       map[key][]ev{},
		evSeen:    map[[2]uint64]struct{}{},
		evSeedA:   maphash.MakeSeed(),
		evSeedB:   maphash.MakeSeed(),
		keyOf:     map[string]keyEntry{},
		dns:       map[key][]DNSObservation{},
		srcs:      newInterner(),
		fams:      newInterner(),
		methods:   newInterner(),
		roots:     newInterner(),
		collected: collectedAt.UTC(),
	}
}

// keyEntry is a cached finding key, with the root it was computed under.
type keyEntry struct {
	root string
	k    key
}

// keyLocked is keyFor through the cache.
func (l *Ledger) keyLocked(root, fqdn string) key {
	if e, ok := l.keyOf[fqdn]; ok && e.root == root {
		return e.k
	}
	k := keyFor(root, fqdn)
	l.keyOf[fqdn] = keyEntry{root: root, k: k}
	return k
}

// keyFor is the internal identity.
func keyFor(root, fqdn string) key {
	return sha256.Sum256([]byte(root + "\x00" + fqdn))
}

// hexKey is on the write path once per finding and once per evidence record,
// so its allocations are worth counting.
func hexKey(k key) string {
	var buf [2 * len(key{})]byte
	hex.Encode(buf[:], k[:])
	return string(buf[:])
}

func nsToTime(ns int64) *time.Time {
	if ns == 0 {
		return nil
	}
	t := time.Unix(0, ns).UTC()
	return &t
}

// evidenceKey is the stable identity of one provider assertion.
func (l *Ledger) fastEvidenceKey(fields ...string) [2]uint64 {
	var a, b maphash.Hash
	a.SetSeed(l.evSeedA)
	b.SetSeed(l.evSeedB)
	for _, f := range fields {
		_, _ = a.WriteString(f)
		_ = a.WriteByte(0)
		_, _ = b.WriteString(f)
		_ = b.WriteByte(0)
	}
	return [2]uint64{a.Sum64(), b.Sum64()}
}

func evidenceKey(findingID key, sourceID, method, recordID, ref, observed, original string) key {
	return sha256.Sum256([]byte(strings.Join([]string{
		hexKey(findingID), sourceID, method, recordID, ref, observed, original,
	}, "\x00")))
}

// Observe records one provider assertion about an already-canonicalized host
// inside root.
func (l *Ledger) Observe(canonicalHost, root string, family source.Family, obs source.Observation) (newName bool) {

	var observedNS int64
	var observedStr string
	if !obs.ObservedAt.IsZero() {
		t := obs.ObservedAt.UTC()
		observedNS = t.UnixNano()
		observedStr = t.Format(time.RFC3339Nano)
	}

	original := obs.Hostname
	if original == canonicalHost {
		original = ""
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(root, canonicalHost)
	fast := l.fastEvidenceKey(root, canonicalHost, obs.SourceID, obs.Method, obs.RecordID, obs.EvidenceRef, observedStr, obs.Hostname)

	a, exists := l.assets[k]
	if !exists {
		a = &asset{
			fqdn:   canonicalHost,
			rootID: l.roots.id(root),
			verif:  vNotChecked,
		}
		l.assets[k] = a
		newName = true
	}

	if _, dup := l.evSeen[fast]; !dup {
		l.evSeen[fast] = struct{}{}
		evKey := evidenceKey(k, obs.SourceID, obs.Method, obs.RecordID, obs.EvidenceRef, observedStr, obs.Hostname)
		l.evs[k] = append(l.evs[k], ev{
			id:         evKey,
			srcID:      l.srcs.id(obs.SourceID),
			famID:      l.fams.id(string(family)),
			methodID:   l.methods.id(obs.Method),
			observedNS: observedNS,
			recordID:   obs.RecordID,
			ref:        obs.EvidenceRef,
			original:   original,
			attrs:      obs.Attrs,
		})
		a.evCount++
	}

	a.srcMask |= l.srcs.bit(obs.SourceID)
	a.famMask |= l.fams.bit(string(family))

	if obs.Hostname != "" {
		if original == "" {
			a.sawCanonical = true
		} else if !containsString(a.originals, original) {
			a.originals = append(a.originals, original)
		}
	}
	if observedNS != 0 {
		if a.firstNS == 0 || observedNS < a.firstNS {
			a.firstNS = observedNS
		}
		if observedNS > a.lastNS {
			a.lastNS = observedNS
		}
	}

	return newName
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// view builds the exported Finding for an asset.
func (l *Ledger) view(k key, a *asset) Finding {
	f := Finding{
		SchemaVersion:        SchemaVersion,
		Kind:                 KindFinding,
		FindingID:            hexKey(k),
		FQDN:                 a.fqdn,
		RootDomain:           l.roots.name(a.rootID),
		Sources:              sortedStrings(l.srcs.names(a.srcMask)),
		Families:             sortedStrings(l.fams.names(a.famMask)),
		FirstSeenAt:          nsToTime(a.firstNS),
		LastSeenAt:           nsToTime(a.lastNS),
		EvidenceCount:        int(a.evCount),
		Verification:         a.verif.String(),
		WildcardSuspected:    a.wildcard,
		NormalizationProfile: NormalizationProfile,
	}
	if a.sawCanonical {
		f.OriginalValues = append(f.OriginalValues, a.fqdn)
	}
	f.OriginalValues = append(f.OriginalValues, a.originals...)
	sort.Strings(f.OriginalValues)
	return f
}

// evidenceView builds the exported Evidence records for an asset.
func (l *Ledger) evidenceView(k key, a *asset) []Evidence {
	stored := l.evs[k]
	out := make([]Evidence, 0, len(stored))

	findingID := hexKey(k)
	for _, e := range stored {
		original := e.original
		if original == "" {
			original = a.fqdn
		}
		out = append(out, Evidence{
			SchemaVersion: SchemaVersion,
			Kind:          KindEvidence,
			EvidenceID:    hexKey(e.id),
			FindingID:     findingID,
			SourceID:      l.srcs.name(e.srcID),
			Family:        l.fams.name(e.famID),
			Method:        l.methods.name(e.methodID),
			ObservedAt:    nsToTime(e.observedNS),
			CollectedAt:   l.collected,
			RecordID:      e.recordID,
			EvidenceRef:   e.ref,
			OriginalValue: original,
			Attributes:    e.attrs,
		})
	}

	if len(out) > 1 {
		sort.Slice(out, func(i, j int) bool { return out[i].EvidenceID < out[j].EvidenceID })
	}
	return out
}

func sortedStrings(s []string) []string {
	if len(s) < 2 {
		return s
	}
	sort.Strings(s)
	return s
}

// AddDNS attaches a resolver observation to a known finding and updates the
// finding's verification state.
func (l *Ledger) AddDNS(root string, o DNSObservation) {
	k := keyFor(root, o.FQDN)
	o.SchemaVersion = SchemaVersion
	o.Kind = KindDNS
	o.FindingID = hexKey(k)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dns[k] = append(l.dns[k], o)
	a, ok := l.assets[k]
	if !ok {
		return
	}
	switch o.Outcome {
	case "resolved":
		a.verif = vResolved
	case "nxdomain":
		if a.verif != vResolved {
			a.verif = vNXDomain
		}
	case "nodata":
		if a.verif != vResolved {
			a.verif = vNoData
		}
	default:
		if a.verif == vNotChecked {
			a.verif = vError
		}
	}
	if o.WildcardSuspected {
		a.wildcard = true
	}
}

// AddSourceRun records a source's terminal diagnostics.
func (l *Ledger) AddSourceRun(r SourceRun) {
	r.SchemaVersion = SchemaVersion
	r.Kind = KindSourceRun
	l.mu.Lock()
	l.runs = append(l.runs, r)
	l.mu.Unlock()
}

// Len reports the number of distinct findings.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.assets)
}

// Has reports whether a hostname is already a finding.
func (l *Ledger) Has(root, fqdn string) bool {
	k := keyFor(root, fqdn)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.assets[k]
	return ok
}

// Findings returns the findings sorted by root then FQDN, which is what
// makes a saved run byte-for-byte comparable with a later one.
func (l *Ledger) Findings() []Finding {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.findingsLocked()
}

func (l *Ledger) findingsLocked() []Finding {
	out := make([]Finding, 0, len(l.assets))
	for k, a := range l.assets {
		out = append(out, l.view(k, a))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RootDomain != out[j].RootDomain {
			return out[i].RootDomain < out[j].RootDomain
		}
		return out[i].FQDN < out[j].FQDN
	})
	return out
}

// sortedKeysLocked returns asset keys in output order.
func (l *Ledger) sortedKeysLocked() []key {
	type sortKey struct {
		root, fqdn string
		k          key
	}
	sk := make([]sortKey, 0, len(l.assets))
	for k, a := range l.assets {
		sk = append(sk, sortKey{root: l.roots.name(a.rootID), fqdn: a.fqdn, k: k})
	}
	sort.Slice(sk, func(i, j int) bool {
		if sk[i].root != sk[j].root {
			return sk[i].root < sk[j].root
		}
		return sk[i].fqdn < sk[j].fqdn
	})
	keys := make([]key, len(sk))
	for i := range sk {
		keys[i] = sk[i].k
	}
	return keys
}

// Finding returns one exported finding by root and hostname.
func (l *Ledger) Finding(root, fqdn string) (Finding, bool) {
	k := keyFor(root, fqdn)
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.assets[k]
	if !ok {
		return Finding{}, false
	}
	return l.view(k, a), true
}

// DNSFor returns the DNS observations for one name, in output order.
func (l *Ledger) DNSFor(root, fqdn string) []DNSObservation {
	k := keyFor(root, fqdn)
	l.mu.Lock()
	obs := append([]DNSObservation(nil), l.dns[k]...)
	l.mu.Unlock()
	sort.Slice(obs, func(i, j int) bool {
		if !obs[i].CheckedAt.Equal(obs[j].CheckedAt) {
			return obs[i].CheckedAt.Before(obs[j].CheckedAt)
		}
		return obs[i].QueryType < obs[j].QueryType
	})
	return obs
}

// EachFinding calls fn for every finding in output order, building one
// record at a time.
func (l *Ledger) EachFinding(fn func(Finding) error) error {
	l.mu.Lock()
	keys := l.sortedKeysLocked()
	l.mu.Unlock()
	for _, k := range keys {
		l.mu.Lock()
		a, ok := l.assets[k]
		var f Finding
		if ok {
			f = l.view(k, a)
		}
		l.mu.Unlock()
		if !ok {
			continue
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

// DNSByFinding returns the DNS observations grouped by finding id, so an
// output projection can fold every queried type into one row.
func (l *Ledger) DNSByFinding() map[string][]DNSObservation {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string][]DNSObservation, len(l.dns))
	for k, obs := range l.dns {
		cp := append([]DNSObservation(nil), obs...)
		sort.Slice(cp, func(i, j int) bool {
			if !cp[i].CheckedAt.Equal(cp[j].CheckedAt) {
				return cp[i].CheckedAt.Before(cp[j].CheckedAt)
			}
			return cp[i].QueryType < cp[j].QueryType
		})
		out[hexKey(k)] = cp
	}
	return out
}

// SourceRuns returns the diagnostics sorted by source ID.
type Disagreement struct {
	SchemaVersion string    `json:"schema_version"`
	Kind          Kind      `json:"kind"`
	FQDN          string    `json:"fqdn"`
	QueryType     string    `json:"query_type"`
	CheckedAt     time.Time `json:"checked_at"`
	// ClaimedBy is the resolver that answered, with what it said.
	ClaimedBy      string      `json:"claimed_by"`
	ClaimedOutcome string      `json:"claimed_outcome"`
	ClaimedRecords []DNSRecord `json:"claimed_records,omitempty"`
	// CheckedBy is the resolver asked the same question to check it: a trusted
	// resolver for a guess, or a second resolver for a known name the first
	// called non-existent.
	CheckedBy      string      `json:"checked_by"`
	CheckedOutcome string      `json:"checked_outcome"`
	CheckedRecords []DNSRecord `json:"checked_records,omitempty"`

	// Kept says whether the name was still reported.
	Kept bool `json:"kept"`
}

// AddDisagreement records one contradiction.
func (l *Ledger) AddDisagreement(d Disagreement) {
	d.SchemaVersion = SchemaVersion
	d.Kind = KindDisagreement
	l.mu.Lock()
	l.disagreements = append(l.disagreements, d)
	l.mu.Unlock()
}

// Disagreements returns the recorded contradictions in a stable order.
func (l *Ledger) Disagreements() []Disagreement {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := append([]Disagreement(nil), l.disagreements...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].FQDN != out[j].FQDN {
			return out[i].FQDN < out[j].FQDN
		}
		return out[i].QueryType < out[j].QueryType
	})
	return out
}

// ContradictedResolvers counts, per resolver, how often a trusted resolver
// did not confirm what it claimed.
func (l *Ledger) ContradictedResolvers() map[string]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]int{}
	for _, d := range l.disagreements {
		if d.ClaimedBy != "" {
			out[d.ClaimedBy]++
		}
	}
	return out
}

// Contribution is one source's name counts: how many distinct findings it
// reported, and how many of those no other source did.
type Contribution struct {
	Unique    int
	Exclusive int
}

// SourceContribution computes, per source id, its unique and exclusive name
// counts from the stored per-name source bitmask.
func (l *Ledger) SourceContribution() map[string]Contribution {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := map[string]Contribution{}
	for _, a := range l.assets {
		srcs := l.srcs.names(a.srcMask)
		sole := len(srcs) == 1
		for _, s := range srcs {
			c := out[s]
			c.Unique++
			if sole {
				c.Exclusive++
			}
			out[s] = c
		}
	}
	return out
}

func (l *Ledger) SourceRuns() []SourceRun {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := append([]SourceRun(nil), l.runs...)
	sort.Slice(out, func(i, j int) bool { return out[i].SourceID < out[j].SourceID })
	return out
}

// Stats summarizes a run for the human-readable report.
type Stats struct {
	Findings      int
	Evidence      int
	Resolved      int
	Wildcard      int
	SourcesOK     int
	SourcesFailed int

	// Incomplete counts sources whose result set is known to be partial.
	Incomplete int
	// DNSErrors counts names with at least one query no resolver could answer.
	DNSErrors int

	// Unverifiable counts sources that returned names and whose provider can cap
	// an answer with nothing in the response to say so.
	Unverifiable int
	// UnverifiableIDs names them, sorted, so the report can say which.
	UnverifiableIDs []string

	// PlanCapped names sources truncated by a free plan's row ceiling.
	PlanCapped []string

	// InferredDenials counts names whose "does not exist" came from a resolver's
	// own cache or synthesis rather than from the zone.
	InferredDenials int
}

// Stats computes the run summary.
func (l *Ledger) Stats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()
	var s Stats
	s.Findings = len(l.assets)
	for _, a := range l.assets {
		s.Evidence += int(a.evCount)
		if a.verif == vResolved {
			s.Resolved++
		}
		if a.wildcard {
			s.Wildcard++
		}
	}
	for _, obs := range l.dns {
		inferred := false
		for _, o := range obs {
			if !o.Definitive() {
				s.DNSErrors++
				break
			}
		}
		for _, o := range obs {
			if o.DenialInferred {
				inferred = true
				break
			}
		}
		if inferred {
			s.InferredDenials++
		}
	}
	for _, r := range l.runs {
		if r.CapsSilently {
			s.Unverifiable++
			s.UnverifiableIDs = append(s.UnverifiableIDs, r.SourceID)
		}
		st := source.Status(r.Status)
		switch {
		case st == source.StatusTruncated && r.ErrorClass == string(source.ErrPlanLimit):
			s.PlanCapped = append(s.PlanCapped, r.SourceID)
		case st.Complete():
			s.SourcesOK++
		case st == source.StatusFailed || st == source.StatusMissingCredentials || st == source.StatusTermsBlocked:
			s.SourcesFailed++
			s.Incomplete++
		default:
			s.Incomplete++
		}
	}
	sort.Strings(s.UnverifiableIDs)
	return s
}

// WriteJSONL writes every record as one JSON object per line, in a
// deterministic order: findings sorted by root and FQDN, each immediately
// followed by its evidence and DNS observations, then the source
// diagnostics.
func (l *Ledger) WriteJSONL(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	l.mu.Lock()
	keys := l.sortedKeysLocked()
	l.mu.Unlock()

	for _, k := range keys {
		l.mu.Lock()
		a, ok := l.assets[k]
		if !ok {
			l.mu.Unlock()
			continue
		}
		finding := l.view(k, a)
		evs := l.evidenceView(k, a)
		obs := append([]DNSObservation(nil), l.dns[k]...)
		l.mu.Unlock()

		if err := enc.Encode(finding); err != nil {
			return err
		}
		for _, e := range evs {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		if len(obs) > 1 {
			sort.Slice(obs, func(i, j int) bool {
				if !obs[i].CheckedAt.Equal(obs[j].CheckedAt) {
					return obs[i].CheckedAt.Before(obs[j].CheckedAt)
				}
				return obs[i].QueryType < obs[j].QueryType
			})
		}
		for _, o := range obs {
			if err := enc.Encode(o); err != nil {
				return err
			}
		}
	}
	for _, r := range l.SourceRuns() {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}

	for _, d := range l.Disagreements() {
		if err := enc.Encode(d); err != nil {
			return err
		}
	}
	return nil
}
