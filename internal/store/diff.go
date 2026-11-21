package store

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Change classifies one hostname between two runs.
type Change string

const (
	// New was not in the store before this run.
	New Change = "new"
	// StillSeen was observed again, with the same DNS answer (or none).
	StillSeen Change = "still_seen"

	// Reappeared was absent from at least one earlier complete run and is back.
	Reappeared Change = "reappeared"

	// DNSChanged was observed again and a resolver gave a different answer for a
	// record type it had answered before.
	DNSChanged Change = "dns_changed"

	// Unconfirmed was not observed this run, and at least one source that had
	// previously reported it did not produce a complete result set.
	Unconfirmed Change = "unconfirmed"

	// NoLongerObserved was not observed, and every source that had ever reported
	// it ran to completion this time.
	NoLongerObserved Change = "no_longer_observed"
)

// Observation is what the current run saw about one hostname.
type Observation struct {
	Key
	Sources           []string
	ProviderFirstSeen *time.Time
	ProviderLastSeen  *time.Time
	Verification      string
	Records           []RR
	Wildcard          bool
	// DNSAnswered lists the record types a resolver answered definitively this
	// run: an answer set, NXDOMAIN or NODATA.
	DNSAnswered []string
	// DNSFailed reports that at least one query for this name got no usable
	// answer.
	DNSFailed bool
}

// Entry is one line of a diff.
type Entry struct {
	Change Change `json:"change"`
	Key
	Sources     []string `json:"sources,omitempty"`
	PrevRecords []RR     `json:"previous_records,omitempty"`
	Records     []RR     `json:"records,omitempty"`
	// Reason explains an Unconfirmed entry: which source's failure is the reason
	// no conclusion can be drawn.
	Reason string `json:"reason,omitempty"`
	// FirstSeen is when subio first observed the name.
	FirstSeen time.Time `json:"first_seen"`
	// MissingRuns is how many consecutive complete runs have not seen it.
	MissingRuns int `json:"missing_runs,omitempty"`

	// DNSUnconfirmed marks a name whose lookup failed this run.
	DNSUnconfirmed bool `json:"dns_unconfirmed,omitempty"`
}

// Diff is the change set of one run against the stored state.
type Diff struct {
	RunID     string `json:"run_id"`
	PrevRunID string `json:"previous_run_id,omitempty"`

	// Roots are the authorization roots this run covered.
	Roots   []string       `json:"roots"`
	Counts  map[Change]int `json:"counts"`
	Entries []Entry        `json:"entries"`
	// IncompleteSources lists the adapters whose failure limits what this diff
	// can conclude, with their status.
	IncompleteSources []string `json:"incomplete_sources,omitempty"`

	// Conclusive is false when any source was incomplete.
	Conclusive bool `json:"conclusive"`
	// FirstRun marks the run that created the store, where everything is new and
	// nothing can be absent.
	FirstRun bool `json:"first_run"`
	// DNSUnconfirmed counts names with a query no resolver could answer.
	DNSUnconfirmed int `json:"dns_unconfirmed,omitempty"`
}

// Count returns the number of entries of one kind.
func (d *Diff) Count(c Change) int { return d.Counts[c] }

// Compute produces the diff of a run against the previous state, and the
// asset records to commit.
func Compute(prev *Snapshot, run Run, observed []Observation) (*Diff, []Asset) {
	completed := run.CompletedSources()
	selected := make(map[string]bool, len(run.SourceStatus))
	for id := range run.SourceStatus {
		selected[id] = true
	}

	inScope := make(map[string]bool, len(run.Roots))
	for _, r := range run.Roots {
		inScope[r] = true
	}

	d := &Diff{
		RunID: run.ID, Roots: run.Roots, Counts: map[Change]int{},
		IncompleteSources: run.IncompleteSources(),
		Conclusive:        run.Complete(),
		FirstRun:          len(prev.Runs) == 0,
	}
	if last, ok := prev.LastRun(); ok {
		d.PrevRunID = last.ID
	}

	var commit []Asset
	seen := make(map[string]bool, len(observed))

	for _, o := range observed {
		key := o.Key.String()
		seen[key] = true
		old, existed := prev.Assets[key]

		a := Asset{
			Key:               o.Key,
			LastRun:           run.ID,
			LastSeen:          run.FinishedAt,
			Sources:           sortedCopy(o.Sources),
			EverSources:       sortedCopy(o.Sources),
			ProviderFirstSeen: o.ProviderFirstSeen,
			ProviderLastSeen:  o.ProviderLastSeen,
			Verification:      o.Verification,
			Records:           sortedRecords(o.Records),
			Wildcard:          o.Wildcard,
			DNSTypes:          sortedCopy(o.DNSAnswered),
			MissingRuns:       0,
		}
		entry := Entry{Key: o.Key, Sources: a.Sources, Records: a.Records, DNSUnconfirmed: o.DNSFailed}
		if o.DNSFailed {
			d.DNSUnconfirmed++
		}

		switch {
		case !existed:
			a.FirstRun, a.FirstSeen = run.ID, run.FinishedAt
			entry.Change = New
			entry.FirstSeen = a.FirstSeen

		default:
			a.FirstRun, a.FirstSeen = old.FirstRun, old.FirstSeen
			a.EverSources = unionSorted(old.EverSources, o.Sources)

			a.ProviderFirstSeen = earliest(old.ProviderFirstSeen, o.ProviderFirstSeen)
			a.ProviderLastSeen = latest(old.ProviderLastSeen, o.ProviderLastSeen)
			entry.FirstSeen = a.FirstSeen
			entry.PrevRecords = old.Records

			var dnsChanged bool
			a.Records, a.DNSTypes, dnsChanged = foldDNS(old, o)
			entry.Records = a.Records

			if len(o.DNSAnswered) == 0 && old.Verification != "" && old.Verification != "not_checked" {
				a.Verification, a.Wildcard = old.Verification, old.Wildcard
			}

			switch {
			case old.MissingRuns > 0:
				entry.Change = Reappeared
			case dnsChanged:
				entry.Change = DNSChanged
			default:
				entry.Change = StillSeen
			}
		}
		d.Counts[entry.Change]++
		d.Entries = append(d.Entries, entry)
		commit = append(commit, a)
	}

	for key, old := range prev.Assets {
		if seen[key] || !inScope[old.Root] {
			continue
		}
		reason := absenceReason(old.EverSources, selected, completed)
		entry := Entry{
			Key: old.Key, Sources: old.Sources, PrevRecords: old.Records,
			FirstSeen: old.FirstSeen,
		}
		a := old
		if reason == "" {
			entry.Change = NoLongerObserved
			a.MissingRuns = old.MissingRuns + 1
			entry.MissingRuns = a.MissingRuns
			a.LastRun = old.LastRun
		} else {
			entry.Change = Unconfirmed
			entry.Reason = reason
			entry.MissingRuns = old.MissingRuns

		}
		d.Counts[entry.Change]++
		d.Entries = append(d.Entries, entry)
		commit = append(commit, a)
	}

	sort.Slice(d.Entries, func(i, j int) bool {
		if d.Entries[i].Change != d.Entries[j].Change {
			return changeRank(d.Entries[i].Change) < changeRank(d.Entries[j].Change)
		}
		if d.Entries[i].Root != d.Entries[j].Root {
			return d.Entries[i].Root < d.Entries[j].Root
		}
		return d.Entries[i].FQDN < d.Entries[j].FQDN
	})
	sort.Slice(commit, func(i, j int) bool { return commit[i].Key.String() < commit[j].Key.String() })
	return d, commit
}

// foldDNS merges this run's definitive answers into what the store knew.
func foldDNS(old Asset, o Observation) (records []RR, types []string, changed bool) {
	if len(o.DNSAnswered) == 0 {
		return old.Records, old.DNSTypes, false
	}
	now := make(map[string]bool, len(o.DNSAnswered))
	for _, t := range o.DNSAnswered {
		now[t] = true
	}
	fresh := sortedRecords(o.Records)

	prev := answeredTypes(old)
	common, whole := map[string]bool{}, true
	for _, t := range prev {
		if now[t] {
			common[t] = true
		} else {
			whole = false
		}
	}
	if len(common) > 0 {
		changed = !RecordsEqual(pickRecords(old.Records, common, whole), pickRecords(fresh, common, whole))
	}

	records = fresh
	for _, r := range old.Records {
		if now[r.Type] || (r.Type == "CNAME" && whole) {
			continue
		}
		records = append(records, r)
	}
	return sortedRecords(records), unionSorted(prev, o.DNSAnswered), changed
}

// answeredTypes returns the types a resolver has answered for an asset.
func answeredTypes(a Asset) []string {
	if len(a.DNSTypes) > 0 {
		return a.DNSTypes
	}
	var out []string
	for _, r := range a.Records {
		if r.Type != "CNAME" {
			out = append(out, r.Type)
		}
	}
	return sortedCopy(out)
}

func pickRecords(rs []RR, types map[string]bool, withCNAME bool) []RR {
	var out []RR
	for _, r := range rs {
		if types[r.Type] || (withCNAME && r.Type == "CNAME") {
			out = append(out, r)
		}
	}
	return out
}

// absenceReason returns "" when the absence is conclusive, or the reason it
// is not.
func absenceReason(everSources []string, selected, completed map[string]bool) string {
	if len(everSources) == 0 {

		return "no recorded source provenance for this name"
	}
	var notRun, failed []string
	for _, src := range everSources {
		switch {
		case !selected[src]:
			notRun = append(notRun, src)
		case !completed[src]:
			failed = append(failed, src)
		}
	}
	sort.Strings(notRun)
	sort.Strings(failed)
	switch {
	case len(failed) > 0 && len(notRun) > 0:
		return fmt.Sprintf("%s did not complete; %s was not run",
			strings.Join(failed, ", "), strings.Join(notRun, ", "))
	case len(failed) > 0:
		return strings.Join(failed, ", ") + " did not complete"
	case len(notRun) > 0:
		return strings.Join(notRun, ", ") + " was not run"
	}
	return ""
}

// changeRank orders the report so the things an operator must act on come
// first and the unchanged bulk comes last.
func changeRank(c Change) int {
	switch c {
	case New:
		return 0
	case Reappeared:
		return 1
	case DNSChanged:
		return 2
	case NoLongerObserved:
		return 3
	case Unconfirmed:
		return 4
	default:
		return 5
	}
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return dedupe(out)
}

func unionSorted(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	sort.Strings(out)
	return dedupe(out)
}

func dedupe(s []string) []string {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func sortedRecords(rs []RR) []RR {
	if len(rs) == 0 {
		return nil
	}
	out := append([]RR(nil), rs...)
	SortRecords(out)

	uniq := out[:1]
	for _, r := range out[1:] {
		if r != uniq[len(uniq)-1] {
			uniq = append(uniq, r)
		}
	}
	return uniq
}

func earliest(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.Before(*a):
		return b
	}
	return a
}

func latest(a, b *time.Time) *time.Time {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	case b.After(*a):
		return b
	}
	return a
}
