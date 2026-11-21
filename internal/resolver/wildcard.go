package resolver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"

	"github.com/theLabXHQ/subio/internal/dnsfast"
)

// WildcardReport records a wildcard classification and the evidence for it.
type WildcardReport struct {
	Parent string
	Type   dnsfast.Type
	// Suspected is true when independent random labels resolved at all, which
	// real names do not do by chance.
	Suspected bool
	// Controls are the random names queried, retained so the classification can
	// be audited and reproduced.
	Controls []string

	// AnswerSet is every answer the controls received, sorted.
	AnswerSet []string
	// Agreement is how many controls resolved.
	Agreement int
	// Samples is how many controls answered at all.
	Samples int
	// PoolRounds is how many extra rounds of controls found pool members the
	// earlier ones had not, for a wildcard that rotates its answers.
	PoolRounds int
}

// Matches reports whether an answer could have come from the wildcard: every
// record in it is one the controls also received.
func (w WildcardReport) Matches(a Answer) bool {
	if !w.Suspected || a.Outcome != Resolved {
		return false
	}
	return subset(answerSet(a), w.AnswerSet)
}

func answerSet(a Answer) []string {
	out := make([]string, 0, len(a.Records))
	for _, r := range a.Records {
		out = append(out, r.Type+"="+r.Value)
	}
	sort.Strings(out)
	return out
}

// subset reports whether every element of a is in b.
func subset(a, b []string) bool {
	if len(a) == 0 {
		return false
	}
	i := 0
	for _, v := range a {
		for i < len(b) && b[i] < v {
			i++
		}
		if i == len(b) || b[i] != v {
			return false
		}
	}
	return true
}

// randomLabel returns a label that cannot plausibly exist, so an answer for
// it is synthesized rather than real.
func randomLabel() string {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "zzsubiocontrol"
	}
	return "zz" + hex.EncodeToString(b[:]) + "zz"
}

const (
	// minAgreement is how many independent controls must resolve before we call
	// it a wildcard.
	minAgreement = 2
	// poolControls is how many extra controls map a wildcard whose first
	// controls disagreed, meaning it answers from a rotating pool.
	poolControls = 8

	// maxPoolRounds bounds how many rounds of poolControls a rotating pool gets.
	maxPoolRounds = 6
)

// Probe names one zone level and record type to test.
type Probe struct {
	Parent string
	Type   dnsfast.Type
}

// detect runs every probe through one stream, so probing thousands of zone
// levels costs a few round trips and not a socket pool each.
func (r *Resolver) detect(ctx context.Context, probes []Probe, samples int) []WildcardReport {
	if samples < minAgreement {
		samples = 3
	}
	reports := make([]WildcardReport, len(probes))
	for i, p := range probes {
		reports[i] = WildcardReport{Parent: p.Parent, Type: p.Type}
	}
	pools := make([]map[string]bool, len(probes))
	round := func(indexes []int, n int) []int {
		owner := make(map[string]int, len(indexes)*n)
		jobs := make([]Job, 0, len(indexes)*n)
		before := make(map[int]int, len(indexes))
		for _, i := range indexes {
			before[i] = len(pools[i])
			for c := 0; c < n; c++ {
				name := randomLabel() + "." + probes[i].Parent
				reports[i].Controls = append(reports[i].Controls, name)
				owner[name] = i
				jobs = append(jobs, Job{Name: name, Type: probes[i].Type})
			}
		}
		for _, a := range r.ResolveJobs(ctx, jobs) {
			i, ok := owner[a.Name]
			if !ok || a.Outcome != Resolved {
				continue
			}
			reports[i].Samples++
			if pools[i] == nil {
				pools[i] = map[string]bool{}
			}
			for _, v := range answerSet(a) {
				pools[i][v] = true
			}
		}
		var grew []int
		for _, i := range indexes {
			if reports[i].Samples >= minAgreement && len(pools[i]) > before[i] {
				grew = append(grew, i)
			}
		}
		return grew
	}

	all := make([]int, len(probes))
	for i := range all {
		all[i] = i
	}

	// A wildcard answering the same way every time needs no second look.
	var rotating []int
	for _, i := range round(all, samples) {
		if rotatingAnswers(pools[i], reports[i].Samples) {
			rotating = append(rotating, i)
		}
	}
	for n := 0; n < maxPoolRounds && len(rotating) > 0; n++ {
		rotating = round(rotating, poolControls)
		for _, i := range rotating {
			reports[i].PoolRounds++
		}
	}

	for i := range reports {
		if reports[i].Samples < minAgreement {
			continue
		}
		reports[i].Suspected = true
		reports[i].Agreement = reports[i].Samples
		set := make([]string, 0, len(pools[i]))
		for v := range pools[i] {
			set = append(set, v)
		}
		sort.Strings(set)
		reports[i].AnswerSet = set
	}
	return reports
}

// rotatingAnswers guesses that several distinct records across several
// controls mean a pool.
func rotatingAnswers(pool map[string]bool, samples int) bool {
	return samples >= minAgreement && len(pool) > 1
}

// Parents returns the distinct ancestor names of host up to, but not beyond,
// root.
func Parents(host, root string) []string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	root = strings.TrimSuffix(strings.ToLower(root), ".")
	if host == root || !strings.HasSuffix(host, "."+root) {
		return nil
	}
	var out []string
	rest := strings.TrimSuffix(host, "."+root)
	labels := strings.Split(rest, ".")

	cur := root
	out = append(out, cur)
	for i := len(labels) - 1; i >= 1; i-- {
		cur = labels[i] + "." + cur
		out = append(out, cur)
	}
	return out
}

// WildcardScanner probes zone levels and caches the verdicts, so a run with
// thousands of names under the same zone probes each level once.
type WildcardScanner struct {
	r       *Resolver
	samples int

	mu    sync.Mutex
	cache map[string]WildcardReport
}

// NewWildcardScanner builds a scanner.
func NewWildcardScanner(r *Resolver, samples int) *WildcardScanner {
	return &WildcardScanner{r: r, samples: samples, cache: map[string]WildcardReport{}}
}

func probeKey(parent string, qtype dnsfast.Type) string { return parent + "|" + qtype.String() }

// Prepare probes every level not yet known in one batch.
func (s *WildcardScanner) Prepare(ctx context.Context, probes []Probe) {
	s.mu.Lock()
	seen := make(map[string]bool, len(probes))
	todo := make([]Probe, 0, len(probes))
	for _, p := range probes {
		k := probeKey(p.Parent, p.Type)
		if _, known := s.cache[k]; known || seen[k] {
			continue
		}
		seen[k] = true
		todo = append(todo, p)
	}
	s.mu.Unlock()
	if len(todo) == 0 {
		return
	}
	reports := s.r.detect(ctx, todo, s.samples)
	s.mu.Lock()
	for _, rep := range reports {
		s.cache[probeKey(rep.Parent, rep.Type)] = rep
	}
	s.mu.Unlock()
}

// Report returns the verdict for one level, probing it if it is not known yet.
func (s *WildcardScanner) Report(ctx context.Context, parent string, qtype dnsfast.Type) WildcardReport {
	s.Prepare(ctx, []Probe{{parent, qtype}})
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache[probeKey(parent, qtype)]
}

// Classify reports whether host's answer is explained by a wildcard at any
// level between host and root, and returns the report that explains it.
func (s *WildcardScanner) Classify(ctx context.Context, host, root string, a Answer) (bool, WildcardReport) {

	parents := Parents(host, root)
	for i := len(parents) - 1; i >= 0; i-- {
		rep := s.Report(ctx, parents[i], a.Type)
		if rep.Matches(a) {
			return true, rep
		}
	}
	return false, WildcardReport{}
}

// Reports returns every cached verdict, for the run report.
func (s *WildcardScanner) Reports() []WildcardReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]WildcardReport, 0, len(s.cache))
	for _, r := range s.cache {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Parent != out[j].Parent {
			return out[i].Parent < out[j].Parent
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// WildcardSynthesized reports whether an answer was expanded from a
// wildcard, using the zone's own signature rather than a probe.
func WildcardSynthesized(a Answer) bool {
	if a.SignedLabels <= 0 || a.Outcome != Resolved {
		return false
	}
	return a.SignedLabels < labelCount(a.Name)
}

// labelCount counts a name's labels, ignoring a trailing dot and the root.
func labelCount(name string) int {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return 0
	}
	return strings.Count(name, ".") + 1
}
