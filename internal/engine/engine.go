// Package engine runs the selected adapters against the authorized roots and
// folds their observations into a ledger.
package engine

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/scope"
	"github.com/theLabXHQ/subio/internal/source"
)

// Engine coordinates a discovery run.
type Engine struct {
	HTTP    source.Doer
	Secrets source.SecretSource
	Profile source.Profile
	// OnFinding, when set, is called once per newly discovered hostname as it is
	// found, which is what makes time-to-first-result a property of the first
	// provider response rather than of the slowest one.
	OnFinding func(host, root string, obs source.Observation)
}

// Run executes every provider against every root.
func (e *Engine) Run(ctx context.Context, roots *scope.Set, providers []source.Provider, led *ledger.Ledger) {
	var (
		mu sync.Mutex

		// summaries accumulate per source across roots.
		sums = map[string]*ledger.SourceRun{}
	)

	register := func(md source.Metadata) *ledger.SourceRun {
		mu.Lock()
		defer mu.Unlock()
		r, ok := sums[md.ID]
		if !ok {
			r = &ledger.SourceRun{
				SourceID:       md.ID,
				Family:         string(md.Family),
				TermsState:     md.Terms.String(),
				QuotaRemaining: -1,
			}
			sums[md.ID] = r
		}
		return r
	}

	sess := &source.Session{HTTP: e.HTTP, Secrets: e.Secrets, Profile: e.Profile}
	if dl, ok := ctx.Deadline(); ok {
		sess.Deadline = dl
	}

	var wg sync.WaitGroup
	for _, root := range roots.Roots() {
		for _, p := range providers {
			wg.Add(1)
			go func(root scope.Root, p source.Provider) {
				defer wg.Done()
				md := p.Metadata()
				agg := register(md)
				started := time.Now()
				// Counted per run, not per source: another root's good names must not hide
				// that this response held nothing readable.
				var inScope, malformed int

				for res := range p.Run(ctx, root.String(), sess) {
					switch {
					case res.Observation != nil:
						obs := *res.Observation
						host, matched, err := roots.Admit(obs.Hostname)
						mu.Lock()
						switch {
						case err == scope.ErrOutOfScope:
							agg.OutOfScope++
							mu.Unlock()
							continue
						case err != nil:
							agg.Malformed++
							malformed++
							mu.Unlock()
							continue
						}
						agg.InScope++
						inScope++
						mu.Unlock()

						if led.Observe(host, matched.String(), md.Family, obs) && e.OnFinding != nil {
							e.OnFinding(host, matched.String(), obs)
						}

					case res.Summary != nil:
						s := res.Summary
						mu.Lock()
						agg.Requests += s.Requests
						agg.Pages += s.Pages
						agg.Retries += s.Retries
						agg.RateLimitHits += s.RateLimitHit
						agg.RawObservation += s.Raw
						agg.Malformed += s.Unusable
						agg.DurationMS += time.Since(started).Milliseconds()
						if s.QuotaRemaining >= 0 {
							agg.QuotaRemaining = s.QuotaRemaining
						}
						if !s.ResetAt.IsZero() {
							v := s.ResetAt.UTC().Format(time.RFC3339)
							agg.ResetAt = &v
						}

						status, class := s.Status, s.ErrorClass
						if status.Complete() && inScope == 0 && malformed > 0 {
							status, class = source.StatusFailed, source.ErrSchemaDrift
						}

						agg.Status = worseStatus(agg.Status, string(status))
						if class != source.ErrNone {
							agg.ErrorClass = string(class)
						}
						if s.Note != "" {
							agg.Note = s.Note
						}

						if s.CapsSilently {
							agg.CapsSilently = true
						}
						mu.Unlock()
					}
				}
			}(root, p)
		}
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	contrib := led.SourceContribution()
	ids := make([]string, 0, len(sums))
	for id := range sums {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := sums[id]
		c := contrib[id]
		r.UniqueNames = c.Unique
		r.MarginalNames = c.Exclusive
		if r.Status == "" {
			r.Status = string(source.StatusSkipped)
		}
		led.AddSourceRun(*r)
	}
}

// statusRank orders statuses from best to worst so that combining a source's
// results across several roots cannot upgrade an incomplete run.
var statusRank = map[string]int{
	string(source.StatusComplete):           0,
	string(source.StatusEmpty):              1,
	string(source.StatusTruncated):          2,
	string(source.StatusPartial):            3,
	string(source.StatusThrottled):          4,
	string(source.StatusTimedOut):           5,
	string(source.StatusCancelled):          6,
	string(source.StatusSkipped):            7,
	string(source.StatusMissingCredentials): 8,
	string(source.StatusTermsBlocked):       9,
	string(source.StatusFailed):             10,
}

func worseStatus(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	if statusRank[b] > statusRank[a] {
		return b
	}
	return a
}
