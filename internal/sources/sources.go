// Package sources holds subio's own passive adapters.
package sources

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// emitter is the adapter-facing helper.
type emitter struct {
	out chan<- source.Result
	md  source.Metadata
	sum source.RunSummary
	// key is the resolved credential, empty when the source needs none.
	key string
}

// Observe sends one provider assertion downstream.
func (e *emitter) Observe(hostname, method, recordID, ref string, observedAt time.Time, attrs map[string]string) {
	if hostname == "" {
		return
	}
	e.sum.Raw++
	e.out <- source.Result{Observation: &source.Observation{
		Hostname:    hostname,
		SourceID:    e.md.ID,
		Method:      method,
		ObservedAt:  observedAt,
		RecordID:    recordID,
		EvidenceRef: ref,
		Attrs:       attrs,
	}}
}

// Unusable records something the provider sent that could not be read.
func (e *emitter) Unusable() { e.sum.Unusable++ }

// Note leaves one line for the operator.
func (e *emitter) Note(s string) { e.sum.Note = s }

// Meta folds one response's disclosed state into the run counters.
func (e *emitter) Meta(m *source.HTTPMeta) {
	if m == nil {
		e.sum.Requests++
		return
	}
	e.sum.Requests += m.Attempts
	if m.Attempts > 1 {
		e.sum.Retries += m.Attempts - 1
	}
	if m.StatusCode != 0 {
		e.sum.Pages++
	}
	e.sum.RateLimitHit += m.RateLimited
	if m.QuotaRemaining >= 0 {
		e.sum.QuotaRemaining = m.QuotaRemaining
	}
	if !m.ResetAt.IsZero() {
		e.sum.ResetAt = m.ResetAt
	}
}

// failureStatus names what a failed request means for this run's result set.
func failureStatus(e *emitter, class source.ErrorClass) source.Status {
	switch class {
	case source.ErrOversize:
		return source.StatusTruncated
	case source.ErrRateLimited:
		return source.StatusThrottled
	case source.ErrDeadline:
		return source.StatusTimedOut
	case source.ErrCancelled:
		return source.StatusCancelled
	}
	if e.sum.Raw > 0 {
		return source.StatusPartial
	}
	return source.StatusFailed
}

// cutStatus is the status of a result set known to be incomplete.
func cutStatus(e *emitter) (source.Status, source.ErrorClass, error) {
	if e.sum.Raw == 0 && e.sum.Unusable > 0 {
		return source.StatusFailed, source.ErrSchemaDrift, nil
	}
	return source.StatusTruncated, source.ErrPartialPagination, nil
}

// present is a JSON field that remembers whether its key appeared at all.
type present[T any] struct {
	Set   bool
	Value T
}

func (p *present[T]) UnmarshalJSON(b []byte) error {
	p.Set = true
	return json.Unmarshal(b, &p.Value)
}

// fetchFunc is one adapter's provider-specific work.
type fetchFunc func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error)

// base supplies the Provider boilerplate every adapter shares: the terms
// gate, the credential check, and the guarantee of exactly one terminal summary.
type base struct {
	md    source.Metadata
	fetch fetchFunc
}

func (b base) Metadata() source.Metadata { return b.md }

func (b base) Run(ctx context.Context, root string, s *source.Session) <-chan source.Result {
	out := make(chan source.Result, 128)
	go func() {
		defer close(out)
		em := &emitter{out: out, md: b.md, sum: source.RunSummary{
			SourceID:       b.md.ID,
			Started:        time.Now().UTC(),
			QuotaRemaining: -1,
		}}

		defer func() {
			if r := recover(); r != nil {
				em.sum.Status = source.StatusFailed
				em.sum.ErrorClass = source.ErrSchemaDrift
			}
			em.sum.Ended = time.Now().UTC()
			out <- source.Result{Summary: &em.sum}
		}()

		if ok, st := source.Allowed(b.md, s.Profile); !ok {
			em.sum.Status = st
			return
		}
		if b.md.Key == source.RequiredKey {
			k, ok := s.Secrets.Secret(b.md.ID)
			if !ok || k == "" {
				em.sum.Status = source.StatusMissingCredentials
				return
			}
			em.key = k
		} else if b.md.Key == source.OptionalKey {
			if k, ok := s.Secrets.Secret(b.md.ID); ok {
				em.key = k
			}
		}

		st, class, err := b.fetch(ctx, root, s, em)
		em.sum.Status = st
		em.sum.ErrorClass = class
		if err != nil && st == "" {
			em.sum.Status = source.StatusFailed
		}
		if em.sum.Status == source.StatusComplete && em.sum.Raw == 0 {

			if em.sum.Unusable > 0 {
				em.sum.Status, em.sum.ErrorClass = source.StatusFailed, source.ErrSchemaDrift
			} else {
				em.sum.Status = source.StatusEmpty
			}
		}
		if ctx.Err() != nil && !em.sum.Status.Complete() {
			em.sum.Status = source.StatusCancelled
		}

		em.sum.CapsSilently = b.md.CapsSilently && em.sum.Raw > 0
	}()
	return out
}

// endpoints holds each provider's base URL.
const termsReviewedAt = "2026-10-31"

type endpoints struct {
	crtsh           string
	crtshdb         string
	crtname         string
	anubis          string
	hackertarget    string
	certspotter     string
	wayback         string
	ccCollinfo      string
	github          string
	securitytrails  string
	chaos           string
	netlas          string
	shodan          string
	scanmalware     string
	shodanct        string
	subdomaincenter string
	thc             string
	urlscan         string
	censys          string
	fofa            string
	dnsrepo         string
	sitedossier     string
}

var defaultEndpoints = endpoints{
	crtsh:           "https://crt.sh",
	crtshdb:         "crt.sh:5432",
	crtname:         "https://crt.name",
	anubis:          "https://anubisdb.com",
	hackertarget:    "https://api.hackertarget.com",
	certspotter:     "https://api.certspotter.com",
	wayback:         "https://web.archive.org",
	ccCollinfo:      "https://index.commoncrawl.org/collinfo.json",
	github:          "https://api.github.com",
	securitytrails:  "https://api.securitytrails.com",
	chaos:           "https://dns.projectdiscovery.io",
	netlas:          "https://app.netlas.io",
	shodan:          "https://api.shodan.io",
	scanmalware:     "https://scanmalware.com",
	shodanct:        "https://ctl.shodan.io",
	subdomaincenter: "https://api.subdomain.center",
	thc:             "https://ip.thc.org",
	urlscan:         "https://urlscan.io",
	censys:          "https://api.platform.censys.io",
	fofa:            "https://fofa.info",
	dnsrepo:         "https://dnsrepo.noc.org",
	sitedossier:     "http://www.sitedossier.com",
}

// Registry holds the available adapters.
type Registry struct {
	byID map[string]source.Provider
}

// NewRegistry returns every adapter subio ships.
func NewRegistry() *Registry { return newRegistryWith(defaultEndpoints) }

func newRegistryWith(ep endpoints) *Registry {
	r := &Registry{byID: map[string]source.Provider{}}
	for _, p := range []source.Provider{
		newCrtSh(ep),
		newCrtShDB(ep),
		newCrtName(ep),
		newAnubis(ep),
		newHackerTarget(ep),
		newCertSpotter(ep),
		newWayback(ep),
		newCommonCrawl(ep),
		newGitHub(ep),
		newSecurityTrails(ep),
		newChaos(ep),
		newNetlas(ep),
		newShodan(ep),
		newScanMalware(ep),
		newShodanCT(ep),
		newSubdomainCenter(ep),
		newTHC(ep),
		newURLScan(ep),
		newCensys(ep),
		newFOFA(ep),
		newDNSRepo(ep),
		newSiteDossier(ep),
	} {
		r.byID[p.Metadata().ID] = p
	}
	return r
}

// All returns every adapter sorted by ID.
func (r *Registry) All() []source.Provider {
	out := make([]source.Provider, 0, len(r.byID))
	for _, p := range r.byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata().ID < out[j].Metadata().ID })
	return out
}

// ByID returns one adapter.
func (r *Registry) ByID(id string) (source.Provider, bool) {
	p, ok := r.byID[strings.ToLower(strings.TrimSpace(id))]
	return p, ok
}

// SelectWith is Select, with withSlow adding the adapters left out of the
// default selection for their cost.
func (r *Registry) SelectWith(include, exclude []string, withSlow bool) ([]source.Provider, []string) {
	var unknown []string
	chosen := map[string]source.Provider{}
	if len(include) == 0 {
		for id, p := range r.byID {

			if p.Metadata().OptIn || (p.Metadata().Slow && !withSlow) {
				continue
			}
			chosen[id] = p
		}
	} else {
		for _, id := range include {
			id = strings.ToLower(strings.TrimSpace(id))
			if id == "" {
				continue
			}
			p, ok := r.byID[id]
			if !ok {
				unknown = append(unknown, id)
				continue
			}
			chosen[id] = p
		}
	}
	for _, id := range exclude {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if _, ok := r.byID[id]; !ok {
			unknown = append(unknown, id)
			continue
		}
		delete(chosen, id)
	}
	out := make([]source.Provider, 0, len(chosen))
	for _, p := range chosen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata().ID < out[j].Metadata().ID })
	sort.Strings(unknown)
	return out, unknown
}

// joinPrefix turns a provider-returned label prefix into an FQDN.
func joinPrefix(prefix, root string) string {
	prefix = strings.TrimSpace(strings.Trim(prefix, "."))
	if prefix == "" {
		return root
	}
	if strings.EqualFold(prefix, root) || strings.HasSuffix(strings.ToLower(prefix), "."+root) {
		return prefix
	}
	return prefix + "." + root
}

// stripWildcard removes a leading "*.
func stripWildcard(name string) (string, bool) {
	n := strings.TrimSpace(name)
	if strings.HasPrefix(n, "*.") {
		return strings.TrimPrefix(n, "*."), true
	}
	return n, false
}

// observeName records one hostname as the provider returned it.
func observeName(em *emitter, name, method, recordID string, at time.Time) {
	host, wild := stripWildcard(name)
	if host == "" {
		em.Unusable()
		return
	}
	var attrs map[string]string
	if wild {
		attrs = map[string]string{"wildcard_certificate": "true"}
	}
	em.Observe(host, method, recordID, "", at, attrs)
}

// observeNameRow reads one element of an array of hostnames that states no time.
func observeNameRow(em *emitter, raw json.RawMessage, method string) {
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		em.Unusable()
		return
	}
	observeName(em, name, method, "", time.Time{})
}
