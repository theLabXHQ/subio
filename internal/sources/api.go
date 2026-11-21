package sources

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

func newSecurityTrails(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "securitytrails",
			Family:          source.FamilyPassiveDNS,
			Key:             source.RequiredKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://securitytrails.com/corp/terms",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://docs.securitytrails.com/docs/quotas-rate-limits",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 60,
				Window:            time.Minute,
				Burst:             2,
				MaxPages:          1,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  32 << 20,
			},
			Note: "monthly quota is account-specific; provider recommends caching, which is not redistribution permission",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return securityTrailsFetch(ep, ctx, root, s, em)
		},
	}
}

func securityTrailsFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.securitytrails + "/v1/domain/" + url.PathEscape(root) +
		"/subdomains?children_only=false&include_inactive=true"
	var out struct {
		Subdomains     present[[]string] `json:"subdomains"`
		SubdomainCount int               `json:"subdomain_count"`
	}
	meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, map[string]string{"APIKEY": em.key, "Accept": "application/json"}, &out)
	em.Meta(meta)
	if err != nil {
		return failureStatus(em, class), class, err
	}
	if !out.Subdomains.Set {
		return source.StatusFailed, source.ErrSchemaDrift, nil
	}
	for _, p := range out.Subdomains.Value {

		em.Observe(joinPrefix(p, root), "passive-dns", "", "", time.Time{}, nil)
	}

	if out.SubdomainCount > 0 && len(out.Subdomains.Value) < out.SubdomainCount {
		return source.StatusTruncated, source.ErrPartialPagination, nil
	}
	return source.StatusComplete, source.ErrNone, nil
}

func newChaos(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "chaos",
			Family:          source.FamilyCurated,
			Key:             source.RequiredKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://projectdiscovery.io/terms",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://chaos.projectdiscovery.io/docs/api",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 30,
				Window:            time.Minute,
				Burst:             1,
				MaxPages:          1,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  32 << 20,
			},
			Note: "the client's MIT license does not grant rights over the dataset it returns",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return chaosFetch(ep, ctx, root, s, em)
		},
	}
}

func chaosFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.chaos + "/dns/" + url.PathEscape(root) + "/subdomains"
	var out struct {
		Domain     string            `json:"domain"`
		Subdomains present[[]string] `json:"subdomains"`
	}
	meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, map[string]string{"Authorization": em.key, "Accept": "application/json"}, &out)
	em.Meta(meta)
	if err != nil {
		return failureStatus(em, class), class, err
	}
	if !out.Subdomains.Set {
		return source.StatusFailed, source.ErrSchemaDrift, nil
	}
	for _, p := range out.Subdomains.Value {
		em.Observe(joinPrefix(p, root), "curated-dataset", "", "", time.Time{}, nil)
	}
	return source.StatusComplete, source.ErrNone, nil
}

func newShodan(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "shodan",
			Family:          source.FamilyScanEngine,
			Key:             source.RequiredKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://www.shodan.io/static/terms.pdf",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://developer.shodan.io/api",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 60,
				Window:            time.Minute,
				Burst:             1,
				PageSize:          100,
				MaxPages:          10,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  32 << 20,
			},

			CorrelationGroup: "shodan",
			Note:             "scan observations, not DNS truth; query credits are plan-dependent",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return shodanFetch(ep, ctx, root, s, em)
		},
	}
}

type shodanEntry struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	LastSeen  string `json:"last_seen"`
}

func shodanFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {

	base := ep.shodan + "/dns/domain/" + url.PathEscape(root) + "?key=" + url.QueryEscape(em.key)
	for page := 1; page <= em.md.Limits.MaxPages; page++ {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		var out struct {
			Domain     string                 `json:"domain"`
			Subdomains present[[]string]      `json:"subdomains"`
			Data       present[[]shodanEntry] `json:"data"`
			More       bool                   `json:"more"`
		}
		meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, base+"&page="+itoa(page),
			map[string]string{"Accept": "application/json"}, &out)
		em.Meta(meta)
		if err != nil {
			return failureStatus(em, class), class, err
		}
		if !out.Subdomains.Set && !out.Data.Set {
			return failureStatus(em, source.ErrSchemaDrift), source.ErrSchemaDrift, nil
		}

		for _, d := range out.Data.Value {
			at := time.Time{}
			for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.999999"} {
				if t, err := time.Parse(layout, d.LastSeen); err == nil {
					at = t.UTC()
					break
				}
			}
			attrs := map[string]string{}
			if d.Type != "" {
				attrs["record_type"] = d.Type
			}
			em.Observe(joinPrefix(d.Subdomain, root), "scan-observation", "", "", at, attrs)
		}
		for _, p := range out.Subdomains.Value {
			em.Observe(joinPrefix(p, root), "scan-observation", "", "", time.Time{}, nil)
		}
		if !out.More {
			return source.StatusComplete, source.ErrNone, nil
		}
	}
	return source.StatusTruncated, source.ErrPartialPagination, nil
}

func newNetlas(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "netlas",
			Family:          source.FamilyScanEngine,
			Key:             source.RequiredKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://netlas.io/terms_of_service/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://docs.netlas.io/api-reference/",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 60,
				Window:            time.Minute,
				Burst:             2,
				PageSize:          20,
				ResultCap:         10000,
				MaxPages:          500,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  16 << 20,
			},
			Note: "only the first 10 000 results are retrievable; certificate collections are limited to 3 req/min",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return netlasFetch(ep, ctx, root, s, em)
		},
	}
}

type netlasItem struct {
	Data struct {
		Domain string `json:"domain"`
	} `json:"data"`
}

func netlasFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	hdr := map[string]string{"X-API-Key": em.key, "Accept": "application/json"}
	const pageSize = 20
	for start := 0; start < em.md.Limits.ResultCap; start += pageSize {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		u := fmt.Sprintf(ep.netlas+"/api/domains/?q=%s&start=%d&fields=domain",
			url.QueryEscape("domain:*."+root), start)
		var out struct {
			Items present[[]netlasItem] `json:"items"`
		}
		meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, hdr, &out)
		em.Meta(meta)
		if err != nil {
			return failureStatus(em, class), class, err
		}
		if !out.Items.Set {
			return failureStatus(em, source.ErrSchemaDrift), source.ErrSchemaDrift, nil
		}
		for _, it := range out.Items.Value {
			em.Observe(it.Data.Domain, "scan-observation", "", "", time.Time{}, nil)
		}
		if len(out.Items.Value) < pageSize {
			return source.StatusComplete, source.ErrNone, nil
		}
	}

	return source.StatusTruncated, source.ErrPartialPagination, nil
}
