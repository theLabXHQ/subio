package sources

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// urlscanPageSize is the largest page the keyless search serves.
const urlscanPageSize = 100

// newURLScan is urlscan.io's search over the pages its crawler has fetched.
func newURLScan(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "urlscan",
			Family:          source.FamilyScanEngine,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://urlscan.io/about/terms/",
			TermsReviewedAt: "2026-11-15",
			DocsURL:         "https://urlscan.io/docs/search/",
			Recursion:       source.RecursionFull,
			Limits: source.Limits{

				RequestsPerWindow: 30,
				Window:            time.Minute,
				Burst:             2,
				MaxPages:          10,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  64 << 20,
			},
			Note: "a page is indexed because a crawler loaded it, so a hostname here was " +
				"reachable at crawl time but may be third-party: a `domain:` search matches " +
				"pages that reference the root as well as pages served from it, and on " +
				"kernel.org 33 results carried 8 in-scope names. The 30-per-minute limit is " +
				"keyed to your IP address rather than an account",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return urlscanFetch(ep, ctx, root, s, em)
		},
	}
}

// urlscanResult is only the part of a search hit subio uses.
type urlscanResult struct {
	Page struct {
		Domain string `json:"domain"`
	} `json:"page"`
	Task struct {
		Domain string `json:"domain"`
		Time   string `json:"time"`
	} `json:"task"`
	Sort []any `json:"sort"`
}

type urlscanPage struct {
	Results []urlscanResult `json:"results"`
	Total   int             `json:"total"`
	HasMore bool            `json:"has_more"`
}

func urlscanFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	var lastClass source.ErrorClass
	after := ""
	for page := 0; page < em.md.Limits.MaxPages; page++ {
		u := fmt.Sprintf("%s/api/v1/search/?q=%s&size=%d", ep.urlscan,
			url.QueryEscape("domain:"+root), urlscanPageSize)
		if after != "" {
			u += "&search_after=" + url.QueryEscape(after)
		}
		var body urlscanPage
		meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, map[string]string{"Accept": "application/json"}, &body)
		em.Meta(meta)
		if err != nil {

			if meta != nil && meta.StatusCode == 404 {
				if page == 0 {
					return source.StatusEmpty, source.ErrNone, nil
				}
				return source.StatusComplete, source.ErrNone, nil
			}
			if page > 0 {

				em.Note(fmt.Sprintf("stopped after %d page(s): %v", page, err))
				return source.StatusPartial, class, nil
			}
			return failureStatus(em, class), class, err
		}
		lastClass = class
		for _, r := range body.Results {
			// The crawl time is when a browser actually fetched the page, so it is an
			// observation of the hostname rather than the time subio asked.
			var at time.Time
			if t, perr := time.Parse(time.RFC3339, r.Task.Time); perr == nil {
				at = t
			}
			for _, host := range []string{r.Page.Domain, r.Task.Domain} {
				if host = strings.TrimSpace(host); host == "" {
					continue
				}
				em.Observe(strings.TrimSuffix(strings.ToLower(host), "."),
					"browser-crawl", "", "", at, nil)
			}
		}
		if !body.HasMore || len(body.Results) == 0 {
			return source.StatusComplete, source.ErrNone, nil
		}

		last := body.Results[len(body.Results)-1].Sort
		if len(last) < 2 {
			em.Note("the answer said more results exist but carried no cursor to reach them")
			return source.StatusPartial, lastClass, nil
		}
		after = fmt.Sprintf("%v,%v", last[0], last[1])
	}

	em.Note(fmt.Sprintf("stopped at the %d-page ceiling with more results available", em.md.Limits.MaxPages))
	return source.StatusPartial, lastClass, nil
}
