package sources

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// newCrtName is the crt.name certificate-transparency index, operated by
// Defendio.
func newCrtName(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "crtname",
			Family:          source.FamilyCT,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://crt.name/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://crt.name/",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 100,
				Window:            24 * time.Hour,

				Burst:          5,
				MaxPages:       1,
				RequestTimeout: 120 * time.Second,

				MaxResponseBytes: 256 << 20,
			},

			CorrelationGroup: "certificate-transparency",
			Note: "100 requests per IP per day, enforced by the provider; subio cannot track " +
				"that across runs. The apex must be an eTLD+1, so a non-apex root is reported skipped.",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return crtNameFetch(ep, ctx, root, s, em)
		},
	}
}

func crtNameFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {

	u := ep.crtname + "/v1/search?apex=" + url.QueryEscape(root) + "&dates=1"
	meta, class, err := s.HTTP.GetLines(ctx, em.md.ID, u, map[string]string{"Accept": "text/plain"}, func(line []byte) error {
		name, stamp, _ := strings.Cut(strings.TrimSpace(string(line)), "\t")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		host, wild := stripWildcard(name)
		var attrs map[string]string
		if wild {
			attrs = map[string]string{"wildcard_certificate": "true"}
		}
		at := time.Time{}
		if t, perr := time.Parse(time.RFC3339, strings.TrimSpace(stamp)); perr == nil {
			at = t.UTC()
		}
		em.Observe(host, "ct-index", "", "", at, attrs)
		return nil
	})
	em.Meta(meta)
	if err != nil {
		switch {
		case meta != nil && meta.StatusCode == 400:

			return source.StatusSkipped, source.ErrScopeRejected, nil
		}
		return failureStatus(em, class), class, err
	}
	return source.StatusComplete, source.ErrNone, nil
}
