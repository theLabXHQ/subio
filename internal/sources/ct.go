package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// crtshEntry is one row of crt.sh's JSON output.
type crtshEntry struct {
	ID             int64  `json:"id"`
	NameValue      string `json:"name_value"`
	CommonName     string `json:"common_name"`
	IssuerName     string `json:"issuer_name"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
}

func newCrtSh(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "crtsh",
			Family:          source.FamilyCT,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://crt.sh/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://crt.sh/",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 12,
				Window:            time.Minute,
				Burst:             1,
				MaxPages:          1,
				RequestTimeout:    90 * time.Second,
				MaxResponseBytes:  96 << 20,
			},
			CorrelationGroup: "certificate-transparency",
			Note:             "shared public CT database; no published quota or SLA, expect timeouts",

			CapsSilently: true,
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return crtshFetch(ep, ctx, root, s, em)
		},
	}
}

// crtshAttempts is how many times crt.sh is asked before the run gives up on
// it.
const crtshAttempts = 3

func crtshFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {

	u := ep.crtsh + "/?q=" + url.QueryEscape("%."+root) + "&output=json"
	row := func(raw json.RawMessage) error {
		var e crtshEntry
		if err := json.Unmarshal(raw, &e); err != nil || strings.TrimSpace(e.NameValue) == "" {

			em.Unusable()
			return nil
		}
		at := parseCrtShTime(e.EntryTimestamp)
		if at.IsZero() {
			at = parseCrtShTime(e.NotBefore)
		}
		ref := ""
		if e.ID != 0 {
			ref = fmt.Sprintf("https://crt.sh/?id=%d", e.ID)
		}
		rec := fmt.Sprintf("%d", e.ID)
		seen := map[string]bool{}
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			host, wild := stripWildcard(name)
			attrs := map[string]string{"issuer": truncate(e.IssuerName, 120)}
			if wild {
				attrs["wildcard_certificate"] = "true"
			}
			em.Observe(host, "certificate-san", rec, ref, at, attrs)
		}
		return nil
	}

	var lastClass source.ErrorClass
	var lastErr error
	for attempt := 0; attempt < crtshAttempts; attempt++ {
		before := em.sum.Raw
		meta, class, err := s.HTTP.GetJSONArray(ctx, em.md.ID, u, nil, row)
		em.Meta(meta)
		if err == nil {
			return source.StatusComplete, source.ErrNone, nil
		}
		lastClass, lastErr = class, err
		if em.sum.Raw > before {

			return failureStatus(em, class), class, err
		}

		if class == source.ErrOversize || ctx.Err() != nil {
			break
		}
	}

	return failureStatus(em, lastClass), lastClass, lastErr
}

// parseCrtShTime handles crt.sh's timestamps, which carry no zone and vary
// in fractional-second precision.
func parseCrtShTime(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// newShodanCT is Shodan's certificate-transparency mirror.
func newShodanCT(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "shodanct",
			Family:          source.FamilyCT,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://static.shodan.io/legal/terms.html",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://ctl.shodan.io/",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 20,
				Window:            time.Minute,
				Burst:             2,
				MaxPages:          1,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  64 << 20,
			},

			CorrelationGroup: "shodan",
			Note: "Shodan's CT mirror, so not independent of the shodan adapter; the page " +
				"states no quota or reuse right, and the rate here is self-imposed",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return shodanCTFetch(ep, ctx, root, s, em)
		},
	}
}

func shodanCTFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.shodanct + "/api/v1/domain/" + url.PathEscape(root) + "/hostnames"

	meta, class, err := s.HTTP.GetJSONArray(ctx, em.md.ID, u, nil, func(raw json.RawMessage) error {
		observeNameRow(em, raw, "ct-index")
		return nil
	})
	em.Meta(meta)
	if err != nil {

		if meta != nil && meta.StatusCode == 200 && meta.Bytes == 0 && em.sum.Raw == 0 {
			return source.StatusEmpty, source.ErrNone, nil
		}
		return failureStatus(em, class), class, err
	}
	return source.StatusComplete, source.ErrNone, nil
}

type certSpotterIssuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	Issuer    struct {
		Name string `json:"name"`
	} `json:"issuer"`
}

func newCertSpotter(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "certspotter",
			Slow:            true,
			Family:          source.FamilyCT,
			Key:             source.OptionalKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://sslmate.com/ct_search_api/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://sslmate.com/help/reference/ct_search_api_v1",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 10,
				Window:            time.Hour,
				Burst:             2,
				MaxPages:          64,
				RequestTimeout:    30 * time.Second,
				MaxResponseBytes:  32 << 20,
			},
			CorrelationGroup: "certificate-transparency",
			Note: "SSLMate product; full-domain search is metered at 10/hour on the Small plan. " +
				"Without a key it still answers, but SSLMate documents unauthenticated use as " +
				"personal or evaluation only, so a commercial run needs the key",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return certSpotterFetch(ep, ctx, root, s, em)
		},
	}
}

func certSpotterFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	// No header at all when there is no key: "Bearer " with nothing after it is
	// a malformed credential, and the API answers an unauthenticated query only
	// when the header is absent.
	var hdr map[string]string
	if em.key != "" {
		hdr = map[string]string{"Authorization": "Bearer " + em.key}
	}
	after := ""
	for page := 0; page < em.md.Limits.MaxPages; page++ {
		u := ep.certspotter + "/v1/issuances?domain=" + url.QueryEscape(root) +
			"&include_subdomains=true&expand=dns_names&expand=issuer"
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		var batch []certSpotterIssuance
		meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, hdr, &batch)
		em.Meta(meta)
		if err != nil {

			return failureStatus(em, class), class, err
		}

		if len(batch) == 0 {
			return source.StatusComplete, source.ErrNone, nil
		}
		for _, iss := range batch {
			at := time.Time{}
			if t, err := time.Parse(time.RFC3339, iss.NotBefore); err == nil {
				at = t.UTC()
			}
			attrs := map[string]string{}
			if iss.Issuer.Name != "" {
				attrs["issuer"] = truncate(iss.Issuer.Name, 120)
			}
			if len(iss.DNSNames) == 0 {

				em.Unusable()
			}
			for _, name := range iss.DNSNames {
				host, wild := stripWildcard(name)
				a := attrs
				if wild {
					a = map[string]string{"wildcard_certificate": "true"}
					if iss.Issuer.Name != "" {
						a["issuer"] = truncate(iss.Issuer.Name, 120)
					}
				}
				em.Observe(host, "certificate-san", iss.ID, "", at, a)
			}
			after = iss.ID
		}
	}

	return source.StatusTruncated, source.ErrPartialPagination, nil
}
