package sources

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// newAnubis is the AnubisDB aggregated subdomain index.
func newAnubis(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "anubis",
			Family:          source.FamilyCurated,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://anubisdb.com/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://anubisdb.com/",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 20,
				Window:            time.Minute,
				Burst:             2,
				MaxPages:          1,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  64 << 20,
			},
			Note: "aggregated index whose upstream lineage is not published; it may re-export " +
				"certificate transparency or passive DNS, so treat agreement with crtsh or " +
				"crtname as possibly the same evidence rather than independent confirmation",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return anubisFetch(ep, ctx, root, s, em)
		},
	}
}

func anubisFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.anubis + "/anubis/subdomains/" + url.PathEscape(root)
	var names []string
	meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, map[string]string{"Accept": "application/json"}, &names)
	em.Meta(meta)
	if err != nil {

		if meta != nil && meta.StatusCode == 404 {
			return source.StatusEmpty, source.ErrNone, nil
		}
		return failureStatus(em, class), class, err
	}
	for _, n := range names {
		host, wild := stripWildcard(n)
		var attrs map[string]string
		if wild {
			attrs = map[string]string{"wildcard_certificate": "true"}
		}

		em.Observe(host, "aggregated-index", "", "", time.Time{}, attrs)
	}
	return source.StatusComplete, source.ErrNone, nil
}

// newHackerTarget is HackerTarget's hostsearch endpoint, which assetfinder
// also uses.
func newHackerTarget(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:     "hackertarget",
			Family: source.FamilyPassiveDNS,

			Key:             source.OptionalKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://hackertarget.com/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://hackertarget.com/ip-tools/",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 50,
				Window:            24 * time.Hour,
				Burst:             3,
				MaxPages:          1,
				ResultCap:         50,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  16 << 20,
			},
			Note: "free tier is 50 API calls per day, enforced per IP by the provider; subio " +
				"cannot track that across runs. It also caps the reply at 50 rows, which the " +
				"provider does not document and does not mark in the body, so a reply of " +
				"exactly 50 is reported as truncated rather than complete. Addresses in the " +
				"reply are recorded as evidence attributes, not as DNS observations",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return hackerTargetFetch(ep, ctx, root, s, em)
		},
	}
}

func hackerTargetFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.hackertarget + "/hostsearch/?q=" + url.QueryEscape(root)
	if em.key != "" {
		u += "&apikey=" + url.QueryEscape(em.key)
	}
	// The endpoint reports quota exhaustion and bad input as a 200 with a
	// message body, so the body has to be inspected rather than trusted.
	var refusal string
	meta, class, err := s.HTTP.GetLines(ctx, em.md.ID, u, map[string]string{"Accept": "text/plain"}, func(line []byte) error {
		text := strings.TrimSpace(string(line))
		if text == "" {
			return nil
		}
		host, ip, hasIP := strings.Cut(text, ",")
		host = strings.TrimSpace(host)
		if host == "" {
			return nil
		}
		if !hasIP || strings.ContainsAny(host, " ") {

			if refusal == "" {
				refusal = truncate(text, 120)
			}
			return nil
		}
		var attrs map[string]string
		if ip = strings.TrimSpace(ip); ip != "" {
			attrs = map[string]string{"provider_reported_address": ip}
		}
		h, _ := stripWildcard(host)
		em.Observe(h, "passive-dns", "", "", time.Time{}, attrs)
		return nil
	})
	em.Meta(meta)
	if err != nil {
		return failureStatus(em, class), class, err
	}
	if em.sum.Raw == 0 && refusal != "" {

		if strings.Contains(strings.ToLower(refusal), "exceeded") ||
			strings.Contains(strings.ToLower(refusal), "limit") {
			return source.StatusThrottled, source.ErrRateLimited, nil
		}
		return source.StatusFailed, source.ErrSchemaDrift, nil
	}

	if em.sum.Raw >= em.md.Limits.ResultCap {
		if em.key == "" {
			return source.StatusTruncated, source.ErrPlanLimit, nil
		}
		return source.StatusTruncated, source.ErrPartialPagination, nil
	}
	return source.StatusComplete, source.ErrNone, nil
}

// newSubdomainCenter is A.R.P.
func newSubdomainCenter(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:     "subdomaincenter",
			Family: source.FamilyCurated,
			Key:    source.NoKey,

			Terms: source.TermsBlockedCommercial,

			TermsURL:        "https://www.arpsyndicate.io/policy.html",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://www.subdomain.center/",

			Recursion: source.RecursionUnknown,

			Limits: source.Limits{
				RequestsPerWindow: 1,
				Window:            13 * time.Second,
				Burst:             1,
				ResultCap:         500,
				MaxPages:          1,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  8 << 20,
			},
			Note: "keyless answers are at most 500 names in random order, so a full answer " +
				"reports truncated and two runs can differ. No key is used. Lineage is not " +
				"published. The operator's general policy licenses personal, non-commercial use only",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return subdomainCenterFetch(ep, ctx, root, s, em)
		},
	}
}

func subdomainCenterFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.subdomaincenter + "/?domain=" + url.QueryEscape(root) + "&engine=cuttlefish"
	rows := 0
	meta, class, err := s.HTTP.GetJSONArray(ctx, em.md.ID, u, map[string]string{"Accept": "application/json"}, func(raw json.RawMessage) error {
		rows++
		observeNameRow(em, raw, "aggregated-index")
		return nil
	})
	em.Meta(meta)
	if err != nil {
		return failureStatus(em, class), class, err
	}

	if rows >= em.md.Limits.ResultCap || meta.MoreResults {
		st, c, err := cutStatus(em)

		if c == source.ErrPartialPagination && rows >= em.md.Limits.ResultCap {
			c = source.ErrPlanLimit
		}
		return st, c, err
	}
	return source.StatusComplete, source.ErrNone, nil
}

// thcPageLimit is the page size asked of ip.thc.org.
const thcPageLimit = 1000

// newTHC is The Hacker's Choice's ip.thc.org subdomain lookup.
func newTHC(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "thc",
			Family:          source.FamilyPassiveDNS,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://ip.thc.org/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://ip.thc.org/docs/API/subdomain-lookup",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 30,
				Window:            time.Minute,
				Burst:             250,
				MaxPages:          250,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  16 << 20,
			},
			Note: "250-token burst and 0.5 tokens/second per IP, enforced by the provider; " +
				"subio cannot track that across runs, and assumes one token per page. No data licence is stated",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return thcFetch(ep, ctx, root, s, em)
		},
	}
}

type thcRequest struct {
	Domain    string `json:"domain"`
	PageState string `json:"page_state"`
	Limit     int    `json:"limit"`
}

type thcDomain struct {
	Domain string `json:"domain"`
}

func thcFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.thc + "/api/v1/lookup/subdomains"
	state := ""
	for page := 0; page < em.md.Limits.MaxPages; page++ {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		var out struct {
			Domains       present[[]thcDomain] `json:"domains"`
			NextPageState string               `json:"next_page_state"`
		}
		meta, class, err := s.HTTP.PostJSON(ctx, em.md.ID, u, nil,
			thcRequest{Domain: root, PageState: state, Limit: thcPageLimit}, &out)
		em.Meta(meta)
		if err != nil {
			return failureStatus(em, class), class, err
		}
		if !out.Domains.Set {
			return failureStatus(em, source.ErrSchemaDrift), source.ErrSchemaDrift, nil
		}

		for _, d := range out.Domains.Value {
			observeName(em, d.Domain, "passive-dns", "", time.Time{})
		}
		if out.NextPageState == "" {
			return source.StatusComplete, source.ErrNone, nil
		}

		if out.NextPageState == state {
			return failureStatus(em, source.ErrPaginationLoop), source.ErrPaginationLoop, nil
		}
		state = out.NextPageState
	}

	return cutStatus(em)
}
