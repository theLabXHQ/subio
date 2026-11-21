package sources

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// dnsrepoRow is a link the result table carries for every name it holds.
var dnsrepoRow = regexp.MustCompile(`href="/\?domain=([A-Za-z0-9._*-]+)\.?"`)

// dnsrepoHeading is on every result page, with results or without.
const dnsrepoHeading = "DNS Database information for Domain"

// dnsrepoCapNotice is the page's own statement that it cut the answer.
const dnsrepoCapNotice = "Limiting to the first"

func newDNSRepo(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:     "dnsrepo",
			Family: source.FamilyPassiveDNS,

			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://dnsrepo.noc.org/",
			TermsReviewedAt: "2026-11-21",
			DocsURL:         "https://dnsrepo.noc.org/",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 10,
				Window:            time.Minute,
				Burst:             1,
				ResultCap:         150,
				MaxPages:          1,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  8 << 20,
			},
			Note: "an HTML page, not an API: keyless answers stop at 150 names and say so on the " +
				"page, which is reported as truncated (plan_limit). Names are historical DNS, so " +
				"some no longer resolve",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return dnsrepoFetch(ep, ctx, root, s, em)
		},
	}
}

func dnsrepoFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	u := ep.dnsrepo + "/?domain=" + url.QueryEscape(root)
	heading, capped := false, false
	meta, class, err := s.HTTP.GetLines(ctx, em.md.ID, u, map[string]string{"Accept": "text/html"}, func(line []byte) error {
		text := string(line)
		if strings.Contains(text, dnsrepoHeading) {
			heading = true
		}
		if strings.Contains(text, dnsrepoCapNotice) {
			capped = true
		}
		for _, m := range dnsrepoRow.FindAllStringSubmatch(text, -1) {
			h, _ := stripWildcard(strings.TrimSuffix(m[1], "."))
			em.Observe(h, "passive-dns", "", "", time.Time{}, nil)
		}
		return nil
	})
	em.Meta(meta)
	if err != nil {
		return failureStatus(em, class), class, err
	}
	if !heading {
		em.Note("the reply was not the dnsrepo result page: its heading was missing")
		return source.StatusFailed, source.ErrSchemaDrift, nil
	}
	if capped {
		return source.StatusTruncated, source.ErrPlanLimit, nil
	}
	if em.sum.Raw == 0 {
		return source.StatusEmpty, source.ErrNone, nil
	}
	return source.StatusComplete, source.ErrNone, nil
}

// sitedossierRow is the link each listed site carries.
var sitedossierRow = regexp.MustCompile(`href="/site/([A-Za-z0-9._-]+)"`)

// sitedossierTitle is the heading of a real listing page.
const sitedossierTitle = "Parent domain:"

// sitedossierNext is the link to the next hundred, absent on the last page.
const sitedossierNext = "Show next 100 items"

// sitedossierPages bounds a run to a thousand names, well past where the
// site stops a keyless client in practice.
const sitedossierPages = 10

func newSiteDossier(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "sitedossier",
			Family:          source.FamilyCurated,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "http://www.sitedossier.com/",
			TermsReviewedAt: "2026-11-21",
			DocsURL:         "http://www.sitedossier.com/",
			Recursion:       source.RecursionFull,

			OptIn: true,

			Limits: source.Limits{
				RequestsPerWindow: 1,
				Window:            3 * time.Second,
				Burst:             1,
				MaxPages:          sitedossierPages,
				RequestTimeout:    45 * time.Second,
				MaxResponseBytes:  4 << 20,
			},
			Note: "an HTML listing served over plain HTTP, the only scheme the site answers on; " +
				"no credential is sent. The site stops automated clients after a few pages, which " +
				"is reported as throttled with the names already read kept",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return sitedossierFetch(ep, ctx, root, s, em)
		},
	}
}

func sitedossierFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	base := ep.sitedossier + "/parentdomain/" + url.PathEscape(root)
	for page := 0; page < sitedossierPages; page++ {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		u := base
		if page > 0 {
			u += "/" + strconv.Itoa(page*100+1)
		}
		listing, more := false, false
		meta, class, err := s.HTTP.GetLines(ctx, em.md.ID, u, map[string]string{"Accept": "text/html"}, func(line []byte) error {
			text := string(line)
			if strings.Contains(text, sitedossierTitle) {
				listing = true
			}
			if strings.Contains(text, sitedossierNext) {
				more = true
			}
			for _, m := range sitedossierRow.FindAllStringSubmatch(text, -1) {
				em.Observe(strings.TrimSuffix(m[1], "."), "curated-listing", "", "", time.Time{}, nil)
			}
			return nil
		})
		em.Meta(meta)
		if err != nil {
			if page > 0 && class == source.ErrRedirectRefused {

				em.Note("the site stopped answering the listing after page " + strconv.Itoa(page))
				return source.StatusThrottled, source.ErrRateLimited, nil
			}
			return failureStatus(em, class), class, err
		}
		if !listing {
			if page > 0 {
				em.Note("the site stopped answering the listing after page " + strconv.Itoa(page))
				return source.StatusThrottled, source.ErrRateLimited, nil
			}
			em.Note("the reply was not a sitedossier listing - the site blocks automated clients after a few requests, or changed its page")
			return source.StatusFailed, source.ErrSchemaDrift, nil
		}
		if !more {
			if em.sum.Raw == 0 {
				return source.StatusEmpty, source.ErrNone, nil
			}
			return source.StatusComplete, source.ErrNone, nil
		}
	}
	return source.StatusTruncated, source.ErrPartialPagination, nil
}
