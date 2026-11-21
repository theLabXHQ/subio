package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

func newWayback(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "wayback",
			Slow:            true,
			Family:          source.FamilyWebArchive,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://archive.org/about/terms.php",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 15,
				Window:            time.Minute,
				Burst:             1,

				MaxPages: 40,
				PageSize: 1,

				RequestTimeout:   30 * time.Second,
				MaxResponseBytes: 64 << 20,
			},
			CorrelationGroup: "web-archive",
			Note:             "archived URLs are historical; a host here may be long gone or third-party",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return waybackFetch(ep, ctx, root, s, em)
		},
	}
}

// waybackSingleLimit bounds the fallback request.
const waybackSingleLimit = 50000

func waybackFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {

	query := ep.wayback + "/cdx/search/cdx?url=" + url.QueryEscape(root) +
		"&matchType=domain&output=text&collapse=urlkey"
	base := query + "&fl=timestamp,original"

	pages, class, err := waybackPageCount(ctx, query, s, em)
	if err != nil {
		return failureStatus(em, class), class, err
	}

	single := pages <= 0
	if single {
		pages = 1
	}
	if pages > em.md.Limits.MaxPages {
		pages = em.md.Limits.MaxPages
	}

	var lastClass source.ErrorClass
	failures, lines, usable := 0, 0, 0
	for page := 0; page < pages; page++ {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		u := base
		if single {
			u += "&limit=" + itoa(waybackSingleLimit)
		} else {
			u += "&page=" + itoa(page)
		}
		meta, c, err := s.HTTP.GetLines(ctx, em.md.ID, u, nil, func(line []byte) error {
			lines++
			emitted := &usable
			ts, rawURL, ok := strings.Cut(strings.TrimSpace(string(line)), " ")
			if !ok {
				em.Unusable()
				return nil
			}
			host := hostFromURL(rawURL)
			if host == "" {
				em.Unusable()
				return nil
			}

			seen := parseWaybackTime(ts)
			if seen.IsZero() {
				em.Unusable()
				return nil
			}
			em.Observe(host, "archived-url", ts,
				"https://web.archive.org/web/"+ts+"/"+rawURL, seen, nil)
			*emitted++
			return nil
		})
		em.Meta(meta)
		if err != nil {
			if c == source.ErrOversize {
				return source.StatusTruncated, c, nil
			}
			failures++
			lastClass = c

			if failures >= 3 {
				return failureStatus(em, lastClass), lastClass, err
			}
			continue
		}
	}
	switch {
	case lines > 0 && usable == 0:

		em.Note("the reply was not CDX data: no line carried an archived URL")
		return source.StatusFailed, source.ErrSchemaDrift, nil
	case failures > 0:
		return source.StatusPartial, lastClass, nil
	case !single && pages == em.md.Limits.MaxPages,
		single && lines >= waybackSingleLimit:

		return source.StatusTruncated, source.ErrPartialPagination, nil
	}
	return source.StatusComplete, source.ErrNone, nil
}

// waybackPageCount asks the CDX server how many pages the query has.
func waybackPageCount(ctx context.Context, base string, s *source.Session, em *emitter) (int, source.ErrorClass, error) {
	var pages int
	meta, class, err := s.HTTP.GetLines(ctx, em.md.ID, base+"&showNumPages=true", nil, func(line []byte) error {
		if n, convErr := strconv.Atoi(strings.TrimSpace(string(line))); convErr == nil && n > 0 {
			pages = n
		}
		return nil
	})
	em.Meta(meta)
	if err != nil {

		if (meta != nil && meta.StatusCode >= 500) ||
			class == source.ErrDeadline || class == source.ErrCancelled ||
			class == source.ErrRateLimited {
			return 0, class, err
		}
		return 0, source.ErrNone, nil
	}
	return pages, source.ErrNone, nil
}

// parseWaybackTime reads the archive's 14-digit timestamp.
func parseWaybackTime(v string) time.Time {
	if len(v) != 14 {
		return time.Time{}
	}
	t, err := time.Parse("20060102150405", v)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// hostFromURL extracts a bare hostname from an archived URL, tolerating the
// schemeless and port-bearing forms archives contain.
func hostFromURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := u.Hostname()
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

type ccIndex struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	CDXAPI string `json:"cdx-api"`
}

type ccRecord struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
}

func newCommonCrawl(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "commoncrawl",
			Slow:            true,
			Family:          source.FamilyWebArchive,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://commoncrawl.org/terms-of-use",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://commoncrawl.org/cdxj-index",
			Recursion:       source.RecursionFull,
			Limits: source.Limits{
				RequestsPerWindow: 20,
				Window:            time.Minute,
				Burst:             1,

				MaxPages:         3,
				RequestTimeout:   120 * time.Second,
				MaxResponseBytes: 64 << 20,
			},
			CorrelationGroup: "web-archive",
			Note:             "crawl data is under a limited license; Common Crawl advises legal counsel before commercial use",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return commonCrawlFetch(ep, ctx, root, s, em)
		},
	}
}

// commonCrawlLimit is the per-index result limit.
const commonCrawlLimit = 100000

func commonCrawlFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	var indexes []ccIndex
	meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, ep.ccCollinfo, nil, &indexes)
	em.Meta(meta)
	if err != nil {
		return failureStatus(em, class), class, err
	}
	if len(indexes) == 0 {

		return source.StatusFailed, source.ErrSchemaDrift, nil
	}

	n := em.md.Limits.MaxPages
	if n > len(indexes) {
		n = len(indexes)
	}
	var lastClass source.ErrorClass
	failures, truncated := 0, false
	for _, idx := range indexes[:n] {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		if idx.CDXAPI == "" {
			em.Unusable()
			continue
		}
		u := idx.CDXAPI + "?url=" + url.QueryEscape("*."+root) + "&output=json&fl=url,timestamp&limit=" + itoa(commonCrawlLimit)
		lines := 0
		m, c, err := s.HTTP.GetLines(ctx, em.md.ID, u, nil, func(line []byte) error {
			lines++
			var rec ccRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				em.Unusable()
				return nil
			}
			host := hostFromURL(rec.URL)
			if host == "" {
				em.Unusable()
				return nil
			}
			em.Observe(host, "crawled-url", idx.ID, "", parseWaybackTime(rec.Timestamp), map[string]string{"crawl": idx.ID})
			return nil
		})
		em.Meta(m)
		if err != nil {

			if m != nil && m.StatusCode == 404 {
				continue
			}
			failures++
			lastClass = c
		}
		if lines >= commonCrawlLimit {
			truncated = true
		}
	}
	if failures == n {
		return failureStatus(em, lastClass), lastClass, fmt.Errorf("commoncrawl: every queried index failed")
	}
	if failures > 0 {
		return source.StatusPartial, lastClass, nil
	}
	if truncated {
		return source.StatusTruncated, source.ErrPartialPagination, nil
	}
	return source.StatusComplete, source.ErrNone, nil
}
