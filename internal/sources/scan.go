package sources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

// Censys Platform API v3.
func newCensys(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "censys",
			Family:          source.FamilyScanEngine,
			Key:             source.RequiredKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://censys.com/terms-of-service/",
			TermsReviewedAt: "2026-11-20",
			DocsURL:         "https://docs.censys.com/reference/v3-globaldata-search-query",
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
			Note: "each page after the first costs one credit; key is a Platform personal access token",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return censysFetch(ep, ctx, root, s, em)
		},
	}
}

type censysHit struct {
	Certificate *struct {
		Resource struct {
			Names []string `json:"names"`
		} `json:"resource"`
	} `json:"certificate_v1"`
	Webproperty *struct {
		Resource struct {
			Hostname string `json:"hostname"`
		} `json:"resource"`
	} `json:"webproperty_v1"`
	Host *struct {
		Resource struct {
			DNS *struct {
				Names []string `json:"names"`
			} `json:"dns"`
		} `json:"resource"`
	} `json:"host_v1"`
}

func censysFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	hdr := map[string]string{"Authorization": "Bearer " + em.key, "Accept": "application/json"}
	u := ep.censys + "/v3/global/search/query"
	token := ""
	seenTokens := map[string]bool{}
	for page := 0; page < em.md.Limits.MaxPages; page++ {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		body := map[string]any{"query": fmt.Sprintf("cert.names: %q", root), "page_size": em.md.Limits.PageSize}
		if token != "" {
			body["page_token"] = token
		}
		var out struct {
			Result present[struct {
				Hits          present[[]censysHit] `json:"hits"`
				NextPageToken string               `json:"next_page_token"`
			}] `json:"result"`
		}
		meta, class, err := s.HTTP.PostJSON(ctx, em.md.ID, u, hdr, body, &out)
		em.Meta(meta)
		if err != nil {
			return failureStatus(em, class), class, err
		}
		if !out.Result.Set || !out.Result.Value.Hits.Set {
			return failureStatus(em, source.ErrSchemaDrift), source.ErrSchemaDrift, nil
		}
		for _, h := range out.Result.Value.Hits.Value {
			n := 0
			if h.Certificate != nil {
				for _, name := range h.Certificate.Resource.Names {
					observeName(em, name, "scan-certificate", "", time.Time{})
					n++
				}
			}
			if h.Webproperty != nil && h.Webproperty.Resource.Hostname != "" {
				observeName(em, h.Webproperty.Resource.Hostname, "scan-observation", "", time.Time{})
				n++
			}
			if h.Host != nil && h.Host.Resource.DNS != nil {
				for _, name := range h.Host.Resource.DNS.Names {
					observeName(em, name, "scan-observation", "", time.Time{})
					n++
				}
			}
			if n == 0 {

				em.Unusable()
			}
		}
		token = out.Result.Value.NextPageToken
		if token == "" {
			return source.StatusComplete, source.ErrNone, nil
		}
		if seenTokens[token] {
			return source.StatusTruncated, source.ErrPaginationLoop, nil
		}
		seenTokens[token] = true
	}
	return source.StatusTruncated, source.ErrPartialPagination, nil
}

// newFOFA is FOFA's host search.
func newFOFA(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "fofa",
			Family:          source.FamilyScanEngine,
			Key:             source.RequiredKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://en.fofa.info/",
			TermsReviewedAt: "2026-11-20",
			DocsURL:         "https://en.fofa.info/api",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 60,
				Window:            time.Minute,
				Burst:             1,
				PageSize:          1000,
				ResultCap:         10000,
				MaxPages:          10,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  32 << 20,
			},
			Note: "results consume F-points or the free quota; key travels as a query parameter and is redacted from logs",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return fofaFetch(ep, ctx, root, s, em)
		},
	}
}

func fofaFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	q := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=%q", root)))
	size := em.md.Limits.PageSize
	for page := 1; page <= em.md.Limits.MaxPages; page++ {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		u := fmt.Sprintf("%s/api/v1/search/all?key=%s&qbase64=%s&fields=host&page=%d&size=%d",
			ep.fofa, url.QueryEscape(em.key), url.QueryEscape(q), page, size)
		var out struct {
			Error   present[bool]              `json:"error"`
			ErrMsg  string                     `json:"errmsg"`
			Size    int                        `json:"size"`
			Results present[[]json.RawMessage] `json:"results"`
		}
		meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, map[string]string{"Accept": "application/json"}, &out)
		em.Meta(meta)
		if err != nil {
			return failureStatus(em, class), class, err
		}
		if out.Error.Value {
			c := fofaErrorClass(out.ErrMsg)
			em.Note("fofa: " + clipNote(out.ErrMsg))
			return failureStatus(em, c), c, nil
		}
		if !out.Error.Set || !out.Results.Set {
			return failureStatus(em, source.ErrSchemaDrift), source.ErrSchemaDrift, nil
		}
		for _, raw := range out.Results.Value {
			h, ok := fofaHost(raw)
			if !ok {
				em.Unusable()
				continue
			}
			observeName(em, h, "scan-observation", "", time.Time{})
		}
		if len(out.Results.Value) < size || page*size >= out.Size {
			return source.StatusComplete, source.ErrNone, nil
		}
		if page*size >= em.md.Limits.ResultCap {
			break
		}
	}
	return source.StatusTruncated, source.ErrPartialPagination, nil
}

// fofaHost reads one result row - ["host"] or "host" - down to a hostname:
// scheme, port and path are not part of the name.
func fofaHost(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		var row []string
		if err := json.Unmarshal(raw, &row); err != nil || len(row) == 0 {
			return "", false
		}
		s = row[0]
	}
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	if s == "" {
		return "", false
	}
	return s, true
}

// fofaErrorClass maps FOFA's in-band error text to a class.
func fofaErrorClass(msg string) source.ErrorClass {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "key") || strings.Contains(m, "auth") || strings.Contains(m, "account"):
		return source.ErrUnauthorized
	case strings.Contains(m, "point") || strings.Contains(m, "quota") || strings.Contains(m, "privilege") || strings.Contains(m, "vip"):
		return source.ErrForbidden
	case strings.Contains(m, "rate") || strings.Contains(m, "frequen") || strings.Contains(m, "too many"):
		return source.ErrRateLimited
	}
	return source.ErrProviderDown
}

func clipNote(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
