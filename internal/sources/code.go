package sources

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/source"
)

func newGitHub(ep endpoints) source.Provider {
	return base{
		md: source.Metadata{
			ID:              "github",
			Family:          source.FamilyCodeSearch,
			Key:             source.RequiredKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://docs.github.com/en/rest/search/search",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 10,
				Window:            time.Minute,
				Burst:             1,
				PageSize:          100,
				ResultCap:         1000,
				MaxPages:          10,
				RequestTimeout:    60 * time.Second,
				MaxResponseBytes:  32 << 20,
			},
			Note: "one token only: rotating tokens to exceed 10 req/min evades a documented limit and breaches GitHub's acceptable-use policy",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return githubFetch(ep, ctx, root, s, em)
		},
	}
}

// hostPattern matches hostname-shaped text inside a code fragment.
var hostPattern = regexp.MustCompile(`(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b`)

type githubItem struct {
	HTMLURL    string `json:"html_url"`
	Path       string `json:"path"`
	SHA        string `json:"sha"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	TextMatches []struct {
		Fragment string `json:"fragment"`
	} `json:"text_matches"`
}

func githubFetch(ep endpoints, ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
	hdr := map[string]string{
		"Authorization": "Bearer " + em.key,

		"Accept":               "application/vnd.github.v3.text-match+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}
	suffix := "." + strings.ToLower(root)
	truncated := false

	for page := 1; page <= em.md.Limits.MaxPages; page++ {
		if ctx.Err() != nil {
			return source.StatusCancelled, source.ClassOfContextErr(ctx.Err()), ctx.Err()
		}
		u := ep.github + "/search/code?q=" + url.QueryEscape("\""+root+"\"") +
			"&per_page=100&page=" + itoa(page)
		var out struct {
			TotalCount        int                   `json:"total_count"`
			IncompleteResults bool                  `json:"incomplete_results"`
			Items             present[[]githubItem] `json:"items"`
		}
		meta, class, err := s.HTTP.GetJSON(ctx, em.md.ID, u, hdr, &out)
		em.Meta(meta)
		if err != nil {
			return failureStatus(em, class), class, err
		}
		if !out.Items.Set {
			return failureStatus(em, source.ErrSchemaDrift), source.ErrSchemaDrift, nil
		}
		if out.IncompleteResults || out.TotalCount > em.md.Limits.ResultCap {
			truncated = true
		}
		for _, item := range out.Items.Value {
			attrs := map[string]string{}
			if item.Repository.FullName != "" {
				attrs["repository"] = item.Repository.FullName
			}
			if item.Path != "" {
				attrs["path"] = truncate(item.Path, 200)
			}
			seen := map[string]bool{}
			for _, tm := range item.TextMatches {
				for _, m := range hostPattern.FindAllString(tm.Fragment, -1) {
					h := strings.ToLower(strings.Trim(m, "."))

					if h != strings.ToLower(root) && !strings.HasSuffix(h, suffix) {
						continue
					}
					if seen[h] {
						continue
					}
					seen[h] = true

					em.Observe(h, "code-match", item.SHA, item.HTMLURL, time.Time{}, attrs)
				}
			}
		}
		if len(out.Items.Value) < 100 {
			if truncated {
				return source.StatusTruncated, source.ErrPartialPagination, nil
			}
			return source.StatusComplete, source.ErrNone, nil
		}
	}

	return source.StatusTruncated, source.ErrPartialPagination, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
