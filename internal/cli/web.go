package cli

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/source"
)

const (
	sourceWeb      = "web"
	webConcurrency = 16
	webPerSecond   = 20
	webTimeout     = 6 * time.Second
	// webMaxBody caps one page so a large or hostile response cannot exhaust
	// memory.
	webMaxBody = 2 << 20

	// maxScripts bounds how many of a page's own script files are fetched.
	maxScripts = 8
)

// scriptSrcRe finds the src of each <script> tag, so a page's own JavaScript
// can be read for the hostnames it names.
var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?([^"'> ]+)`)

// webStats is what the web source did, for its run-report row.
type webStats struct {
	fetched int
	found   int
	errors  int
}

// webScrape reads each found host's own page and headers for the hostnames
// it references — a CSP policy, a link, an absolute URL — and keeps the
// in-scope ones.
func (d *dnsStage) webScrape(ctx context.Context) {
	type target struct{ name, addr string }
	var targets []target
	for _, f := range d.led.Findings() {
		if f.WildcardSuspected {
			continue
		}
		addrs := d.addressesOf(f.RootDomain, f.FQDN)
		if len(addrs) > 0 {
			targets = append(targets, target{f.FQDN, addrs[0].String()})
		}
	}
	if len(targets) == 0 {
		return
	}

	lim := sched.NewLimiter(webPerSecond, time.Second, webConcurrency, nil)
	sem := make(chan struct{}, webConcurrency)
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		found []string
	)
	for _, t := range targets {
		if lim.Wait(ctx) != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(name, addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			refs, err := webReferences(ctx, name, addr)
			mu.Lock()
			d.web.fetched++
			if err != nil {
				d.web.errors++
			}
			for _, ref := range refs {
				if host := d.admitWeb(ref.host, name, ref.kind); host != "" {
					found = append(found, host)
				}
			}
			mu.Unlock()
		}(t.name, t.addr)
	}
	wg.Wait()
	d.followRecords(ctx, found)
	d.addWebRun()
}

// webRef is one referenced hostname and where it was seen.
type webRef struct {
	host string
	kind string
}

// webReferences fetches https://name/ (dialing the resolved address) and
// returns the hostnames its headers and body mention.
func webReferences(ctx context.Context, name, addr string) ([]webRef, error) {
	dialer := &net.Dialer{Timeout: webTimeout}
	tr := &http.Transport{

		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(addr, "443"))
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, ServerName: name}, //nolint:gosec
		TLSHandshakeTimeout: webTimeout,
		DisableKeepAlives:   true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   webTimeout,

		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Hostname() != name {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	var refs []webRef
	add := func(text, kind string) {
		for _, h := range hostInText.FindAllString(text, -1) {
			refs = append(refs, webRef{host: strings.ToLower(strings.Trim(h, ".")), kind: kind})
		}
	}

	header, body, err := webGet(ctx, client, "https://"+name+"/")
	if err != nil {
		return nil, err
	}
	for _, h := range header.Values("Content-Security-Policy") {
		add(h, "csp")
	}
	for _, h := range header.Values("Content-Security-Policy-Report-Only") {
		add(h, "csp")
	}
	for _, h := range header.Values("Access-Control-Allow-Origin") {
		add(h, "cors")
	}
	for _, h := range header.Values("Link") {
		add(h, "link")
	}
	add(string(body), "body")

	for _, path := range wellKnownPaths {
		if _, doc, err := webGet(ctx, client, "https://"+name+path); err == nil {
			add(string(doc), "well-known")
			if path == "/robots.txt" {
				for _, m := range sitemapRe.FindAllStringSubmatch(string(doc), -1) {
					if u := sameHostScriptURL(strings.TrimSpace(m[1]), name); u != "" {
						if _, sm, serr := webGet(ctx, client, u); serr == nil {
							add(string(sm), "sitemap")
						}
					}
				}
			}
		}
	}

	seen := map[string]bool{}
	fetched := 0
	for _, m := range scriptSrcRe.FindAllStringSubmatch(string(body), -1) {
		if fetched >= maxScripts {
			break
		}
		u := sameHostScriptURL(m[1], name)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		fetched++
		if _, js, err := webGet(ctx, client, u); err == nil {
			add(string(js), "js")

			if m := sourceMapRe.FindSubmatch(js); m != nil {
				if mu := sameHostScriptURL(strings.TrimSpace(string(m[1])), name); mu != "" && !seen[mu] {
					seen[mu] = true
					if _, sm, merr := webGet(ctx, client, mu); merr == nil {
						add(string(sm), "sourcemap")
					}
				}
			}
		}
	}
	return refs, nil
}

// wellKnownPaths are documents a host publishes about itself.
var wellKnownPaths = []string{
	"/robots.txt",
	"/sitemap.xml",
	"/.well-known/security.txt",
	"/.well-known/openid-configuration",
}

// sourceMapRe finds the //# sourceMappingURL= comment a bundler appends.
var sourceMapRe = regexp.MustCompile(`(?m)^[/*#\s]*sourceMappingURL=(\S+?)\s*(?:\*/)?$`)

// sitemapRe reads the Sitemap: lines robots.txt carries, which are absolute
// URLs and frequently on a different host of the same owner.
var sitemapRe = regexp.MustCompile(`(?im)^\s*sitemap:\s*(\S+)`)

// webGet performs one bounded GET through the shared client and returns the
// response headers and the capped body.
func webGet(ctx context.Context, client *http.Client, url string) (http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", webUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, webMaxBody))
	return resp.Header, body, nil
}

// sameHostScriptURL returns an absolute https URL for a script src only when
// it stays on the found host: a relative path, or an absolute URL whose host
// is this one.
func sameHostScriptURL(src, host string) string {
	src = strings.TrimSpace(src)
	switch {
	case src == "":
		return ""
	case strings.HasPrefix(src, "//"):

		rest := src[2:]
		h, _, _ := strings.Cut(rest, "/")
		if strings.EqualFold(h, host) {
			return "https://" + rest
		}
		return ""
	case strings.HasPrefix(src, "https://"), strings.HasPrefix(src, "http://"):
		_, rest, _ := strings.Cut(src, "://")
		h, path, _ := strings.Cut(rest, "/")
		h, _, _ = strings.Cut(h, ":")
		if strings.EqualFold(h, host) {
			return "https://" + host + "/" + path
		}
		return ""
	case strings.HasPrefix(src, "/"):
		return "https://" + host + src
	default:
		return "https://" + host + "/" + src
	}
}

const webUserAgent = "subio/0.1 (+https://github.com/theLabXHQ/subio)"

// admitWeb records an in-scope hostname seen on the web and returns it when
// it is new, so it can be resolved.
func (d *dnsStage) admitWeb(raw, fromName, kind string) string {
	host, root, err := d.o.Roots.Admit(raw)
	if err != nil || d.led.Has(root.String(), host) {
		return ""
	}
	d.rootOf[host] = root.String()
	d.led.Observe(host, root.String(), source.FamilyActiveDNS, source.Observation{
		Hostname: host, SourceID: sourceWeb, Method: "web-" + kind,
		RecordID: fromName, Attrs: map[string]string{"found_in": fromName, "via": kind},
	})
	d.web.found++
	return host
}

// addWebRun records what the web source did.
func (d *dnsStage) addWebRun() {
	if d.web.fetched == 0 {
		return
	}
	status := source.StatusComplete
	switch {
	case d.web.errors > 0:
		status = source.StatusPartial
	case d.web.found == 0:
		status = source.StatusEmpty
	}
	d.led.AddSourceRun(ledger.SourceRun{
		SourceID: sourceWeb, Family: string(source.FamilyActiveDNS), Status: string(status),
		TermsState: termsNotApplicable, Requests: d.web.fetched, RawObservation: d.web.found,
		InScope: d.web.found, UniqueNames: d.web.found, MarginalNames: d.web.found,
		QuotaRemaining: -1,
	})
}
