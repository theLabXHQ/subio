// Package fetch is the only outbound HTTP surface adapters may use.
package fetch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/source"
)

// DefaultMaxBytes caps a response body when the provider documents no size.
const DefaultMaxBytes int64 = 32 << 20

// DefaultUserAgent identifies the tool honestly.
const DefaultUserAgent = "subio/0.1 (+https://github.com/theLabXHQ/subio)"

// maxRetryWait bounds how long a retry may wait for its rate token.
const maxRetryWait = 8 * time.Second

// maxRedirects bounds same-host redirects.
const maxRedirects = 5

// errForeignRedirect marks a redirect that was refused.
var errForeignRedirect = errors.New("redirect to another host refused")

// errMethodChanged marks a redirect that would have rewritten the request.
var errMethodChanged = errors.New("redirect that changes the method refused")

// checkRedirect keeps a request on the host the adapter chose.
func checkRedirect(req *http.Request, via []*http.Request) error {
	req.Header.Del("Referer")
	first := via[0].URL
	if !strings.EqualFold(req.URL.Host, first.Host) ||
		(first.Scheme == "https" && req.URL.Scheme != "https") {
		return errForeignRedirect
	}

	if req.Method != via[0].Method {
		return errMethodChanged
	}
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	return nil
}

// Config parameterizes a Client.
type Config struct {
	Scheduler *sched.Scheduler
	UserAgent string
	// MaxAttempts bounds total tries per request, including the first.
	MaxAttempts int
	// Transport is overridden in tests.
	Transport http.RoundTripper

	// RequestTimeout bounds one request for a source that declares no timeout of
	// its own.
	RequestTimeout time.Duration
	Clock          sched.Clock
	// Rand is the jitter source; nil uses a locked global.
	Rand *rand.Rand
}

// Client implements source.Doer.
type Client struct {
	hc          *http.Client
	sch         *sched.Scheduler
	ua          string
	maxAttempts int
	// defaultTimeout bounds a request for a source that declares no timeout.
	defaultTimeout time.Duration
	clk            sched.Clock

	mu     sync.RWMutex
	limits map[string]source.Limits

	randMu sync.Mutex
	rnd    *rand.Rand
}

// New builds a Client.
func New(cfg Config) *Client {
	if cfg.Scheduler == nil {
		cfg.Scheduler = sched.New(sched.Config{})
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = DefaultUserAgent
	}
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 3
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = sched.RealClock{}
	}
	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return &Client{

		hc:             &http.Client{Transport: cfg.Transport, CheckRedirect: checkRedirect},
		sch:            cfg.Scheduler,
		ua:             cfg.UserAgent,
		maxAttempts:    cfg.MaxAttempts,
		defaultTimeout: cfg.RequestTimeout,
		clk:            cfg.Clock,
		limits:         map[string]source.Limits{},
		rnd:            rnd,
	}
}

// Register declares a source's documented limits so the scheduler and the
// body cap can honor them.
func (c *Client) Register(m source.Metadata) {
	c.mu.Lock()
	c.limits[m.ID] = m.Limits
	c.mu.Unlock()
	c.sch.Register(m.ID, m.Limits.RequestsPerWindow, m.Limits.Window, m.Limits.Burst)
}

func (c *Client) limitsFor(sourceID string) source.Limits {
	c.mu.RLock()
	l := c.limits[sourceID]
	c.mu.RUnlock()
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = DefaultMaxBytes
	}
	if l.RequestTimeout <= 0 {
		l.RequestTimeout = c.defaultTimeout
	}
	return l
}

// Redact removes credential-shaped values from a string that may be printed.
func Redact(s string) string {
	for _, key := range []string{"apikey", "api_key", "api-key", "key", "token", "access_token", "secret", "password", "auth"} {
		s = redactParam(s, key)
	}
	return s
}

func redactParam(s, key string) string {
	low := strings.ToLower(s)
	out := s
	for i := 0; ; {
		j := strings.Index(low[i:], key+"=")
		if j < 0 {
			return out
		}
		start := i + j + len(key) + 1

		if start-len(key)-1 > 0 {
			switch out[start-len(key)-2] {
			case '?', '&', ';', ' ', ':', ',':
			default:
				i = start
				continue
			}
		}
		end := start
		for end < len(out) && out[end] != '&' && out[end] != ';' && out[end] != ' ' {
			end++
		}
		if end > start {
			out = out[:start] + "[REDACTED]" + out[end:]
			low = strings.ToLower(out)
			i = start + len("[REDACTED]")
			continue
		}
		i = end
	}
}

// classify maps an HTTP status to a sanitized error class.
func classify(status int) source.ErrorClass {
	switch {
	case status == http.StatusUnauthorized:
		return source.ErrUnauthorized
	case status == http.StatusForbidden:
		return source.ErrForbidden
	case status == http.StatusTooManyRequests:
		return source.ErrRateLimited
	case status >= 500:
		return source.ErrProviderDown
	case status >= 300:

		return source.ErrSchemaDrift
	}
	return source.ErrNone
}

// classOfBodyErr says why consuming a 2xx body failed.
func classOfBodyErr(reqErr error, runCtx context.Context, readErr error) source.ErrorClass {
	if errors.Is(reqErr, context.DeadlineExceeded) && runCtx.Err() == nil {

		return source.ErrDeadline
	}
	if runCtx.Err() != nil {
		return source.ClassOfContextErr(runCtx.Err())
	}
	if readErr != nil {
		return source.ErrTransport
	}

	return source.ErrSchemaDrift
}

const (

	// quotaNearlyGone is the remaining allowance below which a provider is
	// treated as nearly spent.
	quotaNearlyGone = 2

	// quotaBackoff is how far the next request on that source is pushed out.
	quotaBackoff = 5 * time.Second
)

// retryable reports whether a status is worth another attempt.
func retryable(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusRequestTimeout ||
		status >= 500
}

// parseRetryAfter reads the header in either documented form: delta-seconds
// or an HTTP date.
func parseRetryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n < 0 {
			return 0
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// readMeta extracts whatever the response disclosed about quota state and
// about being cut short.
func readMeta(resp *http.Response, now time.Time) *source.HTTPMeta {
	m := &source.HTTPMeta{
		StatusCode:     resp.StatusCode,
		RetryAfter:     parseRetryAfter(resp.Header, now),
		QuotaRemaining: -1,
	}
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("X-Truncated"))) {
	case "1", "true", "yes":
		m.MoreResults = true
	}
	for _, k := range []string{"X-Ratelimit-Remaining", "X-RateLimit-Remaining", "Ratelimit-Remaining", "X-Rate-Limit-Remaining"} {
		if v := resp.Header.Get(k); v != "" {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				m.QuotaRemaining = n
				break
			}
		}
	}
	for _, k := range []string{"X-Ratelimit-Reset", "X-RateLimit-Reset", "Ratelimit-Reset"} {
		if v := resp.Header.Get(k); v != "" {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {

				if n > 1_000_000_000 {
					m.ResetAt = time.Unix(n, 0).UTC()
				} else if n > 0 {
					m.ResetAt = now.Add(time.Duration(n) * time.Second)
				}
				break
			}
		}
	}
	return m
}

// backoff returns a full-jitter exponential delay.
func (c *Client) backoff(attempt int) time.Duration {
	base := time.Duration(1<<uint(attempt)) * 250 * time.Millisecond
	if base > 8*time.Second {
		base = 8 * time.Second
	}
	c.randMu.Lock()
	j := c.rnd.Int63n(int64(base) + 1)
	c.randMu.Unlock()
	return time.Duration(j)
}

// capReader wraps a body with a byte ceiling and records whether it was hit.
type capReader struct {
	r         io.Reader
	remaining int64
	n         int64
	truncated bool

	// readErr is the first failure the underlying body returned, if any.
	readErr error
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		c.truncated = true
		return 0, io.EOF
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	c.n += int64(n)
	if err != nil && !errors.Is(err, io.EOF) && c.readErr == nil {
		c.readErr = err
	}
	return n, err
}

// do performs one budgeted request with bounded retries and hands the body
// to consume.
func (c *Client) do(ctx context.Context, sourceID, method, rawURL string, payload []byte, hdr map[string]string,
	consume func(io.Reader) error) (*source.HTTPMeta, source.ErrorClass, error) {

	lim := c.limitsFor(sourceID)
	safeURL := Redact(rawURL)

	// Every return goes through finish, so a caller always learns how many
	// requests this call really sent, even when none produced a response.
	var attempts, limited int
	finish := func(m *source.HTTPMeta, class source.ErrorClass, err error) (*source.HTTPMeta, source.ErrorClass, error) {
		if m == nil {
			m = &source.HTTPMeta{QuotaRemaining: -1}
		}
		m.Attempts, m.RateLimited = attempts, limited
		return m, class, err
	}

	if _, err := url.Parse(rawURL); err != nil {
		return finish(nil, source.ErrTransport, fmt.Errorf("fetch: bad url %s", safeURL))
	}

	var lastMeta *source.HTTPMeta
	var lastClass source.ErrorClass = source.ErrTransport
	var lastErr error = errors.New("fetch: no attempt made")

	for attempt := 0; attempt < c.maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return finish(lastMeta, source.ClassOfContextErr(err), err)
		}

		if attempt > 0 && c.sch.Delay(sourceID) > maxRetryWait {
			return finish(lastMeta, lastClass, lastErr)
		}
		release, err := c.sch.Acquire(ctx, sourceID)
		if err != nil {
			if errors.Is(err, sched.ErrBreakerOpen) {
				return finish(lastMeta, source.ErrProviderDown, err)
			}
			return finish(lastMeta, source.ClassOfContextErr(err), err)
		}

		actx, acancel := context.WithTimeout(ctx, lim.RequestTimeout)
		attempts++
		meta, class, body, resp, timedOut, err := c.attempt(actx, sourceID, method, rawURL, safeURL, payload, hdr)
		if err != nil {
			acancel()
			release()
			lastMeta, lastClass, lastErr = meta, class, err

			if class == source.ErrRedirectRefused {
				return finish(meta, class, err)
			}
			c.sch.Fail(sourceID)

			if timedOut {
				return finish(meta, source.ErrDeadline, err)
			}
			if attempt+1 < c.maxAttempts {
				if werr := c.clk.Sleep(ctx, c.backoff(attempt)); werr != nil {
					return finish(meta, source.ClassOfContextErr(werr), werr)
				}
				continue
			}
			return finish(meta, class, err)
		}

		if class != source.ErrNone {
			drainClose(resp)
			acancel()
			release()
			lastMeta, lastClass = meta, class
			lastErr = fmt.Errorf("fetch: %s returned HTTP %d for %s", sourceID, meta.StatusCode, safeURL)

			if meta.StatusCode == http.StatusTooManyRequests {
				limited++

				c.sch.Penalize(sourceID, meta.RetryAfter)
			}
			if meta.StatusCode >= 500 {

				c.sch.Fail(sourceID)
			}
			if !retryable(meta.StatusCode) || attempt+1 >= c.maxAttempts {
				return finish(meta, class, lastErr)
			}

			wait := meta.RetryAfter
			if wait <= 0 {
				wait = c.backoff(attempt)
			}

			if dl, ok := ctx.Deadline(); ok && c.clk.Now().Add(wait).After(dl) {
				return finish(meta, source.ErrRateLimited,
					fmt.Errorf("fetch: %s Retry-After %s exceeds run deadline", sourceID, wait))
			}
			if werr := c.clk.Sleep(ctx, wait); werr != nil {
				return finish(meta, source.ClassOfContextErr(werr), werr)
			}
			continue
		}

		cr := &capReader{r: body, remaining: lim.MaxResponseBytes}
		cerr := consume(cr)

		reqErr := actx.Err()
		meta.Bytes = cr.n
		meta.Truncated = cr.truncated
		drainClose(resp)
		acancel()
		release()

		c.sch.Succeed(sourceID)

		if meta.QuotaRemaining >= 0 && meta.QuotaRemaining <= quotaNearlyGone {
			c.sch.Penalize(sourceID, quotaBackoff)
		}

		if meta.Truncated {
			return finish(meta, source.ErrOversize,
				fmt.Errorf("fetch: %s response exceeded %d bytes and was truncated", sourceID, lim.MaxResponseBytes))
		}
		if cerr != nil {
			return finish(meta, classOfBodyErr(reqErr, ctx, cr.readErr),
				fmt.Errorf("fetch: %s reading body: %v", sourceID, cerr))
		}
		return finish(meta, source.ErrNone, nil)
	}
	return finish(lastMeta, lastClass, lastErr)
}

// attempt performs one request.
func (c *Client) attempt(ctx context.Context, sourceID, method, rawURL, safeURL string, payload []byte, hdr map[string]string) (
	_ *source.HTTPMeta, _ source.ErrorClass, _ io.Reader, _ *http.Response, timedOut bool, _ error) {

	// A fresh reader per attempt: the previous one was consumed by the previous
	// send.
	var reqBody io.Reader
	if payload != nil {
		reqBody = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reqBody)
	if err != nil {
		return nil, source.ErrTransport, nil, nil, false, fmt.Errorf("fetch: build request for %s", safeURL)
	}
	req.Header.Set("User-Agent", c.ua)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		if errors.Is(err, errForeignRedirect) {
			return nil, source.ErrRedirectRefused, nil, nil, false,
				fmt.Errorf("fetch: %s was redirected to another host for %s; not followed", sourceID, safeURL)
		}
		if errors.Is(err, errMethodChanged) {
			return nil, source.ErrRedirectRefused, nil, nil, false,
				fmt.Errorf("fetch: %s was redirected with a changed method for %s; not followed", sourceID, safeURL)
		}
		expired := errors.Is(err, context.DeadlineExceeded) || isNetTimeout(err)
		class := source.ErrTransport
		if expired {
			class = source.ErrDeadline
		}

		kind := "transport error"
		if expired {
			kind = "timed out"
		}
		return nil, class, nil, nil, expired,
			fmt.Errorf("fetch: %s %s for %s", sourceID, kind, safeURL)
	}
	meta := readMeta(resp, c.clk.Now())
	if class := classify(resp.StatusCode); class != source.ErrNone {
		return meta, class, nil, resp, false, nil
	}
	return meta, source.ErrNone, resp.Body, resp, false, nil
}

// isNetTimeout reports a net.Error that timed out, which covers the dial and
// read deadlines as well as the request context.
func isNetTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func drainClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}

// GetJSON decodes a JSON body into out.
func (c *Client) GetJSON(ctx context.Context, sourceID, rawURL string, hdr map[string]string, out any) (*source.HTTPMeta, source.ErrorClass, error) {
	return c.do(ctx, sourceID, http.MethodGet, rawURL, nil, hdr, func(r io.Reader) error {
		return json.NewDecoder(r).Decode(out)
	})
}

// PostJSON sends body as JSON and decodes a JSON response into out.
func (c *Client) PostJSON(ctx context.Context, sourceID, rawURL string, hdr map[string]string, body, out any) (*source.HTTPMeta, source.ErrorClass, error) {
	payload, err := json.Marshal(body)
	if err != nil {

		return &source.HTTPMeta{QuotaRemaining: -1}, source.ErrTransport,
			fmt.Errorf("fetch: %s request body cannot be encoded", sourceID)
	}
	return c.do(ctx, sourceID, http.MethodPost, rawURL, payload, hdr, func(r io.Reader) error {
		return json.NewDecoder(r).Decode(out)
	})
}

// GetLines streams a line-delimited body.
func (c *Client) GetLines(ctx context.Context, sourceID, rawURL string, hdr map[string]string, fn func(line []byte) error) (*source.HTTPMeta, source.ErrorClass, error) {
	return c.do(ctx, sourceID, http.MethodGet, rawURL, nil, hdr, func(r io.Reader) error {
		return scanLines(r, fn)
	})
}

// GetJSONArray streams the elements of a top-level JSON array.
func (c *Client) GetJSONArray(ctx context.Context, sourceID, rawURL string, hdr map[string]string, fn func(json.RawMessage) error) (*source.HTTPMeta, source.ErrorClass, error) {
	return c.do(ctx, sourceID, http.MethodGet, rawURL, nil, hdr, func(r io.Reader) error {
		dec := json.NewDecoder(r)
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return fmt.Errorf("expected a JSON array, got %v", tok)
		}
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return err
			}
			if err := fn(raw); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	})
}

var _ source.Doer = (*Client)(nil)
