// Package source defines the provider contract every passive adapter must
// satisfy.
package source

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Family groups sources by the kind of evidence they produce.
type Family string

const (
	FamilyCT          Family = "certificate-transparency"
	FamilyPassiveDNS  Family = "passive-dns"
	FamilyCodeSearch  Family = "code-search"
	FamilyScanEngine  Family = "scan-engine"
	FamilyWebArchive  Family = "web-archive"
	FamilyThreatIntel Family = "threat-intel"
	FamilyCurated     Family = "curated-dataset"
	FamilyLocalImport Family = "local-import"
	// FamilyActiveDNS is a name subio found by asking resolvers: a guess that
	// answered, or a name in a DNS record.
	FamilyActiveDNS Family = "active-dns"

	// FamilyActiveHTTP is a name subio found by connecting to the target's own
	// servers over HTTP: a virtual host that serves a distinct site on an IP
	// even though no DNS record points to it.
	FamilyActiveHTTP Family = "active-http"
)

// KeyRequirement states whether the adapter needs a credential.
type KeyRequirement uint8

const (
	NoKey KeyRequirement = iota
	OptionalKey
	RequiredKey
)

// Terms is the reviewed data-use state for a provider.
type Terms uint8

const (
	// TermsUnknown: no official terms page was read.
	TermsUnknown Terms = iota
	// TermsReviewRequired: an official page was read but commercial retention,
	// caching, and automated access are not all explicitly permitted.
	TermsReviewRequired

	// TermsBlockedCommercial: an official page explicitly forbids use of the
	// data or the public API in a commercial or publicly distributed product.
	TermsBlockedCommercial
	// TermsPermitted: an official page explicitly permits commercial retention,
	// caching, and automated access.
	TermsPermitted
)

func (t Terms) String() string {
	switch t {
	case TermsReviewRequired:
		return "review_required"
	case TermsBlockedCommercial:
		return "blocked_commercial"
	case TermsPermitted:
		return "permitted"
	default:
		return "unknown"
	}
}

// Profile selects how strictly terms are enforced.
type Profile uint8

const (

	// ProfilePersonal permits sources whose terms are merely unresolved.
	ProfilePersonal Profile = iota
	// ProfileCommercial permits only TermsPermitted sources: unknown and
	// review-required both fail closed.
	ProfileCommercial
)

// Recursion states what a provider returns for a root query.
type Recursion uint8

const (
	RecursionUnknown Recursion = iota
	RecursionNone
	RecursionDirect
	RecursionFull
)

// Limits records what the provider's own documentation states.
type Limits struct {

	// RequestsPerWindow and Window express the documented rate ceiling, e.g.
	RequestsPerWindow int
	Window            time.Duration
	// Burst is the documented concurrent-request allowance.
	Burst int

	// ResultCap is a documented hard ceiling on total results per query, e.g.
	ResultCap int
	// PageSize is the documented maximum results per page.
	PageSize int
	// MaxPages bounds our own paging regardless of provider behavior.
	MaxPages int
	// RequestTimeout bounds a single HTTP request.
	RequestTimeout time.Duration

	// MaxResponseBytes caps a response body before decoding.
	MaxResponseBytes int64
}

// Metadata is static adapter description.
type Metadata struct {
	ID              string
	Family          Family
	Key             KeyRequirement
	Terms           Terms
	TermsURL        string
	TermsReviewedAt string
	DocsURL         string
	Recursion       Recursion
	Limits          Limits

	// CorrelationGroup names a known shared upstream.
	CorrelationGroup string
	// Note is a one-line operator-visible caveat.
	Note string

	// OptIn keeps an adapter out of the default selection, so it runs only when
	// named with -s.
	OptIn bool

	// Slow keeps an adapter out of the default selection for the time it costs
	// against what it adds; -all-sources, or naming it with -s, runs it.
	Slow bool

	// CapsSilently marks a provider that can return a partial answer with
	// nothing in the response to say it did.
	CapsSilently bool
}

// Observation is one provider assertion about one hostname.
type Observation struct {
	// Hostname as the provider returned it, before canonicalization.
	Hostname string
	SourceID string

	// Method describes how the name appeared, e.g.
	Method string

	// ObservedAt is the provider-stated observation time.
	ObservedAt time.Time
	// RecordID is the provider's stable identifier for the underlying record
	// (certificate id, archive digest, commit sha).
	RecordID string
	// EvidenceRef points at the record.
	EvidenceRef string
	// Attrs carries small, allowlisted extras such as
	// "wildcard_certificate=true".
	Attrs map[string]string
}

// Status is the terminal state of one source run.
type Status string

const (
	StatusComplete           Status = "complete"
	StatusEmpty              Status = "empty"
	StatusPartial            Status = "partial"
	StatusTruncated          Status = "truncated"
	StatusFailed             Status = "failed"
	StatusThrottled          Status = "throttled"
	StatusTimedOut           Status = "timed_out"
	StatusCancelled          Status = "cancelled"
	StatusMissingCredentials Status = "missing_credentials"
	StatusTermsBlocked       Status = "terms_blocked"
	StatusSkipped            Status = "skipped"
)

// Terminal reports whether a status means the source produced everything it
// was going to.
func (s Status) Complete() bool {
	return s == StatusComplete || s == StatusEmpty
}

// ErrorClass is a sanitized failure category.
type ErrorClass string

const (
	ErrNone              ErrorClass = ""
	ErrUnauthorized      ErrorClass = "unauthorized"
	ErrForbidden         ErrorClass = "forbidden_entitlement"
	ErrRateLimited       ErrorClass = "rate_limited"
	ErrProviderDown      ErrorClass = "provider_unavailable"
	ErrSchemaDrift       ErrorClass = "schema_drift"
	ErrPartialPagination ErrorClass = "partial_pagination"

	// ErrPlanLimit is a truncation the provider's free plan imposes on every
	// request alike: the answer stopped at the plan's documented or measured row
	// ceiling.
	ErrPlanLimit      ErrorClass = "plan_limit"
	ErrPaginationLoop ErrorClass = "pagination_loop"
	ErrDeadline       ErrorClass = "deadline"
	ErrOversize       ErrorClass = "oversize_response"
	ErrScopeRejected  ErrorClass = "scope_rejected"
	ErrTransport      ErrorClass = "transport"

	// ErrRedirectRefused means the provider redirected to a different host, or
	// in a way that would have dropped a request body, and subio did not follow.
	ErrRedirectRefused ErrorClass = "redirect_refused"

	// ErrCancelled means the run was stopped - interrupted, or cancelled by its
	// caller - while this source was still working.
	ErrCancelled ErrorClass = "cancelled"
)

// ClassOfContextErr classifies a dead context.
func ClassOfContextErr(err error) ErrorClass {
	if errors.Is(err, context.Canceled) {
		return ErrCancelled
	}
	return ErrDeadline
}

// RunSummary terminates every source run.
type RunSummary struct {
	SourceID     string
	Status       Status
	ErrorClass   ErrorClass
	Requests     int
	Pages        int
	Retries      int
	RateLimitHit int
	// Raw is every observation the adapter emitted, including duplicates.
	Raw int

	// Unusable counts records the provider sent that could not be read.
	Unusable int
	// Started and Ended bound the run.
	Started time.Time
	Ended   time.Time
	// QuotaRemaining is a provider-reported remaining allowance when the
	// response exposes one; -1 when unknown.
	QuotaRemaining int
	// ResetAt is a provider-reported quota reset time when exposed.
	ResetAt time.Time

	// Note is one sanitized line an adapter may leave for the operator, for a
	// condition a status and an error class cannot express — typically what to
	// do about it.
	Note string

	// CapsSilently is copied from the adapter's metadata when this run returned
	// a non-empty answer, so a ledger record carries the caveat with the status
	// rather than requiring the reader to know which provider caps.
	CapsSilently bool
}

// Duration is the wall time of the source run.
func (r RunSummary) Duration() time.Duration { return r.Ended.Sub(r.Started) }

// Result is one item on a source's output stream: an observation, or the
// terminal summary.
type Result struct {
	Observation *Observation
	Summary     *RunSummary
}

// Session carries the per-run budget and services an adapter may use.
type Session struct {
	// HTTP performs a budgeted, rate-limited, size-capped request.
	HTTP Doer
	// Secrets resolves a credential by adapter ID without exposing it to logs.
	Secrets SecretSource
	// Deadline is the run-wide deadline shared by all sources.
	Deadline time.Time
	// Profile selects terms enforcement.
	Profile Profile
}

// Doer is the budgeted HTTP surface available to adapters.
type Doer interface {

	// GetJSON issues one GET and decodes a JSON body into out.
	GetJSON(ctx context.Context, sourceID, url string, hdr map[string]string, out any) (*HTTPMeta, ErrorClass, error)

	// GetLines issues one GET and streams a line-delimited body.
	GetLines(ctx context.Context, sourceID, url string, hdr map[string]string, fn func(line []byte) error) (*HTTPMeta, ErrorClass, error)

	// GetJSONArray issues one GET and streams the elements of a top-level JSON
	// array.
	GetJSONArray(ctx context.Context, sourceID, url string, hdr map[string]string, fn func(elem json.RawMessage) error) (*HTTPMeta, ErrorClass, error)

	// PostJSON issues one POST whose body is the JSON encoding of body, and
	// decodes a JSON response into out.
	PostJSON(ctx context.Context, sourceID, url string, hdr map[string]string, body, out any) (*HTTPMeta, ErrorClass, error)
}

// HTTPMeta reports what one response disclosed about quota state.
type HTTPMeta struct {
	StatusCode     int
	Bytes          int64
	RetryAfter     time.Duration
	QuotaRemaining int
	ResetAt        time.Time
	Truncated      bool
	// MoreResults reports that the provider itself said this answer is cut, in
	// an X-Truncated header.
	MoreResults bool
	// Attempts is how many requests were actually sent for this call, retries
	// included.
	Attempts int
	// RateLimited is how many of those attempts were answered with a 429.
	RateLimited int
}

// SecretSource resolves credentials.
type SecretSource interface {
	Secret(sourceID string) (value string, present bool)
}

// Provider is one passive adapter.
type Provider interface {
	// Metadata must not perform I/O.
	Metadata() Metadata
	// Run streams observations for one root and closes the channel after sending
	// exactly one Result carrying a Summary.
	Run(ctx context.Context, root string, s *Session) <-chan Result
}

// ErrTermsBlocked reports a source refused before any request was made.
var ErrTermsBlocked = errors.New("source: terms do not permit this profile")

// Allowed reports whether a source may run under a profile, and why not.
func Allowed(m Metadata, p Profile) (bool, Status) {
	if m.Terms == TermsBlockedCommercial && p == ProfileCommercial {
		return false, StatusTermsBlocked
	}
	if p == ProfileCommercial && m.Terms != TermsPermitted {
		return false, StatusTermsBlocked
	}
	return true, StatusComplete
}
