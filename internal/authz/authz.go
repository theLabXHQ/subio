// Package authz reads the written authorization record that every active
// method requires: who granted it, over which roots, for which methods, and
// until when.
package authz

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/scope"
)

// ErrNotAuthorized reports a missing or insufficient authorization record.
var ErrNotAuthorized = errors.New("authorization: the record does not cover this")

// outOfScopeError is a record that exists but does not cover the domain.
type outOfScopeError struct{ msg string }

func (e outOfScopeError) Error() string        { return e.msg }
func (e outOfScopeError) Is(target error) bool { return target == ErrNotAuthorized }

// MethodPublicData declares a run that only reads public third-party
// datasets — certificate transparency logs, web archives, crawl indexes
// — and sends nothing to the target.
const MethodPublicData = "public-data"

// MethodPassiveProviders declares passive collection that includes
// credentialed provider APIs.
const MethodPassiveProviders = "passive-providers"

// MethodActiveDNS declares queries sent to the target's own nameservers.
const MethodActiveDNS = "active-dns"

// MethodActiveTLS declares TLS connections to the target's own hosts, to
// read certificate names.
const MethodActiveTLS = "active-tls"

// MethodActiveHTTP declares HTTP(S) requests to the target's own hosts, to
// read the hostnames their pages and headers reference — a CSP policy, a
// link, an absolute URL.
const MethodActiveHTTP = "active-http"

// Allows reports whether the record lists a method.
func (a *Authorization) Allows(method string) bool {
	for _, m := range a.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// Authorization is the written record active discovery needs before it may
// run.
type Authorization struct {
	// Owner is who authorized the run.
	Owner string `json:"owner"`
	// Scope lists the root domains the owner authorized, exactly.
	Scope []string `json:"scope"`
	// GrantedAt and ExpiresAt bound the permission.
	GrantedAt string `json:"granted_at"`
	ExpiresAt string `json:"expires_at"`

	// Contact is who to reach if the run needs to stop.
	Contact string `json:"stop_contact"`
	// Methods lists what was authorized: public-data, passive-providers or
	// active-dns.
	Methods []string `json:"allowed_methods"`
	// MaxQPS and MaxCandidates are limits on active discovery that the record
	// imposes on whoever runs it.
	MaxQPS        int    `json:"max_qps,omitempty"`
	MaxCandidates int    `json:"max_candidates,omitempty"`
	Note          string `json:"note,omitempty"`
}

// PublicDataOnly reports whether this record covers nothing beyond reading
// public third-party datasets.
func (a *Authorization) PublicDataOnly() bool {
	if len(a.Methods) == 0 {
		return false
	}
	for _, m := range a.Methods {
		if m != MethodPublicData {
			return false
		}
	}
	return true
}

// ClaimsTargetAuthority reports whether the record asserts permission from
// the target's owner, which only an active method requires.
func (a *Authorization) ClaimsTargetAuthority() bool {
	for _, m := range a.Methods {
		if m == MethodActiveDNS || m == MethodActiveTLS || m == MethodActiveHTTP {
			return true
		}
	}
	return false
}

// Describe is the one-line statement of what the record does and does not
// say, printed with every result so it cannot be quietly upgraded later.
func (a *Authorization) Describe() string {
	switch {
	case a.PublicDataOnly():
		return "public-dataset reads only; no packet is sent to the target and no authority over it is claimed"
	case a.ClaimsTargetAuthority():
		return "includes active methods; asserts permission from the target's owner"
	default:
		return "passive collection including credentialed provider APIs; governed by each provider's terms, not by the target's permission"
	}
}

// knownMethods guards against a typo silently widening what a record covers.
var knownMethods = map[string]bool{
	MethodPublicData:       true,
	MethodPassiveProviders: true,
	MethodActiveDNS:        true,
	MethodActiveTLS:        true,
	MethodActiveHTTP:       true,
}

// LoadAuthorization reads and validates an authorization record.
func LoadAuthorization(path string) (*Authorization, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a Authorization
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("authorization: %s is not valid authorization JSON: %w", path, err)
	}
	var missing []string
	if a.Owner == "" {
		missing = append(missing, "owner")
	}
	if len(a.Scope) == 0 {
		missing = append(missing, "scope")
	}
	if a.GrantedAt == "" {
		missing = append(missing, "granted_at")
	}
	if a.Contact == "" {
		missing = append(missing, "stop_contact")
	}
	if len(a.Methods) == 0 {
		missing = append(missing, "allowed_methods")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("authorization: authorization record is missing: %s", strings.Join(missing, ", "))
	}
	for _, m := range a.Methods {
		if !knownMethods[m] {
			return nil, fmt.Errorf("authorization: unknown method %q: use %s, %s or %s",
				m, MethodPublicData, MethodPassiveProviders, MethodActiveDNS+", "+MethodActiveTLS)
		}
	}
	if a.ExpiresAt != "" {
		t, err := time.Parse("2006-01-02", a.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("authorization: expires_at must be YYYY-MM-DD, got %q", a.ExpiresAt)
		}
		if time.Now().After(t.AddDate(0, 0, 1)) {
			return nil, fmt.Errorf("authorization: authorization expired on %s", a.ExpiresAt)
		}
	}
	return &a, nil
}

// Permits reports whether domain is inside the authorized scope.
func (a *Authorization) Permits(domain string) error {
	host, err := scope.Canonical(domain)
	if err != nil {
		return outOfScopeError{fmt.Sprintf("authorization: %q is not a domain: %v", domain, err)}
	}
	for _, s := range a.Scope {
		root, err := scope.NewRoot(s)
		if err != nil {
			return outOfScopeError{fmt.Sprintf("authorization: authorization scope entry %q is not a domain: %v", s, err)}
		}
		if root.Contains(host) {
			return nil
		}
	}
	sorted := append([]string(nil), a.Scope...)
	sort.Strings(sorted)
	return outOfScopeError{fmt.Sprintf("authorization: %s is not in the authorized scope (%s)", host, strings.Join(sorted, ", "))}
}
