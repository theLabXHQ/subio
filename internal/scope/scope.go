// Package scope implements hostname canonicalization and the authorization
// boundary.
package scope

import (
	"errors"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Profile names the normalization contract recorded in every emitted record.
const Profile = "idna2008-uts46"

const (
	maxNameLen  = 253
	maxLabelLen = 63
)

var (
	ErrEmpty        = errors.New("scope: empty hostname")
	ErrSyntax       = errors.New("scope: illegal character in hostname")
	ErrWildcard     = errors.New("scope: wildcard label is not a hostname")
	ErrTrailingDots = errors.New("scope: more than one trailing dot")
	ErrNotFQDN      = errors.New("scope: expected at least two labels")
	ErrNameTooLong  = errors.New("scope: hostname exceeds 253 octets")
	ErrLabelLen     = errors.New("scope: label length out of range")
	ErrLabelSyntax  = errors.New("scope: illegal DNS label")
	ErrIDNA         = errors.New("scope: IDNA conversion failed")
	ErrRootIsIP     = errors.New("scope: a root must be a domain, not an IP address")
)

// lookupProfile is UTS-46 with transitional processing disabled, i.e.
var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
)

// Canonical returns the comparison key for raw: lowercase, one trailing dot
// removed, each ordinary label converted to its IDNA2008 A-label.
func Canonical(raw string) (string, error) { return canonical(raw, 2) }

// CanonicalZone canonicalizes a DNS zone name, which may be a single label:
// a TLD is a real zone and often the most interesting one to ask a question
// about.
func CanonicalZone(raw string) (string, error) { return canonical(raw, 1) }

func canonical(raw string, minLabels int) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ErrEmpty
	}
	if strings.ContainsAny(s, " /\\:@\t\r\n?#%") {
		return "", ErrSyntax
	}
	if strings.Contains(s, "*") {
		return "", ErrWildcard
	}
	if strings.HasSuffix(s, "..") {
		return "", ErrTrailingDots
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", ErrEmpty
	}

	labels := strings.Split(s, ".")
	if len(labels) < minLabels {
		return "", ErrNotFQDN
	}
	out := make([]string, len(labels))
	for i, label := range labels {
		norm, err := canonicalLabel(label)
		if err != nil {
			return "", err
		}
		out[i] = norm
	}
	name := strings.Join(out, ".")
	if len(name) > maxNameLen {
		return "", ErrNameTooLong
	}
	return name, nil
}

func canonicalLabel(label string) (string, error) {
	if label == "" || len(label) > maxLabelLen {
		return "", ErrLabelLen
	}
	if label[0] == '_' {

		for i := 0; i < len(label); i++ {
			if !isServiceByte(label[i]) {
				return "", ErrLabelSyntax
			}
		}
		return strings.ToLower(label), nil
	}

	if isPlainASCII(label) {
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrLabelSyntax
		}
		return strings.ToLower(label), nil
	}

	if !utf8.ValidString(label) {
		return "", ErrLabelSyntax
	}
	norm, err := lookupProfile.ToASCII(label)
	if err != nil {
		return "", ErrIDNA
	}
	norm = strings.ToLower(norm)
	if norm == "" || len(norm) > maxLabelLen {
		return "", ErrLabelLen
	}
	if norm[0] == '-' || norm[len(norm)-1] == '-' {
		return "", ErrLabelSyntax
	}
	for i := 0; i < len(norm); i++ {
		if !isHostByte(norm[i]) {
			return "", ErrLabelSyntax
		}
	}
	return norm, nil
}

// isPlainASCII reports a label of letters, digits, hyphens and underscores
// that is not a Punycode A-label, whose encoding IDNA still has to validate.
func isPlainASCII(label string) bool {
	if len(label) >= 4 && strings.EqualFold(label[:4], "xn--") {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !isHostByte(c) && c != '_' && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func isHostByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
}

func isServiceByte(c byte) bool {
	return isHostByte(c) || c == '_' || (c >= 'A' && c <= 'Z')
}

// Root is an operator-supplied authorization root.
type Root struct {
	name string
}

// NewRoot canonicalizes and validates an authorization root.
func NewRoot(raw string) (Root, error) {
	name, err := Canonical(raw)
	if err != nil {
		return Root{}, err
	}

	if allDigits(name[strings.LastIndexByte(name, '.')+1:]) {
		return Root{}, ErrRootIsIP
	}
	return Root{name: name}, nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// String returns the canonical root.
func (r Root) String() string { return r.name }

// Zero reports whether the root was never initialized.
func (r Root) Zero() bool { return r.name == "" }

// Contains reports whether an already-canonical host is the root itself or a
// descendant of it.
func (r Root) Contains(canonicalHost string) bool {
	if r.name == "" || canonicalHost == "" {
		return false
	}
	if canonicalHost == r.name {
		return true
	}
	return len(canonicalHost) > len(r.name)+1 &&
		strings.HasSuffix(canonicalHost, r.name) &&
		canonicalHost[len(canonicalHost)-len(r.name)-1] == '.'
}

// Set is a collection of authorization roots.
type Set struct {
	roots []Root

	// canon caches Canonical by raw input.
	mu    sync.Mutex
	canon map[string]canonEntry
}

type canonEntry struct {
	host string
	err  error
}

const canonCacheMax = 1 << 17

func (s *Set) canonical(raw string) (string, error) {
	s.mu.Lock()
	if e, ok := s.canon[raw]; ok {
		s.mu.Unlock()
		return e.host, e.err
	}
	s.mu.Unlock()
	host, err := Canonical(raw)
	s.mu.Lock()
	if s.canon == nil || len(s.canon) >= canonCacheMax {
		s.canon = make(map[string]canonEntry, 1024)
	}
	s.canon[raw] = canonEntry{host, err}
	s.mu.Unlock()
	return host, err
}

// NewSet builds a scope set from operator input.
func NewSet(raws ...string) (*Set, error) {
	s := &Set{}
	for _, raw := range raws {
		r, err := NewRoot(raw)
		if err != nil {
			return nil, err
		}
		s.roots = append(s.roots, r)
	}
	return s, nil
}

// Roots returns the configured roots.
func (s *Set) Roots() []Root { return s.roots }

// Admit canonicalizes raw and reports the matching root.
func (s *Set) Admit(raw string) (host string, root Root, err error) {
	host, err = s.canonical(raw)
	if err != nil {
		return "", Root{}, err
	}
	for _, r := range s.roots {
		if r.Contains(host) {
			return host, r, nil
		}
	}
	return host, Root{}, ErrOutOfScope
}

// ErrOutOfScope reports a name that no configured root admits.
var ErrOutOfScope = errors.New("scope: hostname outside every authorized root")
