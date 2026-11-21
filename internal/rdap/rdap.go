// Package rdap is a small RDAP client: the IANA registry bootstrap, one
// domain lookup, and the standardized reverse search by nameserver.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/idna"

	"github.com/theLabXHQ/subio/internal/source"
)

// DefaultBootstrapURL is IANA's authoritative map of TLD to RDAP base URL
// (RFC 9224).
const DefaultBootstrapURL = "https://data.iana.org/rdap/dns.json"

// SourceID is the scheduler key every request this package makes is charged
// to, so RDAP traffic is rate-limited like any adapter's.
const SourceID = "rdap"

var (

	// ErrNoServer means IANA's bootstrap lists no RDAP server for that TLD.
	ErrNoServer = errors.New("rdap: no RDAP server is registered for this TLD")
	// ErrUnsupported means the server answered that it does not implement the
	// query, which is permitted for search.
	ErrUnsupported = errors.New("rdap: this server does not support that query")
	// ErrNotFound means the server has no such object.
	ErrNotFound = errors.New("rdap: no such object")
)

// Doer is the HTTP surface this package needs.
type Doer interface {
	GetJSON(ctx context.Context, sourceID, rawURL string, hdr map[string]string, out any) (*source.HTTPMeta, source.ErrorClass, error)
}

// Client is an RDAP client.
type Client struct {
	HTTP Doer
	// BootstrapURL overrides IANA's for tests.
	BootstrapURL string

	// FollowReferral allows one hop from the registry's answer to the
	// registrar's RDAP server named in a "related" link.
	FollowReferral bool

	mu       sync.Mutex
	services map[string]string
	bootErr  error
	booted   bool
}

// Identity is a contact as RDAP states it.
type Identity struct {
	Org     string `json:"org,omitempty"`
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Country string `json:"country,omitempty"`

	// Redacted records that the server said it withheld the registrant, or
	// published a privacy service in its place.
	Redacted bool `json:"redacted,omitempty"`
	// PrivacyService names the proxy the registrant was replaced with, when one
	// was recognised.
	PrivacyService string `json:"privacy_service,omitempty"`
}

// Domain is the subset of an RDAP domain object subio uses.
type Domain struct {
	LDHName     string   `json:"ldh_name"`
	Registrant  Identity `json:"registrant"`
	Registrar   string   `json:"registrar,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	// Server is the RDAP base URL that answered, so a handle (which is only
	// unique within one registry) is never compared across two of them.
	Server string `json:"server"`
	// Referred records that the registrant came from a registrar's server one
	// hop on from the registry's answer.
	Referred bool `json:"referred,omitempty"`
}

// privacyServices are proxy and redaction strings seen in place of a real
// registrant.
var privacyServices = []string{
	"redacted", "redacted for privacy", "data protected", "not disclosed",
	"privacy", "private by design", "withheld for privacy", "domains by proxy",
	"whoisguard", "contact privacy", "perfect privacy", "proxy protection",
	"identity protect", "domain protection services", "anonymize",
	"gdpr masked", "statutory masking enabled", "on behalf of",
	"super privacy service", "privacyguardian", "namecheap inc",
}

// legalSuffixes are company-form tokens dropped before comparing two
// organisation names, so "Example, Inc.
var legalSuffixes = map[string]bool{
	"inc": true, "incorporated": true, "llc": true, "lc": true, "ltd": true,
	"limited": true, "corp": true, "corporation": true, "co": true,
	"company": true, "gmbh": true, "ag": true, "sa": true, "sas": true,
	"sarl": true, "bv": true, "nv": true, "plc": true, "oy": true, "ab": true,
	"as": true, "aps": true, "srl": true, "spa": true, "pty": true,
	"kk": true, "kg": true, "ohg": true, "se": true, "holdings": true,
	"holding": true, "group": true, "international": true, "trust": true,
}

// MatchKeys returns every key this identity can be compared on, and false
// when it can support no comparison at all.
func (id Identity) MatchKeys() ([]string, bool) {
	if id.Redacted {
		return nil, false
	}

	if p := firstNonEmpty(id.Org, id.Name); p != "" && looksLikePrivacy(p) {
		return nil, false
	}
	var keys []string
	if e := strings.ToLower(strings.TrimSpace(id.Email)); strings.Contains(e, "@") && !looksLikePrivacy(e) {

		keys = append(keys, "email:"+e)
	}
	seen := map[string]bool{}
	for _, v := range []string{id.Org, id.Name} {
		if k, ok := normalizeOrg(v); ok && !seen[k] {
			seen[k] = true
			keys = append(keys, "org:"+k)
		}
	}
	return keys, len(keys) > 0
}

// Comparable reports whether this identity can be matched against another.
func (id Identity) Comparable() bool {
	_, ok := id.MatchKeys()
	return ok
}

// normalizeOrg lowercases, strips punctuation, drops trailing company-form
// tokens and collapses whitespace.
func normalizeOrg(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || looksLikePrivacy(v) {
		return "", false
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 0x80:
			b.WriteRune(r)
		default:
			b.WriteByte(' ')
		}
	}
	fields := strings.Fields(b.String())
	for len(fields) > 1 && legalSuffixes[fields[len(fields)-1]] {
		fields = fields[:len(fields)-1]
	}
	key := strings.Join(fields, " ")

	if len(key) < 4 {
		return "", false
	}
	return key, true
}

func looksLikePrivacy(v string) bool {
	v = strings.ToLower(v)
	for _, p := range privacyServices {
		if strings.Contains(v, p) {
			return true
		}
	}
	return false
}

type bootstrapDoc struct {
	Services [][][]string `json:"services"`
}

func (c *Client) bootstrap(ctx context.Context) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.booted {
		return c.services, c.bootErr
	}
	c.booted = true
	u := c.BootstrapURL
	if u == "" {
		u = DefaultBootstrapURL
	}
	var doc bootstrapDoc
	if _, _, err := c.HTTP.GetJSON(ctx, SourceID, u, nil, &doc); err != nil {
		c.bootErr = fmt.Errorf("rdap: the IANA bootstrap could not be read: %w", err)
		return nil, c.bootErr
	}
	svc := map[string]string{}
	for _, s := range doc.Services {
		if len(s) < 2 {
			continue
		}
		var base string
		for _, raw := range s[1] {

			if strings.HasPrefix(strings.ToLower(raw), "https://") {
				base = raw
				break
			}
		}
		if base == "" {
			continue
		}
		for _, suffix := range s[0] {
			suffix = strings.ToLower(strings.Trim(suffix, "."))
			if suffix != "" {
				svc[suffix] = base
			}
		}
	}
	if len(svc) == 0 {
		c.bootErr = errors.New("rdap: the IANA bootstrap listed no https RDAP servers")
		return nil, c.bootErr
	}
	c.services = svc
	return svc, nil
}

// BaseFor returns the RDAP base URL for a domain's suffix.
func (c *Client) BaseFor(ctx context.Context, domain string) (string, error) {
	svc, err := c.bootstrap(ctx)
	if err != nil {
		return "", err
	}
	d, err := toASCII(domain)
	if err != nil {
		return "", err
	}
	labels := strings.Split(d, ".")
	for i := 0; i < len(labels); i++ {
		if base, ok := svc[strings.Join(labels[i:], ".")]; ok {
			return base, nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrNoServer, d)
}

func toASCII(domain string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return "", errors.New("rdap: empty domain")
	}
	a, err := idna.Lookup.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("rdap: %q is not a usable domain name", d)
	}
	return a, nil
}

type domainDoc struct {
	LDHName     string        `json:"ldhName"`
	Entities    []entityDoc   `json:"entities"`
	Nameservers []nsDoc       `json:"nameservers"`
	Links       []linkDoc     `json:"links"`
	Redacted    []redactedDoc `json:"redacted"`
	// ErrorCode is present when the body is an RDAP error object rather than a
	// domain.
	ErrorCode int `json:"errorCode"`
}

type nsDoc struct {
	LDHName string `json:"ldhName"`
}

type linkDoc struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
	Type string `json:"type"`
}

type redactedDoc struct {
	Name struct {
		Type        string `json:"type"`
		Description string `json:"description"`
	} `json:"name"`
	Method string `json:"method"`
}

type entityDoc struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []entityDoc     `json:"entities"`
}

// Lookup fetches one domain.
func (c *Client) Lookup(ctx context.Context, domain string) (*Domain, error) {
	base, err := c.BaseFor(ctx, domain)
	if err != nil {
		return nil, err
	}
	d, err := toASCII(domain)
	if err != nil {
		return nil, err
	}
	out, err := c.lookupAt(ctx, base, d)
	if err != nil {
		return nil, err
	}

	if c.FollowReferral && !out.usable() {
		if href, ok := referral(out.links, base); ok {
			if ref, err := c.lookupAt(ctx, href, d); err == nil && ref.usable() {
				ref.Domain.Referred = true
				if len(ref.Domain.Nameservers) == 0 {
					ref.Domain.Nameservers = out.Domain.Nameservers
				}
				return &ref.Domain, nil
			}
		}
	}
	return &out.Domain, nil
}

type lookupResult struct {
	Domain
	links []linkDoc
}

// usable reports whether this answer carries a registrant worth comparing.
func (r lookupResult) usable() bool { return r.Registrant.Comparable() }

func (c *Client) lookupAt(ctx context.Context, base, domain string) (lookupResult, error) {
	u := joinRDAP(base, "domain/"+url.PathEscape(domain))
	var doc domainDoc
	meta, _, err := c.HTTP.GetJSON(ctx, SourceID, u, acceptRDAP, &doc)
	if err != nil {
		if meta != nil && meta.StatusCode == 404 {
			return lookupResult{}, fmt.Errorf("%w: %s", ErrNotFound, domain)
		}
		if meta != nil && (meta.StatusCode == 400 || meta.StatusCode == 501) {
			return lookupResult{}, fmt.Errorf("%w: %s", ErrUnsupported, base)
		}
		return lookupResult{}, fmt.Errorf("rdap: %s: %w", domain, err)
	}
	if doc.ErrorCode == 404 {
		return lookupResult{}, fmt.Errorf("%w: %s", ErrNotFound, domain)
	}
	res := lookupResult{links: doc.Links}
	res.LDHName = strings.ToLower(strings.TrimSuffix(doc.LDHName, "."))
	if res.LDHName == "" {
		res.LDHName = domain
	}
	res.Server = base
	for _, ns := range doc.Nameservers {
		if n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns.LDHName), ".")); n != "" {
			res.Nameservers = append(res.Nameservers, n)
		}
	}
	res.Registrant, res.Registrar = contacts(doc.Entities)
	if registrantRedacted(doc.Redacted) {
		res.Registrant.Redacted = true
	}
	return res, nil
}

var acceptRDAP = map[string]string{"Accept": "application/rdap+json, application/json"}

// contacts walks the entity list, one level of nesting included, and returns
// the registrant and the registrar's name.
func contacts(ents []entityDoc) (registrant Identity, registrar string) {
	var walk func(list []entityDoc, depth int)
	walk = func(list []entityDoc, depth int) {
		for _, e := range list {
			card := parseVCard(e.VCardArray)
			for _, role := range e.Roles {
				switch strings.ToLower(role) {
				case "registrant":
					if !registrant.Comparable() {
						registrant = identityOf(e.Handle, card)
					}
				case "registrar":
					if registrar == "" {
						registrar = firstOf(card, "fn", "org")
					}
				}
			}
			if depth < 1 {
				walk(e.Entities, depth+1)
			}
		}
	}
	walk(ents, 0)
	if !registrant.Comparable() {

		registrant.Redacted = true
		if n := registrant.Org + " " + registrant.Name + " " + registrant.Email; looksLikePrivacy(n) {
			registrant.PrivacyService = strings.TrimSpace(firstNonEmpty(registrant.Org, registrant.Name, registrant.Email))
		}
	}
	return registrant, registrar
}

func identityOf(handle string, card map[string]string) Identity {
	id := Identity{
		Handle:  strings.TrimSpace(handle),
		Org:     firstOf(card, "org", "fn"),
		Name:    firstOf(card, "fn"),
		Email:   strings.ToLower(firstOf(card, "email")),
		Country: strings.ToUpper(firstOf(card, "country", "cc")),
	}
	if id.Org != "" && id.Org == id.Name {

		id.Name = ""
	}

	if p := firstNonEmpty(id.Org, id.Name); p != "" && looksLikePrivacy(p) {
		id.Redacted = true
		id.PrivacyService = p
	}
	return id
}

func firstOf(card map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(card[k]); v != "" {
			return v
		}
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// registrantRedacted reads the RFC 9537 redaction list: a server that
// withholds the registrant is required to say so there, which is a far
// better signal than guessing from a missing field.
func registrantRedacted(list []redactedDoc) bool {
	for _, r := range list {
		v := strings.ToLower(r.Name.Type + " " + r.Name.Description)
		if strings.Contains(v, "registrant") || strings.Contains(v, "registry registrant id") {
			return true
		}
	}
	return false
}

// parseVCard flattens a jCard (RFC 7095) into property name -> first value.
func parseVCard(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var outer []any
	if err := json.Unmarshal(raw, &outer); err != nil {
		return nil
	}
	out := map[string]string{}
	for _, item := range outer {
		props, ok := item.([]any)
		if !ok {
			continue
		}
		for _, p := range props {
			f, ok := p.([]any)
			if !ok || len(f) < 4 {
				continue
			}
			name, _ := f[0].(string)
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if params, ok := f[1].(map[string]any); ok {
				if cc, ok := params["cc"].(string); ok && out["cc"] == "" {
					out["cc"] = cc
				}
			}
			if v := vcardValue(name, f[3]); v != "" {
				if _, seen := out[name]; !seen {
					out[name] = v
				}
			}
		}
	}
	return out
}

func vcardValue(name string, v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, strings.TrimSpace(s))
			}
		}
		if len(parts) == 0 {
			return ""
		}
		if name == "adr" {

			return parts[len(parts)-1]
		}
		return strings.Join(parts, " ")
	}
	return ""
}

type searchDoc struct {
	Results []domainDoc `json:"domainSearchResults"`
	// Notices is present on some servers that answer 200 with an explanation
	// instead of a result set.
	ErrorCode int `json:"errorCode"`
}

// SearchByNameserver asks one RDAP server for the domains delegated to a
// nameserver: RFC 9082's /domains?nsLdhName= search, the only reverse lookup
// the protocol defines.
func (c *Client) SearchByNameserver(ctx context.Context, base, ns string) ([]string, error) {
	n, err := toASCII(ns)
	if err != nil {
		return nil, err
	}
	u := joinRDAP(base, "domains") + "?nsLdhName=" + url.QueryEscape(n)
	var doc searchDoc
	meta, _, err := c.HTTP.GetJSON(ctx, SourceID, u, acceptRDAP, &doc)
	if err != nil {
		if meta != nil {
			switch meta.StatusCode {
			case 400, 401, 403, 404, 422, 429, 501:

				return nil, fmt.Errorf("%w: %s (HTTP %d)", ErrUnsupported, base, meta.StatusCode)
			}
		}
		return nil, fmt.Errorf("rdap: nameserver search on %s: %w", base, err)
	}
	if doc.ErrorCode != 0 {
		return nil, fmt.Errorf("%w: %s (RDAP error %d)", ErrUnsupported, base, doc.ErrorCode)
	}
	out := make([]string, 0, len(doc.Results))
	for _, r := range doc.Results {
		if n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.LDHName), ".")); n != "" {
			out = append(out, n)
		}
	}
	return out, nil
}

func joinRDAP(base, path string) string {
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	return base + path
}

// referral picks the registrar's RDAP URL out of a registry answer's links.
func referral(links []linkDoc, from string) (string, bool) {
	fromHost := hostOf(from)
	for _, l := range links {
		if !strings.EqualFold(l.Rel, "related") {
			continue
		}
		if l.Type != "" && !strings.Contains(strings.ToLower(l.Type), "rdap") {
			continue
		}
		u, err := url.Parse(strings.TrimSpace(l.Href))
		if err != nil || !strings.EqualFold(u.Scheme, "https") || u.User != nil {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h == "" || h == fromHost || !publicHost(h) {
			continue
		}

		p := u.Path
		if i := strings.LastIndex(p, "/domain/"); i >= 0 {
			p = p[:i+1]
		}
		u.Path = p
		u.RawQuery, u.Fragment = "", ""
		return u.String(), true
	}
	return "", false
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// publicHost accepts only a multi-label DNS name.
func publicHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return false
	}

	labels := strings.Split(strings.TrimSuffix(h, "."), ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}

	_, err := idna.Lookup.ToASCII(h)
	return err == nil
}
