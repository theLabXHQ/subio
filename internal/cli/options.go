package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/authz"
	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/gen"
	"github.com/theLabXHQ/subio/internal/output"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/scope"
	"github.com/theLabXHQ/subio/internal/source"
)

// Options is the fully validated configuration of one discover run.
type Options struct {
	Roots    *scope.Set
	RootList []string

	Include []string
	// RootNotes says how a root given as a URL or a scope-file wildcard was
	// read, so the operator sees what was searched.
	RootNotes []string
	// AllSources adds the adapters left out of the default for their cost.
	AllSources bool
	Exclude    []string
	Profile    source.Profile

	SecretsFile string

	RunTimeout  time.Duration
	Concurrency int
	PerSource   int

	Format output.Format
	Fields output.Fields
	Color  bool

	// NoColor is the flag as given.
	NoColor    bool
	OutputFile string
	LedgerFile string
	Manifest   string
	ScopeID    string

	// Sorted buffers results and emits them in canonical order.
	Sorted bool

	// StoreDir enables incremental history.
	StoreDir string
	// ChangedOnly prints only names that are new, back, or whose DNS answer
	// moved.
	ChangedOnly bool

	// RetireAfter drops assets unseen for this many consecutive complete runs.
	RetireAfter int
	// Compact rewrites the asset log after committing.
	Compact bool

	Silent  bool
	Verbose bool
	Stats   bool

	Resolve bool

	// CDN also asks Team Cymru which AS routes each resolved address, so an edge
	// with no telltale CNAME is still marked.
	CDN bool

	// ResolverProfile is a profile an earlier run wrote: its dropped resolvers
	// are left out and its slowed ones start at their measured rate.
	ResolverProfile    string
	ResolverProfileOut string
	profile            *resolverProfile
	Servers            []netip.AddrPort
	UsingPublic        bool
	// Authoritative queries each root's own nameservers directly instead of a
	// recursive resolver, which removes a lying or rate-limited middleman and
	// cache staleness.
	Authoritative bool
	Types         []dnsfast.Type
	TypesRaw      string
	QPS           int
	ResolverQPS   int
	DNSWorkers    int
	DNSWindow     int
	DNSTimeout    time.Duration
	DNSRetries    int
	TCPRetry      bool
	Wildcard      bool
	WildcardN     int

	// Active discovery.
	Active          bool
	AuthFile        string
	Auth            *authz.Authorization
	Brute           bool
	WordFiles       []string
	UzbekWords      bool
	No0x20          bool
	NoNegativeCache bool
	Wordlists       []*gen.Wordlist
	Permute         bool
	PermuteWordFile string
	PermuteWords    *gen.Wordlist

	// CandidateFiles hold full candidate names from any external generator
	// (subwiz, an LLM, gotator, dnsgen).
	CandidateFiles []string
	Candidates     []*gen.Wordlist
	Mine           bool
	AXFR           bool
	NSEC           bool
	PTR            bool
	TLS            bool
	// Web reads the hostnames the found hosts' own pages and headers reference
	// (CSP, links, absolute URLs), which can name hosts with no DNS record.
	Web bool
	// Vhost probes found addresses for virtual hosts: names a server serves a
	// distinct site for although no DNS record points to them.
	Vhost bool

	// ActiveAll turns on every active method that needs only active-dns, for a
	// full sweep without naming each.
	ActiveAll     bool
	Depth         int
	HistoryNames  []string
	MaxCandidates int
	TrustedRaw    string
	Trusted       []netip.AddrPort
	TrustedQPS    int
}

// ErrUsage reports a problem the operator must fix.
var ErrUsage = errors.New("usage")

func usageErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUsage, fmt.Sprintf(format, a...))
}

// parseDiscover builds Options from argv.
func parseDiscover(args []string, out io.Writer) (*Options, error) {
	o := &Options{
		Profile:     source.ProfilePersonal,
		RunTimeout:  10 * time.Minute,
		Concurrency: 16,
		PerSource:   2,
		QPS:         1000,
		DNSWorkers:  16,
		DNSWindow:   256,
		DNSTimeout:  2 * time.Second,
		DNSRetries:  1,
		TCPRetry:    true,
		Wildcard:    true,
		WildcardN:   3,
		Stats:       true,
		TypesRaw:    "A",

		MaxCandidates: defaultMaxCandidates,
		Depth:         1,
		TrustedQPS:    100,
	}
	var (
		roots, rootFiles          []string
		profileName, formatName   string
		resolversRaw              string
		noColor, jsonl, csvOut    bool
		showAll                   bool
		noTCP, noWildcard, noStat bool
	)

	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("input")
	r.listVar(g, &roots, true, "string", "root domain to enumerate; repeatable and comma separated", "d", "domain")
	r.listVar(g, &rootFiles, false, "file", "file of root domains, one per line; - for stdin", "l", "list")

	g = r.group("sources")
	r.listVar(g, &o.Include, true, "string", "only these adapters (default: every enabled one but the slow ones)", "s", "source")
	r.boolVar(g, &o.AllSources, "also run the slow adapters - wayback, commoncrawl, certspotter - which cost minutes for a few names", "as", "all-sources")
	r.listVar(g, &o.Exclude, true, "string", "skip these adapters", "es", "exclude-source")
	r.stringVar(g, &profileName, "terms profile: personal or commercial", "p", "profile")
	r.stringVar(g, &o.SecretsFile, "file of `source_id = value` lines; mode must be 600", "sf", "secrets-file")

	g = r.group("output")
	r.stringVar(g, &o.OutputFile, "write results to this file as well as stdout", "o", "output")
	r.stringVar(g, &formatName, "output format: plain, jsonl or csv", "of", "output-format")
	r.boolVar(g, &jsonl, "shorthand for -of jsonl", "j", "jsonl")
	r.boolVar(g, &csvOut, "shorthand for -of csv", "csv")
	r.stringVar(g, &o.LedgerFile, "write the full evidence ledger (findings, evidence, DNS, diagnostics) here", "ledger")
	r.stringVar(g, &o.Manifest, "write a run manifest here", "m", "manifest")
	r.stringVar(g, &o.ScopeID, "label recorded in the manifest instead of a hash of the roots", "scope-id")
	r.boolVar(g, &o.Sorted, "emit results sorted by name instead of streaming them as found", "sorted")

	g = r.group("history")
	r.stringVar(g, &o.StoreDir, "directory holding run history; enables the diff", "store")
	r.boolVar(g, &o.ChangedOnly, "print only new, returning, DNS-changed or no-longer-observed names", "co", "changed-only")
	r.intVar(g, &o.RetireAfter, "drop assets unseen for this many consecutive complete runs; 0 keeps all", "retire-after")
	r.boolVar(g, &o.Compact, "rewrite the logs after committing", "compact")
	r.boolVar(g, &o.Fields.Change, "show each name's change against the history", "ch", "show-change")

	g = r.group("display fields")
	r.boolVar(g, &showAll, "show every field below", "a", "all")
	r.boolVar(g, &o.Fields.Sources, "show which adapters reported the name", "src", "show-sources")
	r.boolVar(g, &o.Fields.Families, "show the evidence families", "fam", "show-families")
	r.boolVar(g, &o.Fields.Evidence, "show the evidence record count", "ec", "evidence-count")
	r.boolVar(g, &o.Fields.FirstSeen, "show the earliest provider-stated time", "fs", "first-seen")
	r.boolVar(g, &o.Fields.LastSeen, "show the latest provider-stated time", "ls", "last-seen")
	r.boolVar(g, &o.Fields.Status, "show the DNS verification status", "st", "status")
	r.boolVar(g, &o.Fields.DNS, "show the answer records", "dns", "records")
	r.boolVar(g, &o.Fields.CNAME, "show the CNAME chain", "cn", "cname")
	r.boolVar(g, &o.Fields.RCode, "show the DNS response code", "rc", "rcode")
	r.boolVar(g, &o.Fields.Resolver, "show which resolver answered", "rsv", "show-resolver")
	r.boolVar(g, &o.Fields.Wildcard, "mark names explained by a wildcard zone", "wc", "wildcard-mark")
	r.boolVar(g, &o.Fields.Root, "show the authorization root", "rt", "show-root")
	r.boolVar(g, &o.Fields.Edge, "show the CDN, WAF or cloud provider in front of the name", "eg", "edge")

	g = r.group("dns stage (active)")
	r.boolVar(g, &o.Resolve, "query DNS for every discovered name; this is ACTIVE", "r", "resolve")
	r.boolVar(g, &o.CDN, "with -resolve, also ask Team Cymru which AS routes each address, to mark CDN, WAF and cloud edges a CNAME does not reveal; one DNS query per distinct address", "cdn")
	r.stringVar(g, &resolversRaw, "resolvers, comma separated, or @file", "rs", "resolvers")
	r.stringVar(g, &o.ResolverProfile, "a resolver profile an earlier run wrote: leave out the resolvers it dropped and start the ones it slowed at their measured rate", "rp", "resolver-profile")
	r.stringVar(g, &o.ResolverProfileOut, "write what this run learned about each resolver, for -rp next time; carries over the entries of -rp it did not re-measure", "rpo", "resolver-profile-out")
	r.stringVar(g, &o.TypesRaw, "record types to query", "ty", "types")
	r.intVar(g, &o.QPS, "global DNS queries per second ceiling; 0 is unlimited", "qps")
	r.intVar(g, &o.ResolverQPS, "per-resolver queries per second ceiling; 0 is unlimited. Bounds each resolver so a global rate split over a public list does not push one past its own limit", "rqps", "resolver-qps")
	r.intVar(g, &o.DNSWorkers, "DNS sockets", "dw", "dns-workers")
	r.intVar(g, &o.DNSWindow, "outstanding queries per DNS socket", "dn", "dns-window")
	r.durationVar(g, &o.DNSTimeout, "per-query timeout", "dt", "dns-timeout")
	r.intVar(g, &o.DNSRetries, "DNS retries after the first attempt", "dr", "dns-retries")
	r.boolVar(g, &noTCP, "do not retry truncated answers over TCP", "no-tcp")
	r.boolVar(g, &noWildcard, "do not probe for wildcard zones", "no-wildcard")
	r.intVar(g, &o.WildcardN, "random control labels per wildcard probe", "wn", "wildcard-controls")
	r.boolVar(g, &o.Authoritative, "query each root's own nameservers directly instead of a recursive resolver; removes a lying or rate-limited middleman and cache staleness. All load lands on the target", "authoritative")

	g = r.group("active discovery (authorized targets only)")
	r.boolVar(g, &o.Active, "allow the methods below; they guess at names on the target's nameservers", "active")
	r.stringVar(g, &o.AuthFile, "record naming these roots and allowing active-dns; required by -active", "auth")
	r.boolVar(g, &o.Brute, "ask a wordlist under each root (built-in list unless -w is given)", "brute")
	r.listVar(g, &o.WordFiles, false, "file", "wordlist for -brute, one label per line; repeatable", "w", "wordlist")
	r.boolVar(g, &o.UzbekWords, "also use the built-in Uzbek and Russian label list with -brute", "uz", "uzbek")
	r.boolVar(g, &o.Permute, "ask variations of known names", "permute")
	r.stringVar(g, &o.PermuteWordFile, "extra words for -permute, one per line", "pw", "permute-words")
	r.listVar(g, &o.CandidateFiles, false, "file", "file of full candidate names to resolve, one per line, from any external generator; repeatable", "cands", "candidates")
	r.boolVar(g, &o.Mine, "read each root's NS, MX, SOA, TXT and SRV records for names", "mine")
	r.boolVar(g, &o.AXFR, "try a zone transfer from each root's nameservers", "axfr")
	r.boolVar(g, &o.NSEC, "walk each root's NSEC chain, where the zone exposes one", "nsec")
	r.boolVar(g, &o.PTR, "read reverse DNS of the addresses found", "ptr")
	r.boolVar(g, &o.TLS, "read certificate names from found hosts on port 443; needs active-tls", "tls")
	r.boolVar(g, &o.Web, "read hostnames the found hosts' pages and headers reference (CSP, links); needs active-http", "web")
	r.boolVar(g, &o.Vhost, "probe found addresses for virtual hosts that serve a distinct site with no DNS record; needs active-http", "vhost")
	r.boolVar(g, &o.ActiveAll, "turn on every method that needs only active-dns: brute, permute, mine, nsec, ptr, axfr", "active-all")
	r.intVar(g, &o.Depth, "with -brute, also ask under found names this many levels down", "depth")
	r.intVar(g, &o.MaxCandidates, "ceiling on generated names per run", "max-candidates")
	r.stringVar(g, &o.TrustedRaw, "keep a generated name only if these resolvers confirm it", "trusted")
	r.intVar(g, &o.TrustedQPS, "queries per second to -trusted resolvers", "trusted-qps")
	r.boolVar(g, &o.No0x20, "turn off DNS-0x20: send query names in lower case instead of mixed case", "no-0x20")
	r.boolVar(g, &o.NoNegativeCache, "ask every query; by default a name at or beneath one just answered NXDOMAIN is answered NXDOMAIN without asking, once its zone has kept that rule (RFC 8020) when checked", "nnc", "no-negative-cache")

	g = r.group("limits")
	r.durationVar(g, &o.RunTimeout, "overall run deadline", "t", "timeout")
	r.intVar(g, &o.Concurrency, "global in-flight HTTP requests", "c", "concurrency")
	r.intVar(g, &o.PerSource, "in-flight HTTP requests per adapter", "ps", "per-source")

	g = r.group("diagnostics")
	r.boolVar(g, &o.Silent, "only results on stdout, nothing on stderr", "silent")
	r.boolVar(g, &o.Verbose, "verbose diagnostics", "v", "verbose")
	r.boolVar(g, &noStat, "do not print the per-source report", "no-stats")
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")

	bare, err := parseInterspersed(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			helpDiscover(out, r)
			return nil, flag.ErrHelp
		}
		return nil, usageErr("%v", err)
	}
	roots = append(roots, bare...)

	for _, f := range rootFiles {
		lines, err := readRootFile(f)
		if err != nil {
			return nil, usageErr("%v", err)
		}
		roots = append(roots, lines...)
	}
	if len(roots) == 0 {
		return nil, usageErr("no root domain given")
	}
	for i, raw := range roots {
		if root, ok := rootFromInput(raw); ok {
			o.RootNotes = append(o.RootNotes, fmt.Sprintf("read %q as the root %s", raw, root))
			roots[i] = root
		}
	}
	set, err := scope.NewSet(roots...)
	if err != nil {
		return nil, usageErr("%v", err)
	}
	o.Roots = set
	for _, rt := range set.Roots() {
		o.RootList = append(o.RootList, rt.String())
	}

	o.Wildcard = !noWildcard
	if err := checkActive(o); err != nil {
		return nil, err
	}

	switch profileName {
	case "", "personal":
		o.Profile = source.ProfilePersonal
	case "commercial":
		o.Profile = source.ProfileCommercial
	default:
		return nil, usageErr("unknown profile %q: use personal or commercial", profileName)
	}

	switch {
	case jsonl && csvOut:
		return nil, usageErr("-jsonl and -csv are mutually exclusive")
	case jsonl:
		formatName = "jsonl"
	case csvOut:
		formatName = "csv"
	}
	f, ok := output.ParseFormat(formatName)
	if !ok {
		return nil, usageErr("unknown output format %q: use plain, jsonl or csv", formatName)
	}
	o.Format = f
	if showAll {

		o.Fields = output.Fields{
			Sources: true, Families: true, Evidence: true,
			FirstSeen: true, LastSeen: true, Status: true, Root: true,
			DNS: o.Resolve, CNAME: o.Resolve, RCode: o.Resolve,
			Resolver: o.Resolve, Wildcard: o.Resolve, Edge: o.Resolve,
			Change: o.StoreDir != "",
		}
	}

	if !o.Resolve && (o.Fields.DNS || o.Fields.CNAME || o.Fields.RCode || o.Fields.Resolver || o.Fields.Edge) {
		return nil, usageErr("DNS display fields need -resolve")
	}
	if o.CDN && !o.Resolve {
		return nil, usageErr("-cdn needs -resolve: it reads the addresses the DNS stage found")
	}
	if o.StoreDir == "" {
		switch {
		case o.ChangedOnly:
			return nil, usageErr("-changed-only needs -store: there is nothing to compare against")
		case o.Fields.Change:
			return nil, usageErr("-show-change needs -store")
		case o.RetireAfter > 0:
			return nil, usageErr("-retire-after needs -store")
		case o.Compact:
			return nil, usageErr("-compact needs -store")
		}
	}
	if o.RetireAfter < 0 {
		return nil, usageErr("-retire-after cannot be negative")
	}
	o.Color = !noColor && isTerminal(os.Stdout)
	o.NoColor = noColor
	o.Stats = !noStat

	o.TCPRetry = !noTCP
	o.Wildcard = !noWildcard
	if o.Resolve {
		types, err := parseTypes(o.TypesRaw)
		if err != nil {
			return nil, usageErr("%v", err)
		}
		o.Types = types
		servers, public, err := parseResolvers(resolversRaw)
		if err != nil {
			return nil, usageErr("%v", err)
		}
		o.Servers, o.UsingPublic = servers, public
		if o.Active && public && o.QPS == 0 {
			return nil, usageErr("-qps 0 with the default public resolvers would flood them: set a ceiling or use -rs")
		}
		if o.TrustedRaw != "" {
			if o.Trusted, _, err = parseResolvers(o.TrustedRaw); err != nil {
				return nil, usageErr("%v", err)
			}
			if o.TrustedQPS < 1 {
				return nil, usageErr("-trusted-qps must be at least 1")
			}
		}
		if o.ResolverProfile != "" {
			if o.profile, err = loadProfile(o.ResolverProfile); err != nil {
				return nil, usageErr("%v", err)
			}
		}
	} else if resolversRaw != "" {
		return nil, usageErr("-resolvers has no effect without -resolve")
	} else if o.ResolverProfile != "" || o.ResolverProfileOut != "" {
		return nil, usageErr("-resolver-profile and -resolver-profile-out need -resolve")
	}
	if o.Authoritative && !o.Resolve {
		return nil, usageErr("-authoritative needs -resolve: it changes which servers the DNS stage asks")
	}

	if o.Concurrency < 1 {
		return nil, usageErr("-concurrency must be at least 1")
	}
	if o.PerSource < 1 {
		return nil, usageErr("-per-source must be at least 1")
	}
	if o.RunTimeout <= 0 {
		return nil, usageErr("-timeout must be positive")
	}
	if o.DNSWorkers < 1 || o.DNSWindow < 1 {
		return nil, usageErr("-dns-workers and -dns-window must be at least 1")
	}
	if o.ResolverQPS < 0 {
		return nil, usageErr("-resolver-qps cannot be negative")
	}
	if o.QPS < 0 {
		return nil, usageErr("-qps cannot be negative")
	}
	if o.DNSTimeout <= 0 {
		return nil, usageErr("-dns-timeout must be positive")
	}
	if o.DNSRetries < 0 {
		return nil, usageErr("-dns-retries cannot be negative")
	}
	if o.WildcardN < 2 {
		return nil, usageErr("-wildcard-controls must be at least 2: one control cannot distinguish a wildcard from a collision")
	}
	if o.Silent && o.Verbose {

		_ = o
	}
	return o, nil
}

// parseInterspersed parses flags that appear before, between and after bare
// arguments, and returns the bare arguments in order.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var bare []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			return bare, nil
		}

		bare = append(bare, rest[0])
		rest = rest[1:]
	}
}

func parseTypes(s string) ([]dnsfast.Type, error) {
	var out []dnsfast.Type
	seen := map[dnsfast.Type]bool{}
	for _, part := range splitList(s) {
		t, ok := dnsfast.TypeByName(part)
		if !ok {
			return nil, fmt.Errorf("unknown record type %q", part)
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("no record types given")
	}
	return out, nil
}

// parseResolvers returns the servers and whether they are the public default.
func parseResolvers(v string) (servers []netip.AddrPort, public bool, err error) {
	if v == "" {
		s, err := resolver.ParseServers(resolver.DefaultServers)
		return s, true, err
	}
	if after, ok := strings.CutPrefix(v, "@"); ok {
		s, err := resolver.LoadResolvers(after)
		return s, false, err
	}
	s, err := resolver.ParseServers(splitList(v))
	return s, false, err
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readRootFile(path string) ([]string, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s contained no root domains", path)
	}
	return out, nil
}

// isTerminal reports whether f is a character device, which is the signal
// that color is wanted.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// isWriterTerminal is isTerminal for an io.Writer that may not be a file, as
// in tests where output is captured into a buffer.
func isWriterTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && isTerminal(f)
}

// rootFromInput reads the two shapes a root most often arrives in that are
// not a bare domain: a URL pasted from a browser or piped from another tool,
// and a bug-bounty scope line, "*.example.com".
func rootFromInput(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return "", false
		}
		s = u.Hostname()
	}
	s = strings.TrimPrefix(s, "*.")
	if s == strings.TrimSpace(raw) || s == "" {
		return "", false
	}
	return s, true
}
