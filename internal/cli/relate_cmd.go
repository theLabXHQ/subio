package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/theLabXHQ/subio/internal/asn"
	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/fetch"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/rdap"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/scope"
	"github.com/theLabXHQ/subio/internal/secrets"
	"github.com/theLabXHQ/subio/internal/source"
	"github.com/theLabXHQ/subio/internal/sources"
)

// Limits relate imposes on the two public services behind -whois and -asn.
var (
	rdapLimits = source.Limits{
		RequestsPerWindow: 60, Window: time.Minute, Burst: 2,
		RequestTimeout: 15 * time.Second, MaxResponseBytes: 2 << 20,
	}
	ripeStatLimits = source.Limits{
		RequestsPerWindow: 60, Window: time.Minute, Burst: 2,
		RequestTimeout: 30 * time.Second, MaxResponseBytes: 16 << 20,
	}
)

// runRelate suggests related root domains from four signals: the registrable
// domains the target's own certificates also cover, the apexes its DNS
// records point at, the domains its registrant also registered, and the
// reverse DNS of the autonomous system it is routed in.
func runRelate(args []string, stdout, stderr io.Writer) int {
	var (
		roots           []string
		rootFiles       []string
		sourcesRaw      = "crtsh"
		minCerts        = 1
		secretsFile     string
		profileName     string
		records         bool
		whois           bool
		whoisMax        = 25
		wantASN         bool
		asnMaxAddresses = 65536
		asnMaxPTR       = 1024
		resolversRaw    string
		asJSON          bool
		silent          bool
		noColor         bool
		timeout         = 5 * time.Minute
	)
	fs := flag.NewFlagSet("relate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("target")
	r.listVar(g, &roots, true, "string", "root domain to find relatives of; repeatable and comma separated", "d", "domain")
	r.listVar(g, &rootFiles, false, "file", "file of root domains, one per line", "l", "list")

	g = r.group("signals")
	r.stringVar(g, &sourcesRaw, "certificate-transparency sources to read (comma separated)", "s", "source")
	r.boolVar(g, &records, "also read the roots' MX, NS, SOA and TXT records for apexes they point at; this queries the roots' nameservers", "records")
	r.boolVar(g, &whois, "also compare each suggested apex's RDAP registrant with the target's, and ask the registry which domains use the target's own nameservers", "whois", "rdap")
	r.boolVar(g, &wantASN, "also read the reverse DNS of the autonomous system the roots are routed in", "asn")

	g = r.group("options")
	r.intVar(g, &minCerts, "only suggest an apex seen in at least this many shared certificates", "min")
	r.intVar(g, &whoisMax, "with -whois, how many suggested apexes to look up, strongest evidence first", "whois-max")
	r.intVar(g, &asnMaxAddresses, "with -asn, skip an autonomous system announcing more than this many addresses; 0 sweeps any size", "asn-max-addresses")
	r.intVar(g, &asnMaxPTR, "with -asn, cap the reverse lookups one run sends", "asn-max-ptr")
	r.durationVar(g, &timeout, "overall deadline", "t", "timeout")
	r.stringVar(g, &secretsFile, "file of `source_id = value` lines; mode must be 600", "sf", "secrets-file")
	r.stringVar(g, &profileName, "terms profile: personal or commercial", "p", "profile")
	r.stringVar(g, &resolversRaw, "resolvers for -records and -asn, comma separated or @file", "rs", "resolvers")

	g = r.group("output")
	r.boolVar(g, &asJSON, "emit machine-readable JSON", "j", "json")
	r.boolVar(g, &silent, "only results on stdout", "silent")
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")

	if err := fs.Parse(args); err != nil {
		w := stderr
		if err == flag.ErrHelp {
			w = stdout
		} else {
			fmt.Fprintf(stderr, "subio: %v\n", err)
		}
		fmt.Fprint(w, `subio relate - suggest related root domains

Subdomain tools enumerate under a root you already know and discard anything
outside it. relate reports those discarded apexes - a sibling brand, a regional
domain, an acquisition - with the evidence for each, ranked by what that
evidence establishes:

  owner    -whois  the registries say the same registrant registered both
  strong   (certs) one certificate covers the target and this apex
  medium   -whois  the registry's domain search ties it to your own nameserver
  weak     -asn    reverse DNS in your autonomous system
           -records an apex your MX, NS, SOA or TXT records point at

These are SUGGESTIONS, not findings. subio never widens scope on its own: it
does not enumerate under a suggested root, and adds nothing to any run. Verify
that you own a domain before adding it with -d.

USAGE
   subio relate -d example.com
   subio relate -d example.com -s crtsh,scanmalware -min 2 -j
   subio relate -d example.com -whois -records
   subio relate -d example.com -asn -rs 9.9.9.9
`)
		r.render(w)
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitConfig
	}
	if rejectBareArgs(fs, stderr) {
		return exitConfig
	}

	log := logx.New(stderr)
	log.Silent = silent
	log.Color = !noColor && isWriterTerminal(stderr)
	banner(stderr, silent, noColor)

	for _, f := range rootFiles {
		lines, err := readRootFile(f)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		roots = append(roots, lines...)
	}
	if len(roots) == 0 {
		log.Logf("error", "give at least one root with -d or -l")
		return exitConfig
	}
	if whoisMax < 0 || asnMaxAddresses < 0 || asnMaxPTR < 0 {
		log.Logf("error", "-whois-max, -asn-max-addresses and -asn-max-ptr cannot be negative")
		return exitConfig
	}
	set, err := scope.NewSet(roots...)
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	var prof source.Profile
	switch profileName {
	case "", "personal":
		prof = source.ProfilePersonal
	case "commercial":
		prof = source.ProfileCommercial
	default:
		log.Logf("error", "unknown profile %q: use personal or commercial", profileName)
		return exitConfig
	}

	targetApexes := map[string]bool{}
	rootNames := make([]string, 0, len(set.Roots()))
	for _, rt := range set.Roots() {
		rootNames = append(rootNames, rt.String())
		if ax := apexOf(rt.String()); ax != "" {
			targetApexes[ax] = true
		}
	}

	reg := sources.NewRegistry()
	var providers []source.Provider
	for _, id := range splitList(sourcesRaw) {
		p, ok := reg.ByID(id)
		if !ok {
			log.Logf("error", "unknown source %q", id)
			return exitConfig
		}
		if p.Metadata().Family != source.FamilyCT {
			log.Logf("warn", "%s is not a certificate-transparency source; only CT sources list sibling domains in a certificate", id)
		}
		providers = append(providers, p)
	}

	sec := secrets.New()
	if secretsFile != "" {
		if err := sec.LoadFile(secretsFile); err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
	}

	scheduler := sched.New(sched.Config{GlobalConcurrency: 8, PerSourceConcurrency: 2})
	client := fetch.New(fetch.Config{Scheduler: scheduler, MaxAttempts: 3})
	for _, p := range providers {
		client.Register(p.Metadata())
	}
	if whois {
		client.Register(source.Metadata{ID: rdap.SourceID, Limits: rdapLimits})
	}
	if wantASN {
		client.Register(source.Metadata{ID: asn.SourceID, Limits: ripeStatLimits})
	}

	ctx, cancel := interruptible(timeout, log)
	defer cancel()
	sess := &source.Session{HTTP: client, Secrets: sec, Profile: prof}
	if dl, ok := ctx.Deadline(); ok {
		sess.Deadline = dl
	}

	// One resolver serves both DNS-backed signals.
	var res *resolver.Resolver
	if records || wantASN {
		servers, public, err := parseResolvers(resolversRaw)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		res, err = resolver.New(resolver.Config{
			Servers: servers, Workers: 8, Window: 32,
			Timeout: 3 * time.Second, Retries: 1,
		})
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		if public {
			log.Logf("warn", "using public resolvers; their operators see the roots queried")
		}
	}

	log.Logf("info", "reading certificate transparency for %d root(s); this discloses them to the sources", len(roots))
	log.Logf("warn", "suggestions only: subio enumerates nothing under a related root and adds nothing to scope")

	var seen []seenName
	incomplete := 0
	for _, rt := range set.Roots() {
		for _, p := range providers {
			obs, sum := collectProvider(ctx, p, rt.String(), sess)
			seen = append(seen, collectObservations(obs, p.Metadata().ID)...)
			if !sum.Status.Complete() {
				incomplete++
				log.Logf("verbose", "%s on %s: %s", p.Metadata().ID, rt.String(), sum.Status)
			}
		}
	}

	if records {
		log.Logf("warn", "-records queries the roots' own nameservers: a mild active step, and a mail or DNS provider will show up as a weak link")
		for _, rt := range set.Roots() {
			seen = append(seen, recordRelated(ctx, res, rt.String())...)
		}
	}

	if wantASN {
		log.Logf("warn", "-asn asks Cymru and RIPEstat about the roots' addresses, then reads public reverse DNS for third-party address space: "+
			"your resolvers see those queries, and nothing is sent to any suggested root")
		seen = append(seen, asnRelated(ctx, res, client, rootNames, asnSweep{
			MaxAddresses: uint64(asnMaxAddresses), PTRBudget: asnMaxPTR,
		}, log)...)
	}

	related := tallyRelated(targetApexes, seen)

	if whois {
		log.Logf("warn", "-whois reads public registry data over RDAP: each suggested apex is disclosed to its own registry, "+
			"but nothing is sent to the apex itself or to any name under it")

		opt := whoisOptions{MaxLookups: whoisMax, FollowReferral: true, Search: true}
		cl := &rdap.Client{HTTP: client, FollowReferral: opt.FollowReferral}
		seen = append(seen, whoisRelated(ctx, cl, rootNames, targetApexes, related, opt, log)...)
		related = tallyRelated(targetApexes, seen)
	}
	related = filterRelated(related, minCerts)

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(related); err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "RELATED APEX\tCONFIDENCE\tSHARED CERTS\tNAMES\tVIA\tEVIDENCE")
		for _, rr := range related {
			evidence := rr.Detail
			if evidence == "" {
				evidence = rr.Example
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n",
				rr.Apex, rr.Confidence, rr.Certs, rr.Names, strings.Join(rr.Via, ","), evidence)
		}
		_ = tw.Flush()
	}

	log.Printf("\n%d related apex(es) suggested.\n", len(related))
	log.Printf("These are NOT in scope and were not enumerated. Verify ownership before adding any with -d.\n")
	if incomplete > 0 {
		log.Logf("warn", "%d source run(s) were incomplete, so the suggestions may be partial", incomplete)
	}
	if why := stoppedEarly(ctx); why != "" {
		log.Logf("warn", "the run did not finish (%s), so these suggestions are partial", why)
		return exitPartial
	}
	if len(related) == 0 {
		return exitEmpty
	}
	return exitOK
}

// filterRelated applies -min.
func filterRelated(related []relatedRoot, minCerts int) []relatedRoot {
	kept := related[:0]
	for _, rr := range related {
		if rr.Certs >= minCerts || hasNonCertificateEvidence(rr.Via) {
			kept = append(kept, rr)
		}
	}
	return kept
}

// recordRelated reads a root's MX, NS, SOA and TXT (including DMARC) records
// and returns the hostnames they name, so apexes the root's own
// infrastructure points at become weak suggestions.
func recordRelated(ctx context.Context, res *resolver.Resolver, root string) []seenName {
	jobs := []resolver.Job{
		{Name: root, Type: dnsfast.TypeMX},
		{Name: root, Type: dnsfast.TypeNS},
		{Name: root, Type: dnsfast.TypeSOA},
		{Name: root, Type: dnsfast.TypeTXT},
		{Name: "_dmarc." + root, Type: dnsfast.TypeTXT},
	}
	var out []seenName
	for _, a := range res.ResolveJobs(ctx, jobs) {
		if a.Outcome != resolver.Resolved {
			continue
		}
		for _, rr := range a.Records {
			switch rr.Type {
			case "MX":

				if f := strings.Fields(rr.Value); len(f) >= 2 {
					out = append(out, seenName{host: f[1], source: "dns", kind: "mx", detail: root + " MX"})
				}
			case "NS":
				out = append(out, seenName{host: rr.Value, source: "dns", kind: "ns", detail: root + " NS"})
			case "SOA":

				if f := strings.Fields(rr.Value); len(f) >= 1 {
					out = append(out, seenName{host: f[0], source: "dns", kind: "soa", detail: root + " SOA"})
				}
			case "TXT":
				for _, h := range hostInText.FindAllString(rr.Value, -1) {
					out = append(out, seenName{host: h, source: "dns", kind: "txt", detail: root + " TXT"})
				}
			}
		}
	}
	return out
}

// collectProvider runs one provider against one root and returns every
// observation and the terminal summary, without the engine's scope filtering.
func collectProvider(ctx context.Context, p source.Provider, root string, sess *source.Session) ([]source.Observation, source.RunSummary) {
	var obs []source.Observation
	var sum source.RunSummary
	for res := range p.Run(ctx, root, sess) {
		switch {
		case res.Observation != nil:
			obs = append(obs, *res.Observation)
		case res.Summary != nil:
			sum = *res.Summary
		}
	}
	return obs, sum
}
