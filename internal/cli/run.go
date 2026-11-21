package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/engine"
	"github.com/theLabXHQ/subio/internal/fetch"
	"github.com/theLabXHQ/subio/internal/gen"
	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/output"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/secrets"
	"github.com/theLabXHQ/subio/internal/source"
	"github.com/theLabXHQ/subio/internal/sources"
	"github.com/theLabXHQ/subio/internal/store"
	"github.com/theLabXHQ/subio/internal/version"
)

func runDiscover(args []string, stdout, stderr io.Writer) int {
	o, err := parseDiscover(args, stdout)
	if err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		fmt.Fprintf(stderr, "subio: %s\n", strings.TrimPrefix(err.Error(), "usage: "))
		return exitConfig
	}

	banner(stderr, o.Silent, o.NoColor)
	log := logx.New(stderr)
	log.Verbose, log.Silent, log.Color = o.Verbose, o.Silent, o.Color
	for _, n := range o.RootNotes {
		log.Logf("info", "%s", n)
	}

	reg := sources.NewRegistry()
	providers, unknown := reg.SelectWith(o.Include, o.Exclude, o.AllSources)
	if len(unknown) > 0 {

		log.Logf("error", "unknown source(s): %s", strings.Join(unknown, ", "))
		log.Logf("error", `run "subio sources" to see the available adapters`)
		return exitConfig
	}
	if len(providers) == 0 {
		log.Logf("error", "every source was excluded")
		return exitConfig
	}

	sec := secrets.New()
	if o.SecretsFile != "" {
		if err := sec.LoadFile(o.SecretsFile); err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
	}

	for _, path := range []string{o.LedgerFile, o.Manifest} {
		if path == "" {
			continue
		}
		if err := checkWritable(path); err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
	}

	// Open the store before anything runs: a baseline that cannot be loaded must
	// stop the run, not silently produce a diff against nothing.
	var st *store.Store
	var snap *store.Snapshot
	if o.StoreDir != "" {
		var err error
		if st, err = store.Open(o.StoreDir); err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		if snap, err = st.Load(); err != nil {
			log.Logf("error", "reading history: %v", err)
			return exitFatal
		}
		if snap.SkippedLines > 0 {
			log.Logf("warn", "history has %d unreadable line(s); they were skipped", snap.SkippedLines)
		}
		log.Logf("verbose", "history: %d known names across %d run(s)", len(snap.Assets), len(snap.Runs))
		if o.Active {

			for _, a := range snap.Assets {
				o.HistoryNames = append(o.HistoryNames, a.FQDN)
			}
		}
	}

	// --------------------------------------------------------- output ----
	// Creating the file empties it, so this comes after every check that can
	// still refuse the run.
	var outFile *os.File
	if o.OutputFile != "" {
		f, err := os.Create(o.OutputFile)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		defer f.Close()
		outFile = f
	}
	var writeErr error
	w := output.New(output.Config{
		Format: o.Format, Fields: o.Fields, Color: o.Color,
		Stdout: stdout, File: fileOrNil(outFile),
		OnError: func(err error) {
			writeErr = err
			log.Logf("error", "writing results: %v", err)
		},
	}, 4096)
	writerDone := make(chan error, 1)
	go func() { writerDone <- w.Run() }()

	ctx, cancel := interruptible(o.RunTimeout, log)
	defer cancel()

	scheduler := sched.New(sched.Config{
		GlobalConcurrency:    o.Concurrency,
		PerSourceConcurrency: o.PerSource,
		BreakerThreshold:     4,
		BreakerCooldown:      30 * time.Second,
	})
	client := fetch.New(fetch.Config{Scheduler: scheduler, MaxAttempts: 3})
	for _, p := range providers {
		client.Register(p.Metadata())
	}
	printNotices(log, providers, sec, o)
	providers = runnableProviders(providers, sec.Has, len(o.Include) > 0)
	if len(providers) == 0 {
		log.Logf("error", "no selected source can run: each one needs a credential")
		return exitConfig
	}

	startedAt := time.Now().UTC()
	led := ledger.New(startedAt)
	eng := &engine.Engine{HTTP: client, Secrets: sec, Profile: o.Profile}

	streaming := o.Format == output.FormatPlain && !o.Sorted && !o.Resolve && o.StoreDir == "" && !o.Fields.NeedsWholeRun()
	if streaming {
		eng.OnFinding = func(host, root string, _ source.Observation) {
			rec := output.NewRecord(host, root, time.Now().UTC())
			rec.Verification = string(ledger.NotChecked)
			w.In() <- rec
		}
	}
	eng.Run(ctx, o.Roots, providers, led)
	passiveEnded := time.Now().UTC()
	log.Logf("verbose", "passive stage finished in %s with %d names",
		passiveEnded.Sub(startedAt).Round(time.Millisecond), led.Len())
	if ctx.Err() != nil {

		log.Logf("warn", "stopped during passive collection: later stages were skipped, and the artifacts describe only what had been collected")
	}

	// ------------------------------------------------- DNS stage (opt-in) ----
	var wildcards []resolver.WildcardReport
	var resolverStats []resolver.ServerStat
	var edeReasons map[string]int64
	var caseFolders int64
	var kDrops int64
	var kDropsKnown bool
	var edges edgeIndex
	if ctx.Err() == nil && o.Resolve && (led.Len() > 0 || o.Active) {
		servers, retries := o.Servers, o.DNSRetries

		recursive := o.Servers
		if o.Authoritative {
			boot, berr := resolver.New(resolver.Config{
				Servers: o.Servers, Workers: 4, Window: 32,
				Timeout: o.DNSTimeout, Retries: o.DNSRetries, QPS: o.QPS,
			})
			if berr != nil {
				log.Logf("error", "%v", berr)
				return exitConfig
			}
			ns := authoritativeServers(ctx, boot, o.RootList, log)
			if len(ns) == 0 {
				log.Logf("error", "authoritative: found no nameserver address for any root; not falling back to a recursive resolver silently")
				return exitPartial
			}
			servers = ns
			o.Servers, o.UsingPublic = ns, false

			if len(o.RootList) > 1 && retries < len(o.RootList) {
				retries = len(o.RootList)
			}
			log.Logf("info", "authoritative: querying %d nameserver address(es) directly; no recursive resolver in between", len(ns))
		}
		var serverQPS map[netip.AddrPort]float64
		if o.profile != nil && !o.Authoritative {
			servers, serverQPS = applyResolverProfile(servers, o.profile, o.ResolverProfile, log)
		}
		res, err := resolver.New(resolver.Config{
			ServerQPS: serverQPS,
			Servers:   servers, Workers: o.DNSWorkers, Window: o.DNSWindow,
			Timeout: o.DNSTimeout, Retries: retries, QPS: o.QPS,
			PerResolverQPS: o.ResolverQPS, TCPOnTruncate: o.TCPRetry,

			DNSSEC: o.Wildcard,

			Case0x20:        !o.No0x20,
			NoNegativeCache: o.NoNegativeCache,
		})
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		var trusted *resolver.Resolver
		if len(o.Trusted) > 0 {
			trusted, err = resolver.New(resolver.Config{
				Servers: o.Trusted, Workers: 2, Window: 16,
				Timeout: o.DNSTimeout, Retries: o.DNSRetries, QPS: o.TrustedQPS,
				TCPOnTruncate: o.TCPRetry,

				Case0x20: !o.No0x20,
			})
			if err != nil {
				log.Logf("error", "%v", err)
				return exitConfig
			}
		}
		dnsStarted := time.Now()
		stage := newDNSStage(res, trusted, led, o, log)
		stage.run(ctx)
		if stage.scanner != nil {
			wildcards = stage.scanner.Reports()
		}
		resolverStats = res.Stats()
		edeReasons = res.EDEReasons()
		caseFolders = res.CaseFolders()
		kDrops, kDropsKnown = res.KernelDrops()
		logNegativeCache(log, res.NegativeCacheStats())
		log.Logf("verbose", "dns stage finished in %s", time.Since(dnsStarted).Round(time.Millisecond))
		if o.CDN && ctx.Err() == nil {
			edges = buildEdgeIndex(ctx, recursive, led, log)
		}
		if o.ResolverProfileOut != "" {
			p := buildProfile(resolverStats, o.profile, time.Now().UTC())
			if err := writeProfile(o.ResolverProfileOut, p); err != nil {
				log.Logf("error", "resolver profile: %v", err)
			} else {
				log.Logf("info", "resolver profile for %d resolver(s) written to %s", len(p.Servers), o.ResolverProfileOut)
			}
		}
	}

	if n := led.Len(); n >= noticeableWriteNames {
		log.Logf("info", "writing %d name(s)%s; on a run this size that takes several seconds", n, artifactTargets(o))
	}
	var diff *store.Diff
	var runRec store.Run
	var commit []store.Asset
	if st != nil {
		runRec = buildRunRecord(o, led, startedAt, time.Now().UTC())
		diff, commit = store.Compute(snap, runRec, observationsFrom(led))
		streamChanges(led, startedAt, diff, o.ChangedOnly, edges, w.In())
	} else if !streaming {
		if err := streamRecords(led, startedAt, edges, w.In()); err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
	}
	close(w.In())
	if err := <-writerDone; err != nil || writeErr != nil {
		if st != nil {
			log.Logf("error", "this run was not recorded, so its changes will be reported again")
		}
		return exitFatal
	}

	if o.LedgerFile != "" {
		if err := writeLedger(o.LedgerFile, led); err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
		log.Logf("info", "ledger written to %s", o.LedgerFile)
	}
	finishedAt := time.Now().UTC()
	if o.Manifest != "" {
		if err := writeManifest(o.Manifest, buildManifest(o, led, wildcards, resolverStats, providers, startedAt, passiveEnded, finishedAt)); err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
		log.Logf("info", "manifest written to %s", o.Manifest)
	}

	if st != nil {
		if err := st.Commit(runRec, commit); err != nil {
			log.Logf("error", "writing history: %v", err)
			return exitFatal
		}
		if o.RetireAfter > 0 {

			n, err := st.Retire(o.RetireAfter, diff.RunID, finishedAt)
			if err != nil {
				log.Logf("error", "retention: %v", err)
				return exitFatal
			}
			if n > 0 {
				log.Logf("info", "retired %d asset(s) unseen for %d consecutive complete runs", n, o.RetireAfter)
			}
		}
		if o.Compact {
			before, after, err := st.Compact()
			if err != nil {
				log.Logf("error", "compaction: %v", err)
				return exitFatal
			}
			log.Logf("info", "compacted history: %d -> %d bytes", before, after)
		}
	}

	stats := led.Stats()

	if stats.Findings == 0 && !o.Silent && stoppedEarly(ctx) == "" {
		log.Printf("\n%s\n", whyEmpty(led.SourceRuns(), o.RootList))
	}
	if o.Stats && !o.Silent {
		printReport(log, led, stats, wildcards, resolverStats, edeReasons, caseFolders,
			kDrops, kDropsKnown, finishedAt.Sub(startedAt))

		if o.Resolve {
			printFanIn(log, led)
		}
		if diff != nil {
			printDiff(log, diff)
		}

		if snap != nil {
			printPersistentFailures(log, store.PersistentFailures(
				snap.Runs, statusBySource(led), persistentWindow, persistentThreshold))
		}
	}

	if why := stoppedEarly(ctx); why != "" {
		log.Logf("warn", "the run did not finish (%s), so the absence of a name proves nothing", why)
		return exitPartial
	}
	switch {
	case stats.Incomplete > 0 || stats.DNSErrors > 0:
		return exitPartial
	case stats.Findings == 0:
		return exitEmpty
	}
	return exitOK
}

// runnableProviders drops adapters that need a key nobody configured, unless
// the operator named them.
func runnableProviders(all []source.Provider, hasKey func(string) bool, named bool) []source.Provider {
	if named {
		return all
	}
	out := make([]source.Provider, 0, len(all))
	for _, p := range all {
		md := p.Metadata()
		if md.Key == source.RequiredKey && !hasKey(md.ID) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// checkWritable reports whether path can be written, without emptying what
// is there.
func checkWritable(path string) error {
	fi, err := os.Stat(path)
	switch {
	case err == nil:
		if fi.IsDir() {
			return fmt.Errorf("%s is a directory", path)
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		return f.Close()
	case errors.Is(err, os.ErrNotExist):
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
		return os.Remove(path)
	}
	return err
}

// statusBySource is this run's per-source status, the same map the store
// record carries, so a failure streak is computed against exactly what will be written.
func statusBySource(led *ledger.Ledger) map[string]string {
	status := map[string]string{}
	for _, r := range led.SourceRuns() {
		status[r.SourceID] = r.Status
	}
	return status
}

// buildRunRecord captures what the run did, including each source's terminal
// status, which is what lets a later diff decide whether an absence means
// anything.
func buildRunRecord(o *Options, led *ledger.Ledger, started, finished time.Time) store.Run {
	status := statusBySource(led)
	profile := "personal"
	if o.Profile == source.ProfileCommercial {
		profile = "commercial"
	}
	return store.Run{
		ID: runID(started, o.RootList), StartedAt: started, FinishedAt: finished,
		ScopeID: hashRoots(o.RootList), Roots: o.RootList, Profile: profile,
		DNSStage: o.Resolve, Findings: led.Len(), DNSErrors: led.Stats().DNSErrors, SourceStatus: status,
		Tool: version.Version,
	}
}

// observationsFrom projects the ledger into what the store needs.
func observationsFrom(led *ledger.Ledger) []store.Observation {
	dns := led.DNSByFinding()
	out := make([]store.Observation, 0, led.Len())
	_ = led.EachFinding(func(f ledger.Finding) error {
		o := store.Observation{
			Key:               store.Key{Root: f.RootDomain, FQDN: f.FQDN},
			Sources:           f.Sources,
			ProviderFirstSeen: f.FirstSeenAt,
			ProviderLastSeen:  f.LastSeenAt,
			Verification:      string(f.Verification),
			Wildcard:          f.WildcardSuspected,
		}
		for _, obs := range dns[f.FindingID] {
			if !obs.Definitive() {
				o.DNSFailed = true
				continue
			}
			o.DNSAnswered = append(o.DNSAnswered, obs.QueryType)
			for _, r := range obs.Records {
				o.Records = append(o.Records, store.RR{Type: r.Type, Value: r.Value})
			}
		}
		out = append(out, o)
		return nil
	})
	return out
}

func fileOrNil(f *os.File) io.Writer {
	if f == nil {
		return nil
	}
	return f
}

// recordFor projects one finding, with its DNS observations, into an output
// record.
func recordFor(f ledger.Finding, obs []ledger.DNSObservation, at time.Time, edges edgeIndex) *output.Record {
	rec := output.NewRecord(f.FQDN, f.RootDomain, at)
	rec.Sources, rec.Families = f.Sources, f.Families
	rec.Evidence = f.EvidenceCount
	rec.FirstSeen, rec.LastSeen = f.FirstSeenAt, f.LastSeenAt
	rec.Verification = string(f.Verification)
	rec.Wildcard = f.WildcardSuspected

	for _, o := range obs {
		if rec.RCode == "" {
			rec.RCode, rec.Resolver = o.RCode, o.Resolver
			t := o.CheckedAt
			rec.CheckedAt = &t
		}
		for _, r := range o.Records {
			rec.Records = append(rec.Records, output.RR{Type: r.Type, Value: r.Value, TTL: r.TTL})
		}
		if len(o.CNAMEChain) > 0 && len(rec.CNAMEChain) == 0 {
			rec.CNAMEChain = o.CNAMEChain
		}
		if o.ErrorClass != "" && rec.ErrorClass == "" {
			rec.ErrorClass = o.ErrorClass
		}
		if o.WildcardSuspected && len(rec.WildcardControls) == 0 {
			rec.WildcardControls = o.WildcardSamples
		}
	}
	rec.Edge = edges.edgeFor(rec.CNAMEChain, rec.Records)
	return rec
}

// streamRecords sends every finding to the writer one at a time.
func streamRecords(led *ledger.Ledger, at time.Time, edges edgeIndex, out chan<- *output.Record) error {
	return led.EachFinding(func(f ledger.Finding) error {
		out <- recordFor(f, led.DNSFor(f.RootDomain, f.FQDN), at, edges)
		return nil
	})
}

// streamChanges sends one record per diff entry, looking each finding up as
// it goes.
func streamChanges(led *ledger.Ledger, at time.Time, diff *store.Diff,
	changedOnly bool, edges edgeIndex, out chan<- *output.Record) {

	for _, e := range diff.Entries {
		if changedOnly {
			switch e.Change {
			case store.New, store.Reappeared, store.DNSChanged, store.NoLongerObserved:
			default:
				continue
			}
		}
		var rec *output.Record
		if f, ok := led.Finding(e.Root, e.FQDN); ok {
			rec = recordFor(f, led.DNSFor(e.Root, e.FQDN), at, edges)
		} else {

			rec = output.NewRecord(e.FQDN, e.Root, at)
			rec.Sources = e.Sources
			rec.Verification = string(ledger.NotChecked)
		}
		rec.Change = string(e.Change)
		rec.MissingRuns = e.MissingRuns
		rec.ChangeReason = e.Reason
		for _, r := range e.PrevRecords {
			rec.PrevRecords = append(rec.PrevRecords, output.RR{Type: r.Type, Value: r.Value})
		}
		out <- rec
	}
}

func writeLedger(path string, led *ledger.Ledger) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	w := bufio.NewWriterSize(f, 64<<10)
	werr := led.WriteJSONL(w)
	ferr := w.Flush()
	cerr := f.Close()
	return errors.Join(werr, ferr, cerr)
}

// Manifest records what a run did, without recording what it looked at: the
// roots are reduced to a hash so a manifest can be attached to a ticket.
type Manifest struct {
	SchemaVersion  string             `json:"manifest_schema_version"`
	LedgerSchema   string             `json:"ledger_schema_version"`
	Tool           string             `json:"tool"`
	ToolVersion    string             `json:"tool_version"`
	RunID          string             `json:"run_id"`
	ScopeID        string             `json:"scope_id"`
	RootCount      int                `json:"root_count"`
	Profile        string             `json:"profile"`
	Sources        []string           `json:"sources"`
	StartedAt      time.Time          `json:"started_at"`
	PassiveEndedAt time.Time          `json:"passive_ended_at"`
	FinishedAt     time.Time          `json:"finished_at"`
	Findings       int                `json:"findings"`
	Normalization  string             `json:"normalization_profile"`
	DNSStage       bool               `json:"dns_stage_enabled"`
	RecordTypes    string             `json:"record_types,omitempty"`
	Resolvers      []string           `json:"resolvers,omitempty"`
	Incomplete     int                `json:"incomplete_sources"`
	DNSErrors      int                `json:"dns_errors,omitempty"`
	WildcardZones  []string           `json:"wildcard_zones,omitempty"`
	SourceRuns     []ledger.SourceRun `json:"source_runs"`
	// ResolverStats says how each resolver behaved, so a dead or lying entry in
	// a resolver list can be found and removed.
	ResolverStats []resolver.ServerStat `json:"resolver_stats,omitempty"`
	// ContradictedResolvers counts, per resolver, how often a trusted resolver
	// did not confirm what it claimed.
	ContradictedResolvers map[string]int `json:"contradicted_resolvers,omitempty"`
	// Active records what authorized active discovery, and which lists it used.
	Active *activeManifest `json:"active,omitempty"`
}

// activeManifest states what active discovery ran on the strength of.
type activeManifest struct {
	AuthorizedBy  string          `json:"authorized_by"`
	ExpiresAt     string          `json:"expires_at,omitempty"`
	MaxCandidates int             `json:"max_candidates"`
	Wordlists     []*gen.Wordlist `json:"wordlists,omitempty"`
	PermuteWords  *gen.Wordlist   `json:"permute_words,omitempty"`
	Candidates    []*gen.Wordlist `json:"candidate_files,omitempty"`
	Trusted       int             `json:"trusted_resolvers,omitempty"`
}

func buildManifest(o *Options, led *ledger.Ledger, wild []resolver.WildcardReport, stats []resolver.ServerStat,
	providers []source.Provider, started, passiveEnded, finished time.Time) Manifest {

	ids := make([]string, 0, len(providers))
	for _, p := range providers {
		ids = append(ids, p.Metadata().ID)
	}
	sort.Strings(ids)

	var resolvers []string
	for _, s := range o.Servers {
		resolvers = append(resolvers, s.String())
	}
	var zones []string
	for _, r := range wild {
		if r.Suspected {
			zones = append(zones, r.Parent+" ("+r.Type.String()+")")
		}
	}
	sort.Strings(zones)

	profile := "personal"
	if o.Profile == source.ProfileCommercial {
		profile = "commercial"
	}
	scopeID := o.ScopeID
	if scopeID == "" {
		scopeID = hashRoots(o.RootList)
	}
	var active *activeManifest
	if o.Active && o.Auth != nil {
		active = &activeManifest{
			AuthorizedBy: o.Auth.Owner, ExpiresAt: o.Auth.ExpiresAt, MaxCandidates: o.MaxCandidates,
			Wordlists: o.Wordlists, PermuteWords: o.PermuteWords, Candidates: o.Candidates, Trusted: len(o.Trusted),
		}
	}
	return Manifest{
		ResolverStats: stats, Active: active, ContradictedResolvers: led.ContradictedResolvers(),
		SchemaVersion: "subio.run-manifest.v2", LedgerSchema: ledger.SchemaVersion,
		Tool: "subio", ToolVersion: version.Version,
		RunID: runID(started, o.RootList), ScopeID: scopeID, RootCount: len(o.RootList),
		Profile: profile, Sources: ids,
		StartedAt: started, PassiveEndedAt: passiveEnded, FinishedAt: finished,
		Findings: led.Len(), Normalization: ledger.NormalizationProfile,
		DNSStage: o.Resolve, RecordTypes: o.TypesRaw, Resolvers: resolvers,
		Incomplete: led.Stats().Incomplete, DNSErrors: led.Stats().DNSErrors, WildcardZones: zones,
		SourceRuns: led.SourceRuns(),
	}
}

func hashRoots(roots []string) string {
	s := append([]string(nil), roots...)
	sort.Strings(s)
	sum := sha256.Sum256([]byte(strings.Join(s, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func runID(at time.Time, roots []string) string {
	sum := sha256.Sum256([]byte(at.Format(time.RFC3339Nano) + hashRoots(roots)))
	return hex.EncodeToString(sum[:8])
}

// noticeableWriteNames is where finalising a run stops being instant.
const noticeableWriteNames = 10000

// artifactTargets names what is about to be written, so the pause is
// accounted for rather than merely announced.
func artifactTargets(o *Options) string {
	var parts []string
	if o.StoreDir != "" {
		parts = append(parts, "the run store")
	}
	if o.LedgerFile != "" {
		parts = append(parts, "the ledger")
	}
	if o.Manifest != "" {
		parts = append(parts, "the manifest")
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return " to " + parts[0]
	default:
		return " to " + strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
}

func writeManifest(path string, m Manifest) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}
