package cli

import (
	"context"
	"hash/maphash"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/authz"
	"github.com/theLabXHQ/subio/internal/dnsfast"
	"github.com/theLabXHQ/subio/internal/gen"
	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/source"
	"strconv"
)

const (

	// defaultMaxCandidates is the ceiling on generated names per run.
	defaultMaxCandidates = 5_000_000
	// minedWordLimit is how many words are taken from a root's known names.
	minedWordLimit = 100
	// permuteRounds lets names found by varying known names be varied once more.
	permuteRounds = 2

	// deepLabels is how much of the wordlist is asked below the first level.
	deepLabels = 5000
	// maxRecordRounds bounds following names found inside DNS answers.
	maxRecordRounds = 8

	sourceDNSRecords   = "dns-records"
	sourceBruteforce   = "bruteforce"
	sourcePermutation  = "permutation"
	termsNotApplicable = "not_applicable"
)

// checkActive enforces the rule for anything that sends guessed names to a
// target's nameservers: an explicit opt-in, and a written record naming the
// roots and permitting active DNS.
func checkActive(o *Options) error {
	if o.ActiveAll {

		o.Brute, o.Permute, o.Mine, o.NSEC, o.PTR, o.AXFR = true, true, true, true, true, true
	}
	wants := o.Brute || o.Permute || o.Mine || o.AXFR || o.NSEC || o.PTR || o.TLS || o.Web || o.Vhost ||
		len(o.WordFiles) > 0 || o.PermuteWordFile != "" || len(o.CandidateFiles) > 0
	if o.Depth < 1 {
		return usageErr("-depth must be at least 1")
	}
	if !o.Active {
		if wants {
			return usageErr("-brute, -w, -permute, -mine, -axfr, -nsec, -ptr and -tls reach the target or guess at its names: add -active and -auth")
		}
		if o.AuthFile != "" {
			return usageErr("-auth has no effect without -active")
		}
		if o.TrustedRaw != "" {
			return usageErr("-trusted has no effect without -active")
		}
		return nil
	}
	if !wants {
		return usageErr("-active needs a method: -brute, -permute, -mine, -axfr, -nsec, -ptr or -tls")
	}
	if o.AuthFile == "" {
		return usageErr("-active needs -auth: a record naming these roots and allowing active-dns (see examples/authorization.template.json)")
	}
	auth, err := authz.LoadAuthorization(o.AuthFile)
	if err != nil {
		return usageErr("%v", err)
	}
	if !auth.Allows(authz.MethodActiveDNS) {
		return usageErr("%s does not allow %s: active discovery queries the target's own nameservers", o.AuthFile, authz.MethodActiveDNS)
	}
	if o.Web && !auth.Allows(authz.MethodActiveHTTP) {
		return usageErr("%s does not allow %s: -web connects to the target's own servers", o.AuthFile, authz.MethodActiveHTTP)
	}
	if o.Vhost && !auth.Allows(authz.MethodActiveHTTP) {
		return usageErr("%s does not allow %s: -vhost connects to the target's own servers", o.AuthFile, authz.MethodActiveHTTP)
	}
	if o.TLS && !auth.Allows(authz.MethodActiveTLS) {
		return usageErr("%s does not allow %s: -tls connects to the target's own servers", o.AuthFile, authz.MethodActiveTLS)
	}
	for _, root := range o.RootList {
		if err := auth.Permits(root); err != nil {
			return usageErr("%v", err)
		}
	}
	o.Auth = auth
	o.Resolve = true
	if !o.Wildcard {
		return usageErr("-no-wildcard cannot be used with generated names: every guess under a wildcard zone would be reported as found")
	}

	if o.MaxCandidates <= 0 {
		return usageErr("-max-candidates must be positive")
	}
	if auth.MaxCandidates > 0 && o.MaxCandidates > auth.MaxCandidates {
		o.MaxCandidates = auth.MaxCandidates
	}
	if auth.MaxQPS > 0 && (o.QPS == 0 || o.QPS > auth.MaxQPS) {
		return usageErr("-qps must be between 1 and %d: that is the limit %s sets", auth.MaxQPS, o.AuthFile)
	}

	if o.Brute || len(o.WordFiles) > 0 {
		o.Brute = true
		if len(o.WordFiles) == 0 {
			o.Wordlists = append(o.Wordlists, gen.Builtin())
		}
		if o.UzbekWords {
			o.Wordlists = append(o.Wordlists, gen.BuiltinUzbek())
		}
		for _, path := range o.WordFiles {
			w, err := gen.LoadWordlist(path)
			if err != nil {
				return usageErr("%v", err)
			}
			if w.Count == 0 {
				return usageErr("%s has no usable labels", path)
			}
			o.Wordlists = append(o.Wordlists, w)
		}

		planned := 0
		for _, w := range o.Wordlists {
			planned += w.Count
		}
		if planned*len(o.RootList) > o.MaxCandidates {
			return usageErr("the wordlists make %d candidates across %d root(s), over the ceiling of %d: use a shorter list or raise -max-candidates",
				planned*len(o.RootList), len(o.RootList), o.MaxCandidates)
		}
	}
	if o.PermuteWordFile != "" {
		o.Permute = true
		w, err := gen.LoadWordlist(o.PermuteWordFile)
		if err != nil {
			return usageErr("%v", err)
		}
		o.PermuteWords = w
	}
	if len(o.CandidateFiles) > 0 {
		planned := 0
		for _, path := range o.CandidateFiles {

			w, err := gen.LoadWordlist(path)
			if err != nil {
				return usageErr("%v", err)
			}
			if w.Count == 0 {
				return usageErr("%s has no usable candidate names", path)
			}
			o.Candidates = append(o.Candidates, w)
			planned += w.Count
		}

		if planned > o.MaxCandidates {
			return usageErr("the candidate files hold %d names, over the ceiling of %d: use -max-candidates to raise it",
				planned, o.MaxCandidates)
		}
	}
	return nil
}

// dnsStage runs every DNS step of one discover run against the same resolver.
type dnsStage struct {
	res     *resolver.Resolver
	trusted *resolver.Resolver
	scanner *resolver.WildcardScanner
	led     *ledger.Ledger
	o       *Options
	log     *logx.Logger

	// secondOpinionOverturned counts known names one resolver denied and another
	// answered.
	secondOpinionOverturned int

	// asked remembers every generated name by hash.
	asked  map[uint64]struct{}
	seed   maphash.Seed
	budget int

	records recordStats
	rootOf  map[string]string

	// nsec3 holds the mapped NSEC3 chain per root, when a zone exposes one.
	nsec3   map[string]*resolver.NSEC3Chain
	nsec3st nsec3Stats
	web     webStats
	vh      vhostStats
}

// nsec3Stats is what offline NSEC3 discovery did across the roots, for its
// row in the run report.
type nsec3Stats struct {
	zones        int
	hashedOwners int
	walkQueries  int
	present      int
	confirmed    int
	pruned       int
	errors       int
	unsupported  int
}

// recordStats is what the names-in-DNS-records source did.
type recordStats struct {
	queries, found, errors int
}

func newDNSStage(res, trusted *resolver.Resolver, led *ledger.Ledger, o *Options, log *logx.Logger) *dnsStage {
	d := &dnsStage{
		res: res, trusted: trusted, led: led, o: o, log: log,
		asked: map[uint64]struct{}{}, seed: maphash.MakeSeed(),
		budget: o.MaxCandidates, rootOf: map[string]string{},
		nsec3: map[string]*resolver.NSEC3Chain{},
	}
	if o.Wildcard {
		d.scanner = resolver.NewWildcardScanner(res, o.WildcardN)
	}
	return d
}

// run performs the stage: known names, then what active discovery was asked for.
func (d *dnsStage) run(ctx context.Context) {
	findings := d.led.Findings()
	names := make([]string, 0, len(findings))
	for _, f := range findings {
		d.rootOf[f.FQDN] = f.RootDomain
		names = append(names, f.FQDN)
	}

	for _, p := range d.res.Vet(ctx) {
		d.log.Logf("warn", "resolver %s is not being used: %s", p.Server, p.Reason)
	}

	if d.o.Mine {
		d.mine(ctx)
	}
	if d.o.AXFR {
		d.zoneTransfers(ctx)
	}
	if d.o.NSEC {
		d.walkNSEC(ctx)
	}
	d.followRecords(ctx, names)

	if d.o.Brute {

		if len(d.o.WordFiles) == 0 {
			n := 0
			for _, w := range d.o.Wordlists {
				n += w.Count
			}
			d.log.Logf("info", "brute: the built-in list is %d English labels. "+
				"On a target that does not work in English, -w with a list of your own "+
				"is the difference between finding those names and not", n)

			if !d.o.UzbekWords && d.anyRootSuggestsUzbek() {
				d.log.Logf("info", "brute: a root here ends in .uz - subio also ships "+
					"an Uzbek and Russian label list, which -uz adds to the run")
			}
		}
		d.brute(ctx)
	}
	if d.o.Permute {
		d.permute(ctx)
	}
	if len(d.o.Candidates) > 0 {
		d.candidateFiles(ctx)
	}
	if d.o.PTR {
		d.reverse(ctx)
	}
	if d.o.TLS {
		d.grabCertificates(ctx)
	}
	if d.o.Web {
		d.webScrape(ctx)
	}
	if d.o.Vhost {
		d.vhostProbe(ctx)
	}
	d.addRecordsRun()
	d.addNSEC3Run()
	if d.secondOpinionOverturned > 0 {
		d.log.Logf("warn", "%d known name(s) one resolver called non-existent were answered by another, "+
			"and are reported; each disagreement is in the ledger", d.secondOpinionOverturned)
	}
}

// followRecords resolves names, then any in-scope names their answers
// mention, until no new ones appear.
func (d *dnsStage) followRecords(ctx context.Context, names []string) {
	for round := 0; len(names) > 0 && round < maxRecordRounds; round++ {
		names = d.resolveNames(ctx, names)
	}
}

// resolveNames queries known names and records the answers.
func (d *dnsStage) resolveNames(ctx context.Context, names []string) []string {
	jobs := make(chan resolver.Job, 2048)
	answers := make(chan resolver.Answer, 2048)
	go func() {
		defer close(jobs)
		for _, n := range names {
			for _, t := range d.o.Types {
				select {
				case jobs <- resolver.Job{Name: n, Type: t}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go d.res.Stream(ctx, jobs, answers)

	var resolved, denied []resolver.Answer
	for a := range answers {
		if a.Outcome == resolver.Resolved {
			resolved = append(resolved, a)
			continue
		}
		if a.Outcome == resolver.NXDomain && a.InferredFrom == "" && d.res.ServerCount() > 1 {
			denied = append(denied, a)
		}
		obs := observation(a)

		if !obs.Definitive() {
			d.records.errors++
		}
		d.led.AddDNS(d.rootOf[a.Name], obs)
	}

	resolved = append(resolved, d.secondOpinions(ctx, denied)...)

	d.prepareWildcards(ctx, resolved)
	var found []string
	for _, a := range resolved {
		obs := observation(a)

		if resolver.WildcardSynthesized(a) {
			obs.WildcardSuspected = true
			obs.WildcardSamples = []string{"rrsig: signed over " +
				strconv.Itoa(a.SignedLabels) + " labels"}
		} else if d.scanner != nil {
			if isWild, rep := d.scanner.Classify(ctx, a.Name, d.rootOf[a.Name], a); isWild {
				obs.WildcardSuspected = true
				obs.WildcardSamples = rep.Controls
			}
		}
		d.led.AddDNS(d.rootOf[a.Name], obs)
		if !obs.WildcardSuspected {
			found = append(found, d.harvest(a)...)
		}
	}
	return found
}

// secondOpinions re-asks a different resolver about each known name one
// resolver called non-existent, and returns the ones the second resolver
// answered.
func (d *dnsStage) secondOpinions(ctx context.Context, denied []resolver.Answer) []resolver.Answer {
	if len(denied) == 0 {
		return nil
	}
	first := make(map[string]resolver.Answer, len(denied))
	jobs := make([]resolver.Job, 0, len(denied))
	for _, a := range denied {
		first[a.Name+"|"+a.Type.String()] = a
		jobs = append(jobs, resolver.Job{Name: a.Name, Type: a.Type, Avoid: a.Resolver})
	}
	var overturned []resolver.Answer
	for _, b := range d.res.ResolveJobs(ctx, jobs) {
		a, ok := first[b.Name+"|"+b.Type.String()]
		if !ok || b.Resolver == a.Resolver {
			continue
		}
		switch b.Outcome {
		case resolver.Resolved:
			d.secondOpinionOverturned++
			d.led.AddDisagreement(disagreement(a, b, true))
			overturned = append(overturned, b)
		case resolver.NXDomain, resolver.NoData:

			d.led.AddDNS(d.rootOf[b.Name], observation(b))
		}

	}
	return overturned
}

// disagreement records a claim and the check that contradicted it.
func disagreement(claimed, checked resolver.Answer, kept bool) ledger.Disagreement {
	dis := ledger.Disagreement{
		FQDN: claimed.Name, QueryType: claimed.Type.String(), CheckedAt: checked.CheckedAt,
		ClaimedBy: claimed.Resolver, ClaimedOutcome: string(claimed.Outcome),
		CheckedBy: checked.Resolver, CheckedOutcome: string(checked.Outcome), Kept: kept,
	}
	for _, r := range claimed.Records {
		dis.ClaimedRecords = append(dis.ClaimedRecords, ledger.DNSRecord{Type: r.Type, Value: r.Value, TTL: r.TTL})
	}
	for _, r := range checked.Records {
		dis.CheckedRecords = append(dis.CheckedRecords, ledger.DNSRecord{Type: r.Type, Value: r.Value, TTL: r.TTL})
	}
	return dis
}

func observation(a resolver.Answer) ledger.DNSObservation {
	obs := ledger.DNSObservation{
		FQDN: a.Name, CheckedAt: a.CheckedAt, Resolver: a.Resolver,
		QueryType: a.Type.String(), RCode: a.RCodeText(), Truncated: a.Truncated,
		Outcome: string(a.Outcome), CNAMEChain: a.CNAMEChain, ErrorClass: a.ErrorClass,
		ExtendedError: a.EDE.String(), DenialInferred: a.DenialWasInferred(),
		InferredFrom: a.InferredFrom,
	}
	for _, r := range a.Records {
		obs.Records = append(obs.Records, ledger.DNSRecord{Type: r.Type, Value: r.Value, TTL: r.TTL})
	}
	return obs
}

// prepareWildcards probes every zone level these answers sit under, in one batch.
func (d *dnsStage) prepareWildcards(ctx context.Context, answers []resolver.Answer) {
	if d.scanner == nil || len(answers) == 0 {
		return
	}
	seen := map[resolver.Probe]bool{}
	var probes []resolver.Probe
	for _, a := range answers {
		root := d.rootOf[a.Name]
		if root == "" {
			continue
		}
		for _, parent := range resolver.Parents(a.Name, root) {
			p := resolver.Probe{Parent: parent, Type: a.Type}
			if !seen[p] {
				seen[p] = true
				probes = append(probes, p)
			}
		}
	}
	d.scanner.Prepare(ctx, probes)
}

// hostInText finds hostname-shaped text in a free-form record such as an SPF
// TXT value.
var hostInText = regexp.MustCompile(`(?i)[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+`)

// harvest records in-scope names mentioned in an answer and returns the new
// ones.
func (d *dnsStage) anyRootSuggestsUzbek() bool {
	for _, root := range d.o.RootList {
		if strings.HasSuffix(root, ".uz") || root == "uz" {
			return true
		}
	}
	return false
}

func (d *dnsStage) harvest(a resolver.Answer) []string {
	var found []string
	for _, r := range a.Records {
		var candidates []string
		switch r.Type {
		case "A", "AAAA":
			continue
		case "CAA", "TXT":

			candidates = hostInText.FindAllString(r.Value, -1)
		case "MX", "SRV", "SOA":
			candidates = strings.Fields(r.Value)
		default:
			candidates = []string{r.Value}
		}
		for _, c := range candidates {
			if name := d.admit(c, a, r.Type); name != "" {
				found = append(found, name)
			}
		}
	}
	return found
}

// admit records a name found in DNS data, if it is in scope and new.
func (d *dnsStage) admit(raw string, a resolver.Answer, recordType string) string {
	host, root, err := d.o.Roots.Admit(raw)
	if err != nil || d.led.Has(root.String(), host) {
		return ""
	}
	d.rootOf[host] = root.String()
	d.led.Observe(host, root.String(), source.FamilyActiveDNS, source.Observation{
		Hostname: host, SourceID: sourceDNSRecords, Method: "dns-record-" + strings.ToLower(recordType),
		RecordID: a.Name, Attrs: map[string]string{"found_in": a.Name, "record_type": recordType},
	})
	d.records.found++
	return host
}

// miningQueries are the records of a root most likely to name other hosts.
var miningQueries = []struct {
	prefix string
	qtype  dnsfast.Type
}{
	{"", dnsfast.TypeNS}, {"", dnsfast.TypeMX}, {"", dnsfast.TypeSOA}, {"", dnsfast.TypeTXT},
	{"_dmarc.", dnsfast.TypeTXT}, {"_sip._tcp.", dnsfast.TypeSRV}, {"_sip._udp.", dnsfast.TypeSRV},
	{"_sips._tcp.", dnsfast.TypeSRV}, {"_xmpp-server._tcp.", dnsfast.TypeSRV}, {"_xmpp-client._tcp.", dnsfast.TypeSRV},
	{"_ldap._tcp.", dnsfast.TypeSRV}, {"_kerberos._tcp.", dnsfast.TypeSRV}, {"_autodiscover._tcp.", dnsfast.TypeSRV},
	{"_caldav._tcp.", dnsfast.TypeSRV}, {"_carddav._tcp.", dnsfast.TypeSRV}, {"_imaps._tcp.", dnsfast.TypeSRV},
	{"_submission._tcp.", dnsfast.TypeSRV}, {"_matrix._tcp.", dnsfast.TypeSRV},

	{"", dnsfast.TypeCAA},
	{"default._bimi.", dnsfast.TypeTXT},
	{"_smtp._tls.", dnsfast.TypeTXT},
	{"_mta-sts.", dnsfast.TypeTXT},
}

// mine asks each root's records for the names they mention.
func (d *dnsStage) mine(ctx context.Context) {
	var jobs []resolver.Job
	for _, root := range d.o.RootList {
		for _, q := range miningQueries {
			jobs = append(jobs, resolver.Job{Name: q.prefix + root, Type: q.qtype})
		}
	}
	d.records.queries += len(jobs)
	var found []string
	for _, a := range d.res.ResolveJobs(ctx, jobs) {
		switch a.Outcome {
		case resolver.Resolved:
			found = append(found, d.harvest(a)...)

			if host, ok := strings.CutPrefix(a.Name, "_mta-sts."); ok {
				if name := d.admit("mta-sts."+host, a, "TXT"); name != "" {
					found = append(found, name)
				}
			}
		case resolver.NXDomain, resolver.NoData:
		default:
			d.records.errors++
		}
	}
	d.followRecords(ctx, found)
}

// addRecordsRun reports the names-in-DNS-records source in the run report.
func (d *dnsStage) addRecordsRun() {
	status := source.StatusComplete
	switch {
	case d.records.errors > 0:
		status = source.StatusPartial
	case d.records.found == 0:
		status = source.StatusEmpty
	}
	d.led.AddSourceRun(ledger.SourceRun{
		SourceID: sourceDNSRecords, Family: string(source.FamilyActiveDNS), Status: string(status),
		TermsState: termsNotApplicable, Requests: d.records.queries, RawObservation: d.records.found,
		InScope: d.records.found, UniqueNames: d.records.found, MarginalNames: d.records.found,
		QuotaRemaining: -1, DNSErrors: d.records.errors,
	})
}

// generatorResult is what one generator did, for its row in the run report.
type generatorResult struct {
	queried, found, explained, unconfirmed, errors int
	// nsec3Pruned counts guesses an NSEC3 chain proved absent offline, so no
	// query was sent for them.
	nsec3Pruned int
	capped      bool
	started     time.Time

	// canaryHits counts names that cannot exist and resolved anyway.
	canaryHits int

	// deniedWrongly counts sampled denials the trusted resolvers contradicted.
	deniedWrongly int
}

// generate sends candidates through the resolver and keeps what a wildcard
// does not explain.
func (d *dnsStage) generate(ctx context.Context, id, method string, res *generatorResult,
	produce func(yield func(string) bool)) []string {

	jobs := make(chan resolver.Job, 2048)
	answers := make(chan resolver.Answer, 2048)

	canaries := d.canaryNames()
	go func() {
		defer close(jobs)
		emitted := 0
		next := 0

		send := func(upto int) bool {
			for ; next < upto && next < len(canaries); next++ {
				if !d.offerNamed(ctx, canaries[next], res, jobs, true) {
					return false
				}
			}
			return true
		}
		if !send(canaryBlock) {
			return
		}
		produce(func(name string) bool {
			emitted++
			if emitted%canarySpacing == 0 {
				if !send(next + 1) {
					return false
				}
			}
			return d.offer(ctx, name, res, jobs)
		})
		send(len(canaries))
	}()
	go d.res.Stream(ctx, jobs, answers)

	isCanary := make(map[string]bool, len(canaries))
	for _, c := range canaries {
		isCanary[c] = true
	}
	var hits []resolver.Answer
	var denialSample []resolver.Answer
	var canaryResolved []resolver.Answer
	for a := range answers {
		switch a.Outcome {
		case resolver.Resolved:
			if isCanary[a.Name] {
				canaryResolved = append(canaryResolved, a)
				continue
			}
			hits = append(hits, a)
		case resolver.NXDomain, resolver.NoData:

			if !isCanary[a.Name] && len(denialSample) < denialSampleSize {
				denialSample = append(denialSample, a)
			}
		default:
			if !isCanary[a.Name] {
				res.errors++
			}
		}
	}
	d.checkDenials(ctx, id, res, denialSample)

	canaryHits := 0
	for _, a := range canaryResolved {
		if d.scanner != nil {
			if isWild, _ := d.scanner.Classify(ctx, a.Name, d.rootOf[a.Name], a); isWild {
				continue
			}
		}
		canaryHits++
	}
	if canaryHits > canaryTolerance {

		d.log.Logf("warn", "%s: %d of %d canary names resolved, so every generated name here is "+
			"unestablished; a resolver or a zone is answering for names that do not exist",
			id, canaryHits, len(canaries))
		res.canaryHits = canaryHits
	}
	return d.accept(ctx, id, method, res, hits)
}

const (

	// canaryBlock is how many canaries go in before the first candidate, and
	// canarySpacing how often one follows.
	canaryBlock   = 8
	canarySpacing = 500
	canaryTotal   = 40
	// canaryTolerance allows a couple of accidents - a real name that happens to
	// match a random label, a single stale answer - without letting a hijack
	// through.
	canaryTolerance = 2
)

// denialSampleSize is how many denials are re-asked of the trusted
// resolvers.
const denialSampleSize = 24

// checkDenials re-asks the trusted resolvers about names the bulk resolvers
// said do not exist.
func (d *dnsStage) checkDenials(ctx context.Context, id string, res *generatorResult, sample []resolver.Answer) {
	if d.trusted == nil || len(sample) == 0 {
		return
	}
	jobs := make([]resolver.Job, 0, len(sample))
	for _, a := range sample {
		jobs = append(jobs, resolver.Job{Name: a.Name, Type: a.Type})
	}

	answered := map[string][]resolver.Answer{}
	for _, a := range d.trusted.ResolveJobs(ctx, jobs) {
		if a.Outcome == resolver.Resolved {
			answered[a.Name] = append(answered[a.Name], a)
		}
	}
	if len(answered) == 0 {
		return
	}
	res.deniedWrongly = len(answered)
	names := make([]string, 0, len(answered))
	for n := range answered {
		names = append(names, n)
	}
	sort.Strings(names)
	d.log.Logf("warn", "%s: the trusted resolvers answered %d of %d sampled denials, starting with %s; "+
		"names this stage did not report may exist",
		id, len(answered), len(sample), names[0])

	for _, a := range sample {
		if checked, ok := answered[a.Name]; ok {
			d.recordDisagreement(a.Name, []resolver.Answer{a}, checked)
		}
	}
}

// canaryNames are names that cannot exist, one set per root, so a resolver
// or zone answering for them is answering for anything.
func (d *dnsStage) canaryNames() []string {
	if len(d.o.RootList) == 0 {
		return nil
	}
	out := make([]string, 0, canaryTotal)
	for i := 0; len(out) < canaryTotal; i++ {
		root := d.o.RootList[i%len(d.o.RootList)]
		out = append(out, randLabel()+"-"+randLabel()+"."+root)
	}
	return out
}

// offer queues one candidate if it is in scope, new and within budget.
func (d *dnsStage) offer(ctx context.Context, name string, res *generatorResult, jobs chan<- resolver.Job) bool {
	return d.offerNamed(ctx, name, res, jobs, false)
}

// offerNamed is offer with control marking: a control is queued and counted
// as a query, but is not charged to the candidate budget.
func (d *dnsStage) offerNamed(ctx context.Context, name string, res *generatorResult, jobs chan<- resolver.Job, control bool) bool {

	host, root, err := d.o.Roots.Admit(name)
	if err != nil {
		return true
	}
	var h maphash.Hash
	h.SetSeed(d.seed)
	_, _ = h.WriteString(host)
	sum := h.Sum64()
	if _, dup := d.asked[sum]; dup || d.led.Has(root.String(), host) {
		return true
	}

	if chain := d.nsec3[root.String()]; chain != nil && chain.Mapped() {
		if st, _ := chain.Match(host); st == resolver.NSEC3Absent {
			d.asked[sum] = struct{}{}
			res.nsec3Pruned++
			return true
		}
	}
	if d.budget <= 0 {
		res.capped = true
		return false
	}
	if !control {

		d.budget--
	}
	d.asked[sum] = struct{}{}
	d.rootOf[host] = root.String()
	res.queried++
	for _, t := range d.o.Types {
		select {
		case jobs <- resolver.Job{Name: host, Type: t}:
		case <-ctx.Done():
			return false
		}
	}
	return true
}

// accept turns resolved guesses into findings.
func (d *dnsStage) accept(ctx context.Context, id, method string, res *generatorResult, hits []resolver.Answer) []string {
	d.prepareWildcards(ctx, hits)

	byName := map[string][]resolver.Answer{}
	var order []string
	for _, a := range hits {
		if _, ok := byName[a.Name]; !ok {
			order = append(order, a.Name)
		}
		byName[a.Name] = append(byName[a.Name], a)
	}
	sort.Strings(order)

	var found []string
	for _, name := range order {
		root := d.rootOf[name]

		explained := res.canaryHits > canaryTolerance || d.scanner != nil
		if res.canaryHits <= canaryTolerance && d.scanner != nil {
			for _, a := range byName[name] {
				if isWild, _ := d.scanner.Classify(ctx, name, root, a); !isWild {
					explained = false
				}
			}
		}
		if explained {
			res.explained++
			continue
		}
		if d.trusted != nil {
			ok, checked := d.confirmed(ctx, name, byName[name])
			if !ok {
				res.unconfirmed++
				d.recordDisagreement(name, byName[name], checked)
				continue
			}
		}
		d.led.Observe(name, root, source.FamilyActiveDNS, source.Observation{
			Hostname: name, SourceID: id, Method: method,
		})
		for _, a := range byName[name] {
			d.led.AddDNS(root, observation(a))
		}
		found = append(found, name)
	}
	res.found += len(found)
	return found
}

// confirmed asks the trusted resolvers.
func (d *dnsStage) confirmed(ctx context.Context, name string, answers []resolver.Answer) (bool, []resolver.Answer) {
	jobs := make([]resolver.Job, 0, len(answers))
	for _, a := range answers {
		jobs = append(jobs, resolver.Job{Name: name, Type: a.Type})
	}
	checked := d.trusted.ResolveJobs(ctx, jobs)
	for _, a := range checked {
		if a.Outcome == resolver.Resolved {
			return true, checked
		}
	}
	return false, checked
}

// recordDisagreement keeps the evidence that a resolver claimed a name a
// trusted resolver did not confirm, naming both sides.
func (d *dnsStage) recordDisagreement(name string, claimed, checked []resolver.Answer) {

	byType := make(map[string]resolver.Answer, len(checked))
	for _, c := range checked {
		byType[c.Type.String()] = c
	}
	for _, a := range claimed {
		dis := ledger.Disagreement{
			FQDN: name, QueryType: a.Type.String(), CheckedAt: a.CheckedAt,
			ClaimedBy: a.Resolver, ClaimedOutcome: string(a.Outcome),
		}
		for _, r := range a.Records {
			dis.ClaimedRecords = append(dis.ClaimedRecords, ledger.DNSRecord{Type: r.Type, Value: r.Value, TTL: r.TTL})
		}
		if c, ok := byType[a.Type.String()]; ok {
			dis.CheckedBy, dis.CheckedOutcome = c.Resolver, string(c.Outcome)
			for _, r := range c.Records {
				dis.CheckedRecords = append(dis.CheckedRecords, ledger.DNSRecord{Type: r.Type, Value: r.Value, TTL: r.TTL})
			}
		}
		d.led.AddDisagreement(dis)
	}
}

func (d *dnsStage) addGeneratorRun(id string, res *generatorResult) {
	status := source.StatusComplete
	var class source.ErrorClass
	switch {
	case res.capped:
		status, class = source.StatusTruncated, source.ErrPartialPagination
	case res.errors > 0:
		status = source.StatusPartial
	case res.found == 0:
		status = source.StatusEmpty
	}
	d.nsec3st.pruned += res.nsec3Pruned
	d.led.AddSourceRun(ledger.SourceRun{
		SourceID: id, Family: string(source.FamilyActiveDNS), Status: string(status), ErrorClass: string(class),
		TermsState: termsNotApplicable, Requests: res.queried, RawObservation: res.found,
		InScope: res.found, UniqueNames: res.found, MarginalNames: res.found,
		DurationMS: time.Since(res.started).Milliseconds(), QuotaRemaining: -1,
		WildcardExplained: res.explained, FailedValidation: res.unconfirmed, DNSErrors: res.errors,
	})
}

// brute asks every wordlist entry under every root, then under found names
// as far down as -depth says.
func (d *dnsStage) brute(ctx context.Context) {
	mined := &gen.Wordlist{Name: "labels of known names"}
	for _, root := range d.o.RootList {
		mined.Labels = append(mined.Labels, gen.Labels(d.knownNames(root), root)...)
	}
	mined.Count = len(mined.Labels)
	labels := gen.Merge(append([]*gen.Wordlist{mined}, d.o.Wordlists...)...)

	res := &generatorResult{started: time.Now()}
	found := d.generate(ctx, sourceBruteforce, "dns-bruteforce", res, func(yield func(string) bool) {
		for _, root := range d.o.RootList {
			if !gen.Brute(root, labels, yield) {
				return
			}
		}
	})
	d.followRecords(ctx, recordsOnly(d, found))

	deeper := labels
	if len(deeper) > deepLabels {
		deeper = deeper[:deepLabels]
	}
	for level := 1; level < d.o.Depth && !res.capped; level++ {
		parents := d.parentsAtLevel(level)
		if len(parents) == 0 {
			break
		}
		found = d.generate(ctx, sourceBruteforce, "dns-bruteforce", res, func(yield func(string) bool) {
			for _, parent := range parents {
				if !gen.Brute(parent, deeper, yield) {
					return
				}
			}
		})
		d.followRecords(ctx, recordsOnly(d, found))
	}
	d.addGeneratorRun(sourceBruteforce, res)
}

// parentsAtLevel returns known names level labels below a root that are
// worth asking under.
func (d *dnsStage) parentsAtLevel(level int) []string {
	var out []string
	for _, f := range d.led.Findings() {
		if f.WildcardSuspected || f.Verification == ledger.NegativeNXDomain || f.FQDN == f.RootDomain {
			continue
		}
		rest := strings.TrimSuffix(f.FQDN, "."+f.RootDomain)
		if strings.Count(rest, ".")+1 == level {
			out = append(out, f.FQDN)
		}
	}
	return out
}

// knownNames is what the run and earlier runs know under a root.
func (d *dnsStage) knownNames(root string) []string {
	var out []string
	for _, f := range d.led.Findings() {
		if f.RootDomain == root && !f.WildcardSuspected {
			out = append(out, f.FQDN)
		}
	}
	suffix := "." + root
	for _, n := range d.o.HistoryNames {
		if strings.HasSuffix(n, suffix) {
			out = append(out, n)
		}
	}
	return out
}

// recordsOnly exists because accepted guesses already have their DNS
// answers; only the names those answers mention still need asking.
func recordsOnly(d *dnsStage, found []string) []string {
	var next []string
	for _, name := range found {
		for _, obs := range d.led.DNSFor(d.rootOf[name], name) {
			for _, r := range obs.Records {
				a := resolver.Answer{Name: name, Records: []resolver.Record{{Type: r.Type, Value: r.Value}}}
				next = append(next, d.harvest(a)...)
			}
		}
	}
	return next
}

// permute varies what is already known.
func (d *dnsStage) permute(ctx context.Context) {
	res := &generatorResult{started: time.Now()}
	seeds := d.seedsByRoot(nil)
	for round := 0; round < permuteRounds && len(seeds) > 0; round++ {
		found := d.generate(ctx, sourcePermutation, "dns-permutation", res, func(yield func(string) bool) {

			for root, names := range seeds {
				for _, rule := range gen.Learn(d.knownNames(root), root) {
					if !rule.Each(root, yield) {
						return
					}
				}
				_ = names
			}
			for _, s := range gen.Strategies() {
				for root, names := range seeds {
					words := d.permuteWords(root)
					for _, name := range names {
						if !gen.Vary(s, name, root, words, yield) {
							return
						}
					}
				}
				if s != gen.Numbers {
					continue
				}

				if round == 0 {
					for root := range seeds {
						for _, n := range gen.LearnAffixes(d.knownNames(root), root) {
							if !yield(n) {
								return
							}
						}
					}
				}
			}
		})
		d.followRecords(ctx, recordsOnly(d, found))
		seeds = d.seedsByRoot(found)
	}
	d.addGeneratorRun(sourcePermutation, res)
}

// seedsByRoot groups names to vary.
func (d *dnsStage) seedsByRoot(only []string) map[string][]string {
	out := map[string][]string{}
	if only != nil {
		for _, name := range only {
			out[d.rootOf[name]] = append(out[d.rootOf[name]], name)
		}
		return out
	}
	for _, f := range d.led.Findings() {
		if !f.WildcardSuspected {
			out[f.RootDomain] = append(out[f.RootDomain], f.FQDN)
		}
	}
	return out
}

// permuteWords are what to vary a root's names with: the operator's list if
// any, then the root's own naming scheme, then common environment words.
func (d *dnsStage) permuteWords(root string) []string {
	names := d.knownNames(root)
	seen := map[string]bool{}
	var out []string
	add := func(words []string) {
		for _, w := range words {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	if d.o.PermuteWords != nil {
		add(d.o.PermuteWords.Labels)
	}
	add(gen.MineWords(names, root, minedWordLimit))
	add(gen.EnvironmentWords())
	return out
}
