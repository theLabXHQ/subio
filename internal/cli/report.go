package cli

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/theLabXHQ/subio/internal/ledger"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/secrets"
	"github.com/theLabXHQ/subio/internal/source"
	"github.com/theLabXHQ/subio/internal/store"
	"github.com/theLabXHQ/subio/internal/version"
)

// printNotices states plainly what the run is about to do.
func printNotices(log *logx.Logger, providers []source.Provider, sec *secrets.Env, o *Options) {
	var ready, missing []string
	for _, p := range providers {
		md := p.Metadata()
		if md.Key == source.RequiredKey && !sec.Has(md.ID) {
			missing = append(missing, md.ID)
			continue
		}
		if ok, _ := source.Allowed(md, o.Profile); !ok {
			continue
		}
		ready = append(ready, md.ID)
	}
	sort.Strings(ready)
	sort.Strings(missing)

	log.Logf("info", "subio %s: %d adapter(s) will run across %d root(s)", version.Version, len(ready), len(o.RootList))
	log.Logf("verbose", "running: %s", strings.Join(ready, ", "))
	if len(missing) > 0 {
		log.Logf("warn", "no credential for: %s", strings.Join(missing, ", "))
	}
	log.Logf("info", "passive collection discloses the queried names to each provider")
	if o.Resolve {
		log.Logf("warn", "-resolve queries the target's nameservers: this is active, not passive")
		if o.UsingPublic {
			log.Logf("warn", "using public resolvers; their operators see every name queried")
		}
	}
	if o.Active && o.Auth != nil {
		log.Logf("warn", "active discovery: guessing names on the target's nameservers, authorized by %s", o.Auth.Owner)
	}
	if o.Profile == source.ProfileCommercial {
		log.Logf("info", "commercial profile: adapters without cleared terms send no requests")
	}
}

// printReport is the per-source diagnostic table.
func printReport(log *logx.Logger, led *ledger.Ledger, st ledger.Stats,
	wild []resolver.WildcardReport, servers []resolver.ServerStat,
	edeReasons map[string]int64, caseFolders int64,
	kernelDrops int64, kernelDropsKnown bool, elapsed time.Duration) {

	runs := led.SourceRuns()
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tSTATUS\tREQ\tIN-SCOPE\tREJECTED\tUNIQUE\tONLY-HERE\tTIME")
	for _, r := range runs {
		status := r.Status

		if r.ErrorClass != "" && string(r.ErrorClass) != string(r.Status) {
			status += " (" + r.ErrorClass + ")"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%dms\n",
			r.SourceID, status, r.Requests, r.InScope,
			r.OutOfScope+r.Malformed, r.UniqueNames, r.MarginalNames, r.DurationMS)
	}
	_ = tw.Flush()
	log.Printf("\n%s", b.String())

	paint := func(c string, v any) string {
		if !log.Color {
			return fmt.Sprint(v)
		}
		return c + fmt.Sprint(v) + "\x1b[0m"
	}
	const bold, dim, green, red = "\x1b[1m", "\x1b[2m", "\x1b[1;32m", "\x1b[1;31m"
	incompleteColor := dim
	if st.Incomplete > 0 {
		incompleteColor = red
	}
	log.Printf("\n%s %s hostnames, %d evidence records in %s",
		paint(dim, "[subio]"), paint(bold, st.Findings), st.Evidence,
		elapsed.Round(time.Millisecond))
	if st.Incomplete > 0 {
		log.Printf(", %s source(s) incomplete", paint(incompleteColor, st.Incomplete))
	}
	log.Printf("\n")
	if st.Resolved > 0 || st.Wildcard > 0 {
		log.Printf("%s %s resolved, %d flagged wildcard-synthesized\n",
			paint(dim, "[subio]"), paint(green, st.Resolved), st.Wildcard)
	}

	if log.Verbose {
		log.Printf("ONLY-HERE counts names no other selected source reported.\n")
	}

	for _, w := range wild {
		if w.Suspected {
			answers := strings.Join(w.AnswerSet, ",")
			if len(w.AnswerSet) > 6 {

				answers = fmt.Sprintf("a pool of %d answers (%s, ...)", len(w.AnswerSet), strings.Join(w.AnswerSet[:3], ","))
			}
			log.Logf("warn", "wildcard: *.%s answers %s for random labels (%d/%d controls resolved)",
				w.Parent, answers, w.Agreement, len(w.Controls))
		}
	}
	for _, r := range runs {
		if r.Note != "" {
			log.Logf("warn", "%s: %s", r.SourceID, r.Note)
		}
		if r.WildcardExplained > 0 {
			log.Printf("%s: %d guess(es) resolved only because a wildcard answers everything; not reported.\n",
				r.SourceID, r.WildcardExplained)
		}
		if r.FailedValidation > 0 {
			log.Printf("%s: %d guess(es) the trusted resolvers did not confirm; not reported.\n",
				r.SourceID, r.FailedValidation)
		}
		if r.DNSErrors > 0 {
			log.Printf("%s: %d name(s) no resolver could answer, so names may be missing.\n",
				r.SourceID, r.DNSErrors)
		}
	}

	// Resolution loss, which nobody in this field publishes.
	var sent, answered, timeouts, refused int64
	for _, s := range servers {
		sent += s.Sent
		answered += s.Answered
		timeouts += s.Timeouts
		refused += s.Refused
	}
	if sent > 0 {
		pct := 100 * float64(answered) / float64(sent)
		rate := func(n int64) string {
			return fmt.Sprintf("%d (%.1f%%)", n, 100*float64(n)/float64(sent))
		}
		log.Printf("\nDNS: %d queries sent, %s answered, %s timed out, %s refused.\n",
			sent, rate(answered), rate(timeouts), rate(refused))

		if kernelDropsKnown && kernelDrops > 0 {
			log.Logf("warn", "this machine discarded %d datagram(s) before subio could read "+
				"them, so some of the timeouts above are local loss rather than an "+
				"unanswered query; a lower -qps recovers them", kernelDrops)
		}

		if caseFolders > 0 {
			var folders []string
			for _, s := range servers {
				if s.FoldsCase {
					folders = append(folders, s.Server)
				}
			}
			sort.Strings(folders)
			log.Logf("warn", "these resolvers answered without echoing the case they were "+
				"sent, so DNS-0x20 proved nothing about their answers: %s. Names from them "+
				"rest on the transaction id and source port alone",
				strings.Join(folders, ", "))
		}

		if len(edeReasons) > 0 {
			keys := make([]string, 0, len(edeReasons))
			for k := range edeReasons {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				if edeReasons[keys[i]] != edeReasons[keys[j]] {
					return edeReasons[keys[i]] > edeReasons[keys[j]]
				}
				return keys[i] < keys[j]
			})
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s (%d)", k, edeReasons[k]))
			}
			log.Printf("The resolvers gave reasons: %s.\n", strings.Join(parts, ", "))

			for _, suspect := range []string{"forged answer", "synthesized", "stale answer"} {
				if n, ok := edeReasons[suspect]; ok {
					log.Logf("warn", "a resolver reported %q %d time(s): those answers "+
						"describe what it served, not necessarily what the zone publishes", suspect, n)
				}
			}
		}

		if pct < 90 {
			explain(log, "Low answer rate: lower -qps or -rqps, raise -dt, or use fewer resolvers.",
				"Around 96% is what a well-configured client gets from public recursives, and a\n"+
					"careless one loses most of the difference to its own settings, not to the\n"+
					"resolvers. Names may be missing for want of an answer rather than a guess.")
		}
	}
	for _, s := range servers {
		if s.Disabled {
			log.Logf("warn", "resolver %s stopped being asked: %d of %d queries timed out", s.Server, s.Timeouts, s.Sent)
		}

		if s.Throttles > 0 {
			log.Logf("warn", "resolver %s refused %d of %d queries and was slowed %d time(s), to %.0f q/s; "+
				"lower -rqps for it, or drop it from the list",
				s.Server, s.Refused, s.Sent, s.Throttles, s.SlowestQPS)
		}
	}

	if st.InferredDenials > 0 {

		explain(log, fmt.Sprintf("%d name(s) were denied from a resolver's cache, not by the zone; re-ask them with -authoritative -qps 50.", st.InferredDenials),
			"That is a real NXDOMAIN and subio read it correctly; what it does not establish\n"+
				"is that anything asked the zone. A zone's own nameservers rate-limit harder than\n"+
				"a recursive resolver: measured on one zone, 100% of queries answered at -qps 50\n"+
				"against 37.5% at the default.")
	}

	if contra := led.ContradictedResolvers(); len(contra) > 0 {
		names := make([]string, 0, len(contra))
		for s := range contra {
			names = append(names, s)
		}
		sort.Slice(names, func(i, j int) bool {
			if contra[names[i]] != contra[names[j]] {
				return contra[names[i]] > contra[names[j]]
			}
			return names[i] < names[j]
		})
		for _, s := range names {
			log.Logf("warn", "resolver %s was contradicted by another resolver %d time(s); consider removing it from your list",
				s, contra[s])
		}
		if log.Verbose {
			log.Printf("Each contradiction is kept in the ledger as a resolver_disagreement record,\n" +
				"with what each side answered.\n")
		}
	}
	if st.Incomplete > 0 {
		explain(log, fmt.Sprintf("%d source(s) incomplete: the names are real, a missing name proves nothing (exit 4).", st.Incomplete), "")
	}
	if st.DNSErrors > 0 {
		explain(log, fmt.Sprintf("%d name(s) got no DNS answer; that is not evidence of absence (exit 4).", st.DNSErrors), "")
	}
	if len(st.PlanCapped) > 0 {

		explain(log, fmt.Sprintf("%s hit the free plan's row limit; a key lifts it. Not counted in the exit code.", strings.Join(st.PlanCapped, ", ")),
			"It hits that limit the same way on every keyless run, so it says nothing about\n"+
				"this one. A later diff still treats what it did not return as unknown, never\n"+
				"as gone.")
	}
	if st.Unverifiable > 0 {

		explain(log, fmt.Sprintf("%s can cap its answer silently; -s crtshdb reads crt.sh's own database.", strings.Join(st.UnverifiableIDs, ", ")),
			"Completeness cannot be established for these sources. Reporting complete means\n"+
				"subio read the whole answer it was given, not that the answer was whole, so a\n"+
				"name's absence there is not evidence.")
	}
}

// persistentWindow and persistentThreshold decide when a repeated failure is
// worth a sentence.
const (
	persistentWindow    = 10
	persistentThreshold = 3
)

// printPersistentFailures names a source that has not finished for several
// runs and says how to stop it holding every run at exit 4.
func printPersistentFailures(log *logx.Logger, fails []store.PersistentFailure) {
	if len(fails) == 0 {
		return
	}
	parts := make([]string, 0, len(fails))
	for _, f := range fails {
		parts = append(parts, fmt.Sprintf("%s in %d consecutive run(s), now %s",
			f.SourceID, f.Runs, f.Status))
	}
	log.Printf("\nPersistently failing: %s.\n", strings.Join(parts, "; "))
	log.Printf("A source that cannot be reached from here holds every run at exit 4, which\n" +
		"is the signal worth reading. Dropping it with -es restores that: a clean run\n" +
		"then exits 0, and the ledger still records that it was not asked.\n")
}

// printDiff reports what changed since the last run.
func printDiff(log *logx.Logger, d *store.Diff) {
	log.Printf("\nchanges")
	if d.PrevRunID != "" {
		log.Printf(" since run %s", d.PrevRunID)
	}
	log.Printf(":\n")

	if d.FirstRun {
		log.Printf("  first run: %d name(s) recorded as the baseline\n", d.Count(store.New))
		return
	}

	order := []struct {
		c     store.Change
		label string
	}{
		{store.New, "new"},
		{store.Reappeared, "returned"},
		{store.DNSChanged, "DNS changed"},
		{store.NoLongerObserved, "no longer observed"},
		{store.Unconfirmed, "unconfirmed"},
		{store.StillSeen, "unchanged"},
	}
	for _, o := range order {
		if n := d.Count(o.c); n > 0 {
			log.Printf("  %-20s %d\n", o.label, n)
		}
	}

	// List the entries worth acting on, bounded so a first-time diff over a
	// large zone does not bury the summary.
	const maxList = 25
	var shown int
	for _, e := range d.Entries {
		switch e.Change {
		case store.New, store.Reappeared, store.DNSChanged, store.NoLongerObserved:
		default:
			continue
		}
		if shown == maxList {
			log.Printf("  ... and more; use -j or -o to get the full set\n")
			break
		}
		shown++
		switch e.Change {
		case store.DNSChanged:
			log.Printf("  %-18s %s  %s -> %s\n", e.Change, e.FQDN,
				store.FormatRecords(e.PrevRecords), store.FormatRecords(e.Records))
		case store.NoLongerObserved:
			log.Printf("  %-18s %s  (unseen in %d consecutive complete run(s))\n",
				e.Change, e.FQDN, e.MissingRuns)
		default:
			log.Printf("  %-18s %s\n", e.Change, e.FQDN)
		}
	}

	if n := d.Count(store.Unconfirmed); n > 0 {
		log.Printf("\n%d name(s) could not be checked this run. They are NOT reported as gone:\n", n)
		var listed int
		for _, e := range d.Entries {
			if e.Change != store.Unconfirmed {
				continue
			}
			if listed == 5 {
				log.Printf("  ... and %d more\n", n-listed)
				break
			}
			listed++
			log.Printf("  %s: %s\n", e.FQDN, e.Reason)
		}
	}

	if d.DNSUnconfirmed > 0 {
		log.Printf("\n%d name(s) got no usable DNS answer this run. Their stored answers are kept,\n"+
			"and this is not reported as a change.\n", d.DNSUnconfirmed)
	}

	if !d.Conclusive {
		explain(log, fmt.Sprintf("Not conclusive (%s): new names are real; a name is called gone only when every source that found it completed.", strings.Join(d.IncompleteSources, ", ")), "")
	}
	if d.Count(store.NoLongerObserved) > 0 {
		explain(log, "\"no longer observed\" means no source reported it this run, not that it was deleted.", "")
	}
}

// logNegativeCache says what the negative cache saved, and names the zones
// it refused to trust, so an operator can see the queries it did not send.
func logNegativeCache(log *logx.Logger, st resolver.NegativeCacheStats) {
	if st.Inferred > 0 {
		log.Logf("info", "%d quer(ies) answered NXDOMAIN without being sent: each name, or one above it, had just been answered NXDOMAIN (RFC 8020); %d sent anyway to check the zone first; -nnc asks every one", st.Inferred, st.Checks)
	}
	if st.Contradicted > 0 {
		log.Logf("info", "%d zone(s) had a name beneath an NXDOMAIN, so nothing in them was inferred", st.Contradicted)
	}
}

// whyEmpty says in words why a run found no name, which is the one question
// a newcomer has and the exit code alone answers only for someone who checks
// it.
func whyEmpty(runs []ledger.SourceRun, roots []string) string {
	var answered, rejected, unreachable int
	var failed, notRun []string
	for _, r := range runs {
		switch source.Status(r.Status) {
		case source.StatusComplete, source.StatusEmpty:
			answered++
			rejected += r.OutOfScope + r.Malformed
		case source.StatusMissingCredentials, source.StatusTermsBlocked, source.StatusSkipped:
			notRun = append(notRun, r.SourceID)
		default:
			failed = append(failed, r.SourceID+" "+r.Status)
			if r.ErrorClass == string(source.ErrTransport) {
				unreachable++
			}
		}
	}
	root := strings.Join(roots, ", ")
	switch {
	case answered == 0 && len(failed) == 0:
		return "Why nothing: no source ran, so nothing was asked. " +
			"`subio sources` lists which need a key and how to set one."
	case answered == 0 && len(failed) > 1 && unreachable*2 > len(failed):

		return fmt.Sprintf("Why nothing: none of the %d source(s) answered, and %d could not be reached at all. "+
			"That looks like this machine's network, not the providers; check it and run again. Exit 4.",
			len(failed), unreachable)
	case answered == 0:
		return fmt.Sprintf("Why nothing: every source that ran failed (%s). "+
			"That is no answer, not an empty zone; exit 4.", strings.Join(failed, ", "))
	case len(failed) > 0:
		return fmt.Sprintf("Why nothing: %d source(s) answered with no name under %s, "+
			"and %d did not answer (%s), so the absence proves nothing; exit 4.",
			answered, root, len(failed), strings.Join(failed, ", "))
	case rejected > 0:
		return fmt.Sprintf("Why nothing: sources returned %d name(s), and every one was outside %s "+
			"or malformed. Check the root is spelled as the names under it are.", rejected, root)
	}
	msg := fmt.Sprintf("Why nothing: all %d source(s) that ran answered, and none knew a name under %s. "+
		"That is an answer; exit 3.", answered, root)
	if len(notRun) > 0 {
		msg += fmt.Sprintf(" %d more need a key or were not selected (%s).", len(notRun), strings.Join(notRun, ", "))
	}
	return msg
}

// explain prints one short line, and the longer reasoning only under -v.
func explain(log *logx.Logger, short, long string) {
	log.Printf("%s\n", short)
	if long != "" && log.Verbose {
		log.Printf("%s\n", long)
	}
}
