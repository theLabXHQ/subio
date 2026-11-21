package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/theLabXHQ/subio/internal/ct"
	"github.com/theLabXHQ/subio/internal/fetch"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/scope"
	"sync"
)

// runCTTail reads a CT log and prints the in-scope names.
func runCTTail(args []string, stdout, stderr io.Writer) int {
	var (
		logBases          []string
		logFile, listFile string
		roots             []string
		rootFiles         []string
		storeDir          string
		recentTiles       int
		all               bool
		asJSON            bool
		silent            bool
		noColor           bool
		timeout           time.Duration = 5 * time.Minute
	)
	fs := flag.NewFlagSet("cttail", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("log")
	r.listVar(g, &logBases, true, "string", "CT log monitoring prefix, e.g. https://log.example; repeatable and comma separated", "log")
	r.stringVar(g, &logFile, "file of log prefixes, one per line", "logs")
	r.stringVar(g, &listFile, "a Chrome CT log list (v3 JSON) to use instead of the built-in snapshot", "log-list")

	g = r.group("scope")
	r.listVar(g, &roots, true, "string", "root domain to keep; repeatable and comma separated", "d", "domain")
	r.listVar(g, &rootFiles, false, "file", "file of root domains, one per line", "l", "list")

	g = r.group("reading")
	r.stringVar(g, &storeDir, "directory holding the per-log checkpoint; enables incremental reads", "store")
	r.intVar(g, &recentTiles, "on a non-incremental run, how far back to start, in tiles of 256 entries", "tiles")
	r.boolVar(g, &all, "read the whole log from the start; this is a lot of bandwidth", "all")
	r.durationVar(g, &timeout, "overall deadline", "t", "timeout")

	g = r.group("output")
	r.boolVar(g, &asJSON, "emit one JSON object per name with its tile and timestamp", "j", "jsonl")
	r.boolVar(g, &silent, "only results on stdout", "silent")
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")

	if err := fs.Parse(args); err != nil {
		w := stderr
		if err == flag.ErrHelp {
			w = stdout
		} else {
			fmt.Fprintf(stderr, "subio: %v\n", err)
		}
		fmt.Fprint(w, `subio cttail - monitor CT logs for in-scope hostnames

Each log's protocol is detected and read with the right reader:

  static-ct  a tiled log (c2sp.org/static-ct-api) publishes static files, and
             the names-tiles extension serves just the subject and DNS names -
             exactly what a subdomain monitor wants, and cheap to read.
  rfc6962    the original queryable API returns whole certificates from
             get-entries, which subio parses itself. Same names, far more
             bandwidth, and a log may cap each answer.

With -store, each run records each log's size and reads only what was added
since, so it finds new certificates cheaply. It does not backfill history: -all
reads a log from the start and is heavy.

No log signature and no inclusion proof is verified: subio reads names and the
scope gate drops every name outside your roots, including the log's millions of
unrelated ones.

USAGE
   subio cttail -log https://log.example -d example.com -store ./ct-state
   subio cttail -logs logs.txt -d example.com -store ./ct-state
   subio cttail -log https://a.example,https://b.example -d example.com -tiles 16
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

	if logFile != "" {
		lines, err := readRootFile(logFile)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		logBases = append(logBases, lines...)
	}
	if len(logBases) == 0 {

		ll, err := ct.Builtin()
		if err != nil {
			log.Logf("error", "built-in log list: %v", err)
			return exitConfig
		}
		if listFile != "" {
			data, rerr := os.ReadFile(listFile)
			if rerr != nil {
				log.Logf("error", "reading %s: %v", listFile, rerr)
				return exitConfig
			}
			if ll, err = ct.ParseLogList(data); err != nil {
				log.Logf("error", "%s: %v", listFile, err)
				return exitConfig
			}
		}
		mon := ll.Monitorable(time.Now())
		if len(mon) == 0 {
			log.Logf("error", "no log in the list accepts certificates issued now; "+
				"the list is %s old - fetch a current one and pass it with -log-list",
				ll.Age(time.Now()).Round(24*time.Hour))
			return exitConfig
		}
		var tiled int
		for _, l := range mon {
			logBases = append(logBases, l.URL)
			if l.Protocol == ct.ProtoStaticCT {
				tiled++
			}
		}

		source := "built-in list"
		if listFile != "" {
			source = listFile
		}
		log.Logf("info", "%s v%s, %d day(s) old: %d of %d log(s) accept certificates issued now (%d tiled, %d rfc6962)",
			source, ll.Version, int(ll.Age(time.Now()).Hours()/24), len(mon), len(ll.Logs), tiled, len(mon)-tiled)
		if listFile == "" {
			log.Logf("info", "a newer list: curl -o logs.json %s then -log-list logs.json", ct.LogListURL)
		}

		if storeDir == "" {
			log.Logf("warn", "%d logs and no -store: a run that does not finish starts over next time. "+
				"-store <dir> keeps each log's position, or -log <url> picks one", len(mon))
		}
	}
	if recentTiles < 0 {
		log.Logf("error", "-tiles cannot be negative")
		return exitConfig
	}
	if recentTiles == 0 {
		recentTiles = 8
	}
	for _, f := range rootFiles {
		lines, err := readRootFile(f)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		roots = append(roots, lines...)
	}
	if len(roots) == 0 {
		log.Logf("error", "give at least one root with -d or -l: a CT log holds every domain's certificates")
		return exitConfig
	}
	set, err := scope.NewSet(roots...)
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}

	scheduler := sched.New(sched.Config{GlobalConcurrency: 4, PerSourceConcurrency: 2})
	client := fetch.New(fetch.Config{Scheduler: scheduler, MaxAttempts: 3})

	client.Register(ctSourceMeta())
	fetcher := ctFetcher{client: client}

	ctx, cancel := interruptible(timeout, log)
	defer cancel()

	if all {
		log.Logf("warn", "reading each log from the start; this can be millions of entries")
	}

	// Each log is tailed independently: its own protocol, its own checkpoint,
	// its own status.
	var allNames []ct.Name
	reports := make([]ctLogReport, 0, len(logBases))

	// Logs are read concurrently because they are independent and belong to
	// different operators, so the concurrency falls on no one provider.
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, ctLogConcurrency)
	for _, base := range logBases {
		wg.Add(1)
		go func(base string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			rep := ctLogReport{Log: base}
			proto, size, derr := ct.Detect(ctx, fetcher, base)
			rep.Protocol = string(proto)
			rep.TreeSize = size
			switch {
			case derr != nil:
				rep.Status = "failed"

				rep.Note = "neither a tiled checkpoint nor an RFC 6962 tree head"
				if ctx.Err() != nil {
					rep.Status, rep.Note = "not read", "the run's time ran out before this log was probed"
				}
				log.Logf("warn", "%s: %v", base, derr)
				mu.Lock()
				reports = append(reports, rep)
				mu.Unlock()
				return
			case proto == ct.ProtoUnknown:
				rep.Status = "failed"
				rep.Note = "the log's protocol could not be determined"
				mu.Lock()
				reports = append(reports, rep)
				mu.Unlock()
				return
			}

			from := int64(recentTiles) * ct.EntriesPerTile
			if size > from {
				from = size - from
			} else {
				from = 0
			}
			if all {
				from = 0
			} else if storeDir != "" {
				if stored, ok := loadCTCheckpoint(storeDir, base); ok {
					from = stored
				}
			}
			log.Logf("verbose", "%s: %s, size %d, reading from entry %d", base, proto, size, from)

			// Each protocol has its own reader.
			var res *ct.Result
			var terr error
			cfg := ct.Config{Base: base, From: from}
			if proto == ct.ProtoRFC6962 {
				log.Logf("verbose", "%s speaks RFC 6962: entries carry whole certificates, so this costs more bandwidth than a tiled log's names", base)
				res, terr = ct.TailRFC6962(ctx, fetcher, ctScope{set}, cfg)
			} else {
				res, terr = ct.Tail(ctx, fetcher, ctScope{set}, cfg)
			}
			if res != nil {
				mu.Lock()
				allNames = append(allNames, res.Names...)
				mu.Unlock()
				rep.Reads, rep.Entries, rep.Names, rep.Unreadable = res.Reads, res.Entries, len(res.Names), res.Unreadable
				if storeDir != "" {
					if serr := saveCTCheckpoint(storeDir, base, res.ToSize); serr != nil {

						log.Logf("error", "recording checkpoint for %s: %v", base, serr)
						rep.Status, rep.Note = "partial", "checkpoint not recorded: "+serr.Error()
						mu.Lock()
						reports = append(reports, rep)
						mu.Unlock()
						return
					}
				}
			}
			if terr != nil {

				rep.Status = "partial"
				rep.Note = terr.Error()
				log.Logf("warn", "%s: %v", base, terr)
			} else {
				rep.Status = "complete"
			}
			mu.Lock()
			reports = append(reports, rep)
			mu.Unlock()
		}(base)
	}
	wg.Wait()

	order := make(map[string]int, len(logBases))
	for i, b := range logBases {
		order[b] = i
	}
	sort.Slice(reports, func(i, j int) bool { return order[reports[i].Log] < order[reports[j].Log] })

	names := dedupeNames(allNames)
	bw := bufio.NewWriterSize(stdout, 64<<10)
	for _, n := range names {
		if asJSON {
			_ = json.NewEncoder(bw).Encode(ctNameJSON{
				Host: n.Host, Index: n.Index, Method: n.Method, Timestamp: n.Timestamp,
			})
		} else {
			fmt.Fprintln(bw, n.Host)
		}
	}
	if ferr := bw.Flush(); ferr != nil {
		log.Logf("error", "writing results: %v", ferr)
		return exitFatal
	}

	incomplete := 0
	var totalReads, totalEntries, totalUnreadable int
	tw := tabwriter.NewWriter(stderr, 0, 8, 2, ' ', 0)

	fmt.Fprintln(tw, "LOG\tPROTOCOL\tSTATUS\tTREE SIZE\tREADS\tENTRIES\tNAMES\tNOTE")
	for _, rep := range reports {
		if rep.Status != "complete" {
			incomplete++
		}
		totalReads += rep.Reads
		totalEntries += rep.Entries
		totalUnreadable += rep.Unreadable
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
			rep.Log, rep.Protocol, rep.Status, rep.TreeSize, rep.Reads, rep.Entries, rep.Names, rep.Note)
	}
	if !silent {
		_ = tw.Flush()
	}

	if ages := nameAges(names, time.Now()); len(ages) > 0 {
		sort.Slice(ages, func(i, j int) bool { return ages[i] < ages[j] })
		log.Logf("info", "certificate age when seen: newest %s, median %s, oldest %s (MMD is 24h)",
			ages[0].Round(time.Minute), ages[len(ages)/2].Round(time.Minute),
			ages[len(ages)-1].Round(time.Minute))
	}
	log.Logf("info", "%d log(s): %d read(s), %d entries scanned, %d distinct in-scope name(s)",
		len(reports), totalReads, totalEntries, len(names))
	if totalUnreadable > 0 {

		log.Logf("warn", "%d of %d entries could not be read, so their names are missing", totalUnreadable, totalEntries)
	}
	if incomplete > 0 {
		log.Logf("warn", "%d of %d log(s) were not read completely; the absence of a name proves nothing", incomplete, len(reports))
	}
	if why := stoppedEarly(ctx); why != "" {
		log.Logf("warn", "the run did not finish (%s); each log's stored position reflects only what was read", why)
		return exitPartial
	}
	switch {
	case incomplete > 0:
		return exitPartial
	case len(names) == 0:
		return exitEmpty
	}
	return exitOK
}

// nameAges is how old each name's certificate was when this run saw it.
func nameAges(names []ct.Name, now time.Time) []time.Duration {
	out := make([]time.Duration, 0, len(names))
	for _, n := range names {
		if n.Timestamp <= 0 {
			continue
		}
		if age := now.Sub(time.UnixMilli(n.Timestamp)); age >= 0 {
			out = append(out, age)
		}
	}
	return out
}

// ctLogConcurrency bounds how many logs are read at once.
const ctLogConcurrency = 6

// ctLogReport is one log's outcome, so a multi-log run says what each log did.
type ctLogReport struct {
	Log        string
	Protocol   string
	Status     string
	Note       string
	TreeSize   int64
	Reads      int
	Entries    int
	Names      int
	Unreadable int
}

// ctNameJSON is one output record.
type ctNameJSON struct {
	Host      string `json:"host"`
	Index     int64  `json:"index"`
	Method    string `json:"method"`
	Timestamp int64  `json:"log_timestamp,omitempty"`
}

// dedupeNames keeps each host once, earliest tile first.
func dedupeNames(in []ct.Name) []ct.Name {
	seen := map[string]bool{}
	var out []ct.Name
	for _, n := range in {
		if !seen[n.Host] {
			seen[n.Host] = true
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}
