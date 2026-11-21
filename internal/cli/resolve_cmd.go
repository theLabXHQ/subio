package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/cdn"
	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/output"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/scope"
)

// runResolve is the standalone DNS stage: it observes DNS for a list of
// names produced elsewhere, so subio composes with other tools in a pipeline.
func runResolve(args []string, stdout, stderr io.Writer) int {
	var (
		input        string
		typesRaw     = "A"
		resolversRaw string
		qps          = 1000
		resolverQPS  int
		workers      = 16
		window       = 256
		timeout      = 2 * time.Second
		retries      = 1
		noTCP        bool
		noNegCache   bool
		asJSON       bool
		resolvedOnly bool
		silent       bool
		verbose      bool
		noColor      bool
		withCDN      bool
		profileIn    string
		profileOut   string
		deadline     time.Duration
	)
	fs := flag.NewFlagSet("resolve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("input")
	r.stringVar(g, &input, "file of hostnames, one per line; - for stdin", "l", "list")

	g = r.group("queries")
	r.stringVar(g, &typesRaw, "record types to query", "ty", "types")
	r.stringVar(g, &resolversRaw, "resolvers, comma separated, or @file", "rs", "resolvers")
	r.intVar(g, &qps, "global queries per second ceiling; 0 is unlimited", "qps")
	r.intVar(g, &resolverQPS, "per-resolver queries per second ceiling; 0 is unlimited", "rqps", "resolver-qps")
	r.intVar(g, &workers, "DNS sockets", "w", "workers")
	r.intVar(g, &window, "outstanding queries per socket", "n", "window")
	r.durationVar(g, &timeout, "per-query timeout", "t", "timeout")
	r.intVar(g, &retries, "retries after the first attempt", "rt", "retries")
	r.boolVar(g, &noTCP, "do not retry truncated answers over TCP", "no-tcp")
	r.boolVar(g, &noNegCache, "ask every query; by default a name at or beneath one just answered NXDOMAIN is answered NXDOMAIN without asking, once its zone has kept that rule (RFC 8020) when checked", "nnc", "no-negative-cache")
	r.durationVar(g, &deadline, "overall deadline; 0 is none", "dl", "deadline")
	r.stringVar(g, &profileIn, "a resolver profile an earlier run wrote: leave out the resolvers it dropped and start the ones it slowed at their measured rate", "rp", "resolver-profile")
	r.stringVar(g, &profileOut, "write what this run learned about each resolver, for -rp next time", "rpo", "resolver-profile-out")

	g = r.group("output")
	r.boolVar(g, &asJSON, "emit one JSON observation per line", "j", "jsonl")
	r.boolVar(g, &resolvedOnly, "print only names that returned an answer", "ro", "resolved-only")
	r.boolVar(g, &withCDN, "mark each answer's CDN, WAF or cloud provider, from its CNAME chain and Team Cymru's origin AS for its addresses; output waits for the whole run", "cdn")
	r.boolVar(g, &silent, "only results on stdout", "silent")
	r.boolVar(g, &verbose, "verbose diagnostics", "v", "verbose")
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")

	if err := fs.Parse(args); err != nil {
		w := stderr
		if err == flag.ErrHelp {
			w = stdout
		} else {

			fmt.Fprintf(stderr, "subio: %v\n", err)
		}
		fmt.Fprint(w, `subio resolve - observe DNS for a list of names

This is ACTIVE: it queries the nameservers responsible for the names you
supply. Run it only against infrastructure you are authorized to query.

An answer is one resolver's observation at one moment. SERVFAIL, REFUSED and
timeout are reported as errors, never as "does not exist".

USAGE
   subio resolve -l names.txt -ty A,AAAA
   subio discover example.com | subio resolve -qps 5000 -j

EXIT CODES
   0  every name got an answer or a negative, at least one with an answer
   2  configuration error (nothing was queried)
   3  every query completed, and no name had an answer
   4  at least one query could not be answered; its absence proves nothing
`)
		r.render(w)
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitConfig
	}
	if rejectBareArgs(fs, stderr) {
		fmt.Fprintln(stderr, "subio: give a file of hostnames with -l")
		return exitConfig
	}
	switch {
	case resolverQPS < 0:
		fmt.Fprintln(stderr, "subio: -resolver-qps cannot be negative")
		return exitConfig
	case qps < 0:
		fmt.Fprintln(stderr, "subio: -qps cannot be negative")
		return exitConfig
	case timeout <= 0:
		fmt.Fprintln(stderr, "subio: -timeout must be positive")
		return exitConfig
	case workers < 1 || window < 1:
		fmt.Fprintln(stderr, "subio: -workers and -window must be at least 1")
		return exitConfig
	case retries < 0:
		fmt.Fprintln(stderr, "subio: -retries cannot be negative")
		return exitConfig
	case deadline < 0:
		fmt.Fprintln(stderr, "subio: -deadline cannot be negative")
		return exitConfig
	}
	if input == "" {
		input = "-"
	}

	log := logx.New(stderr)
	banner(stderr, silent, noColor)
	log.Verbose, log.Silent, log.Color = verbose, silent, !noColor && isWriterTerminal(stderr)

	types, err := parseTypes(typesRaw)
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	var servers []netip.AddrPort
	var public bool
	if servers, public, err = parseResolvers(resolversRaw); err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	var profile *resolverProfile
	var serverQPS map[netip.AddrPort]float64
	if profileIn != "" {
		if profile, err = loadProfile(profileIn); err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		servers, serverQPS = applyResolverProfile(servers, profile, profileIn, log)
	}
	names, malformed, err := readNames(input)
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	if len(names) == 0 {
		log.Logf("error", "no usable hostnames on input")
		return exitConfig
	}

	res, err := resolver.New(resolver.Config{
		Servers: servers, Workers: workers, Window: window,
		Timeout: timeout, Retries: retries, QPS: qps, PerResolverQPS: resolverQPS, TCPOnTruncate: !noTCP,
		ServerQPS: serverQPS, NoNegativeCache: noNegCache,
	})
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}

	ctx, cancel := interruptible(deadline, log)
	defer cancel()

	log.Logf("info", "%d names x %d type(s) across %d resolver(s)", len(names), len(types), len(servers))
	log.Logf("warn", "this queries the target's nameservers: active, not passive")
	if public {
		log.Logf("warn", "using public resolvers; their operators see every name queried")
	}
	if malformed > 0 {
		log.Logf("warn", "%d input line(s) were not valid hostnames and were skipped", malformed)
	}

	jobs := make(chan resolver.Job, 2048)
	answers := make(chan resolver.Answer, 2048)
	go func() {
		defer close(jobs)
		for _, n := range names {
			for _, t := range types {
				select {
				case jobs <- resolver.Job{Name: n, Type: t}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go res.Stream(ctx, jobs, answers)

	bw := bufio.NewWriterSize(stdout, 64<<10)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	started := time.Now()
	var answered, negative, errored int
	var held []resolver.Answer

	emit := func(a resolver.Answer, edge *cdn.Edge) error {
		if asJSON {
			j := jsonAnswer(a)
			j.Edge = edge
			return enc.Encode(j)
		}
		mark := ""
		if edge != nil {
			mark = " [" + string(edge.Kind) + ":" + edge.Provider + "]"
		}
		if a.Outcome == resolver.Resolved {
			vals := make([]string, 0, len(a.Records))
			for _, rr := range a.Records {
				vals = append(vals, rr.Type+":"+rr.Value)
			}
			_, err := fmt.Fprintf(bw, "%s\t%s%s\n", a.Name, strings.Join(vals, " "), mark)
			return err
		}
		_, err := fmt.Fprintf(bw, "%s\t%s\n", a.Name, a.Outcome)
		return err
	}

	for a := range answers {
		switch a.Outcome {
		case resolver.Resolved:
			answered++
		case resolver.NXDomain, resolver.NoData:
			negative++
		default:
			errored++
		}
		if resolvedOnly && a.Outcome != resolver.Resolved {
			continue
		}
		if withCDN {

			held = append(held, a)
			continue
		}
		if err := emit(a, nil); err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
	}
	if withCDN {
		var addrs []netip.Addr
		seen := map[netip.Addr]bool{}
		for _, a := range held {
			for _, rr := range a.Records {
				if ad, err := netip.ParseAddr(rr.Value); err == nil && (rr.Type == "A" || rr.Type == "AAAA") && !seen[ad] {
					seen[ad] = true
					addrs = append(addrs, ad)
				}
			}
		}
		ix := edgeIndex{}
		if len(addrs) > 0 && ctx.Err() == nil {
			origin, failed := originByAddr(ctx, res, addrs, log)
			for ad, n := range origin {
				ix[ad] = n
			}
			if len(failed) > 0 {
				log.Logf("warn", "-cdn: no origin answer for %d of %d address(es); those answers are unmarked, which is not the same as being an origin", len(failed), len(addrs))
			}
		}
		for _, a := range held {
			var rrs []output.RR
			for _, rr := range a.Records {
				rrs = append(rrs, output.RR{Type: rr.Type, Value: rr.Value})
			}
			if err := emit(a, ix.edgeFor(a.CNAMEChain, rrs)); err != nil {
				log.Logf("error", "%v", err)
				return exitFatal
			}
		}
	}
	if err := bw.Flush(); err != nil {
		log.Logf("error", "writing results: %v", err)
		return exitFatal
	}

	if profileOut != "" {
		p := buildProfile(res.Stats(), profile, time.Now().UTC())
		if err := writeProfile(profileOut, p); err != nil {
			log.Logf("error", "resolver profile: %v", err)
		}
	}

	if !silent {
		elapsed := time.Since(started)
		total := answered + negative + errored
		log.Printf("\n%d answered, %d negative, %d error in %s (%.0f q/s)\n",
			answered, negative, errored, elapsed.Round(time.Millisecond),
			float64(total)/max(elapsed.Seconds(), 1e-9))
		if errored > 0 {
			log.Printf("error means the resolver could not answer. It is not evidence of absence.\n")
		}
		logNegativeCache(log, res.NegativeCacheStats())
	}
	if why := stoppedEarly(ctx); why != "" {
		log.Logf("warn", "the run did not finish (%s): names not yet queried are not names without records", why)
		return exitPartial
	}
	return resolveExit(answered, errored)
}

// resolveExit is the code a scheduled job reads.
func resolveExit(answered, errored int) int {
	switch {
	case errored > 0:
		return exitPartial
	case answered == 0:
		return exitEmpty
	}
	return exitOK
}

type answerJSON struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Outcome    string            `json:"outcome"`
	RCode      string            `json:"rcode,omitempty"`
	Records    []resolver.Record `json:"records,omitempty"`
	CNAMEChain []string          `json:"cname_chain,omitempty"`
	Resolver   string            `json:"resolver"`
	CheckedAt  time.Time         `json:"checked_at"`
	ErrorClass string            `json:"error_class,omitempty"`
	Truncated  bool              `json:"truncated,omitempty"`
	Tries      int               `json:"tries"`
	Edge       *cdn.Edge         `json:"edge,omitempty"`
	// InferredFrom names the NXDOMAIN this negative was inferred from instead of
	// asked; see resolver.Answer.
	InferredFrom string `json:"inferred_from,omitempty"`
}

func jsonAnswer(a resolver.Answer) answerJSON {
	return answerJSON{
		Name: a.Name, Type: a.Type.String(), Outcome: string(a.Outcome),
		RCode: a.RCodeText(), Records: a.Records, CNAMEChain: a.CNAMEChain,
		Resolver: a.Resolver, CheckedAt: a.CheckedAt, ErrorClass: a.ErrorClass,
		Truncated: a.Truncated, Tries: a.Tries, InferredFrom: a.InferredFrom,
	}
}

// readNames reads and canonicalizes hostnames, reporting how many lines were
// rejected rather than dropping them silently.
func readNames(path string) (names []string, malformed int, err error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		defer f.Close()
		r = f
	}
	seen := make(map[string]bool, 1024)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if i := strings.IndexAny(line, " \t"); i > 0 {
			line = line[:i]
		}
		h, err := scope.Canonical(line)
		if err != nil {
			malformed++
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		names = append(names, h)
	}
	return names, malformed, sc.Err()
}
