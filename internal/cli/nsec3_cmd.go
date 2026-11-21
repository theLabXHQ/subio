package cli

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/resolver"
	"github.com/theLabXHQ/subio/internal/scope"
)

// runNSEC3 reports a zone's NSEC3 posture before anything is enumerated.
func runNSEC3(args []string, stdout, stderr io.Writer) int {
	var (
		zones        []string
		zoneFiles    []string
		resolversRaw string
		queries      = 3
		asJSON       bool
		silent       bool
		noColor      bool
		timeout      = 30 * time.Second
	)
	fs := flag.NewFlagSet("nsec3", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("zone")
	r.listVar(g, &zones, true, "string", "zone to inspect; repeatable and comma separated", "d", "domain")
	r.listVar(g, &zoneFiles, false, "file", "file of zones, one per line", "l", "list")

	g = r.group("options")
	r.intVar(g, &queries, "queries per zone; each asks for one name that cannot exist", "q", "queries")
	r.stringVar(g, &resolversRaw, "resolvers, comma separated or @file", "rs", "resolvers")
	r.durationVar(g, &timeout, "overall deadline", "t", "timeout")

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
		fmt.Fprint(w, `subio nsec3 - report a zone's NSEC3 posture before walking it

Walking an NSEC3 ring can list a whole zone without guessing, or it can be the
most expensive thing a run does. This says which, from a few queries:

  OPT-OUT yes  a gap never proves absence, so the ring can never close and a
               walk maps only what it happens to see
  OPT-OUT no   a closed ring is a complete list of the zone's names
  ITERATIONS   the per-guess CPU cost of matching hashes offline
  HASH         an algorithm subio cannot reproduce means every guess must be
               queried instead, which removes the point of walking

It is not a walk. Each query asks for a name that cannot exist - what any
resolver sends on a typo - and no name is read from the zone.

USAGE
   subio nsec3 -d example.com
   subio nsec3 -l zones.txt -rs 9.9.9.9 -j
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

	for _, f := range zoneFiles {
		lines, err := readRootFile(f)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitConfig
		}
		zones = append(zones, lines...)
	}
	if len(zones) == 0 {
		log.Logf("error", "give at least one zone with -d or -l")
		return exitConfig
	}
	if queries < 1 {
		log.Logf("error", "-q must be at least 1")
		return exitConfig
	}

	canon := make([]string, 0, len(zones))
	seen := map[string]bool{}
	for _, z := range zones {
		host, err := scope.CanonicalZone(z)
		if err != nil {
			log.Logf("warn", "skipping %q: %v", z, err)
			continue
		}
		if !seen[host] {
			seen[host] = true
			canon = append(canon, host)
		}
	}
	if len(canon) == 0 {
		log.Logf("error", "no usable zone name was given")
		return exitConfig
	}

	servers, public, err := parseResolvers(resolversRaw)
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	res, err := resolver.New(resolver.Config{
		Servers: servers, Workers: 2, Window: 4,
		Timeout: 3 * time.Second, Retries: 1,
	})
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}
	if public {
		log.Logf("warn", "using public resolvers; their operators see the zones asked about")
	}
	log.Logf("info", "%d query/queries per zone for a name that cannot exist; no name is read from any zone", queries)

	ctx, cancel := interruptible(timeout, log)
	defer cancel()

	reports := make([]nsec3Report, 0, len(canon))
	for _, z := range canon {
		if why := stoppedEarly(ctx); why != "" {
			log.Logf("warn", "stopped after %d of %d zone(s): %s", len(reports), len(canon), why)
			break
		}
		reports = append(reports, probeNSEC3(ctx, res, z, queries))
	}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reports); err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
	} else {
		tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
		fmt.Fprintln(tw, "ZONE\tDENIAL\tHASH\tITER\tSALT\tOPT-OUT\tWALKABLE\tVERDICT")
		for _, rep := range reports {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				rep.Zone, rep.Denial, rep.HashName(), rep.iterationsText(),
				rep.saltText(), optOutText(rep), yesNo(rep.Walkable), rep.Verdict)
		}
		_ = tw.Flush()
	}

	withNSEC3, walkable := 0, 0
	for _, rep := range reports {
		if rep.NSEC3 {
			withNSEC3++
		}
		if rep.Walkable {
			walkable++
		}
	}
	log.Printf("\n%d zone(s): %d use NSEC3, %d in total could be walked to a complete list.\n",
		len(reports), withNSEC3, walkable)

	if why := stoppedEarly(ctx); why != "" {
		log.Logf("warn", "%d of %d zone(s) were never asked, so this is not a full answer", len(canon)-len(reports), len(canon))
		return exitPartial
	}
	if withNSEC3 == 0 {
		return exitEmpty
	}
	return exitOK
}

// nsec3Report is one zone's posture.
type nsec3Report struct {
	Zone string `json:"zone"`
	// NSEC3 is whether NSEC3 records were read.
	NSEC3 bool `json:"nsec3"`

	// Denial is what proved absence: "nsec3", "nsec", "nsec-synthesized" for a
	// black-lies zone, "none" when the zone answered with neither, or
	// "no-answer" when nothing usable came back.
	Denial string `json:"denial"`
	// Synthesized marks a denial record generated for the query rather than
	// taken from the zone, which cannot be walked however plain it looks.
	Synthesized bool `json:"synthesized,omitempty"`
	// HashAlg is the algorithm the records declare; 1 is SHA-1, the only one RFC
	// 5155 defines.
	HashAlg uint8 `json:"hash_algorithm,omitempty"`

	// Supported is whether subio can reproduce that hash offline.
	Supported bool `json:"hash_supported"`
	// Iterations is the extra hash rounds per name, the per-guess CPU cost.
	Iterations uint16 `json:"iterations"`
	// Salt is hex, empty when the zone uses none.
	Salt string `json:"salt"`

	// OptOut is whether any gap read may span an unsigned delegation.
	OptOut bool `json:"opt_out"`
	// Walkable is whether a walk could in principle reach a closed ring: NSEC3,
	// a reproducible hash, and no opt-out.
	Walkable bool `json:"walkable_to_closure"`
	// Gaps and Hashes are what these few queries already mapped, which says how
	// quickly the ring yields.
	Gaps    int `json:"gaps_seen"`
	Hashes  int `json:"hashed_owners_seen"`
	Queries int `json:"queries_sent"`
	// Verdict is the one-line reading of the row.
	Verdict string `json:"verdict"`
	// Err is a sanitized failure note.
	Err string `json:"error,omitempty"`
}

func (r nsec3Report) HashName() string {
	switch {
	case !r.NSEC3:
		return "-"
	case r.HashAlg == 1:
		return "SHA-1"
	default:
		return fmt.Sprintf("alg%d", r.HashAlg)
	}
}

func (r nsec3Report) iterationsText() string {
	if !r.NSEC3 {
		return "-"
	}
	return fmt.Sprintf("%d", r.Iterations)
}

func (r nsec3Report) saltText() string {
	if !r.NSEC3 {
		return "-"
	}
	if r.Salt == "" {
		return "(none)"
	}
	return r.Salt
}

func optOutText(r nsec3Report) string {
	if !r.NSEC3 {
		return "-"
	}
	return yesNo(r.OptOut)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// probeNSEC3 sends a few queries for names that cannot exist and reads the
// NSEC3 records that prove their absence.
func probeNSEC3(ctx context.Context, res *resolver.Resolver, zone string, queries int) nsec3Report {
	rep := nsec3Report{Zone: zone}
	chain, err := res.WalkNSEC3(ctx, zone, queries)
	if chain == nil {
		rep.Err = sanitizeNSEC3Err(err)
		rep.Verdict = "could not be asked: " + rep.Err
		return rep
	}
	rep.Queries = chain.Queries
	rep.Gaps, rep.Hashes = chain.Gaps(), chain.HashedOwners()
	if !chain.Params() {
		if err != nil {
			rep.Err = sanitizeNSEC3Err(err)
		}
		switch {
		case chain.NSEC() && chain.Synthesized():

			rep.Denial = "nsec-synthesized"
			rep.Synthesized = true
			rep.Verdict = "synthesized NSEC (black lies): the record echoes the name asked for, so a walk returns no real name and only makes traffic"
		case chain.NSEC():

			rep.Denial = "nsec"
			rep.Walkable = true
			rep.Verdict = "plain NSEC: each record names its successor, so the zone walks with no hashing at all"
		case !chain.Answered():
			rep.Denial = "no-answer"
			rep.Verdict = "no usable answer came back, so nothing is known about this zone"
		default:
			rep.Denial = "none"
			rep.Verdict = "answered without NSEC or NSEC3: unsigned, or DNSSEC records not returned by this resolver"
		}
		return rep
	}
	rep.Denial = "nsec3"
	rep.NSEC3 = true
	rep.HashAlg = chain.HashAlg
	rep.Supported = chain.Supported
	rep.Iterations = chain.Iterations
	rep.Salt = hex.EncodeToString(chain.Salt)
	rep.OptOut = chain.OptOut()

	switch {
	case !chain.Supported:
		rep.Verdict = fmt.Sprintf("hash algorithm %d cannot be reproduced offline, so every guess would have to be queried", chain.HashAlg)
	case chain.OptOut():
		rep.Verdict = "opt-out: a gap never proves absence, so the ring cannot be closed and a walk maps only what it sees"
	default:
		rep.Walkable = true
		rep.Verdict = "no opt-out: a walk can reach a closed ring, which is a complete list of the zone"
	}
	if chain.Supported && chain.Iterations > 100 {
		rep.Verdict += fmt.Sprintf("; %d iterations is a high per-guess cost", chain.Iterations)
	}
	return rep
}

// sanitizeNSEC3Err keeps an error short and free of anything but the failure
// kind, so a report can be pasted without carrying resolver internals.
func sanitizeNSEC3Err(err error) string {
	if err == nil {
		return "no NSEC3 record in the answer"
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}
