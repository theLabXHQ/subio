package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/store"
)

// runHistory inspects and maintains the run history a store accumulates.
func runHistory(args []string, stdout, stderr io.Writer) int {
	var (
		dir     string
		runs    bool
		assets  bool
		export  bool
		compact bool
		retire  int
		asJSON  bool
		root    string
		silent  bool
	)
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)

	g := r.group("store")
	r.stringVar(g, &dir, "directory holding the run history", "store")

	g = r.group("inspect")
	r.boolVar(g, &runs, "list the runs", "runs")
	r.boolVar(g, &assets, "list the current known names", "assets")
	r.stringVar(g, &root, "limit -assets to one authorization root", "root")
	r.boolVar(g, &export, "write every known name as JSON lines to stdout", "export")

	g = r.group("maintain")
	r.intVar(g, &retire, "drop names unseen for this many consecutive complete runs", "retire-after")
	r.boolVar(g, &compact, "rewrite the logs, keeping one record per name and every readable run", "compact")

	g = r.group("output")
	r.boolVar(g, &asJSON, "machine-readable output", "j", "json")
	r.boolVar(g, &silent, "suppress notices", "silent")
	var noColor bool
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")

	if err := fs.Parse(args); err != nil {
		w := stderr
		if err == flag.ErrHelp {
			w = stdout
		} else {
			fmt.Fprintf(stderr, "subio: %v\n", err)
		}
		fmt.Fprint(w, `subio history - inspect and maintain a run history

A store is an append-only log of what previous runs observed, plus each run's
per-source status. The status is what lets a diff tell "no source reported this
name" apart from "the source that knew it failed".

USAGE
   subio discover example.com -store ./state        # record a run and diff it
   subio history -store ./state                     # summary
   subio history -store ./state -runs
   subio history -store ./state -assets -root example.com
   subio history -store ./state -export > inventory.jsonl
   subio history -store ./state -compact -retire-after 5
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
	if dir == "" {
		fmt.Fprintln(stderr, "subio: -store <dir> is required")
		return exitConfig
	}
	if retire < 0 {
		fmt.Fprintln(stderr, "subio: -retire-after cannot be negative")
		return exitConfig
	}
	log := logx.New(stderr)
	log.Silent = silent
	log.Color = isWriterTerminal(stderr) && !noColor

	s, err := store.OpenExisting(dir)
	if err != nil {
		log.Logf("error", "%v", err)
		return exitConfig
	}

	if retire > 0 {
		n, err := s.Retire(retire, "history-"+time.Now().UTC().Format("20060102T150405Z"), time.Now().UTC())
		if err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
		log.Logf("info", "retired %d name(s) unseen for %d consecutive complete runs", n, retire)
	}
	if compact {
		before, after, err := s.Compact()
		if err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
		log.Logf("info", "compacted: %d -> %d bytes", before, after)
	}

	if export {
		n, err := s.Export(stdout)
		if err != nil {
			log.Logf("error", "%v", err)
			return exitFatal
		}
		log.Logf("info", "exported %d name(s)", n)
		return exitOK
	}

	snap, err := s.Load()
	if err != nil {
		log.Logf("error", "%v", err)
		return exitFatal
	}
	if snap.SkippedLines > 0 {
		log.Logf("warn", "%d unreadable line(s) were skipped", snap.SkippedLines)
	}

	switch {
	case runs:
		return historyRuns(stdout, stderr, snap, asJSON)
	case assets:
		return historyAssets(stdout, stderr, snap, root, asJSON)
	}

	st, err := s.Stat()
	if err != nil {
		log.Logf("error", "%v", err)
		return exitFatal
	}
	if asJSON {
		return encodeJSON(stdout, stderr, st)
	}
	fmt.Fprintf(stdout, "store:   %s\n", s.Dir())
	fmt.Fprintf(stdout, "names:   %d\n", st.Assets)
	fmt.Fprintf(stdout, "runs:    %d\n", st.Runs)
	fmt.Fprintf(stdout, "logs:    %d bytes of names, %d bytes of runs\n", st.AssetLogSize, st.RunLogSize)
	if last, ok := snap.LastRun(); ok {
		fmt.Fprintf(stdout, "last:    %s at %s\n", last.ID, last.FinishedAt.Format(time.RFC3339))
		if inc := last.IncompleteSources(); len(inc) > 0 {
			fmt.Fprintf(stdout, "         incomplete sources: %v\n", inc)
		}
	}
	// Unseen names are reported, with the caveat attached, so the count is never
	// mistaken for a list of decommissioned assets.
	var unseen int
	for _, a := range snap.Assets {
		if a.MissingRuns > 0 {
			unseen++
		}
	}
	if unseen > 0 {
		fmt.Fprintf(stdout, "unseen:  %d name(s) not observed in the most recent complete run(s)\n", unseen)
		fmt.Fprintf(stdout, "         that means no source reported them, not that DNS records were deleted\n")
	}
	return exitOK
}

func historyRuns(stdout, stderr io.Writer, snap *store.Snapshot, asJSON bool) int {
	if asJSON {
		return encodeJSON(stdout, stderr, snap.Runs)
	}
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN\tFINISHED\tROOTS\tFINDINGS\tDNS\tCOMPLETE\tINCOMPLETE SOURCES")
	for _, r := range snap.Runs {
		complete := "yes"
		if !r.Complete() {
			complete = "no"
		}
		dns := "-"
		if r.DNSStage {
			dns = "yes"
		}
		inc := "-"
		if v := r.IncompleteSources(); len(v) > 0 {
			inc = joinLimit(v, 3)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
			r.ID, r.FinishedAt.Format("2006-01-02 15:04"), len(r.Roots), r.Findings, dns, complete, inc)
	}
	return flushTab(tw, stderr)
}

func historyAssets(stdout, stderr io.Writer, snap *store.Snapshot, root string, asJSON bool) int {
	list := make([]store.Asset, 0, len(snap.Assets))
	for _, a := range snap.Assets {
		if root != "" && a.Root != root {
			continue
		}
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Root != list[j].Root {
			return list[i].Root < list[j].Root
		}
		return list[i].FQDN < list[j].FQDN
	})
	if asJSON {
		return encodeJSON(stdout, stderr, list)
	}
	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tFIRST SEEN\tLAST SEEN\tUNSEEN RUNS\tSOURCES\tRECORDS")
	for _, a := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			a.FQDN, a.FirstSeen.Format("2006-01-02"), a.LastSeen.Format("2006-01-02"),
			a.MissingRuns, joinLimit(a.Sources, 3), store.FormatRecords(a.Records))
	}
	return flushTab(tw, stderr)
}

func flushTab(tw *tabwriter.Writer, stderr io.Writer) int {
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "subio: %v\n", err)
		return exitFatal
	}
	return exitOK
}

func encodeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(stderr, "subio: %v\n", err)
		return exitFatal
	}
	return exitOK
}

// joinLimit renders a short list, summarizing the tail rather than wrapping
// a table column.
func joinLimit(v []string, n int) string {
	if len(v) <= n {
		return fmt.Sprint(join(v))
	}
	return fmt.Sprintf("%s +%d", join(v[:n]), len(v)-n)
}

func join(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
