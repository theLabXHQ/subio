package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/theLabXHQ/subio/internal/logx"
	"github.com/theLabXHQ/subio/internal/secrets"
	"github.com/theLabXHQ/subio/internal/source"
	"github.com/theLabXHQ/subio/internal/sources"
)

type sourceRow struct {
	ID         string `json:"id"`
	Family     string `json:"family"`
	Key        string `json:"key"`
	Configured bool   `json:"configured"`
	Terms      string `json:"terms"`

	// TermsReviewedAt is the day the provider's own pages were last read for
	// this repository, and TermsReviewedDays how long ago that was.
	TermsReviewedAt   string `json:"terms_reviewed_at,omitempty"`
	TermsReviewedDays int    `json:"terms_reviewed_days_ago,omitempty"`
	Enabled           bool   `json:"enabled_in_profile"`
	CapsSilently      bool
	OptIn             bool   `json:"opt_in,omitempty"`
	Slow              bool   `json:"slow,omitempty"`
	Reason            string `json:"disabled_reason,omitempty"`
	RateLimit         string `json:"documented_rate_limit"`
	ResultCap         int    `json:"documented_result_cap,omitempty"`
	Correlation       string `json:"correlation_group,omitempty"`
	DocsURL           string `json:"docs_url"`
	TermsURL          string `json:"terms_url"`
	Note              string `json:"note,omitempty"`
}

// termsAge is how many whole days ago a review date was, or 0 when there is
// no date or it cannot be read.
func termsAge(reviewed string) int {
	if reviewed == "" {
		return 0
	}
	t, err := time.Parse("2006-01-02", reviewed)
	if err != nil {
		return 0
	}
	days := int(time.Since(t).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// reviewedText shows the date with its age, so the age is visible without
// arithmetic.
func reviewedText(row sourceRow) string {
	if row.TermsReviewedAt == "" {
		return "never"
	}
	return fmt.Sprintf("%s (%dd)", row.TermsReviewedAt, row.TermsReviewedDays)
}

// runSources lists the adapters without touching the network.
func runSources(args []string, stdout, stderr io.Writer) int {
	var (
		asJSON      bool
		secretsFile string
		profileName string
		noColor     bool
		verbose     bool
	)
	fs := flag.NewFlagSet("sources", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	r := newRegistry(fs)
	g := r.group("options")
	r.boolVar(g, &asJSON, "emit machine-readable JSON", "j", "json")
	r.stringVar(g, &secretsFile, "file of `source_id = value` lines; mode must be 600", "sf", "secrets-file")
	r.stringVar(g, &profileName, "terms profile: personal or commercial", "p", "profile")
	r.boolVar(g, &noColor, "disable color", "nc", "no-color")
	r.boolVar(g, &verbose, "also show each adapter's terms state and review date, and the caveats", "v", "verbose")

	if err := fs.Parse(args); err != nil {
		w := stderr
		if err == flag.ErrHelp {
			w = stdout
		} else {
			fmt.Fprintf(stderr, "subio: %v\n", err)
		}
		fmt.Fprint(w, `subio sources - list adapters (no network access)

Shows each adapter's evidence family, whether a credential is required and
configured, its reviewed terms state, and its documented rate limit.

A credential is never validated: "configured" means a value was found, nothing
more. Checking it would mean issuing a request you did not ask for.
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

	var prof source.Profile
	switch profileName {
	case "", "personal":
		prof = source.ProfilePersonal
		profileName = "personal"
	case "commercial":
		prof = source.ProfileCommercial
	default:
		fmt.Fprintf(stderr, "subio: unknown profile %q: use personal or commercial\n", profileName)
		return exitConfig
	}

	sec := secrets.New()
	if secretsFile != "" {
		if err := sec.LoadFile(secretsFile); err != nil {
			fmt.Fprintf(stderr, "subio: %v\n", err)
			return exitConfig
		}
	}

	rows := collectSourceRows(prof, profileName, sec)
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(stderr, "subio: %v\n", err)
			return exitFatal
		}
		return exitOK
	}

	tw := tabwriter.NewWriter(stdout, 0, 8, 2, ' ', 0)
	if verbose {
		fmt.Fprintln(tw, "SOURCE\tFAMILY\tKEY\tDEFAULT\tLIMIT\tTERMS\tREVIEWED")
	} else {
		fmt.Fprintln(tw, "SOURCE\tFAMILY\tKEY\tDEFAULT\tLIMIT")
	}
	enabled := 0
	var keyless []string
	for _, row := range rows {
		state := "no"
		switch {
		case row.Enabled && row.OptIn:
			state = "-s only"
		case row.Enabled && row.Slow:
			state = "-as"
		case row.Enabled:
			state = "yes"
		case row.Key == "required" && !row.Configured:
			state = "needs key"
			keyless = append(keyless, row.ID)
		}
		if row.Enabled {
			enabled++
		}
		keyState := "-"
		switch {
		case row.Key == "optional" && row.Configured:
			keyState = "optional (set)"
		case row.Key == "optional":
			keyState = "optional"
		case row.Key == "required" && row.Configured:
			keyState = "required (set)"
		case row.Key == "required":
			keyState = "required"
		}
		if verbose {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				row.ID, row.Family, keyState, state, row.RateLimit, row.Terms, reviewedText(row))
		} else {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", row.ID, row.Family, keyState, state, row.RateLimit)
		}
	}
	_ = tw.Flush()

	log := logx.New(stderr)
	log.Color = !noColor && isWriterTerminal(stderr)
	summary := fmt.Sprintf("\n%d of %d adapters enabled", enabled, len(rows))
	if len(keyless) > 0 {
		summary += fmt.Sprintf("; set SUBIO_KEY_<NAME> to enable %s", strings.Join(keyless, ", "))
	}
	log.Printf("%s.\n", summary)
	if prof == source.ProfileCommercial && enabled == 0 {
		log.Printf("No provider's terms are cleared for commercial use yet; clear one against your own contract first.\n")
	}
	if !verbose {
		return exitOK
	}
	for _, row := range rows {
		if !row.Enabled && row.Reason != "" {
			log.Printf("  %-16s disabled: %s\n", row.ID, row.Reason)
		}
	}
	var caps []string
	for _, row := range rows {
		if row.CapsSilently {
			caps = append(caps, row.ID)
		}
	}
	if len(caps) > 0 {
		log.Printf(`
Completeness cannot be established for: %s. Such a provider can return a short
result set with nothing in the response to say so, so its "complete" means the
whole answer was read, not that the answer was whole. The ledger marks those
runs caps_silently. crt.sh's own database holds more than its HTTP endpoint
returns - measured 2334 names against 21 for the same domain - and -s crtshdb
queries it.
`, strings.Join(caps, ", "))
	}
	return exitOK
}

func collectSourceRows(prof source.Profile, profileName string, sec *secrets.Env) []sourceRow {
	var rows []sourceRow
	for _, p := range sources.NewRegistry().All() {
		md := p.Metadata()
		row := sourceRow{
			ID: md.ID, Family: string(md.Family), Terms: md.Terms.String(),
			RateLimit: rateString(md), ResultCap: md.Limits.ResultCap,
			OptIn:        md.OptIn,
			Slow:         md.Slow,
			CapsSilently: md.CapsSilently,
			Correlation:  md.CorrelationGroup, DocsURL: md.DocsURL,
			TermsURL: md.TermsURL, Note: md.Note,
			TermsReviewedAt: md.TermsReviewedAt, TermsReviewedDays: termsAge(md.TermsReviewedAt),
		}
		switch md.Key {
		case source.NoKey:
			row.Key, row.Configured = "none", true
		case source.OptionalKey:
			row.Key, row.Configured = "optional", sec.Has(md.ID)
		case source.RequiredKey:
			row.Key, row.Configured = "required", sec.Has(md.ID)
		}
		allowed, _ := source.Allowed(md, prof)
		switch {
		case !allowed:
			row.Reason = "terms not cleared for the " + profileName + " profile"
		case md.Key == source.RequiredKey && !row.Configured:
			row.Reason = "no credential configured (set SUBIO_KEY_" + strings.ToUpper(md.ID) + ")"
		default:
			row.Enabled = true
		}
		rows = append(rows, row)
	}
	return rows
}

func rateString(md source.Metadata) string {
	l := md.Limits
	if l.RequestsPerWindow <= 0 || l.Window <= 0 {
		return "not stated"
	}
	return fmt.Sprintf("%d / %s", l.RequestsPerWindow, l.Window)
}
