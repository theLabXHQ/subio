package output

import (
	"strconv"
	"strings"
	"time"
)

// Fields selects which bracketed fields plain text prints.
type Fields struct {
	Sources   bool
	Families  bool
	Evidence  bool
	FirstSeen bool
	LastSeen  bool
	DNS       bool
	CNAME     bool
	RCode     bool
	Resolver  bool
	Wildcard  bool
	Status    bool
	Root      bool
	Change    bool
	Edge      bool
}

// NeedsWholeRun reports a field whose value is only known once every source
// has answered.
func (f Fields) NeedsWholeRun() bool {
	return f.Sources || f.Families || f.Evidence || f.FirstSeen || f.LastSeen
}

const (
	cReset  = "\x1b[0m"
	cHost   = "\x1b[36m"
	cSource = "\x1b[34m"
	cGood   = "\x1b[32m"
	cWarn   = "\x1b[33m"
	cDim    = "\x1b[90m"
)

// FormatText renders one record as a line.
func FormatText(r *Record, f Fields, color bool) string {
	var b strings.Builder
	b.Grow(96)
	paint := func(c, s string) {
		if color {
			b.WriteString(c)
			b.WriteString(s)
			b.WriteString(cReset)
			return
		}
		b.WriteString(s)
	}
	paint(cHost, r.Host)

	field := func(c, s string) {
		if s == "" {
			return
		}
		b.WriteString(" [")
		paint(c, s)
		b.WriteString("]")
	}

	if f.Change && r.Change != "" {
		c := cDim
		switch r.Change {
		case "new", "reappeared":
			c = cGood
		case "dns_changed", "no_longer_observed":
			c = cWarn
		}
		field(c, r.Change)
	}
	if f.Root {
		field(cDim, r.Root)
	}
	if f.Sources {
		field(cSource, strings.Join(r.Sources, ","))
	}
	if f.Families {
		field(cSource, strings.Join(r.Families, ","))
	}
	if f.Evidence && r.Evidence > 0 {
		field(cDim, strconv.Itoa(r.Evidence))
	}
	if f.FirstSeen && r.FirstSeen != nil {
		field(cDim, r.FirstSeen.UTC().Format(time.RFC3339))
	}
	if f.LastSeen && r.LastSeen != nil {
		field(cDim, r.LastSeen.UTC().Format(time.RFC3339))
	}
	if f.Status {
		c := cDim
		switch r.Verification {
		case "resolved":
			c = cGood
		case "resolution_error":
			c = cWarn
		}
		field(c, r.Verification)
	}
	if f.RCode {
		field(cDim, r.RCode)
	}
	if f.DNS && len(r.Records) > 0 {
		vals := make([]string, 0, len(r.Records))
		for _, rr := range r.Records {
			vals = append(vals, rr.Type+":"+rr.Value)
		}
		field(cGood, strings.Join(vals, " "))
	}
	if f.CNAME && len(r.CNAMEChain) > 0 {
		field(cDim, strings.Join(r.CNAMEChain, " -> "))
	}
	if f.Resolver {
		field(cDim, r.Resolver)
	}
	if f.Wildcard && r.Wildcard {
		field(cWarn, "wildcard")
	}
	if f.Edge && r.Edge != nil {
		field(cWarn, string(r.Edge.Kind)+":"+r.Edge.Provider)
	}
	if r.ErrorClass != "" && (f.Status || f.RCode) {
		field(cWarn, r.ErrorClass)
	}
	return b.String()
}
