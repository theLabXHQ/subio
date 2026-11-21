package cli

import (
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// rejectBareArgs reports arguments left after parsing.
func rejectBareArgs(fs *flag.FlagSet, stderr io.Writer) bool {
	if fs.NArg() == 0 {
		return false
	}
	fmt.Fprintf(stderr, "subio: unexpected argument %q: this command takes only flags\n", fs.Arg(0))
	return true
}

// listFlag is a repeatable string flag; commaSplit also splits on commas, so
// both "-d a -d b" and "-d a,b" work.
type listFlag struct {
	vals       *[]string
	commaSplit bool
}

func (l listFlag) String() string {
	if l.vals == nil {
		return ""
	}
	return strings.Join(*l.vals, ",")
}

func (l listFlag) Set(s string) error {
	if !l.commaSplit {
		*l.vals = append(*l.vals, s)
		return nil
	}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l.vals = append(*l.vals, p)
		}
	}
	return nil
}

// secondsFlag accepts integer seconds ("10") or a Go duration ("1500ms"), so
// an operator does not have to remember which one a given flag wanted.
type secondsFlag struct{ d *time.Duration }

func (s secondsFlag) String() string {
	if s.d == nil {
		return ""
	}
	return s.d.String()
}

func (s secondsFlag) Set(v string) error {
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		*s.d = time.Duration(n * float64(time.Second))
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("expected seconds or a duration, got %q", v)
	}
	*s.d = d
	return nil
}

// flagDoc is one row of the grouped help.
type flagDoc struct {
	names string
	typ   string
	usage string
	def   string
}

type group struct {
	title string
	flags []flagDoc
}

// registry registers flags under every alias while recording one help row
// per flag, so "-s" and "-source" are the same flag but appear once in the help.
type registry struct {
	fs     *flag.FlagSet
	groups []*group
}

func newRegistry(fs *flag.FlagSet) *registry { return &registry{fs: fs} }

func (r *registry) group(title string) *group {
	g := &group{title: title}
	r.groups = append(r.groups, g)
	return g
}

func (g *group) add(names, typ, usage, def string) {
	g.flags = append(g.flags, flagDoc{names, typ, usage, def})
}

func (r *registry) boolVar(g *group, p *bool, usage string, names ...string) {
	for _, n := range names {
		r.fs.BoolVar(p, n, *p, usage)
	}
	g.add(dashed(names), "", usage, "")
}

func (r *registry) stringVar(g *group, p *string, usage string, names ...string) {
	for _, n := range names {
		r.fs.StringVar(p, n, *p, usage)
	}
	g.add(dashed(names), "string", usage, *p)
}

func (r *registry) intVar(g *group, p *int, usage string, names ...string) {
	for _, n := range names {
		r.fs.IntVar(p, n, *p, usage)
	}
	g.add(dashed(names), "int", usage, strconv.Itoa(*p))
}

func (r *registry) durationVar(g *group, p *time.Duration, usage string, names ...string) {
	def := ""
	if *p > 0 {
		def = p.String()
	}
	r.varFlag(g, secondsFlag{p}, "duration", usage, def, names...)
}

func (r *registry) listVar(g *group, p *[]string, commaSplit bool, typ, usage string, names ...string) {
	r.varFlag(g, listFlag{p, commaSplit}, typ, usage, "", names...)
}

func (r *registry) varFlag(g *group, v flag.Value, typ, usage, def string, names ...string) {
	for _, n := range names {
		r.fs.Var(v, n, usage)
	}
	g.add(dashed(names), typ, usage, def)
}

func dashed(names []string) string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = "-" + n
	}
	return strings.Join(out, ", ")
}
