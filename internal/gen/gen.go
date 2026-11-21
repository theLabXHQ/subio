// Package gen produces candidate hostnames for active discovery.
package gen

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxLabel = 63
	maxName  = 253
)

// validLabel reports a label a resolver can be asked about.
func validLabel(l string) bool {
	if l == "" || len(l) > maxLabel || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// Wordlist is a loaded list of labels.
type Wordlist struct {
	Name    string   `json:"name"`
	SHA256  string   `json:"sha256"`
	Labels  []string `json:"-"`
	Count   int      `json:"labels"`
	Skipped int      `json:"skipped_lines"`
}

// LoadWordlist reads one entry per line, lowercased and deduplicated.
func LoadWordlist(path string) (*Wordlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	w, err := parseWords(io.TeeReader(f, h))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	w.Name = path
	w.SHA256 = hex.EncodeToString(h.Sum(nil))
	return w, nil
}

func parseWords(r io.Reader) (*Wordlist, error) {
	w := &Wordlist{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || line[0] == '#' {
			continue
		}
		line = strings.TrimSuffix(line, ".")
		ok := true
		for _, l := range strings.Split(line, ".") {
			ok = ok && validLabel(l)
		}
		if !ok {
			w.Skipped++
			continue
		}
		if !seen[line] {
			seen[line] = true
			w.Labels = append(w.Labels, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	w.Count = len(w.Labels)
	return w, nil
}

// Merge combines lists, keeping each entry once.
func Merge(lists ...*Wordlist) []string {
	seen := map[string]bool{}
	var out []string
	for _, w := range lists {
		for _, l := range w.Labels {
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// Brute yields one candidate per label under root and stops when yield does.
func Brute(root string, labels []string, yield func(string) bool) bool {
	for _, l := range labels {
		name := l + "." + root
		if len(name) > maxName {
			continue
		}
		if !yield(name) {
			return false
		}
	}
	return true
}

// Strategy is one way of varying a known name.
type Strategy int

// Ordered by how much each tends to find per query.
const (
	// Numbers steps a number in a label: web01 to web02.
	Numbers Strategy = iota
	// Replace swaps one hyphen-separated part: api-dev to api-staging.
	Replace
	// Sibling replaces the first label beneath a known subzone: a.eu.x to staging.eu.x.
	Sibling
	// Join adds a word to the first label: api to api-dev, dev-api, apidev, devapi.
	Join
	// Insert adds a new label: api.x to dev.api.x and api.dev.x.
	Insert

	// FirstNumber appends a number to a label that has none: storage to storage2
	// and storage02.
	FirstNumber
	strategies
)

// Strategies lists every strategy in priority order: the order a run with a
// candidate budget spends it in.
func Strategies() []Strategy {
	return []Strategy{Numbers, Sibling, Insert, Replace, FirstNumber, Join}
}

// numberSteps is how far a number is stepped each way.
const numberSteps = 3

var digitRun = regexp.MustCompile(`[0-9]+`)

// Vary yields the variations of name under root for one strategy.
func Vary(s Strategy, name, root string, words []string, yield func(string) bool) bool {
	rest, ok := strings.CutSuffix(name, "."+root)
	if !ok {
		return true
	}
	if !suppressOff && excessiveDigits(rest) {
		return true
	}
	labels := strings.Split(rest, ".")
	emit := func(ls []string) bool {
		for _, l := range ls {
			if !validLabel(l) {
				return true
			}
		}
		out := strings.Join(ls, ".") + "." + root
		if len(out) > maxName {
			return true
		}
		return yield(out)
	}
	with := func(i int, repl string) []string {
		cp := append([]string(nil), labels...)
		cp[i] = repl
		return cp
	}

	switch s {
	case Numbers:
		for i, l := range labels {
			loc := digitRun.FindAllStringIndex(l, -1)
			if len(loc) == 0 {
				continue
			}

			at := loc[len(loc)-1]
			digits := l[at[0]:at[1]]
			n, err := strconv.Atoi(digits)
			if err != nil {
				continue
			}
			for d := -numberSteps; d <= numberSteps; d++ {
				if d == 0 || n+d < 0 {
					continue
				}
				next := fmt.Sprintf("%0*d", len(digits), n+d)
				if !emit(with(i, l[:at[0]]+next+l[at[1]:])) {
					return false
				}
			}
		}
	case FirstNumber:

		for i, l := range labels {
			if digitRun.MatchString(l) {
				continue
			}
			for n := 2; n <= numberSteps+1; n++ {
				if !emit(with(i, fmt.Sprintf("%s%d", l, n))) {
					return false
				}
				if !emit(with(i, fmt.Sprintf("%s%02d", l, n))) {
					return false
				}
			}
		}
	case Replace:
		for i, l := range labels {
			spans := partSpans(l)
			if len(spans) < 2 {
				continue
			}
			for si, sp := range spans {
				for _, w := range words {
					if w == l[sp[0]:sp[1]] || repeatsPart(l, spans, si, w) {
						continue
					}
					if !emit(with(i, l[:sp[0]]+w+l[sp[1]:])) {
						return false
					}
				}
			}
		}
	case Sibling:
		if len(labels) < 2 {
			return true
		}
		for _, w := range words {
			if w == labels[0] || !attach(w, labels[1], true).dot {
				continue
			}
			if !emit(with(0, w)) {
				return false
			}
		}
	case Join:
		first := labels[0]
		for _, w := range words {
			after, before := attach(w, first, false), attach(w, first, true)
			for _, j := range []struct {
				ok     bool
				joined string
			}{
				{after.hyphen, first + "-" + w}, {before.hyphen, w + "-" + first},
				{after.concat, first + w}, {before.concat, w + first},
			} {
				if j.ok && !emit(with(0, j.joined)) {
					return false
				}
			}
		}
	case Insert:
		for _, w := range words {
			if attach(w, labels[0], true).dot {
				if !emit(append([]string{w}, labels...)) {
					return false
				}
			}

			between := attach(w, labels[0], false).dot
			if between && len(labels) > 1 {
				between = attach(w, labels[1], true).dot
			}
			if between && !emit(append([]string{labels[0], w}, labels[1:]...)) {
				return false
			}
		}
	}
	return true
}

// partSpans returns where the hyphen- and underscore-separated parts of a label are.
func partSpans(l string) [][2]int {
	var out [][2]int
	start := -1
	for i := 0; i <= len(l); i++ {
		if i == len(l) || l[i] == '-' || l[i] == '_' {
			if start >= 0 {
				out = append(out, [2]int{start, i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	return out
}

// MineWords returns the most frequent parts of known names, split on dots,
// hyphens and underscores.
func MineWords(names []string, root string, limit int) []string {
	counts := map[string]int{}
	for _, n := range names {
		rest, ok := strings.CutSuffix(n, "."+root)
		if !ok {
			continue
		}
		for _, part := range strings.FieldsFunc(rest, func(r rune) bool { return r == '.' || r == '-' || r == '_' }) {
			if len(part) < 2 || len(part) > 24 || isNumeric(part) {
				continue
			}
			counts[part]++
		}
	}
	words := make([]string, 0, len(counts))
	for w := range counts {
		words = append(words, w)
	}
	sort.Slice(words, func(i, j int) bool {
		if counts[words[i]] != counts[words[j]] {
			return counts[words[i]] > counts[words[j]]
		}
		return words[i] < words[j]
	})
	if len(words) > limit {
		words = words[:limit]
	}
	return words
}

func isNumeric(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}
