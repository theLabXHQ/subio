package gen

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// maxLanguageRatio is how many names a rule may generate per name it was
// learned from.
const maxLanguageRatio = 25

// maxSplitDepth bounds how many times a too-broad group is divided and retried.
const maxSplitDepth = 4

// Rule describes a family of names learned from a group of similar known
// names.
type Rule struct {
	slots []slot
	// Observed is how many known names this rule was learned from.
	Observed int
	// Size is how many names the rule describes, observed ones included.
	Size int
}

type slot struct {
	fixed  string
	values []string
	lo, hi int
	width  int
	number bool
}

func (s slot) size() int {
	switch {
	case s.number:
		return s.hi - s.lo + 1
	case s.values != nil:
		return len(s.values)
	}
	return 1
}

// token is one piece of a name: a run of letters, a run of digits, or a separator.
type token struct {
	text string
	kind byte
}

func tokenize(rest string) []token {
	var out []token
	start := 0
	kindOf := func(c byte) byte {
		switch {
		case c >= '0' && c <= '9':
			return 'n'
		case c == '.' || c == '-' || c == '_':
			return 's'
		}
		return 'w'
	}
	for i := 1; i <= len(rest); i++ {

		if i == len(rest) || kindOf(rest[i]) != kindOf(rest[start]) || kindOf(rest[start]) == 's' {
			out = append(out, token{rest[start:i], kindOf(rest[start])})
			start = i
		}
	}
	return out
}

// shape is what two names must share to be compared position by position:
// the same run of word, number and separator tokens.
func shape(toks []token) string {
	var b strings.Builder
	for _, t := range toks {
		if t.kind == 's' {
			b.WriteString(t.text)
		} else {
			b.WriteByte(t.kind)
		}
	}
	return b.String()
}

// Learn derives rules from the names known under root.
func Learn(names []string, root string) []Rule {
	groups := map[string][][]token{}
	for _, n := range names {
		rest, ok := strings.CutSuffix(n, "."+root)
		if !ok {
			continue
		}
		toks := tokenize(rest)
		groups[shape(toks)] = append(groups[shape(toks)], toks)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var rules []Rule
	for _, k := range keys {
		rules = append(rules, learnGroup(groups[k], 0)...)
	}
	sort.SliceStable(rules, func(i, j int) bool {

		return rules[i].Size*rules[j].Observed < rules[j].Size*rules[i].Observed
	})
	return rules
}

func learnGroup(group [][]token, depth int) []Rule {
	if len(group) < 2 {
		return nil
	}
	rule, ok := buildRule(group)
	if ok && rule.Size > rule.Observed && rule.Size <= rule.Observed*maxLanguageRatio {
		return []Rule{rule}
	}
	if ok && rule.Size <= rule.Observed {
		return nil
	}
	if depth >= maxSplitDepth {
		return nil
	}
	pos := splitPosition(group)
	if pos < 0 {
		return nil
	}
	parts := map[string][][]token{}
	for _, toks := range group {
		parts[toks[pos].text] = append(parts[toks[pos].text], toks)
	}
	keys := make([]string, 0, len(parts))
	for k := range parts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Rule
	for _, k := range keys {
		out = append(out, learnGroup(parts[k], depth+1)...)
	}
	return out
}

// splitPosition picks the word position with the fewest distinct values
// above one, which divides a group into the most coherent parts.
func splitPosition(group [][]token) int {
	best, bestCount := -1, 0
	for pos, t := range group[0] {
		if t.kind != 'w' {
			continue
		}
		seen := map[string]bool{}
		for _, toks := range group {
			seen[toks[pos].text] = true
		}
		if n := len(seen); n > 1 && (best < 0 || n < bestCount) {
			best, bestCount = pos, n
		}
	}
	return best
}

func buildRule(group [][]token) (Rule, bool) {
	r := Rule{Observed: len(group), Size: 1}
	for pos, first := range group[0] {
		switch first.kind {
		case 's':
			r.slots = append(r.slots, slot{fixed: first.text})
		case 'w':
			seen := map[string]bool{}
			for _, toks := range group {
				seen[toks[pos].text] = true
			}
			if len(seen) == 1 {
				r.slots = append(r.slots, slot{fixed: first.text})
				continue
			}
			values := make([]string, 0, len(seen))
			for v := range seen {
				values = append(values, v)
			}
			sort.Strings(values)
			r.slots = append(r.slots, slot{values: values})
		case 'n':
			s, ok := numberSlot(group, pos)
			if !ok {
				return Rule{}, false
			}
			r.slots = append(r.slots, s)
		}
		last := r.slots[len(r.slots)-1]
		r.Size *= last.size()

		if r.Size > r.Observed*maxLanguageRatio {
			return r, true
		}
	}
	return r, true
}

// numberSlot merges the numbers seen at a position into the range they span.
func numberSlot(group [][]token, pos int) (slot, bool) {
	s := slot{number: true, lo: -1}
	for _, toks := range group {
		text := toks[pos].text
		if len(text) > 9 {
			return slot{}, false
		}
		n, err := strconv.Atoi(text)
		if err != nil {
			return slot{}, false
		}
		if s.lo < 0 || n < s.lo {
			s.lo = n
		}
		if n > s.hi {
			s.hi = n
		}
		if text[0] == '0' && len(text) > 1 && len(text) > s.width {
			s.width = len(text)
		}
	}
	return s, true
}

// Each yields every name the rule describes, observed ones included, and
// stops when yield does.
func (r Rule) Each(root string, yield func(string) bool) bool {
	idx := make([]int, len(r.slots))
	var b strings.Builder
	for {
		b.Reset()
		for i, s := range r.slots {
			switch {
			case s.number:
				if s.width > 0 {
					fmt.Fprintf(&b, "%0*d", s.width, s.lo+idx[i])
				} else {
					b.WriteString(strconv.Itoa(s.lo + idx[i]))
				}
			case s.values != nil:
				b.WriteString(s.values[idx[i]])
			default:
				b.WriteString(s.fixed)
			}
		}
		rest := b.String()
		if nameIsValid(rest) && len(rest)+1+len(root) <= maxName && !yield(rest+"."+root) {
			return false
		}

		i := len(idx) - 1
		for ; i >= 0; i-- {
			idx[i]++
			if idx[i] < r.slots[i].size() {
				break
			}
			idx[i] = 0
		}
		if i < 0 {
			return true
		}
	}
}

func nameIsValid(rest string) bool {
	for _, l := range strings.Split(rest, ".") {
		if !validLabel(l) {
			return false
		}
	}
	return true
}

// Labels returns the distinct whole labels of known names under root, most
// frequent first.
func Labels(names []string, root string) []string {
	counts := map[string]int{}
	for _, n := range names {
		rest, ok := strings.CutSuffix(n, "."+root)
		if !ok {
			continue
		}
		for _, l := range strings.Split(rest, ".") {
			if validLabel(l) {
				counts[l]++
			}
		}
	}
	out := make([]string, 0, len(counts))
	for l := range counts {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if counts[out[i]] != counts[out[j]] {
			return counts[out[i]] > counts[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}
