package gen

import (
	"sort"
	"strings"
)

// LearnAffixes learns which whole labels the target puts in front of names
// it already has, and proposes the same move for the names that lack it.
func LearnAffixes(names []string, root string) []string {
	known := map[string]bool{}
	var rests []string
	for _, n := range names {
		rest, ok := strings.CutSuffix(n, "."+root)
		if !ok || rest == "" {
			continue
		}
		if !known[rest] {
			known[rest] = true
			rests = append(rests, rest)
		}
	}
	sort.Strings(rests)

	support := map[string]int{}
	for _, r := range rests {
		label, under, ok := strings.Cut(r, ".")
		if ok && known[under] {
			support[label]++
		}
	}
	type prefix struct {
		label string
		n     int
	}
	var prefixes []prefix
	for l, n := range support {

		if n >= affixMinPairs && n*affixMinShare >= len(rests) {
			prefixes = append(prefixes, prefix{l, n})
		}
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].n != prefixes[j].n {
			return prefixes[i].n > prefixes[j].n
		}
		return prefixes[i].label < prefixes[j].label
	})
	if len(prefixes) > affixMaxPrefixes {
		prefixes = prefixes[:affixMaxPrefixes]
	}
	budget := affixGuessRatio * len(rests)
	var out []string
	seen := map[string]bool{}
	add := func(rest string) {
		if len(out) >= budget || rest == "" || known[rest] || seen[rest] || !nameIsValid(rest) || len(rest)+1+len(root) > maxName {
			return
		}
		seen[rest] = true
		out = append(out, rest+"."+root)
	}
	for _, p := range prefixes {
		if len(out) >= budget {
			break
		}
		for _, r := range rests {
			if !strings.HasPrefix(r, p.label+".") {
				add(p.label + "." + r)
			} else {
				add(strings.TrimPrefix(r, p.label+"."))
			}
		}
	}
	return out
}

const (
	// affixMinPairs is how many names must show a prefix before it is applied.
	affixMinPairs = 3

	// affixMinShare: a prefix must sit over at least one known name in this
	// many.
	affixMinShare = 300

	// affixMaxPrefixes and affixGuessRatio bound the output.
	affixMaxPrefixes = 16
	affixGuessRatio  = 4
)
