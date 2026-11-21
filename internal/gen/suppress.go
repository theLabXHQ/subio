package gen

import (
	"regexp"
	"strings"
)

// suppressOff disables suppression so a test can count what it removes.
var suppressOff bool

// joins says which ways a word may be attached to a label: as its own label,
// with a hyphen, or run together.
type joins struct{ dot, hyphen, concat bool }

var (
	joinAll  = joins{true, true, true}
	joinNone = joins{}
	joinDot  = joins{dot: true}
)

// attach reports how word may be placed before (or, with before false,
// after) label.
func attach(word, label string, before bool) joins {
	if word == label {

		return joinNone
	}
	if suppressOff {
		return joinAll
	}

	a, b := word, label
	if !before {
		a, b = label, word
	}
	if endsDigit(a) && startsDigit(b) {
		return joinNone
	}
	sw, sl := stripDigits(word), stripDigits(label)
	if sw == sl {

		return joinNone
	}
	if sw == "" {
		return joinAll
	}
	for _, sp := range partSpans(label) {
		if stripDigits(label[sp[0]:sp[1]]) == sw {
			return joinDot
		}
	}
	if strings.HasSuffix(sl, sw) {

		return joinDot
	}
	if strings.HasPrefix(sl, sw) {

		return joins{dot: true, hyphen: true}
	}
	return joinAll
}

// repeatsPart reports whether putting word in place of label's part at skip
// would leave two parts naming the same word, as dev in api-dev becomes dev-dev.
func repeatsPart(label string, spans [][2]int, skip int, word string) bool {
	if suppressOff {
		return false
	}
	sw := stripDigits(word)
	if sw == "" {
		return false
	}
	for i, sp := range spans {
		if i != skip && stripDigits(label[sp[0]:sp[1]]) == sw {
			return true
		}
	}
	return false
}

var allDigits = regexp.MustCompile(`[0-9]+`)

func stripDigits(s string) string { return allDigits.ReplaceAllString(s, "") }

func startsDigit(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }
func endsDigit(s string) bool   { return s != "" && s[len(s)-1] >= '0' && s[len(s)-1] <= '9' }

// ptrShaped matches four short numbers in a row, which is an address written
// into a name: ip-10-0-0-1, 10.0.0.1.static, dyn-203-0-113-7.
var ptrShaped = regexp.MustCompile(`(^|[^0-9])[0-9]{1,3}[-_.][0-9]{1,3}[-_.][0-9]{1,3}[-_.][0-9]{1,3}([^0-9]|$)`)

// maxDigitRun is the longest digit run an ordinary label carries.
const maxDigitRun = 4

// excessiveDigits reports a name that an address or a counter generated, not
// a person.
func excessiveDigits(rest string) bool {
	if ptrShaped.MatchString(rest) {
		return true
	}
	for _, l := range strings.Split(rest, ".") {
		runs := allDigits.FindAllString(l, -1)
		if len(runs) > 2 {
			return true
		}
		for _, r := range runs {
			if len(r) > maxDigitRun {
				return true
			}
		}
	}
	return false
}
