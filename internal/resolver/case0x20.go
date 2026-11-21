package resolver

import (
	"crypto/rand"
	"strings"
)

// mixCase returns name with the case of its letters chosen at random.
func mixCase(name string) string {
	n := len(name)
	if n == 0 {
		return name
	}
	bits := make([]byte, (n+7)/8)
	if _, err := rand.Read(bits); err != nil {
		return name
	}
	out := []byte(name)
	for i := 0; i < n; i++ {
		c := out[i]
		set := bits[i/8]&(1<<(i%8)) != 0
		switch {
		case c >= 'a' && c <= 'z':
			if set {
				out[i] = c - 'a' + 'A'
			}
		case c >= 'A' && c <= 'Z':
			if !set {
				out[i] = c - 'A' + 'a'
			}
		}
	}
	return string(out)
}

// sameNameExactly reports whether a response echoed the question byte for
// byte in the part that carries the 0x20 entropy.
func sameNameExactly(got, want string) bool {
	return strings.TrimSuffix(got, ".") == strings.TrimSuffix(want, ".")
}

// inferredDenialCodes are the Extended DNS Error codes that mean a negative
// answer did not come from the zone on this occasion.
var inferredDenialCodes = map[uint16]struct{}{3: {}, 19: {}, 29: {}}

// DenialWasInferred reports that this negative answer came from the
// resolver's own cache or synthesis rather than from the zone on this
// occasion.
func (a Answer) DenialWasInferred() bool {
	if !a.EDE.Present {
		return false
	}
	if a.Outcome != NXDomain && a.Outcome != NoData {
		return false
	}
	_, ok := inferredDenialCodes[a.EDE.Code]
	return ok
}
