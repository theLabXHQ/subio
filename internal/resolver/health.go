package resolver

import (
	"sync"
	"time"
)

const (
	// healthWeight is how much one query moves the average: about the last 32
	// queries carry most of it.
	healthWeight = 1.0 / 32

	// benchAtTimeoutShare is the recent timeout share that benches a resolver.
	benchAtTimeoutShare = 0.9
	// benchFor is how long a benched resolver is left out before it is asked
	// again, with its record cleared.
	benchFor = 30 * time.Second
)

type health struct {
	mu    sync.Mutex
	share float64
}

// note adds one query's outcome and returns the recent timeout share.
func (h *health) note(timeout bool) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	x := 0.0
	if timeout {
		x = 1
	}
	h.share += healthWeight * (x - h.share)
	return h.share
}

func (h *health) reset() {
	h.mu.Lock()
	h.share = 0
	h.mu.Unlock()
}

// asked reports whether a resolver is being sent queries now: not refused by
// Vet, and not benched.
func (s *serverState) asked(now time.Time) bool {
	return !s.disabled.Load() && now.UnixNano() >= s.benchedUntil.Load()
}
