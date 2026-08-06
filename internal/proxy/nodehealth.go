package proxy

import (
	"sync"
	"time"
)

// crashWindow is how far back recent failures are considered when
// deciding whether to quarantine a node.
const crashWindow = 60 * time.Second

// crashQuarantineAfter is how many failures within crashWindow before a
// node stops accepting new sessions entirely, rather than continuing to
// spawn processes that are likely to fail again.
const crashQuarantineAfter = 5

// maxBackoffDelay caps the exponential backoff between spawn attempts.
const maxBackoffDelay = 30 * time.Second

type spawnDecision int

const (
	spawnAllow spawnDecision = iota
	spawnBackoff
	spawnQuarantined
)

// nodeHealth tracks recent spawn failures for one stdio node and decides
// whether the next new session's spawn attempt should proceed, wait out a
// backoff, or be refused outright because the node is quarantined. A pure
// decision function over crash history (given `now` explicitly) -- this is
// the timing-free test seam; real wall-clock backoff/quarantine timing is
// exercised only through this, never through real sleeps.
//
// Quarantine is sticky: it isn't cleared just because the crash window
// elapses, since Phase 1 has no admin surface to explicitly re-approve a
// node (that arrives with tool pinning/quarantine in Phase 3, design doc
// §5) -- a gateway restart is the only way to clear it for now.
type nodeHealth struct {
	mu          sync.Mutex
	failures    []time.Time
	quarantined bool
}

func newNodeHealth() *nodeHealth { return &nodeHealth{} }

func (h *nodeHealth) decide(now time.Time) spawnDecision {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)

	if h.quarantined {
		return spawnQuarantined
	}
	if len(h.failures) == 0 {
		return spawnAllow
	}
	last := h.failures[len(h.failures)-1]
	if now.Sub(last) < backoffFor(len(h.failures)) {
		return spawnBackoff
	}
	return spawnAllow
}

// recordFailure records a spawn or crash failure at now, quarantining the
// node if this pushes it over the threshold within the window.
func (h *nodeHealth) recordFailure(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pruneLocked(now)
	h.failures = append(h.failures, now)
	if len(h.failures) >= crashQuarantineAfter {
		h.quarantined = true
	}
}

func (h *nodeHealth) pruneLocked(now time.Time) {
	if h.quarantined {
		return // quarantine is sticky -- don't age failures out once tripped
	}
	cutoff := now.Add(-crashWindow)
	i := 0
	for i < len(h.failures) && h.failures[i].Before(cutoff) {
		i++
	}
	h.failures = h.failures[i:]
}

// backoffFor returns the exponential backoff delay after failureCount
// recent failures, capped at maxBackoffDelay.
func backoffFor(failureCount int) time.Duration {
	if failureCount <= 0 {
		return 0
	}
	shift := failureCount
	if shift > 10 { // avoid overflow; well past the cap by this point anyway
		shift = 10
	}
	d := time.Duration(1<<uint(shift)) * time.Second
	if d > maxBackoffDelay {
		return maxBackoffDelay
	}
	return d
}
