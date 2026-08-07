package proxy

import (
	"testing"
	"time"
)

// TestNodeHealth_Decide is the secondary, timing-free test seam agreed in
// the Phase 1 spec (GitHub issue #1): given a crash history, what's the
// next spawn decision. No real process spawning or real sleeping here --
// that would make backoff/quarantine timing-flaky.
func TestNodeHealth_Decide(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("no failures allows immediately", func(t *testing.T) {
		h := newNodeHealth()
		if got := h.decide(base); got != spawnAllow {
			t.Fatalf("decide = %v, want spawnAllow", got)
		}
	})

	t.Run("one failure backs off immediately after", func(t *testing.T) {
		h := newNodeHealth()
		h.recordFailure(base)
		if got := h.decide(base.Add(100 * time.Millisecond)); got != spawnBackoff {
			t.Fatalf("decide = %v, want spawnBackoff", got)
		}
	})

	t.Run("allows again once the backoff delay has elapsed", func(t *testing.T) {
		h := newNodeHealth()
		h.recordFailure(base)
		delay := backoffFor(1)
		if got := h.decide(base.Add(delay + time.Second)); got != spawnAllow {
			t.Fatalf("decide = %v, want spawnAllow once backoff elapsed", got)
		}
	})

	t.Run("quarantines after repeated failures within the window", func(t *testing.T) {
		h := newNodeHealth()
		for i := 0; i < crashQuarantineAfter; i++ {
			h.recordFailure(base.Add(time.Duration(i) * time.Millisecond))
		}
		if got := h.decide(base.Add(time.Hour)); got != spawnQuarantined {
			t.Fatalf("decide = %v, want spawnQuarantined after %d failures", got, crashQuarantineAfter)
		}
	})

	t.Run("failures outside the window don't count toward quarantine", func(t *testing.T) {
		h := newNodeHealth()
		for i := 0; i < crashQuarantineAfter-1; i++ {
			h.recordFailure(base)
		}
		// One more failure long after the window has passed for the
		// earlier ones -- should NOT push it over the threshold, since
		// those earlier failures have aged out.
		got := h.decide(base.Add(crashWindow * 2))
		if got == spawnQuarantined {
			t.Fatalf("decide = %v, want not quarantined once old failures are outside the window", got)
		}
	})

	t.Run("quarantine is sticky, not cleared by the window alone", func(t *testing.T) {
		h := newNodeHealth()
		for i := 0; i < crashQuarantineAfter; i++ {
			h.recordFailure(base)
		}
		// Long after the crash window -- quarantine must still hold; it
		// requires explicit reset, not just time passing.
		if got := h.decide(base.Add(crashWindow * 100)); got != spawnQuarantined {
			t.Fatalf("decide = %v, want spawnQuarantined to remain sticky", got)
		}
	})

	t.Run("backoff delay grows with repeated failures, capped", func(t *testing.T) {
		if d1, d2 := backoffFor(1), backoffFor(2); d2 <= d1 {
			t.Fatalf("expected backoff to grow: backoffFor(1)=%v, backoffFor(2)=%v", d1, d2)
		}
		if got := backoffFor(20); got > 30*time.Second {
			t.Fatalf("expected backoff to be capped, got %v", got)
		}
	})
}
