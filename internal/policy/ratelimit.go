package policy

import (
	"sync"
	"time"
)

// rateLimiter is a simple in-memory, per-process, fixed-window counter --
// explicitly not durable, not shared across replicas, and not the primary
// access-control mechanism (defense-in-depth only, MASTER_PLAN.md §6,
// 2026-08-04: "approximate enforcement is fine for v1... exact global
// enforcement rides the same optional shared-store upgrade path... if a
// customer needs it later"). clock is injectable so window-boundary
// behavior is testable without waiting out real time.
type rateLimiter struct {
	mu     sync.Mutex
	clock  func() time.Time
	counts map[string]*windowCount
}

type windowCount struct {
	windowStart time.Time
	count       int
}

func newRateLimiter(clock func() time.Time) *rateLimiter {
	return &rateLimiter{clock: clock, counts: make(map[string]*windowCount)}
}

// allow reports whether one more call under key is within maxCalls for a
// fixed window of length window, starting from whenever key's window last
// reset. Consumes one call from the budget on every call, allowed or not,
// so a client hammering past the limit doesn't get to keep "peeking" for
// free.
func (r *rateLimiter) allow(key string, maxCalls int, window time.Duration) bool {
	now := r.clock()

	r.mu.Lock()
	defer r.mu.Unlock()

	wc, ok := r.counts[key]
	if !ok || now.Sub(wc.windowStart) >= window {
		wc = &windowCount{windowStart: now}
		r.counts[key] = wc
	}
	wc.count++
	return wc.count <= maxCalls
}
