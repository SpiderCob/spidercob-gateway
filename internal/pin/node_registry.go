package pin

import "time"

// AddNode enrolls a new node into the background tool-pinning rotation
// on an already-running Scheduler (issue #57): the pinning half of
// hot-reload. interval <= 0 means "use DefaultInterval," matching
// intervalFor's existing fallback for a node absent from Intervals.
// Deliberately leaves lastRun unset for this node -- dueForRefresh's
// existing zero-value handling (a node never seen is always due) means
// the very next RunOnce tick (bounded by checkInterval, not a forced
// synchronous fetch on the caller's own goroutine) picks it up for its
// first TOFU observation. Idempotent: adding an already-enrolled node
// just resets its interval, same as re-registering with a store-backed
// registry generally being a fine no-op-shaped operation.
func (s *Scheduler) AddNode(node string, interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.nodes {
		if n == node {
			if interval > 0 {
				s.intervals[node] = interval
			} else {
				delete(s.intervals, node)
			}
			return
		}
	}
	s.nodes = append(s.nodes, node)
	if interval > 0 {
		s.intervals[node] = interval
	}
}

// RemoveNode drops a node from the background tool-pinning rotation
// (issue #57) -- its next scheduled RunOnce tick simply won't include it
// anymore. Also clears its lastRun and per-node interval bookkeeping, so
// a later re-add of the same name starts clean rather than inheriting
// stale refresh history. Idempotent: removing a node that was never
// enrolled (or already removed) is a no-op, not an error.
func (s *Scheduler) RemoveNode(node string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, n := range s.nodes {
		if n == node {
			s.nodes = append(s.nodes[:i], s.nodes[i+1:]...)
			break
		}
	}
	delete(s.intervals, node)
	delete(s.lastRun, node)
}
