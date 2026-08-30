package pin

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Fetcher retrieves node's current tool definitions, however the
// caller's transport does that (stdio, streamable HTTP, ...). Injected
// so this package stays decoupled from MCP transport details --
// internal/proxy, which already owns node connections, supplies the
// real implementation; tests supply a fake.
type Fetcher func(ctx context.Context, node string) ([]ToolDef, error)

// dueForRefresh is the scheduler's pure decision function -- mirrors
// nodeHealth's pure-decision-function pattern from Phase 1 (and
// rateLimiter's injectable-clock pattern), kept out of any goroutine so
// refresh-timing logic is directly unit-testable without real waits. An
// interval <= 0 means "always due" -- the sentinel for "no per-node or
// default interval configured."
func dueForRefresh(lastRun time.Time, interval time.Duration, now time.Time) bool {
	if interval <= 0 {
		return true
	}
	return lastRun.IsZero() || now.Sub(lastRun) >= interval
}

// SchedulerConfig is Scheduler's construction input.
type SchedulerConfig struct {
	Registry *Registry
	Fetch    Fetcher
	Nodes    []string
	// Intervals gives a per-node refresh interval (story: admin-
	// configurable refresh interval per node); a node absent from this
	// map uses DefaultInterval.
	Intervals map[string]time.Duration
	// DefaultInterval is used for any node not present in Intervals.
	DefaultInterval time.Duration
	// CheckInterval is how often the background loop wakes up to see
	// whether any node is due -- independent of, and normally much
	// shorter than, any individual node's refresh interval.
	CheckInterval time.Duration
	// FetchTimeout bounds each individual node's Fetch call within
	// RunOnce (issue found by Copilot's review on PR #10): without it,
	// RunOnce called Fetch with context.Background(), so a hung Fetcher
	// implementation would block the loop goroutine forever -- Stop()
	// would then deadlock waiting on done, and one slow/hung node would
	// delay every subsequent node's refresh in that same tick. Falls
	// back to DefaultFetchTimeout when zero.
	FetchTimeout time.Duration
	// Clock is injectable for tests; real callers leave it nil (defaults
	// to time.Now).
	Clock func() time.Time
}

// DefaultFetchTimeout bounds a single node's tools/list-equivalent
// fetch during a pin refresh -- long enough for a real upstream to
// respond, short enough that one hung node can't meaningfully delay
// the rest of a refresh tick or block Scheduler.Stop().
const DefaultFetchTimeout = 30 * time.Second

// Scheduler periodically calls Fetcher for every configured node and
// feeds the result to a Registry, on a per-node interval -- mirrors
// proxy.Gateway's idle-session reaper (ticker + stop/done channels), the
// established pattern for this repo's background loops. A TOFU pin is
// only a rug-pull defense if it's actually re-checked after being
// established; without this running continuously, "pinned once, trusted
// forever" would defeat the point of issue #9.
type Scheduler struct {
	registry        *Registry
	fetch           Fetcher
	clock           func() time.Time
	defaultInterval time.Duration
	checkInterval   time.Duration
	fetchTimeout    time.Duration

	// mu guards nodes, intervals, and lastRun. Before issue #57, nodes
	// and intervals were unguarded -- safe only because they were
	// written once, in NewScheduler, before Start could possibly run.
	// AddNode/RemoveNode (node_registry.go) can now mutate them
	// concurrently with RunOnce's reads on the background loop's own
	// goroutine.
	mu        sync.Mutex
	nodes     []string
	intervals map[string]time.Duration
	lastRun   map[string]time.Time

	stop chan struct{}
	done chan struct{}
}

// NewScheduler builds a Scheduler from cfg. Panics on a nil Registry or
// Fetch -- both are required for the scheduler to do anything, so a
// caller-side construction bug should fail immediately and loudly rather
// than silently run a no-op background loop.
func NewScheduler(cfg SchedulerConfig) *Scheduler {
	if cfg.Registry == nil {
		panic("pin: NewScheduler requires a non-nil Registry")
	}
	if cfg.Fetch == nil {
		panic("pin: NewScheduler requires a non-nil Fetch")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	checkInterval := cfg.CheckInterval
	if checkInterval <= 0 {
		checkInterval = time.Minute
	}
	fetchTimeout := cfg.FetchTimeout
	if fetchTimeout <= 0 {
		fetchTimeout = DefaultFetchTimeout
	}
	intervals := cfg.Intervals
	if intervals == nil {
		// AddNode (issue #57) writes into this map after construction --
		// it must never be nil, even when the caller left Intervals
		// unset (the common case: no per-node overrides at startup).
		intervals = make(map[string]time.Duration)
	}
	return &Scheduler{
		registry:        cfg.Registry,
		fetch:           cfg.Fetch,
		clock:           clock,
		nodes:           cfg.Nodes,
		intervals:       intervals,
		defaultInterval: cfg.DefaultInterval,
		checkInterval:   checkInterval,
		fetchTimeout:    fetchTimeout,
		lastRun:         make(map[string]time.Time),
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}
}

// intervalFor is called with s.mu already held by its only caller,
// RunOnce -- unlike lastRun's own lock/unlock-per-access pattern, folding
// this into RunOnce's single snapshot avoids a lock per node per tick.
func (s *Scheduler) intervalFor(node string) time.Duration {
	if iv, ok := s.intervals[node]; ok {
		return iv
	}
	return s.defaultInterval
}

// RunOnce checks every configured node and, for each one due for
// refresh, fetches its current tools and reconciles them via
// Registry.Observe. A fetch or Observe error for one node is logged and
// does not stop the others -- one unreachable or misbehaving node must
// never block drift detection on every other node. Exported (rather than
// only reachable via the background loop) so tests can drive it directly
// with a fake clock and Fetcher -- no goroutines or real waits involved.
func (s *Scheduler) RunOnce(ctx context.Context) {
	now := s.clock()

	// Decide which nodes are due under one lock, then release it before
	// any actual fetch -- a fetch can take up to fetchTimeout, and
	// AddNode/RemoveNode (issue #57) must never block on that.
	s.mu.Lock()
	var toRefresh []string
	for _, node := range s.nodes {
		if dueForRefresh(s.lastRun[node], s.intervalFor(node), now) {
			toRefresh = append(toRefresh, node)
		}
	}
	s.mu.Unlock()

	for _, node := range toRefresh {
		fetchCtx, cancel := context.WithTimeout(ctx, s.fetchTimeout)
		tools, err := s.fetch(fetchCtx, node)
		cancel()
		if err != nil {
			slog.Warn("pin: refresh fetch failed", "node", node, "error", err)
		} else if err := s.registry.Observe(ctx, node, tools); err != nil {
			slog.Warn("pin: refresh observe failed", "node", node, "error", err)
		}

		// Record the attempt regardless of outcome: a persistently
		// unreachable node should wait for its next interval, not be
		// retried on every single check tick.
		s.mu.Lock()
		s.lastRun[node] = now
		s.mu.Unlock()
	}
}

// Start begins the background refresh loop. Mirrors proxy.Gateway's
// reapLoop: a ticker at checkInterval granularity wakes RunOnce, which
// itself decides per-node whether enough time has actually passed.
func (s *Scheduler) Start() {
	go s.loop()
}

func (s *Scheduler) loop() {
	defer close(s.done)
	t := time.NewTicker(s.checkInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.RunOnce(context.Background())
		}
	}
}

// Stop halts the background loop and waits for it to exit.
func (s *Scheduler) Stop() {
	close(s.stop)
	<-s.done
}
