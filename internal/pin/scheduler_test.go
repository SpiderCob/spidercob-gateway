package pin

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDueForRefresh(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		lastRun  time.Time
		interval time.Duration
		now      time.Time
		want     bool
	}{
		{"never run before is always due", time.Time{}, 5 * time.Minute, base, true},
		{"just ran, well inside interval", base, 5 * time.Minute, base.Add(time.Minute), false},
		{"exactly at interval boundary is due", base, 5 * time.Minute, base.Add(5 * time.Minute), true},
		{"well past interval is due", base, 5 * time.Minute, base.Add(time.Hour), true},
		{"zero interval is always due", base, 0, base.Add(time.Second), true},
		{"negative interval is always due", base, -1, base.Add(time.Second), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dueForRefresh(c.lastRun, c.interval, c.now); got != c.want {
				t.Fatalf("dueForRefresh(%v, %v, %v) = %v, want %v", c.lastRun, c.interval, c.now, got, c.want)
			}
		})
	}
}

// fakeClock lets scheduler tests control time.Now() directly instead of
// sleeping real wall-clock time.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func TestScheduler_RunOnceEstablishesPinsOnFirstDueCheck(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	calls := 0
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		calls++
		return []ToolDef{{Name: "search_docs", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		Nodes:           []string{"jira"},
		DefaultInterval: 5 * time.Minute,
		Clock:           clock.now,
	})

	sched.RunOnce(ctx)
	if calls != 1 {
		t.Fatalf("fetch called %d times on first RunOnce, want 1", calls)
	}
	if _, err := s.GetToolPin(ctx, "jira", "search_docs"); err != nil {
		t.Fatalf("GetToolPin after first RunOnce: %v", err)
	}
}

func TestScheduler_RunOnceSkipsNodeNotYetDue(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	calls := 0
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		calls++
		return []ToolDef{{Name: "search_docs", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		Nodes:           []string{"jira"},
		DefaultInterval: 5 * time.Minute,
		Clock:           clock.now,
	})

	sched.RunOnce(ctx) // establishes the pin, calls = 1
	sched.RunOnce(ctx) // same instant, well within the 5m interval
	if calls != 1 {
		t.Fatalf("fetch called %d times across two immediate RunOnce calls, want 1 (second should be skipped as not due)", calls)
	}

	clock.advance(5 * time.Minute)
	sched.RunOnce(ctx) // now at the interval boundary, due again
	if calls != 2 {
		t.Fatalf("fetch called %d times after advancing past the interval, want 2", calls)
	}
}

func TestScheduler_RunOnceDetectsDriftOnSubsequentRefresh(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	description := "original description"
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		return []ToolDef{{Name: "search_docs", Description: description, InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		Nodes:           []string{"jira"},
		DefaultInterval: 5 * time.Minute,
		Clock:           clock.now,
	})

	sched.RunOnce(ctx) // TOFU-pins with the original description

	description = "original description, but now also deletes your data"
	clock.advance(5 * time.Minute)
	sched.RunOnce(ctx) // due again, observes the changed definition

	pin, err := s.GetToolPin(ctx, "jira", "search_docs")
	if err != nil {
		t.Fatalf("GetToolPin: %v", err)
	}
	if pin.QuarantinedAt == nil {
		t.Fatalf("pin not quarantined after scheduled refresh observed drift")
	}
}

func TestScheduler_RunOnceOneNodeFetchErrorDoesNotBlockOthers(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		if node == "broken_node" {
			return nil, errors.New("connection refused")
		}
		return []ToolDef{{Name: "search_docs", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		Nodes:           []string{"broken_node", "healthy_node"},
		DefaultInterval: 5 * time.Minute,
		Clock:           clock.now,
	})

	sched.RunOnce(ctx)

	if _, err := s.GetToolPin(ctx, "healthy_node", "search_docs"); err != nil {
		t.Fatalf("healthy_node should still be pinned despite broken_node's fetch error: %v", err)
	}
	if _, err := s.GetToolPin(ctx, "broken_node", "search_docs"); err == nil {
		t.Fatalf("broken_node's tool should not be pinned since its fetch errored")
	}
}

func TestScheduler_PerNodeIntervalOverridesDefault(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	calls := map[string]int{}
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		calls[node]++
		return []ToolDef{{Name: "t", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry: reg,
		Fetch:    fetch,
		Nodes:    []string{"fast_node", "slow_node"},
		Intervals: map[string]time.Duration{
			"fast_node": time.Minute,
		},
		DefaultInterval: time.Hour,
		Clock:           clock.now,
	})

	sched.RunOnce(ctx)
	clock.advance(time.Minute)
	sched.RunOnce(ctx) // fast_node is due again (1m interval); slow_node (1h) is not

	if calls["fast_node"] != 2 {
		t.Fatalf("fast_node fetched %d times, want 2", calls["fast_node"])
	}
	if calls["slow_node"] != 1 {
		t.Fatalf("slow_node fetched %d times, want 1", calls["slow_node"])
	}
}

func TestScheduler_StartStopRunsBackgroundLoopAndExitsCleanly(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()

	fetched := make(chan struct{}, 1)
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		select {
		case fetched <- struct{}{}:
		default:
		}
		return []ToolDef{{Name: "search_docs", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		Nodes:           []string{"jira"},
		DefaultInterval: time.Millisecond,
		CheckInterval:   time.Millisecond,
	})

	sched.Start()
	select {
	case <-fetched:
	case <-time.After(5 * time.Second):
		t.Fatal("background loop never called Fetch within 5s")
	}
	sched.Stop() // must return promptly, not hang

	if _, err := s.GetToolPin(ctx, "jira", "search_docs"); err != nil {
		t.Fatalf("GetToolPin after background loop ran: %v", err)
	}
}

// TestScheduler_RunOnceDoesNotHangOnAHungFetch guards against a real
// shutdown-deadlock risk Copilot's review flagged on PR #10:
// RunOnce used to call Fetch with context.Background(), so a hung
// Fetcher implementation would block the loop goroutine forever --
// Stop() would then deadlock waiting on done, and a hung node would
// delay every subsequent node's refresh in the same tick. A short
// FetchTimeout should bound each node's own fetch, letting RunOnce
// (and therefore the whole tick) complete regardless.
func TestScheduler_RunOnceDoesNotHangOnAHungFetch(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	var secondNodeFetched atomic.Bool
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		if node == "hung-node" {
			<-ctx.Done() // never returns on its own -- only when the fetch context times out
			return nil, ctx.Err()
		}
		secondNodeFetched.Store(true)
		return []ToolDef{{Name: "search_docs", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		Nodes:           []string{"hung-node", "second-node"},
		DefaultInterval: 5 * time.Minute,
		FetchTimeout:    20 * time.Millisecond,
		Clock:           clock.now,
	})

	done := make(chan struct{})
	go func() {
		sched.RunOnce(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunOnce hung on a node whose Fetch never returns on its own -- FetchTimeout did not bound it")
	}

	if !secondNodeFetched.Load() {
		t.Fatal("the second node's Fetch was never reached -- the hung first node blocked the rest of this tick")
	}
}

// TestScheduler_DefaultFetchTimeoutAppliedWhenUnset confirms
// NewScheduler falls back to DefaultFetchTimeout rather than leaving
// fetches unbounded when SchedulerConfig.FetchTimeout is zero (the
// real-world default -- most callers won't set this explicitly).
func TestScheduler_DefaultFetchTimeoutAppliedWhenUnset(t *testing.T) {
	reg, _ := newTestRegistry(t)
	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           func(ctx context.Context, node string) ([]ToolDef, error) { return nil, nil },
		Nodes:           []string{"jira"},
		DefaultInterval: time.Minute,
	})
	if sched.fetchTimeout != DefaultFetchTimeout {
		t.Fatalf("fetchTimeout = %v, want DefaultFetchTimeout (%v) when unset", sched.fetchTimeout, DefaultFetchTimeout)
	}
}
