package pin

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestScheduler_AddNode_EnrollsIntoNextTick(t *testing.T) {
	reg, s := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	calls := map[string]int{}
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		calls[node]++
		return []ToolDef{{Name: "search_docs", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}

	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		Nodes:           []string{"jira"},
		DefaultInterval: 5 * time.Minute,
		Clock:           clock.now,
	})

	// A node not yet enrolled must not appear in RunOnce at all.
	sched.RunOnce(ctx)
	if calls["confluence"] != 0 {
		t.Fatalf("unexpected fetch for an unenrolled node: %d calls", calls["confluence"])
	}

	sched.AddNode("confluence", 0)
	sched.RunOnce(ctx)
	if calls["confluence"] != 1 {
		t.Fatalf("expected AddNode to make the node due on the very next RunOnce, got %d calls", calls["confluence"])
	}
	if _, err := s.GetToolPin(ctx, "confluence", "search_docs"); err != nil {
		t.Fatalf("GetToolPin after AddNode+RunOnce: %v", err)
	}
}

func TestScheduler_AddNode_PerNodeIntervalHonored(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	calls := 0
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		calls++
		return []ToolDef{{Name: "t", Description: "d", InputSchema: []byte(`{}`)}}, nil
	}
	sched := NewScheduler(SchedulerConfig{
		Registry:        reg,
		Fetch:           fetch,
		DefaultInterval: time.Minute,
		Clock:           clock.now,
	})

	sched.AddNode("slow-node", time.Hour)
	sched.RunOnce(ctx) // first check is always due (never seen before)
	if calls != 1 {
		t.Fatalf("expected 1 call on first RunOnce, got %d", calls)
	}

	clock.advance(5 * time.Minute) // well within the 1h per-node interval, past the 1m default
	sched.RunOnce(ctx)
	if calls != 1 {
		t.Fatalf("expected the per-node 1h interval (not the 1m default) to still apply, got %d calls", calls)
	}
}

func TestScheduler_RemoveNode_DropsFromNextTick(t *testing.T) {
	reg, _ := newTestRegistry(t)
	ctx := context.Background()
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}

	calls := 0
	fetch := func(ctx context.Context, node string) ([]ToolDef, error) {
		calls++
		return []ToolDef{{Name: "t", Description: "d", InputSchema: []byte(`{}`)}}, nil
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
		t.Fatalf("sanity check: expected 1 call, got %d", calls)
	}

	sched.RemoveNode("jira")
	clock.advance(time.Hour) // well past any interval
	sched.RunOnce(ctx)
	if calls != 1 {
		t.Fatalf("expected RemoveNode to stop future refreshes, got %d total calls", calls)
	}
}

func TestScheduler_AddNode_Idempotent(t *testing.T) {
	reg, _ := newTestRegistry(t)
	sched := NewScheduler(SchedulerConfig{
		Registry: reg,
		Fetch:    func(context.Context, string) ([]ToolDef, error) { return nil, nil },
		Nodes:    []string{"jira"},
	})
	sched.AddNode("jira", time.Hour)
	sched.AddNode("jira", time.Hour)
	if got := len(sched.nodes); got != 1 {
		t.Fatalf("expected exactly one entry for a node added twice, got %d: %v", got, sched.nodes)
	}
}

func TestScheduler_RemoveNode_Idempotent(t *testing.T) {
	reg, _ := newTestRegistry(t)
	sched := NewScheduler(SchedulerConfig{
		Registry: reg,
		Fetch:    func(context.Context, string) ([]ToolDef, error) { return nil, nil },
	})
	sched.RemoveNode("never-added") // must not panic
}

// TestScheduler_NodeRegistry_ConcurrentAddRemoveAndRunOnce is the race
// proof: RunOnce (as the background loop calls it) and admin add/remove
// (on whatever goroutine an HTTP admin request uses) happen concurrently
// against the same node list. Run with -race.
func TestScheduler_NodeRegistry_ConcurrentAddRemoveAndRunOnce(t *testing.T) {
	reg, _ := newTestRegistry(t)
	sched := NewScheduler(SchedulerConfig{
		Registry: reg,
		Fetch:    func(context.Context, string) ([]ToolDef, error) { return nil, nil },
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			sched.AddNode("racer", 0)
			sched.RemoveNode("racer")
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			sched.RunOnce(context.Background())
		}
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
