package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
)

func testAuditRecord(action, resource string) audit.Record {
	return audit.Record{
		Timestamp:          time.Now(),
		ActorNHISubject:    "agent:spider-snoop-backend",
		ActorHumanUsername: "alice",
		ActorHumanRole:     "admin",
		Action:             action,
		Resource:           resource,
	}
}

func TestAppendAuditRecord_FirstEntryGetsGenesisPrevHash(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	entry, err := s.AppendAuditRecord(ctx, testAuditRecord("create_agent", "agt_1"))
	if err != nil {
		t.Fatalf("AppendAuditRecord: %v", err)
	}
	if entry.ID == 0 {
		t.Fatal("expected a non-zero ID")
	}
	if entry.PrevHash != audit.GenesisPrevHash {
		t.Fatalf("PrevHash = %q, want the genesis sentinel", entry.PrevHash)
	}
	if entry.Hash == "" {
		t.Fatal("expected a non-empty Hash")
	}
}

func TestAppendAuditRecord_SecondEntryChainsToFirst(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	first, err := s.AppendAuditRecord(ctx, testAuditRecord("create_agent", "agt_1"))
	if err != nil {
		t.Fatalf("AppendAuditRecord (first): %v", err)
	}
	second, err := s.AppendAuditRecord(ctx, testAuditRecord("create_group", "engineering"))
	if err != nil {
		t.Fatalf("AppendAuditRecord (second): %v", err)
	}
	if second.PrevHash != first.Hash {
		t.Fatalf("second.PrevHash = %q, want first.Hash %q", second.PrevHash, first.Hash)
	}
}

func TestListAuditRecords_ReturnsChainOrder(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	actions := []string{"create_agent", "create_group", "delete_node"}
	for _, a := range actions {
		if _, err := s.AppendAuditRecord(ctx, testAuditRecord(a, "res")); err != nil {
			t.Fatalf("AppendAuditRecord(%s): %v", a, err)
		}
	}

	entries, err := s.ListAuditRecords(ctx)
	if err != nil {
		t.Fatalf("ListAuditRecords: %v", err)
	}
	if len(entries) != len(actions) {
		t.Fatalf("got %d entries, want %d", len(entries), len(actions))
	}
	for i, a := range actions {
		if entries[i].Action != a {
			t.Fatalf("entries[%d].Action = %q, want %q", i, entries[i].Action, a)
		}
	}

	stored := make([]audit.StoredRecord, len(entries))
	for i, e := range entries {
		stored[i] = e.StoredRecord
	}
	if err := audit.Verify(stored); err != nil {
		t.Fatalf("audit.Verify on a real, freshly-written chain: %v", err)
	}
}

func TestListAuditRecords_EmptyWhenNoneAppended(t *testing.T) {
	s := openTestStore(t)
	entries, err := s.ListAuditRecords(context.Background())
	if err != nil {
		t.Fatalf("ListAuditRecords: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %+v, want empty", entries)
	}
}

// TestAppendAuditRecord_ConcurrentAppendsProduceAValidChain mirrors this
// package's existing ResolveOrCreateExternalUser concurrency test: many
// goroutines appending at once must still leave a single, gap-free,
// verifiable chain -- proving the store's transaction actually
// serializes the read-last-hash-then-insert correctly under real
// concurrent load, not just in the single-threaded happy path.
func TestAppendAuditRecord_ConcurrentAppendsProduceAValidChain(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	const n = 20

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.AppendAuditRecord(ctx, testAuditRecord("concurrent_action", "res")); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("AppendAuditRecord under concurrency: %v", err)
	}

	entries, err := s.ListAuditRecords(ctx)
	if err != nil {
		t.Fatalf("ListAuditRecords: %v", err)
	}
	if len(entries) != n {
		t.Fatalf("got %d entries, want %d", len(entries), n)
	}
	stored := make([]audit.StoredRecord, len(entries))
	for i, e := range entries {
		stored[i] = e.StoredRecord
	}
	if err := audit.Verify(stored); err != nil {
		t.Fatalf("audit.Verify after concurrent appends: %v", err)
	}
}
