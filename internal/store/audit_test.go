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

func seedAuditRecords(t *testing.T, s *SQLiteStore, n int) []AuditLogEntry {
	t.Helper()
	ctx := context.Background()
	var entries []AuditLogEntry
	for i := 0; i < n; i++ {
		e, err := s.AppendAuditRecord(ctx, testAuditRecord("action", "res"))
		if err != nil {
			t.Fatalf("AppendAuditRecord: %v", err)
		}
		entries = append(entries, e)
	}
	return entries
}

func TestListAuditRecordsPage_MostRecentFirst(t *testing.T) {
	s := openTestStore(t)
	seeded := seedAuditRecords(t, s, 3)

	page, err := s.ListAuditRecordsPage(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("ListAuditRecordsPage: %v", err)
	}
	if len(page) != 3 {
		t.Fatalf("got %d records, want 3", len(page))
	}
	if page[0].ID != seeded[2].ID || page[1].ID != seeded[1].ID || page[2].ID != seeded[0].ID {
		t.Fatalf("page ids = [%d, %d, %d], want most-recent-first [%d, %d, %d]",
			page[0].ID, page[1].ID, page[2].ID, seeded[2].ID, seeded[1].ID, seeded[0].ID)
	}
}

func TestListAuditRecordsPage_BeforeIDExcludesAtAndAfter(t *testing.T) {
	s := openTestStore(t)
	seeded := seedAuditRecords(t, s, 5)

	page, err := s.ListAuditRecordsPage(context.Background(), 10, seeded[3].ID)
	if err != nil {
		t.Fatalf("ListAuditRecordsPage: %v", err)
	}
	if len(page) != 3 {
		t.Fatalf("got %d records, want 3 (ids 1,2,3 of 5)", len(page))
	}
	for _, e := range page {
		if e.ID >= seeded[3].ID {
			t.Fatalf("record id %d should have been excluded (before_id = %d)", e.ID, seeded[3].ID)
		}
	}
}

func TestListAuditRecordsPage_LimitRespected(t *testing.T) {
	s := openTestStore(t)
	seedAuditRecords(t, s, 5)

	page, err := s.ListAuditRecordsPage(context.Background(), 2, 0)
	if err != nil {
		t.Fatalf("ListAuditRecordsPage: %v", err)
	}
	if len(page) != 2 {
		t.Fatalf("got %d records, want 2", len(page))
	}
}

func TestListAuditRecordsPage_OverLargeLimitClamped(t *testing.T) {
	s := openTestStore(t)
	seedAuditRecords(t, s, DefaultAuditPageSize+5)

	page, err := s.ListAuditRecordsPage(context.Background(), MaxAuditPageSize+1000, 0)
	if err != nil {
		t.Fatalf("ListAuditRecordsPage: %v", err)
	}
	if len(page) > MaxAuditPageSize {
		t.Fatalf("got %d records, want at most MaxAuditPageSize (%d)", len(page), MaxAuditPageSize)
	}
}

func TestListAuditRecordsPage_ZeroOrNegativeLimitDefaults(t *testing.T) {
	s := openTestStore(t)
	seedAuditRecords(t, s, DefaultAuditPageSize+5)

	for _, limit := range []int{0, -1} {
		page, err := s.ListAuditRecordsPage(context.Background(), limit, 0)
		if err != nil {
			t.Fatalf("ListAuditRecordsPage(limit=%d): %v", limit, err)
		}
		if len(page) != DefaultAuditPageSize {
			t.Fatalf("limit=%d: got %d records, want DefaultAuditPageSize (%d)", limit, len(page), DefaultAuditPageSize)
		}
	}
}

func TestListAuditRecordsPage_EmptyTable(t *testing.T) {
	s := openTestStore(t)
	page, err := s.ListAuditRecordsPage(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("ListAuditRecordsPage: %v", err)
	}
	if len(page) != 0 {
		t.Fatalf("got %d records, want 0", len(page))
	}
}
