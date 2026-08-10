package authserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

func TestDenylist_TryConsumeRollsBackInMemoryMarkOnPersistFailure(t *testing.T) {
	// Regression test: tryConsume used to mark jti consumed in-memory
	// before persisting it. If the store write failed, the in-memory mark
	// stuck around anyway, so a client retry of the same one-time-use
	// assertion would be (wrongly) treated as a replay (fresh=false)
	// instead of surfacing another server_error for the caller to retry.
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	d := newDenylist(s)

	// Force the persistence leg of tryConsume to fail deterministically.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	expiresAt := time.Now().Add(time.Hour)
	fresh, err := d.tryConsume(context.Background(), "jti-1", expiresAt)
	if err == nil {
		t.Fatal("expected tryConsume to surface the persistence failure")
	}
	if !fresh {
		t.Fatal("expected fresh=true on the attempt that actually hit the store error, not a replay verdict")
	}
	if d.isRevoked("jti-1") {
		t.Fatal("expected the in-memory mark to be rolled back after the persist failure")
	}
}
