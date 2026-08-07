package policy

import (
	"testing"
	"time"
)

func TestRateLimiter_AllowsUpToMaxCallsWithinWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiter(func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if !rl.allow("key", 3, time.Minute) {
			t.Fatalf("call %d: expected allowed (within limit)", i+1)
		}
	}
	if rl.allow("key", 3, time.Minute) {
		t.Fatal("4th call within the same window should be rejected")
	}
}

func TestRateLimiter_ResetsAfterWindowElapses(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiter(func() time.Time { return now })

	for i := 0; i < 2; i++ {
		if !rl.allow("key", 2, time.Minute) {
			t.Fatalf("call %d: expected allowed", i+1)
		}
	}
	if rl.allow("key", 2, time.Minute) {
		t.Fatal("3rd call should be rejected before the window elapses")
	}

	now = now.Add(time.Minute + time.Second) // past the window
	if !rl.allow("key", 2, time.Minute) {
		t.Fatal("expected allowed again once the window has elapsed")
	}
}

func TestRateLimiter_KeysAreIndependent(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl := newRateLimiter(func() time.Time { return now })

	if !rl.allow("a", 1, time.Minute) {
		t.Fatal("expected key a's first call allowed")
	}
	if rl.allow("a", 1, time.Minute) {
		t.Fatal("expected key a's second call rejected")
	}
	if !rl.allow("b", 1, time.Minute) {
		t.Fatal("expected key b's first call allowed independently of key a's budget")
	}
}
