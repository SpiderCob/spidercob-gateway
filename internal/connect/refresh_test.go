package connect

import (
	"testing"
	"time"
)

// TestDueForRefresh_TableDriven is the primary seam for issue #52's core
// timing decision -- "given a token's issued/expiry time and the current
// time, should it be refreshed now" -- kept as a pure function with no
// goroutines or real sleeping, mirroring internal/policy's rateLimiter
// clock-injection precedent and internal/pin.Scheduler's per-node
// due-ness check.
func TestDueForRefresh_TableDriven(t *testing.T) {
	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := issued.Add(100 * time.Second) // a round, easy-to-reason-about lifetime

	tests := []struct {
		name   string
		now    time.Time
		want   bool
		reason string
	}{
		{
			name:   "just issued, nowhere near due",
			now:    issued.Add(1 * time.Second),
			want:   false,
			reason: "1% of lifetime elapsed",
		},
		{
			name: "74% elapsed, just under the 75% threshold",
			now:  issued.Add(74 * time.Second),
			want: false,
		},
		{
			name:   "exactly at the 75% threshold",
			now:    issued.Add(75 * time.Second),
			want:   true,
			reason: "threshold is inclusive -- refreshing right at the boundary is safer than refreshing one tick late",
		},
		{
			name: "76% elapsed, past the threshold",
			now:  issued.Add(76 * time.Second),
			want: true,
		},
		{
			name: "already at expiry",
			now:  expires,
			want: true,
		},
		{
			name:   "already past expiry",
			now:    expires.Add(10 * time.Second),
			want:   true,
			reason: "an already-expired token is unconditionally due, regardless of the refresh-fraction math",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dueForRefresh(tc.now, issued, expires, DefaultRefreshFraction)
			if got != tc.want {
				t.Fatalf("dueForRefresh(now=%s) = %v, want %v (%s)", tc.now.Sub(issued), got, tc.want, tc.reason)
			}
		})
	}
}

func TestDueForRefresh_ZeroTokenNeverIssuedIsAlwaysDue(t *testing.T) {
	// The zero value of time.Time (never-issued) must never be treated as
	// "recently issued, not due yet" -- a node whose very first mint
	// hasn't happened is always due.
	var neverIssued time.Time
	if !dueForRefresh(time.Now(), neverIssued, neverIssued, DefaultRefreshFraction) {
		t.Fatal("a token that was never issued must always be due for refresh")
	}
}
