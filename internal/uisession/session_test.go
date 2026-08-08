package uisession

import (
	"testing"
	"time"
)

func TestValid(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		session Session
		now     time.Time
		maxAge  time.Duration
		want    bool
	}{
		{"freshly created, well inside maxAge", Session{CreatedAt: base}, base.Add(time.Minute), time.Hour, true},
		{"exactly at maxAge boundary is expired", Session{CreatedAt: base}, base.Add(time.Hour), time.Hour, false},
		{"well past maxAge is expired", Session{CreatedAt: base}, base.Add(24 * time.Hour), time.Hour, false},
		{"zero-value session (never created) is always invalid", Session{}, base, time.Hour, false},
		{"zero maxAge is always invalid", Session{CreatedAt: base}, base, 0, false},
		{"negative maxAge is always invalid", Session{CreatedAt: base}, base, -1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Valid(c.session, c.now, c.maxAge); got != c.want {
				t.Fatalf("Valid(%+v, %v, %v) = %v, want %v", c.session, c.now, c.maxAge, got, c.want)
			}
		})
	}
}
