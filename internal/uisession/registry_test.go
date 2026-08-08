package uisession

import (
	"testing"
	"time"
)

// fakeClock lets registry tests control time.Now() directly instead of
// sleeping real wall-clock time -- same pattern internal/pin's
// scheduler_test.go already uses.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time          { return f.t }
func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

func newTestRegistry(maxAge time.Duration) (*Registry, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	return NewRegistry(RegistryConfig{MaxAge: maxAge, Clock: clock.now}), clock
}

func TestRegistry_CreateThenGetSucceeds(t *testing.T) {
	reg, _ := newTestRegistry(time.Hour)

	s, err := reg.Create("spidersnoop-human-token-abc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if s.Token == "" {
		t.Fatal("Create returned a session with an empty Token")
	}
	if s.HumanToken != "spidersnoop-human-token-abc" {
		t.Fatalf("HumanToken = %q, want the token passed to Create", s.HumanToken)
	}

	got, ok := reg.Get(s.Token)
	if !ok {
		t.Fatal("Get after Create: not found")
	}
	if got.Token != s.Token || got.HumanToken != s.HumanToken {
		t.Fatalf("Get returned %+v, want %+v", got, s)
	}
}

func TestRegistry_CreateProducesDistinctTokens(t *testing.T) {
	reg, _ := newTestRegistry(time.Hour)

	a, err := reg.Create("human-a")
	if err != nil {
		t.Fatalf("Create a: %v", err)
	}
	b, err := reg.Create("human-b")
	if err != nil {
		t.Fatalf("Create b: %v", err)
	}
	if a.Token == b.Token {
		t.Fatalf("two Create calls produced the same token %q", a.Token)
	}
}

func TestRegistry_GetUnknownTokenNotFound(t *testing.T) {
	reg, _ := newTestRegistry(time.Hour)

	if _, ok := reg.Get("never-issued"); ok {
		t.Fatal("Get on a token that was never created returned ok=true")
	}
}

func TestRegistry_GetAfterDeleteNotFound(t *testing.T) {
	reg, _ := newTestRegistry(time.Hour)

	s, err := reg.Create("human-a")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	reg.Delete(s.Token)

	if _, ok := reg.Get(s.Token); ok {
		t.Fatal("Get after Delete returned ok=true")
	}
}

func TestRegistry_DeleteUnknownTokenIsNotAnError(t *testing.T) {
	reg, _ := newTestRegistry(time.Hour)
	reg.Delete("never-issued") // must not panic
}

func TestRegistry_GetAgedOutSessionNotFound(t *testing.T) {
	reg, clock := newTestRegistry(time.Hour)

	s, err := reg.Create("human-a")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, ok := reg.Get(s.Token); !ok {
		t.Fatal("session should be valid immediately after Create")
	}

	clock.advance(2 * time.Hour)
	if _, ok := reg.Get(s.Token); ok {
		t.Fatal("Get on a session older than maxAge returned ok=true")
	}
}
