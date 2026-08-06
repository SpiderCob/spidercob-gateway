package proxy

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type fakeUpstream struct {
	tornDown bool
	err      error
}

func (u *fakeUpstream) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (u *fakeUpstream) alive() bool                                  { return true }

func (u *fakeUpstream) teardown(context.Context) error {
	u.tornDown = true
	return u.err
}

func TestSessionManager_CreateAssignsUniqueIDs(t *testing.T) {
	m := newSessionManager(time.Hour)
	s1, err := m.create("jira", &fakeUpstream{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s2, err := m.create("jira", &fakeUpstream{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s1.id == "" || s2.id == "" {
		t.Fatal("expected non-empty session IDs")
	}
	if s1.id == s2.id {
		t.Fatal("expected unique session IDs, got the same one twice")
	}
}

func TestSessionManager_GetReturnsWhatWasCreated(t *testing.T) {
	m := newSessionManager(time.Hour)
	created, err := m.create("jira", &fakeUpstream{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, ok := m.get(created.id)
	if !ok {
		t.Fatal("expected to find the session that was just created")
	}
	if got.node != "jira" {
		t.Fatalf("node = %q, want jira", got.node)
	}
}

func TestSessionManager_GetUnknownIDFails(t *testing.T) {
	m := newSessionManager(time.Hour)
	if _, ok := m.get("does-not-exist"); ok {
		t.Fatal("expected lookup of an unknown session ID to fail")
	}
}

func TestSessionManager_EndTearsDownUpstreamAndRemovesMapping(t *testing.T) {
	m := newSessionManager(time.Hour)
	up := &fakeUpstream{}
	s, err := m.create("jira", up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := m.end(context.Background(), s.id); err != nil {
		t.Fatalf("end: %v", err)
	}
	if !up.tornDown {
		t.Fatal("expected the upstream to be torn down")
	}
	if _, ok := m.get(s.id); ok {
		t.Fatal("expected the session to be gone after end")
	}
}

func TestSessionManager_EndUnknownIDIsRejected(t *testing.T) {
	m := newSessionManager(time.Hour)
	err := m.end(context.Background(), "does-not-exist")
	if !errors.Is(err, errSessionNotFound) {
		t.Fatalf("expected errSessionNotFound, got %v", err)
	}
}

func TestSessionManager_EndIsIdempotent(t *testing.T) {
	// A session already torn down (explicitly or reaped) must not be
	// silently re-creatable or double-torn-down by a second end() call.
	m := newSessionManager(time.Hour)
	up := &fakeUpstream{}
	s, err := m.create("jira", up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := m.end(context.Background(), s.id); err != nil {
		t.Fatalf("first end: %v", err)
	}
	if err := m.end(context.Background(), s.id); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("second end: expected errSessionNotFound, got %v", err)
	}
}

func TestSessionManager_ReapIdleRemovesOnlyExpiredSessions(t *testing.T) {
	m := newSessionManager(10 * time.Millisecond)
	staleUp := &fakeUpstream{}
	stale, err := m.create("jira", staleUp)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	freshUp := &fakeUpstream{}
	fresh, err := m.create("jira", freshUp)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	m.reapIdle(context.Background())

	if !staleUp.tornDown {
		t.Fatal("expected the idle session's upstream to be torn down")
	}
	if _, ok := m.get(stale.id); ok {
		t.Fatal("expected the idle session to be gone")
	}
	if freshUp.tornDown {
		t.Fatal("did not expect the fresh session's upstream to be torn down")
	}
	if _, ok := m.get(fresh.id); !ok {
		t.Fatal("expected the fresh session to still be present")
	}
}

func TestSessionManager_TouchExtendsIdleDeadline(t *testing.T) {
	m := newSessionManager(20 * time.Millisecond)
	up := &fakeUpstream{}
	s, err := m.create("jira", up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(12 * time.Millisecond)
	m.touch(s.id) // resets the idle clock before the 20ms deadline

	time.Sleep(12 * time.Millisecond) // 24ms since create, but only 12ms since touch
	m.reapIdle(context.Background())

	if up.tornDown {
		t.Fatal("touch should have prevented this session from being reaped yet")
	}
	if _, ok := m.get(s.id); !ok {
		t.Fatal("expected the touched session to still be present")
	}
}
