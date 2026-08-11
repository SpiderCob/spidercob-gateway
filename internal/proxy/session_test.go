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
	s1, err := m.create("jira", "agent:test-agent", &fakeUpstream{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s2, err := m.create("jira", "agent:test-agent", &fakeUpstream{})
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
	created, err := m.create("jira", "agent:test-agent", &fakeUpstream{})
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
	if got.principal != "agent:test-agent" {
		t.Fatalf("principal = %q, want agent:test-agent", got.principal)
	}
}

func TestSessionManager_ListReturnsLiveSessionsWithPrincipalAndNode(t *testing.T) {
	m := newSessionManager(time.Hour)
	s1, err := m.create("jira", "agent:ci-bot", &fakeUpstream{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s2, err := m.create("slack", "user:alice", &fakeUpstream{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got := m.list()
	if len(got) != 2 {
		t.Fatalf("list() = %+v, want 2 sessions", got)
	}
	byID := make(map[string]SessionInfo, len(got))
	for _, si := range got {
		byID[si.ID] = si
	}
	if si, ok := byID[s1.id]; !ok || si.Node != "jira" || si.Principal != "agent:ci-bot" {
		t.Fatalf("session 1 = %+v, want node=jira principal=agent:ci-bot", si)
	}
	if si, ok := byID[s2.id]; !ok || si.Node != "slack" || si.Principal != "user:alice" {
		t.Fatalf("session 2 = %+v, want node=slack principal=user:alice", si)
	}
}

func TestSessionManager_ListExcludesEndedSessions(t *testing.T) {
	m := newSessionManager(time.Hour)
	up := &fakeUpstream{}
	s, err := m.create("jira", "agent:ci-bot", up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := m.end(context.Background(), s.id); err != nil {
		t.Fatalf("end: %v", err)
	}

	got := m.list()
	if len(got) != 0 {
		t.Fatalf("list() after end = %+v, want empty", got)
	}
}

func TestSessionManager_ListOnEmptyManagerReturnsEmptyNotNil(t *testing.T) {
	m := newSessionManager(time.Hour)
	got := m.list()
	if len(got) != 0 {
		t.Fatalf("list() on empty manager = %+v, want empty", got)
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
	s, err := m.create("jira", "agent:test-agent", up)
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
	s, err := m.create("jira", "agent:test-agent", up)
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

// blockingUpstream is a sessionUpstream whose teardown() blocks until
// release is closed, signaling on started (buffered, so a single send never
// blocks) the moment it begins. Used to make the timing of removal-from-map
// vs. teardown-completion observable instead of racy.
type blockingUpstream struct {
	release  chan struct{}
	started  chan struct{}
	tornDown bool
}

func newBlockingUpstream(release chan struct{}) *blockingUpstream {
	return &blockingUpstream{release: release, started: make(chan struct{}, 1)}
}

func (u *blockingUpstream) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (u *blockingUpstream) alive() bool                                  { return true }

func (u *blockingUpstream) teardown(context.Context) error {
	select {
	case u.started <- struct{}{}:
	default:
	}
	<-u.release
	u.tornDown = true
	return nil
}

func TestSessionManager_ReapIdle_RemovesAllExpiredFromMapBeforeAnyTeardownRuns(t *testing.T) {
	// Regression test: reapIdle used to select expired sessions into a
	// list under one lock, then unlock and tear each down one at a time
	// via a fresh end() call per session. That meant an already-expired
	// session's removal from the map could be delayed behind an unrelated
	// sibling session's slow teardown -- a caller could keep "finding" and
	// using a session that had already been decided to be reaped. The fix
	// selects *and removes* every expired session from the map in one
	// atomic pass, then tears each down afterward, outside the lock.
	m := newSessionManager(10 * time.Millisecond)

	release := make(chan struct{})
	up1 := newBlockingUpstream(release)
	up2 := newBlockingUpstream(release)
	s1, err := m.create("jira", "agent:test-agent", up1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	s2, err := m.create("jira", "agent:test-agent", up2)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(20 * time.Millisecond) // both now idle-expired

	done := make(chan struct{})
	go func() {
		m.reapIdle(context.Background())
		close(done)
	}()

	select {
	case <-up1.started:
	case <-up2.started:
	case <-time.After(time.Second):
		t.Fatal("neither teardown started in time")
	}

	// Both sessions must already be gone from the map -- neither's removal
	// should wait behind the other's still-blocked teardown.
	if _, ok := m.get(s1.id); ok {
		t.Fatal("expected s1 to already be removed from the map")
	}
	if _, ok := m.get(s2.id); ok {
		t.Fatal("expected s2 to already be removed from the map")
	}

	close(release)
	<-done
	if !up1.tornDown || !up2.tornDown {
		t.Fatal("expected both sessions to eventually be torn down")
	}
}

// failThenSucceedUpstream fails its first teardown() call and succeeds on
// the next, simulating a transient failure (e.g. a signal that didn't land,
// a momentarily-unreachable upstream).
type failThenSucceedUpstream struct {
	fail     bool
	calls    int
	tornDown bool
}

func (u *failThenSucceedUpstream) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (u *failThenSucceedUpstream) alive() bool                                  { return true }

func (u *failThenSucceedUpstream) teardown(context.Context) error {
	u.calls++
	if u.fail {
		u.fail = false
		return errors.New("transient teardown failure")
	}
	u.tornDown = true
	return nil
}

func TestSessionManager_EndIsRetryableAfterTeardownFailure(t *testing.T) {
	// Regression test: end() used to delete the session mapping *before*
	// calling teardown(). If teardown failed, the mapping was already
	// gone, so a retry had nothing left to act on and the upstream (e.g. a
	// stdio child process) could leak with no way to reach it again.
	m := newSessionManager(time.Hour)
	up := &failThenSucceedUpstream{fail: true}
	s, err := m.create("jira", "agent:test-agent", up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := m.end(context.Background(), s.id); err == nil {
		t.Fatal("expected the first end() to surface the teardown failure")
	}
	if up.calls != 1 {
		t.Fatalf("expected exactly one teardown attempt so far, got %d", up.calls)
	}

	// A session mid-teardown (even a failed attempt) must not be usable as
	// a normal live session -- it must not be mistaken for a fresh one.
	if _, ok := m.get(s.id); ok {
		t.Fatal("a session that failed to tear down must not be usable as a live session")
	}

	if err := m.end(context.Background(), s.id); err != nil {
		t.Fatalf("retry end: %v", err)
	}
	if up.calls != 2 {
		t.Fatalf("expected teardown to be retried, got %d calls", up.calls)
	}
	if !up.tornDown {
		t.Fatal("expected the retry to succeed")
	}
	if _, ok := m.get(s.id); ok {
		t.Fatal("expected the session to be gone after the retry succeeds")
	}
}

// deadUpstream simulates a resource that's already gone on its own (e.g. a
// stdio child process that already exited) -- teardown() still surfaces an
// error (its historical exit status), but alive() correctly reports false.
type deadUpstream struct {
	teardownCalls int
	teardownErr   error
}

func (u *deadUpstream) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (u *deadUpstream) alive() bool                                  { return false }

func (u *deadUpstream) teardown(context.Context) error {
	u.teardownCalls++
	return u.teardownErr
}

func TestSessionManager_EndCompletesWhenUpstreamConfirmsAlreadyGone(t *testing.T) {
	// Regression test: requiring teardown() to succeed before removing the
	// mapping (added to fix the leak-on-failure bug) must not get an
	// already-dead upstream permanently stuck -- e.g. a crashed stdio
	// process whose Close() surfaces its exit code as an "error" forever,
	// even though there's nothing left to clean up. alive()==false is the
	// authoritative "nothing is being leaked" signal, independent of
	// whatever teardown() itself returns.
	m := newSessionManager(time.Hour)
	up := &deadUpstream{teardownErr: errors.New("exit status 1")}
	s, err := m.create("crash", "agent:test-agent", up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := m.end(context.Background(), s.id); err != nil {
		t.Fatalf("end: expected no error for a confirmed-dead upstream, got %v", err)
	}
	if _, ok := m.get(s.id); ok {
		t.Fatal("expected the session to be gone after end")
	}
}

// stuckUpstream always fails to tear down while still reporting itself
// alive -- a genuine "kill signal didn't land" scenario.
type stuckUpstream struct {
	teardownCalls int
	failUntilCall int
}

func (u *stuckUpstream) ServeHTTP(http.ResponseWriter, *http.Request) {}
func (u *stuckUpstream) alive() bool                                  { return true }

func (u *stuckUpstream) teardown(context.Context) error {
	u.teardownCalls++
	if u.teardownCalls <= u.failUntilCall {
		return errors.New("still running, kill signal ignored")
	}
	return nil
}

func TestSessionManager_ReapIdleRequeuesStillAliveSessionOnTeardownFailure(t *testing.T) {
	// A session that's genuinely still alive despite a failed reap
	// attempt must not just vanish from bookkeeping -- it has to stay
	// reachable for a retry (next reapIdle pass, or an explicit end()).
	m := newSessionManager(10 * time.Millisecond)
	up := &stuckUpstream{failUntilCall: 1}
	s, err := m.create("jira", "agent:test-agent", up)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(20 * time.Millisecond)
	m.reapIdle(context.Background())

	if up.teardownCalls != 1 {
		t.Fatalf("expected exactly one teardown attempt, got %d", up.teardownCalls)
	}
	if _, ok := m.get(s.id); ok {
		t.Fatal("a session that failed to tear down must not be usable as a live session")
	}

	// Retry via an explicit end() call -- must actually reach the upstream
	// again, not report "not found" for a session that's still pending.
	if err := m.end(context.Background(), s.id); err != nil {
		t.Fatalf("retry end: %v", err)
	}
	if up.teardownCalls != 2 {
		t.Fatalf("expected teardown to be retried, got %d calls", up.teardownCalls)
	}
}

func TestSessionManager_ReapIdleRemovesOnlyExpiredSessions(t *testing.T) {
	m := newSessionManager(10 * time.Millisecond)
	staleUp := &fakeUpstream{}
	stale, err := m.create("jira", "agent:test-agent", staleUp)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	freshUp := &fakeUpstream{}
	fresh, err := m.create("jira", "agent:test-agent", freshUp)
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
	s, err := m.create("jira", "agent:test-agent", up)
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
