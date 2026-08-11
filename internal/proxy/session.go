package proxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// sessionCookieName is the mirrored cookie set alongside Mcp-Session-Id so
// native cookie-based load-balancer stickiness works out of the box under
// v1.1 HA, without customers hand-configuring header hashing (design doc
// decisions log, 2026-08-04).
const sessionCookieName = "spidercob_session"

var errSessionNotFound = errors.New("session not found")

// sessionUpstream is whatever a session's real upstream resource is --
// for streamable_http nodes, the real upstream's own session (torn down
// via DELETE); for stdio nodes, a dedicated child process spawned for this
// session alone. The gateway never exposes either identity to the client;
// only the gateway-minted session ID crosses that boundary.
type sessionUpstream interface {
	http.Handler
	teardown(ctx context.Context) error
	// alive reports whether the upstream resource is still usable.
	// streamable_http upstreams have no persistent process to die, so
	// they're always alive; stdio upstreams become dead once their
	// child process exits, expectedly or not.
	alive() bool
}

// mcpSession is one gateway-minted client-facing session.
type mcpSession struct {
	id       string
	node     string
	upstream sessionUpstream
	// principal is the "user:<username>"/"agent:<client_id>" identity
	// (AuthClaims.Subject) that authenticated the initialize call which
	// created this session -- set once at create time, never mutated
	// afterward, so it needs no locking of its own. Exists so an admin
	// (issue #35, kill-session) can tell whose session they'd be
	// interrupting before ending it.
	principal string

	mu         sync.Mutex
	lastActive time.Time
	// ending is set the moment end() begins tearing this session down --
	// including a failed attempt -- so get() stops handing it out even
	// before teardown actually finishes. A request bearing this session ID
	// must never be mistaken for a live one just because teardown hasn't
	// completed (or failed and is awaiting retry) yet.
	ending bool

	// teardownMu serializes teardown attempts for this session (an
	// explicit end() call racing a reapIdle pass, or a retried end() after
	// a failure) so upstream.teardown() is never invoked concurrently for
	// the same session, and teardownDone prevents calling it again once it
	// has actually succeeded.
	teardownMu   sync.Mutex
	teardownDone bool
}

func (s *mcpSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *mcpSession) idleSince() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActive
}

// sessionManager owns every live session's client-facing-ID -> upstream
// mapping. It is the single place both explicit revocation and idle
// timeout tear a session down through (design doc §6: "the gateway owns
// session mapping").
type sessionManager struct {
	idleTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*mcpSession
}

func newSessionManager(idleTimeout time.Duration) *sessionManager {
	return &sessionManager{
		idleTimeout: idleTimeout,
		sessions:    make(map[string]*mcpSession),
	}
}

// create mints a new opaque, cryptographically random session ID -- never
// the upstream's own session identifier -- and registers the mapping.
// principal is the authenticated identity (AuthClaims.Subject) that
// established this session, recorded for admin visibility (issue #35).
func (m *sessionManager) create(node, principal string, upstream sessionUpstream) (*mcpSession, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, fmt.Errorf("mint session id: %w", err)
	}
	s := &mcpSession{id: id, node: node, principal: principal, upstream: upstream, lastActive: time.Now()}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

func (m *sessionManager) get(id string) (*mcpSession, bool) {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	ending := s.ending
	s.mu.Unlock()
	if ending {
		// Already being (or having failed to be) torn down -- never hand
		// this back out as if it were still a live, usable session.
		return nil, false
	}
	return s, true
}

func (m *sessionManager) touch(id string) {
	if s, ok := m.get(id); ok {
		s.touch()
	}
}

// SessionInfo is a point-in-time snapshot of one live session, exposed
// for admin visibility (issue #35, kill-session) -- deliberately not
// *mcpSession itself, so a caller outside this package can't reach into
// its locks or its upstream.
type SessionInfo struct {
	ID        string
	Node      string
	Principal string
	IdleSince time.Time
}

// list returns a snapshot of every currently live session -- "live"
// meaning present in the map and not already ending, the same notion of
// liveness get() already uses.
func (m *sessionManager) list() []SessionInfo {
	m.mu.Lock()
	sessions := make([]*mcpSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()

	out := make([]SessionInfo, 0, len(sessions))
	for _, s := range sessions {
		s.mu.Lock()
		ending := s.ending
		lastActive := s.lastActive
		s.mu.Unlock()
		if ending {
			continue
		}
		out = append(out, SessionInfo{ID: s.id, Node: s.node, Principal: s.principal, IdleSince: lastActive})
	}
	return out
}

// allIDs returns every currently live session ID -- used to tear everything
// down on gateway shutdown.
func (m *sessionManager) allIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	return ids
}

// end tears down the session's upstream resource and removes the mapping.
// Ending an already-gone session (already ended, or reaped for idleness)
// is rejected, not silently treated as a no-op -- a request bearing a
// dead session ID must never be mistaken for a fresh one.
//
// The mapping is only removed once the upstream is confirmed gone. If
// teardown fails AND the upstream still reports itself alive, the session
// stays in the map (still marked ending, so get() keeps refusing it)
// specifically so a caller -- an explicit DELETE retry, or the next
// reapIdle pass -- can call end() again and actually finish tearing it
// down, instead of the mapping vanishing and leaking the underlying
// resource (notably a stdio child process) with no way left to reach it.
// A teardown error alongside alive()==false isn't treated as a leak (e.g.
// a stdio process that already exited on its own can surface its
// historical exit code from Close() even though there's nothing left to
// clean up) -- there's nothing to retry, so the mapping is removed anyway.
func (m *sessionManager) end(ctx context.Context, id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	m.mu.Unlock()
	if !ok {
		return errSessionNotFound
	}

	s.mu.Lock()
	s.ending = true
	s.mu.Unlock()

	// Serializes concurrent/retried end() calls for this exact session so
	// upstream.teardown() is never in flight twice at once, and so a call
	// that arrives just after a concurrent success doesn't call it again.
	s.teardownMu.Lock()
	defer s.teardownMu.Unlock()
	if s.teardownDone {
		return nil
	}
	if err := s.upstream.teardown(ctx); err != nil && s.upstream.alive() {
		return err
	}
	s.teardownDone = true

	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
	return nil
}

// reapIdle tears down every session whose idle timeout has elapsed. Meant
// to be called periodically by the gateway.
//
// Selection *and* removal from the map happen together in one locked pass
// so an already-expired session's removal can never be delayed behind a
// sibling session's slow teardown -- teardown itself runs afterward,
// outside the lock, where it can't block new sessions being created or
// looked up.
func (m *sessionManager) reapIdle(ctx context.Context) {
	now := time.Now()

	m.mu.Lock()
	var expired []*mcpSession
	for id, s := range m.sessions {
		if now.Sub(s.idleSince()) >= m.idleTimeout {
			delete(m.sessions, id)
			expired = append(expired, s)
		}
	}
	m.mu.Unlock()

	for _, s := range expired {
		s.mu.Lock()
		s.ending = true
		s.mu.Unlock()

		s.teardownMu.Lock()
		if !s.teardownDone {
			if err := s.upstream.teardown(ctx); err != nil && s.upstream.alive() {
				// Still genuinely alive despite the failed attempt -- put
				// the mapping back (still marked ending, so it can't be
				// reused as a live session in the meantime) so a future
				// reapIdle pass or an explicit end() can retry, instead of
				// silently leaking it now that it's off this loop's list.
				s.teardownMu.Unlock()
				m.mu.Lock()
				m.sessions[s.id] = s
				m.mu.Unlock()
				continue
			}
			s.teardownDone = true
		}
		s.teardownMu.Unlock()
	}
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
