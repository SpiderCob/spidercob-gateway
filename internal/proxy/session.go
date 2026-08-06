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

	mu         sync.Mutex
	lastActive time.Time
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
func (m *sessionManager) create(node string, upstream sessionUpstream) (*mcpSession, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, fmt.Errorf("mint session id: %w", err)
	}
	s := &mcpSession{id: id, node: node, upstream: upstream, lastActive: time.Now()}
	m.mu.Lock()
	m.sessions[id] = s
	m.mu.Unlock()
	return s, nil
}

func (m *sessionManager) get(id string) (*mcpSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok
}

func (m *sessionManager) touch(id string) {
	if s, ok := m.get(id); ok {
		s.touch()
	}
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
func (m *sessionManager) end(ctx context.Context, id string) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return errSessionNotFound
	}
	return s.upstream.teardown(ctx)
}

// reapIdle tears down every session whose idle timeout has elapsed. Meant
// to be called periodically by the gateway.
func (m *sessionManager) reapIdle(ctx context.Context) {
	now := time.Now()
	m.mu.Lock()
	var expired []string
	for id, s := range m.sessions {
		if now.Sub(s.idleSince()) >= m.idleTimeout {
			expired = append(expired, id)
		}
	}
	m.mu.Unlock()

	for _, id := range expired {
		_ = m.end(ctx, id) // best-effort; a session ended concurrently is fine
	}
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
