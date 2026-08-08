package uisession

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Registry is the in-memory store of currently-live UI sessions,
// keyed by their opaque cookie token. Deliberately not store-backed --
// same precedent as the MCP protocol's own Mcp-Session-Id mapping,
// which the design doc's HA section already treats as legitimately
// memory-resident, not persisted. Safe for concurrent use.
type Registry struct {
	maxAge time.Duration
	clock  func() time.Time

	mu       sync.Mutex
	sessions map[string]Session
}

// RegistryConfig is Registry's construction input. Mirrors
// pin.SchedulerConfig's exported-Clock-field pattern: real callers
// leave Clock nil (defaults to time.Now), while tests -- including
// other packages' tests, like internal/adminapi's, which need to
// control UI-session expiry timing without a real wait -- set it
// directly, no unexported cross-package escape hatch needed.
type RegistryConfig struct {
	// MaxAge bounds a UI session's total lifetime, independent of (and
	// in addition to) the live per-request introspection check callers
	// layer on top using a session's HumanToken.
	MaxAge time.Duration
	// Clock is injectable for tests; real callers leave it nil.
	Clock func() time.Time
}

// NewRegistry builds a Registry from cfg.
func NewRegistry(cfg RegistryConfig) *Registry {
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Registry{maxAge: cfg.MaxAge, clock: clock, sessions: make(map[string]Session)}
}

// Create mints a new session bound to humanToken and returns it. The
// caller (internal/adminapi's session handler) is responsible for
// having already verified humanToken via SpiderSnoopIntrospector
// before calling Create -- Create itself performs no verification, it
// only records the mapping from a fresh opaque token to that already-
// verified human token.
func (r *Registry) Create(humanToken string) (Session, error) {
	token, err := randomToken()
	if err != nil {
		return Session{}, fmt.Errorf("uisession: generate token: %w", err)
	}
	s := Session{Token: token, HumanToken: humanToken, CreatedAt: r.clock()}
	r.mu.Lock()
	r.sessions[token] = s
	r.mu.Unlock()
	return s, nil
}

// Get returns the session for token if it exists and hasn't aged past
// the registry's maxAge. An aged-out session is treated identically to
// a missing one -- fail-static, never resurrect a decision from a
// stale lookup -- but is not proactively swept from the map here; a
// long-idle registry accumulating aged-out entries is an acceptable v0
// memory cost (session volume is bounded by admin headcount, not
// request volume) rather than adding a background reaper for this
// issue.
func (r *Registry) Get(token string) (Session, bool) {
	r.mu.Lock()
	s, ok := r.sessions[token]
	r.mu.Unlock()
	if !ok {
		return Session{}, false
	}
	if !Valid(s, r.clock(), r.maxAge) {
		return Session{}, false
	}
	return s, true
}

// Delete removes a session (logout). Idempotent -- deleting an
// already-gone or never-issued token is not an error, so callers don't
// need to Get before Delete just to avoid one.
func (r *Registry) Delete(token string) {
	r.mu.Lock()
	delete(r.sessions, token)
	r.mu.Unlock()
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
