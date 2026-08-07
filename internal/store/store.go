// Package store abstracts persistence. SQLite (modernc.org/sqlite, no cgo)
// is the phase-2 implementation; Postgres arrives with HA (design doc §8).
//
// Scope for this package, as of Phase 2a (issue #3): users, agents (NHI),
// groups, user_groups, agent_groups, revocations. The Phase 3+ tables
// (mcp_nodes, tool_pins, policies, sanitizer_profiles, idp_trust,
// audit_log) are out of scope here and land with the phases that need
// them.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by lookup methods when no matching row exists.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a uniqueness constraint would be violated
// (duplicate username, client_id, or group name).
var ErrConflict = errors.New("store: already exists")

// User is a local (Mode A) human account. Password hashing is
// internal/identity's responsibility -- PasswordHash is an opaque string
// as far as this package is concerned.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

// Agent is a non-human identity (NHI): a service account authenticating via
// client_credentials. SecretHash is opaque here, same as User.PasswordHash.
type Agent struct {
	ID         int64
	ClientID   string
	SecretHash string
	Name       string
	CreatedAt  time.Time
}

// Group is a named policy-assignment target. Membership tables
// (user_groups, agent_groups) exist and are assignable starting this
// phase, but nothing reads them for access decisions until Phase 3's
// policy engine.
type Group struct {
	ID   int64
	Name string
}

// Revocation is one denylisted access-token jti, persisted so the
// authserver's in-memory denylist survives a gateway restart.
type Revocation struct {
	JTI       string
	ExpiresAt time.Time
	RevokedAt time.Time
}

// Store is the persistence seam for identity data. A single SQLite-backed
// implementation exists today (sqlite.go); callers should depend on this
// interface, not the concrete type, so a future Postgres implementation
// (HA, design doc §8) is a drop-in.
type Store interface {
	Ping() error
	Close() error

	CreateUser(ctx context.Context, username, passwordHash string) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserByID(ctx context.Context, id int64) (User, error)

	CreateAgent(ctx context.Context, clientID, secretHash, name string) (Agent, error)
	GetAgentByClientID(ctx context.Context, clientID string) (Agent, error)
	GetAgentByID(ctx context.Context, id int64) (Agent, error)

	CreateGroup(ctx context.Context, name string) (Group, error)
	AssignUserGroup(ctx context.Context, userID, groupID int64) error
	AssignAgentGroup(ctx context.Context, agentID, groupID int64) error
	UserGroups(ctx context.Context, userID int64) ([]Group, error)
	AgentGroups(ctx context.Context, agentID int64) ([]Group, error)

	// RevokeJTI denylists a token's jti until expiresAt (its own natural
	// expiry -- no point keeping a revocation past the point the token
	// would've stopped validating anyway).
	RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	// LoadRevocations returns every not-yet-expired revocation, for
	// hydrating the authserver's in-memory denylist on startup.
	LoadRevocations(ctx context.Context) ([]Revocation, error)
}
