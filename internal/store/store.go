// Package store abstracts persistence. SQLite (modernc.org/sqlite, no cgo)
// is the phase-2 implementation; Postgres arrives with HA (design doc §8).
//
// Scope as of Phase 4b (issue #15): users, agents (NHI, now soft-
// revocable via RevokedAt), groups (now deletable, membership now
// removable), user_groups, agent_groups, revocations (issue #3),
// external_identities (JIT-provisioned Mode B users, issue #5), policies
// (issue #7), tool_pins (issue #9), and now mcp_nodes (issue #15: name,
// transport, upstream_url/command/args, source "config"|"admin").
// Trusted external-IdP config (idp_trust in design doc §8) stays
// config-file-only, same bootstrap pattern config.Nodes itself used to
// be -- internal/adminapi (issue #13) manages agents/groups/policies/
// nodes over HTTP now, but idp_trust still has no admin-managed
// equivalent. Unlike policies (fully replaced from config on every
// startup, no independent state of its own) or tool_pins (never touched
// by config, must survive a restart unchanged or TOFU is trivially
// bypassed), mcp_nodes splits the difference by row: "config"-sourced
// rows are upserted from config.Nodes on every startup (config stays
// authoritative for those specifically), "admin"-sourced rows are never
// touched by the config bootstrap at all. The remaining Phase 3+ tables
// (sanitizer_profiles, audit_log) are still out of scope here and land
// with the phases that need them.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
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
// RevokedAt is nil until an admin revokes the agent (issue #13) -- soft,
// never a hard delete, so agent_groups and any future audit references
// stay intact; AuthenticateAgent (internal/identity) must treat a revoked
// agent's otherwise-valid credentials the same as ErrInvalidCredentials.
type Agent struct {
	ID         int64
	ClientID   string
	SecretHash string
	Name       string
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

// Group is a named policy-assignment target. Membership tables
// (user_groups, agent_groups) exist and are assignable starting this
// phase, but nothing reads them for access decisions until Phase 3's
// policy engine.
type Group struct {
	ID   int64
	Name string
}

// ExternalIdentity links a JIT-provisioned (Mode B) user to the external
// IdP identity that provisioned it -- one row per (issuer, subject) a user
// has authenticated through.
type ExternalIdentity struct {
	ID        int64
	UserID    int64
	Issuer    string
	Subject   string
	CreatedAt time.Time
}

// PolicyRuleType distinguishes an ALLOW rule from a DENY rule -- Phase 3a's
// evaluator is explicitly not allow-only (design doc §5, MASTER_PLAN.md §6
// 2026-08-04): DENY rules express carve-outs without enumerating every
// other tool individually, and always win over a matching ALLOW.
type PolicyRuleType string

const (
	PolicyAllow PolicyRuleType = "allow"
	PolicyDeny  PolicyRuleType = "deny"
)

// Policy is one rule: principals in GroupID may (ALLOW) or may not (DENY)
// reach Node, restricted to Methods (empty = every method) and, only when
// Methods includes "tools/call", to Tools (empty = every tool). RateLimit*
// and BlockOnScanFlag are only consulted for ALLOW rules -- see
// internal/policy's evaluator for exactly how.
type Policy struct {
	ID                     int64
	GroupID                int64
	Node                   string
	RuleType               PolicyRuleType
	Methods                []string
	Tools                  []string
	RateLimitMaxCalls      *int
	RateLimitWindowSeconds *int
	BlockOnScanFlag        bool
	CreatedAt              time.Time
}

// NewPolicy is the input shape for ReplacePolicies -- the same fields as
// Policy minus ID/CreatedAt, which the store assigns.
type NewPolicy struct {
	GroupID                int64
	Node                   string
	RuleType               PolicyRuleType
	Methods                []string
	Tools                  []string
	RateLimitMaxCalls      *int
	RateLimitWindowSeconds *int
	BlockOnScanFlag        bool
}

// ToolPin is one tool's trust-on-first-observation baseline (issue #9):
// Hash covers name+description+inputSchema together, computed by
// internal/pin. InputSchema is the raw pinned inputSchema itself (issue
// #11) -- Hash alone can't be used for schema enforcement, since a hash
// can't be un-hashed back into the schema it was computed over; nil
// means no inputSchema was ever pinned (a tool that legitimately takes
// no structured arguments), not that one was pinned and is empty.
// QuarantinedAt is nil until a refresh observes a hash that no longer
// matches -- there is no re-approval mechanism in this phase, so once
// set it stays set until a human edits the store directly.
type ToolPin struct {
	ID            int64
	Node          string
	ToolName      string
	Hash          string
	InputSchema   *string
	PinnedAt      time.Time
	QuarantinedAt *time.Time
	DriftDetail   *string
}

// Node is one MCP server registered behind the gateway (issue #15).
// Source distinguishes a config.json-bootstrapped row ("config",
// upserted and kept authoritative on every startup via UpsertConfigNode
// -- the same "config wins" posture Policies already has) from one
// registered via the admin API ("admin" -- the only rows the admin API
// itself may delete). UpstreamURL/Command are pointers, not plain
// strings, because exactly one is meaningful per Transport, and the
// column is genuinely NULL for the other case, not just empty.
type Node struct {
	ID                        int64
	Name                      string
	Transport                 string
	UpstreamURL               *string
	Command                   *string
	Args                      []string
	PinRefreshIntervalSeconds *int
	Source                    string // "config" | "admin"
	CreatedAt                 time.Time
}

const (
	NodeSourceConfig = "config"
	NodeSourceAdmin  = "admin"
)

// AuditLogEntry is one persisted audit_log row (issue #23): an
// audit.Record together with the ID and hash-chain values it was
// actually stored with. Embeds audit.StoredRecord directly so a
// caller wanting to run audit.Verify against real rows (e.g.
// internal/audit/testdata/verifychain) doesn't need to convert field
// by field.
type AuditLogEntry struct {
	ID int64
	audit.StoredRecord
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
	// ListAgents returns every registered agent, revoked or not -- the
	// caller (issue #13's admin API) decides how to present that.
	ListAgents(ctx context.Context) ([]Agent, error)
	// RevokeAgent soft-revokes an agent (sets RevokedAt, never deletes the
	// row). Idempotent: revoking an already-revoked agent is not an error.
	// Returns ErrNotFound if no agent with this client_id exists.
	RevokeAgent(ctx context.Context, clientID string) error

	// GetUserByExternalIdentity resolves a user previously JIT-provisioned
	// for this (issuer, subject) pair. Returns ErrNotFound on first login.
	GetUserByExternalIdentity(ctx context.Context, issuer, subject string) (User, error)
	// LinkExternalIdentity records that userID was provisioned by/is
	// reachable via this (issuer, subject) pair.
	LinkExternalIdentity(ctx context.Context, userID int64, issuer, subject string) error
	// ResolveOrCreateExternalUser atomically resolves the existing user for
	// (issuer, subject), or creates one (with newUsername/newPasswordHash)
	// and links it, in a single transaction -- so two concurrent
	// first-logins for the same external identity can't race into two
	// different user rows. created reports whether a new user was made.
	ResolveOrCreateExternalUser(ctx context.Context, issuer, subject, newUsername, newPasswordHash string) (user User, created bool, err error)

	CreateGroup(ctx context.Context, name string) (Group, error)
	// GetGroupByName looks up a group by its unique name -- the
	// get-or-create bootstrap path (config-declared SeedAgents.Groups and
	// Policies, issue #7) needs this to resolve an already-existing group
	// after CreateGroup returns ErrConflict.
	GetGroupByName(ctx context.Context, name string) (Group, error)
	// ListGroups returns every group.
	ListGroups(ctx context.Context) ([]Group, error)
	// DeleteGroup removes a group. Returns ErrConflict if any policy row
	// still references it -- the groups/policies FK is ON DELETE CASCADE
	// at the schema level (so a raw DELETE would succeed by silently
	// wiping those policy rows too), but a group deletion silently
	// discarding an admin's configured allow/deny rules is exactly the
	// "dangling, confusing policy state" issue #13 exists to prevent, so
	// this checks and refuses first rather than relying on that cascade.
	DeleteGroup(ctx context.Context, name string) error
	AssignUserGroup(ctx context.Context, userID, groupID int64) error
	AssignAgentGroup(ctx context.Context, agentID, groupID int64) error
	// RemoveUserGroup/RemoveAgentGroup undo AssignUserGroup/AssignAgentGroup.
	// Idempotent: removing a membership that doesn't exist is not an error.
	RemoveUserGroup(ctx context.Context, userID, groupID int64) error
	RemoveAgentGroup(ctx context.Context, agentID, groupID int64) error
	UserGroups(ctx context.Context, userID int64) ([]Group, error)
	AgentGroups(ctx context.Context, agentID int64) ([]Group, error)

	// ReplacePolicies atomically replaces the entire policies table with
	// the given set. Config is the sole source of policy truth in this
	// phase (no admin API exists yet, issue #7) -- unlike identity data
	// (users/agents, which must never be silently regenerated on
	// restart), policy has no independent state of its own beyond config,
	// so treating config as the complete desired state and reapplying it
	// fresh on every startup is simpler and safer than diffing or
	// accumulating stale rules across restarts.
	ReplacePolicies(ctx context.Context, policies []NewPolicy) error
	// PoliciesForGroups returns every policy rule attached to any of
	// groupIDs, scoped to node -- the evaluator's hot-path query.
	PoliciesForGroups(ctx context.Context, groupIDs []int64, node string) ([]Policy, error)
	// AllPolicies returns every policy row, unfiltered -- issue #13's
	// admin API view, not scoped to any one principal the way
	// PoliciesForGroups is.
	AllPolicies(ctx context.Context) ([]Policy, error)

	// GetToolPin looks up one (node, tool_name) pin. Returns ErrNotFound
	// if this tool has never been observed for this node -- the caller
	// (internal/pin) treats that as "TOFU: establish a new pin," not an
	// error.
	GetToolPin(ctx context.Context, node, toolName string) (ToolPin, error)
	// CreateToolPin establishes a new pin (TOFU) with no quarantine.
	// inputSchema is the tool's raw pinned inputSchema (issue #11's
	// schema-enforcement seam reads it back later); pass "" for a tool
	// with no inputSchema. Returns ErrConflict if a pin for this
	// (node, tool_name) already exists -- the caller should treat that as
	// a logic error (TOFU only ever applies once per tool), not something
	// to silently overwrite.
	CreateToolPin(ctx context.Context, node, toolName, hash, inputSchema string) (ToolPin, error)
	// QuarantineToolPin marks an existing pin as drifted, persisting
	// driftDetail for later investigation (story 12). Idempotent: calling
	// it again just updates the detail/timestamp, it doesn't error on an
	// already-quarantined pin.
	QuarantineToolPin(ctx context.Context, node, toolName, driftDetail string) error
	// ToolPinsForNode returns every pin for node, for building a
	// quarantine set once per tools/list filter call rather than querying
	// per tool name.
	ToolPinsForNode(ctx context.Context, node string) ([]ToolPin, error)

	// CreateNode registers a new node. Returns ErrConflict if a node with
	// this name already exists, regardless of source.
	CreateNode(ctx context.Context, n Node) (Node, error)
	// GetNodeByName looks up one node. Returns ErrNotFound if none
	// exists.
	GetNodeByName(ctx context.Context, name string) (Node, error)
	// UpsertConfigNode creates a "config"-sourced node, or -- if a node
	// with this name already exists and is itself "config"-sourced --
	// updates its transport/upstream_url/command/args/
	// pin_refresh_interval_seconds in place. Returns ErrConflict if a
	// node with this name already exists with source "admin" -- config
	// must never silently overwrite an admin-registered node just
	// because a later config.json happens to reuse its name.
	UpsertConfigNode(ctx context.Context, n Node) (Node, error)
	// ListNodes returns every node, any source, in a stable order.
	ListNodes(ctx context.Context) ([]Node, error)
	// DeleteNode removes a node by name. Returns ErrNotFound if none
	// exists. Callers (internal/adminapi) are responsible for refusing to
	// delete a "config"-sourced row -- this method is a dumb CRUD
	// surface, not where that policy lives.
	DeleteNode(ctx context.Context, name string) error

	// RevokeJTI denylists a token's jti until expiresAt (its own natural
	// expiry -- no point keeping a revocation past the point the token
	// would've stopped validating anyway).
	RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
	// LoadRevocations returns every not-yet-expired revocation, for
	// hydrating the authserver's in-memory denylist on startup.
	LoadRevocations(ctx context.Context) ([]Revocation, error)

	// AppendAuditRecord persists rec as the new last entry in the
	// hash-chained audit log (issue #23): inside one transaction, reads
	// the current last row's hash (or audit.GenesisPrevHash if the
	// table is empty), computes the new row's hash via audit.Hash, and
	// inserts. Deliberately the only write method this package offers
	// for audit_log -- there is no update or delete of any kind, so
	// there is no code path that could alter a record after it's
	// written.
	AppendAuditRecord(ctx context.Context, rec audit.Record) (AuditLogEntry, error)
	// ListAuditRecords returns every audit_log row in chain order
	// (ascending id) -- the read side audit.Verify runs against.
	ListAuditRecords(ctx context.Context) ([]AuditLogEntry, error)
	// ListAuditRecordsPage returns up to limit audit_log rows in
	// descending id order (most recent first), starting just before
	// beforeID (beforeID == 0 means "start from the most recent
	// record") -- the admin UI's audit viewer (issue #25) reads
	// through this, never ListAuditRecords, which exists for
	// audit.Verify's different need (the whole chain, in order). limit
	// <= 0 falls back to DefaultAuditPageSize; limit above
	// MaxAuditPageSize is clamped to it -- a single request can never
	// force the whole table to serialize.
	ListAuditRecordsPage(ctx context.Context, limit int, beforeID int64) ([]AuditLogEntry, error)
}

// DefaultAuditPageSize and MaxAuditPageSize bound ListAuditRecordsPage
// (issue #25): the former is used when a caller passes a non-positive
// limit, the latter is the hard ceiling no requested limit can exceed.
const (
	DefaultAuditPageSize = 20
	MaxAuditPageSize     = 100
)
