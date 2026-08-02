// Package store abstracts persistence. SQLite (modernc.org/sqlite, no cgo)
// is the phase-1 implementation; Postgres arrives with HA (design doc §8).
package store

// Store is a placeholder seam. The real interface lands with the sqlite
// implementation and migrations for: users, agents, groups, mcp_nodes,
// tool_pins, policies, sanitizer_profiles, idp_trust, revocations, audit_log.
type Store interface {
	Ping() error
}
