-- Phase 2a identity core (issue #3). Phase 3+ tables (mcp_nodes, tool_pins,
-- policies, sanitizer_profiles, idp_trust, audit_log) land in later
-- migrations, not here.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    name        TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE groups (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE user_groups (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE agent_groups (
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (agent_id, group_id)
);

-- Persisted mirror of the authserver's in-memory jti denylist (design doc
-- §7: in-memory is single-process only; this table is what survives a
-- restart, not a replacement for the in-memory check on the hot path).
CREATE TABLE revocations (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
