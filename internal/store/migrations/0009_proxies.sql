-- Issue #63 (design.md §10, self-hosted fleet control plane, Phase 1):
-- a proxy is a new principal kind, structurally identical to agents
-- (client_credentials-style client_id/secret_hash pairing, soft
-- revocation) but semantically distinct -- a proxy authenticates to a
-- control plane to pull/receive policy, it never calls tools/call
-- against a node the way an agent does, so it gets its own table
-- rather than a shared "kind" column on agents (avoids touching any
-- existing Agent code, schema, or tests).
CREATE TABLE proxies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    name        TEXT NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  TIMESTAMP
);
