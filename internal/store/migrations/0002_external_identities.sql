-- Phase 2b (issue #5): JIT-provisioned users are resolved-or-created by
-- keying off an external IdP's (issuer, subject) pair, kept as its own
-- mapping table rather than nullable columns on users -- Mode A
-- (password) and Mode B (externally-authenticated) accounts stay
-- structurally uniform in `users`.
CREATE TABLE external_identities (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (issuer, subject)
);
