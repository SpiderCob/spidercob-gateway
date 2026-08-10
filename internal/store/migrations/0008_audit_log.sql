-- Phase 4c-4 (issue #23): hash-chained audit trail. Currently written
-- to by internal/adminapi.logAdminAction only -- one row per successful
-- admin mutation. ts is set explicitly by the application (not
-- DEFAULT CURRENT_TIMESTAMP) because it must be the exact value hashed
-- into audit.Hash; a DB-assigned default the app never sees couldn't be
-- verified against. Genuinely append-only: no UPDATE/DELETE of this
-- table exists anywhere in store.Store's interface, on purpose.
CREATE TABLE audit_log (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                    TIMESTAMP NOT NULL,
    actor_nhi_subject     TEXT,
    actor_human_username  TEXT NOT NULL,
    actor_human_role      TEXT NOT NULL,
    action                TEXT NOT NULL,
    resource              TEXT NOT NULL,
    prev_hash             TEXT NOT NULL,
    hash                  TEXT NOT NULL
);
