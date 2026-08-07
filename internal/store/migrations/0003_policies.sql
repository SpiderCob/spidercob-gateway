-- Phase 3a (issue #7): the real policy evaluator's rule storage. Config is
-- the sole source of policy truth in this phase (no admin API exists yet)
-- -- see store.ReplacePolicies's doc comment for why a full replace on
-- every startup is the chosen bootstrap semantics, unlike identity data.
CREATE TABLE policies (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id                   INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    node                       TEXT NOT NULL,
    rule_type                  TEXT NOT NULL CHECK (rule_type IN ('allow', 'deny')),
    -- JSON string arrays. Empty array ("[]") means "matches every method"
    -- (methods) or "matches every tool" (tools, only meaningful when
    -- methods includes tools/call) -- see internal/policy's matching logic.
    methods                    TEXT NOT NULL DEFAULT '[]',
    tools                      TEXT NOT NULL DEFAULT '[]',
    rate_limit_max_calls       INTEGER,
    rate_limit_window_seconds  INTEGER,
    block_on_scan_flag         INTEGER NOT NULL DEFAULT 0,
    created_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_policies_group_node ON policies(group_id, node);
