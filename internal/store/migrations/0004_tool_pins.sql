-- Phase 3b (issue #9): tool pinning / rug-pull defense. A pin is
-- established via TOFU (trust on first observation, internal/pin.Registry)
-- and must persist across restarts -- see internal/pin's doc comment for
-- why re-establishing on every boot would make the whole defense
-- trivially bypassable.
CREATE TABLE tool_pins (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    -- node is the config-defined node name (no persisted mcp_nodes table
    -- exists yet), same posture as policies/trusted_idps/seed_agents.
    node           TEXT NOT NULL,
    tool_name      TEXT NOT NULL,
    -- hash covers name+description+inputSchema together (one combined
    -- hash, not separate schema/description columns -- see internal/pin
    -- for the canonicalization this is computed over).
    hash           TEXT NOT NULL,
    pinned_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- NULL means not quarantined. Set the moment a refresh observes a
    -- hash that no longer matches -- there is no re-approval mechanism in
    -- this phase (Phase 4), so once set this stays set until a human
    -- edits the store directly.
    quarantined_at TIMESTAMP,
    drift_detail   TEXT,
    UNIQUE (node, tool_name)
);
