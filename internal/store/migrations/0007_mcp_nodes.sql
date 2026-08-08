-- Phase 4b (issue #15): MCP node persistence. A row's source
-- distinguishes a config.json-bootstrapped node ("config", upserted and
-- kept authoritative on every startup -- see store.UpsertConfigNode) from
-- one registered via the admin API ("admin", the only rows the admin API
-- may delete). No canonical_uri/upstream_auth/status/health columns from
-- design doc §8's original sketch: canonical_uri is derived
-- (issuer + "/mcp/" + name), not stored; upstream_auth/status/health
-- aren't implemented anywhere in the transport layer yet and would be
-- dead schema.
CREATE TABLE mcp_nodes (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    name                          TEXT NOT NULL UNIQUE,
    transport                     TEXT NOT NULL,
    upstream_url                  TEXT,
    command                       TEXT,
    args                          TEXT, -- JSON array, NULL means none
    pin_refresh_interval_seconds  INTEGER,
    source                        TEXT NOT NULL CHECK (source IN ('config', 'admin')),
    created_at                    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
