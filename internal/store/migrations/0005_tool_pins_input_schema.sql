-- Phase 3c (issue #11): schema enforcement needs the tool's actual
-- pinned inputSchema, not just its hash -- tool_pins (0004) deliberately
-- stored only a combined hash for drift detection, which has no way to
-- reconstruct the original schema bytes. NULL means no inputSchema was
-- ever pinned for this tool (a tool that legitimately takes no
-- structured arguments) -- schema enforcement must skip validation in
-- that case, not treat it as a violation.
ALTER TABLE tool_pins ADD COLUMN input_schema TEXT;
