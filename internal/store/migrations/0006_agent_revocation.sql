-- Phase 4 (issue #13): the admin API needs to revoke an agent (NHI)
-- immediately, without losing referential integrity with agent_groups or
-- any future audit references -- soft revocation (a nullable timestamp),
-- not a hard DELETE, the same posture the revocations table already
-- takes for individual tokens. NULL means never revoked.
ALTER TABLE agents ADD COLUMN revoked_at TIMESTAMP;
