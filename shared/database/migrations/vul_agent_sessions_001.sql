-- Migration: vul_agent_sessions
-- Purpose: Local auth table for vulnerability agent scan submissions.
--          Populated once at agent register time. Eliminates per-scan onboarding call.

BEGIN;

CREATE TABLE IF NOT EXISTS vul_agent_sessions (
    id              SERIAL PRIMARY KEY,
    agent_id        VARCHAR(20)  NOT NULL,
    account_id      UUID         NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    api_key_hash    VARCHAR(64)  NOT NULL,
    status          VARCHAR(20)  NOT NULL DEFAULT 'active',
    hostname        VARCHAR(255),
    resource_uid    VARCHAR(512),
    provisioned_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ,

    UNIQUE (agent_id)
);

CREATE INDEX IF NOT EXISTS idx_vul_sessions_agent     ON vul_agent_sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_vul_sessions_account   ON vul_agent_sessions(account_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_vul_sessions_api_key   ON vul_agent_sessions(api_key_hash);

COMMIT;
