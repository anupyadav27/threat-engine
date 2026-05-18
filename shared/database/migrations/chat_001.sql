-- =============================================================================
-- Migration: chat_001.sql
-- Target DB: threat_engine_inventory
-- Creates: chat_sessions, chat_messages, quick_questions
-- =============================================================================

BEGIN;

-- ── Chat sessions ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chat_sessions (
    session_id  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   VARCHAR(255) NOT NULL,
    user_id     VARCHAR(255) NOT NULL,
    title       VARCHAR(500) NOT NULL DEFAULT 'New Chat',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_tenant  ON chat_sessions(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_sessions_user    ON chat_sessions(user_id, tenant_id);

-- ── Chat messages ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chat_messages (
    message_id       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id       UUID         NOT NULL REFERENCES chat_sessions(session_id) ON DELETE CASCADE,
    tenant_id        VARCHAR(255) NOT NULL,
    role             VARCHAR(20)  NOT NULL CHECK (role IN ('user', 'assistant')),
    content          TEXT         NOT NULL,
    generated_query  TEXT,
    query_type       VARCHAR(20)  CHECK (query_type IN ('sql', 'cypher', 'api', 'none')),
    latency_ms       INTEGER,
    token_count      INTEGER,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_session  ON chat_messages(session_id, created_at);
CREATE INDEX IF NOT EXISTS idx_chat_messages_tenant   ON chat_messages(tenant_id, created_at DESC);

-- ── Quick questions (platform-wide seed data, no tenant scope) ────────────────
CREATE TABLE IF NOT EXISTS quick_questions (
    id               SERIAL       PRIMARY KEY,
    category         VARCHAR(100) NOT NULL,
    question_text    TEXT         NOT NULL,
    description      TEXT,
    min_role_level   INTEGER      NOT NULL DEFAULT 4,  -- 4=viewer+, 1=platform_admin only
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    sort_order       INTEGER      NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_quick_questions_active ON quick_questions(is_active, category, sort_order);

-- ── Seed quick questions ──────────────────────────────────────────────────────
INSERT INTO quick_questions (category, question_text, description, min_role_level, sort_order) VALUES

-- Security Posture
('Security Posture', 'How many critical findings do we have right now?',
 'Total critical severity findings across all engines', 4, 1),
('Security Posture', 'Which cloud accounts have the lowest security posture score?',
 'Ranked list of accounts by overall posture score', 4, 2),
('Security Posture', 'Show me all findings from the last 7 days by severity',
 'Recent findings breakdown with severity distribution', 4, 3),

-- Compliance
('Compliance', 'What is our PCI-DSS compliance score this month?',
 'Framework score and control pass/fail summary', 4, 10),
('Compliance', 'Which compliance frameworks are we failing?',
 'All frameworks with score below 80%', 4, 11),
('Compliance', 'Show me the top 10 failing controls across all frameworks',
 'Most common control failures impacting multiple frameworks', 4, 12),

-- Threats & Attack Paths
('Threats', 'What are the top 5 attack paths to crown jewel assets?',
 'Highest-risk attack paths with blast radius', 4, 20),
('Threats', 'Which resources have both critical CVEs and network exposure?',
 'Resources at highest combined risk from vulnerability + network posture', 4, 21),
('Threats', 'What is the blast radius if our most critical EC2 is compromised?',
 'Lateral movement paths and affected resource count', 4, 22),

-- Inventory & Access
('Inventory', 'How many resources were discovered in the last scan?',
 'Resource count by type and cloud provider', 4, 30),
('Inventory', 'Show me all publicly exposed S3 buckets',
 'S3 buckets with public access enabled across all accounts', 4, 31),

-- IAM & Access
('Access', 'Which IAM users have not rotated their access keys in 90 days?',
 'Stale access keys by account and user', 4, 40),
('Access', 'Show me all IAM roles with wildcard permissions',
 'Overprivileged roles with * actions or * resources', 4, 41),
('Access', 'Which resources have cross-account access configured?',
 'Resources allowing access from outside the primary account', 4, 42),

-- CDR / Detections
('Detections', 'Were there any suspicious login attempts in the last 24 hours?',
 'CDR identity threat detections and auth failure spikes', 4, 50)

ON CONFLICT DO NOTHING;

COMMIT;
