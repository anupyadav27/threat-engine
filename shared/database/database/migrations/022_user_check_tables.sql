-- =============================================================================
-- Migration 022: user_check_rules + user_check_discoveries
--
-- Stores user-created rules and discoveries built via the Rule Builder wizard.
-- Schema mirrors rule_checks / rule_discoveries so the check engine can consume
-- them with zero code changes (same JSONB contract, same is_active / source cols).
-- =============================================================================

-- ---------------------------------------------------------------------------
-- user_check_rules
-- Same template as rule_checks, with additional flat columns for UI querying
-- (severity, category, title, description, frameworks, for_each, conditions)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_check_rules (
    id               SERIAL          PRIMARY KEY,

    -- Core identity (same as rule_checks)
    rule_id          VARCHAR(255)    NOT NULL,
    service          VARCHAR(100)    NOT NULL,
    provider         VARCHAR(50)     NOT NULL DEFAULT 'aws',

    -- User-facing metadata (extra vs rule_checks)
    severity         VARCHAR(20)     NOT NULL DEFAULT 'medium',
    category         VARCHAR(100),
    title            TEXT            NOT NULL,
    description      TEXT,

    -- Rule logic (flat columns for querying + JSONB for full tree)
    for_each         VARCHAR(255)    NOT NULL,          -- discovery_id this rule iterates over
    conditions       JSONB           NOT NULL DEFAULT '{}'::jsonb,  -- condition tree as JSON
    condition_logic  VARCHAR(10)     NOT NULL DEFAULT 'all',        -- all | any
    frameworks       JSONB           NOT NULL DEFAULT '[]'::jsonb,  -- ["CIS","NIST 800-53",...]

    -- Same template as rule_checks
    check_type       VARCHAR(50)     NOT NULL DEFAULT 'user',
    check_config     JSONB           NOT NULL DEFAULT '{}'::jsonb,  -- check-engine compatible payload
    version          VARCHAR(50)              DEFAULT '1.0',
    source           VARCHAR(50)     NOT NULL DEFAULT 'user',
    generated_by     VARCHAR(50)              DEFAULT 'rule_builder',

    -- Multi-tenancy (same as rule_checks)
    tenant_id        VARCHAR(255),
    customer_id      VARCHAR(255),

    is_active        BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ              DEFAULT NOW(),
    updated_at       TIMESTAMPTZ              DEFAULT NOW(),

    UNIQUE (rule_id, tenant_id)
    -- No FK to rule_checks — user rules are independent
);

-- ---------------------------------------------------------------------------
-- user_check_discoveries
-- Same template as rule_discoveries, with flat action / items_for / item_fields
-- columns for introspection. discoveries_data JSONB is fully compatible with
-- the format rule_discoveries.discoveries_data uses.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_check_discoveries (
    id               SERIAL          PRIMARY KEY,

    -- Core identity
    discovery_id     VARCHAR(255)    NOT NULL,   -- e.g. aws.ec2.describe_instances
    service          VARCHAR(100)    NOT NULL,
    provider         VARCHAR(50)     NOT NULL DEFAULT 'aws',

    -- Flat fields for introspection
    action           VARCHAR(255)    NOT NULL,   -- yaml_action / python_method
    items_for        TEXT,                        -- e.g. {{ response.Reservations }}
    item_fields      JSONB           NOT NULL DEFAULT '{}'::jsonb, -- {FieldName: '{{ item.FieldName }}', ...}

    -- Full JSONB payload compatible with rule_discoveries.discoveries_data
    discoveries_data JSONB           NOT NULL DEFAULT '[]'::jsonb,

    -- Same template as rule_discoveries
    version          VARCHAR(20)              DEFAULT '1.0',
    source           VARCHAR(50)     NOT NULL DEFAULT 'user',
    generated_by     VARCHAR(50)              DEFAULT 'rule_builder',

    -- Multi-tenancy
    tenant_id        VARCHAR(255),
    customer_id      VARCHAR(255),

    is_active        BOOLEAN         NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ              DEFAULT NOW(),
    updated_at       TIMESTAMPTZ              DEFAULT NOW(),

    UNIQUE (discovery_id, tenant_id)
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_ucr_service_provider  ON user_check_rules(service, provider);
CREATE INDEX IF NOT EXISTS idx_ucr_tenant            ON user_check_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ucr_severity          ON user_check_rules(severity);
CREATE INDEX IF NOT EXISTS idx_ucr_for_each          ON user_check_rules(for_each);
CREATE INDEX IF NOT EXISTS idx_ucr_is_active         ON user_check_rules(is_active);
CREATE INDEX IF NOT EXISTS idx_ucr_source            ON user_check_rules(source);

CREATE INDEX IF NOT EXISTS idx_ucd_discovery_id      ON user_check_discoveries(discovery_id);
CREATE INDEX IF NOT EXISTS idx_ucd_service_provider  ON user_check_discoveries(service, provider);
CREATE INDEX IF NOT EXISTS idx_ucd_tenant            ON user_check_discoveries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ucd_is_active         ON user_check_discoveries(is_active);

-- ---------------------------------------------------------------------------
-- Comments
-- ---------------------------------------------------------------------------
COMMENT ON TABLE user_check_rules IS
  'User-created check rules built via the Rule Builder wizard. Same schema template as rule_checks (source=user, check_type=user).';

COMMENT ON TABLE user_check_discoveries IS
  'User-created discovery definitions. Same schema template as rule_discoveries (source=user). discoveries_data is check-engine compatible.';
