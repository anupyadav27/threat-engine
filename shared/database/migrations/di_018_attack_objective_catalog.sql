-- di_018_attack_objective_catalog.sql
-- Creates the attack_objective_catalog table in threat_engine_di.
-- Stores the multi-CSP service → attack objective mapping loaded from
-- catalog/attack_objectives/*.yaml by upload_objective_catalog.py.
--
-- objective_type values:
--   DATA_THEFT | DATA_DESTRUCTION | SECRET_THEFT | DECRYPTION
--   PRIVILEGE_ESCALATION | CLUSTER_TAKEOVER | ACCOUNT_TAKEOVER
--   AI_MODEL_ACCESS | CODE_ACCESS
--
-- required_capability: the edge type that must exist on the final hop
-- for a path to fully satisfy the objective (CAN_READ, CAN_DECRYPT, etc.)
--
-- crown_jewel_type: link to existing classification vocabulary used by
-- crown_jewel_classifier.py so existing paths remain compatible.

CREATE TABLE IF NOT EXISTS attack_objective_catalog (
    id                  SERIAL PRIMARY KEY,
    objective_type      VARCHAR(50)  NOT NULL,
    description         TEXT,
    provider            VARCHAR(20)  NOT NULL,
    resource_type       VARCHAR(120) NOT NULL,
    service_category    VARCHAR(50),
    service_subcategory VARCHAR(60),
    required_capability VARCHAR(50)  NOT NULL,
    crown_jewel_type    VARCHAR(50),
    mitre_technique     VARCHAR(20),
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_attack_objective_resource
        UNIQUE (objective_type, provider, resource_type)
);

CREATE INDEX IF NOT EXISTS idx_aoc_provider_rtype
    ON attack_objective_catalog (provider, resource_type)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_aoc_objective
    ON attack_objective_catalog (objective_type)
    WHERE is_active = TRUE;

-- Fallback derivation table: crown_jewel_type + access_capability → objective_type.
-- Used when a resource_type is not yet in attack_objective_catalog.
CREATE TABLE IF NOT EXISTS attack_objective_fallback (
    id                  SERIAL PRIMARY KEY,
    crown_jewel_type    VARCHAR(50)  NOT NULL,
    access_capability   VARCHAR(50)  NOT NULL DEFAULT '*',
    objective_type      VARCHAR(50)  NOT NULL,
    required_capability VARCHAR(50)  NOT NULL,

    CONSTRAINT uq_aof_cj_cap
        UNIQUE (crown_jewel_type, access_capability)
);

INSERT INTO attack_objective_fallback
    (crown_jewel_type, access_capability, objective_type, required_capability)
VALUES
    ('data',               'can_read',    'DATA_THEFT',           'can_read'),
    ('data',               'can_write',   'DATA_DESTRUCTION',     'can_write'),
    ('data',               '*',           'DATA_THEFT',           'can_read'),
    ('data_warehouse',     '*',           'DATA_THEFT',           'can_read'),
    ('encryption_control', 'can_decrypt', 'DECRYPTION',           'can_decrypt'),
    ('encryption_control', 'can_read',    'SECRET_THEFT',         'can_read'),
    ('encryption_control', '*',           'SECRET_THEFT',         'can_read'),
    ('secrets',            '*',           'SECRET_THEFT',         'can_read'),
    ('identity',           'can_assume',  'PRIVILEGE_ESCALATION', 'can_assume'),
    ('identity',           '*',           'PRIVILEGE_ESCALATION', 'can_assume'),
    ('infra_control',      '*',           'CLUSTER_TAKEOVER',     'can_assume'),
    ('ai_model',           'can_invoke',  'AI_MODEL_ACCESS',      'can_invoke'),
    ('ai_model',           '*',           'AI_MODEL_ACCESS',      'can_invoke'),
    ('code',               '*',           'CODE_ACCESS',          'can_read')
ON CONFLICT (crown_jewel_type, access_capability) DO NOTHING;

DO $$ BEGIN RAISE NOTICE 'di_018: attack_objective_catalog + attack_objective_fallback created'; END $$;
