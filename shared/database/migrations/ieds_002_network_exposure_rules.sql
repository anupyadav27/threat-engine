-- =============================================================================
-- IEDS-M02: Internet & External Exposure Detection System
-- Database: threat_engine_network
-- Table:    network_exposure_rules
-- =============================================================================
-- Stores YAML-defined exposure detection rules across all CSPs and tiers.
-- Loaded by: scripts/load_exposure_rules.py from catalog/rule/network_exposure/
-- Tier 1: no conditions (catalog flag only; exposure_conditions is empty)
-- Tier 2: simple emitted-field checks (exposure_conditions JSONB)
-- Tier 3: multi-step graph traversal (traversal_steps JSONB)
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS network_exposure_rules (
    rule_id                 VARCHAR(64)  PRIMARY KEY,
    tier                    SMALLINT     NOT NULL,
    csp                     VARCHAR(32)  NOT NULL,
    resource_type           VARCHAR(128) NOT NULL,
    origin_type             VARCHAR(64)  NOT NULL,
    title                   VARCHAR(512) NOT NULL,
    description             TEXT,
    severity                VARCHAR(20)  NOT NULL DEFAULT 'high',

    -- CI gate: fields that MUST exist in the discovery YAML emit block
    required_emitted_fields TEXT[]       DEFAULT ARRAY[]::TEXT[],

    -- Tier 2: [{field, operator, value}] — simple field-value checks
    exposure_conditions     JSONB        DEFAULT '[]'::jsonb,

    -- Tier 3: [{step, source, check, field, operator, value, traverse, target_type, relation}]
    traversal_steps         JSONB        DEFAULT '[]'::jsonb,

    is_active               BOOLEAN      DEFAULT TRUE,
    loaded_from             VARCHAR(512),
    loaded_at               TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT chk_ner_tier CHECK (tier IN (1, 2, 3)),
    CONSTRAINT chk_ner_csp  CHECK (csp IN ('aws','azure','gcp','oci','alicloud','ibm','k8s','all'))
);

CREATE INDEX IF NOT EXISTS idx_ner_csp_type ON network_exposure_rules(csp, resource_type) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_ner_tier     ON network_exposure_rules(tier) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_ner_origin   ON network_exposure_rules(origin_type) WHERE is_active;

COMMENT ON TABLE network_exposure_rules IS
    'YAML-loaded internet/external exposure detection rules (Tier 1-3). Loaded by scripts/load_exposure_rules.py.';

COMMIT;
