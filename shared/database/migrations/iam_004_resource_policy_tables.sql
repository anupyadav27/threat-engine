-- iam_004: IAM resource policy and action-resource mapping tables
-- Written to threat_engine_iam. Drives IAM resource policy edge derivation.
-- Seeded by: catalog/iam/upload_iam_policy_rules.py

BEGIN;

-- ── Table 1: iam_resource_policy_rules ──────────────────────────────────────
-- Maps (csp, resource_type) → where to find the attached resource policy
-- and how to derive GRANTS_ACCESS_TO edges from it.
CREATE TABLE IF NOT EXISTS iam_resource_policy_rules (
    id                  BIGSERIAL PRIMARY KEY,
    csp                 VARCHAR(50)  NOT NULL,
    resource_type       VARCHAR(200) NOT NULL,   -- e.g. s3.bucket, sqs.queue
    policy_field        VARCHAR(200) NOT NULL,   -- field in emitted_fields with policy JSON
    principal_key       VARCHAR(200),            -- key inside Principal block (AWS, Service, Federated)
    relation_type       VARCHAR(100) NOT NULL DEFAULT 'GRANTS_ACCESS_TO',
    attack_path_category VARCHAR(50) NOT NULL DEFAULT 'data_access',
    description         TEXT,
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT uq_rpr_rule UNIQUE (csp, resource_type, policy_field, principal_key)
);

CREATE INDEX IF NOT EXISTS idx_rpr_csp_type
    ON iam_resource_policy_rules (csp, resource_type)
    WHERE is_active = TRUE;

-- ── Table 2: iam_action_resource_map ────────────────────────────────────────
-- Maps action prefixes to the resource types they operate on.
-- Used to expand wildcard Resource:* policy statements into CAN_ACCESS edges.
CREATE TABLE IF NOT EXISTS iam_action_resource_map (
    id                  BIGSERIAL PRIMARY KEY,
    csp                 VARCHAR(50)  NOT NULL,
    action_prefix       VARCHAR(100) NOT NULL,   -- e.g. s3:, rds:, secretsmanager:
    resource_types      TEXT[]       NOT NULL,   -- resource types this prefix operates on
    attack_path_category VARCHAR(50) NOT NULL DEFAULT 'lateral_movement',
    description         TEXT,
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT uq_arm_rule UNIQUE (csp, action_prefix)
);

CREATE INDEX IF NOT EXISTS idx_arm_csp
    ON iam_action_resource_map (csp)
    WHERE is_active = TRUE;

COMMIT;
