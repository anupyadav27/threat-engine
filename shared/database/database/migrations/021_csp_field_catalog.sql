-- ============================================================================
-- Migration 021: CSP Field Catalog
-- ============================================================================
-- Purpose:
--   Stores the field-level discovery catalog for all CSPs (OCI, AWS, Azure, GCP).
--   This is the "field picker" backing table for the rule builder UI and the
--   single source of truth for what fields each CSP service produces.
--
-- Architecture:
--   oci_field_rule_catalog.csv  →  (loader script)  →  csp_field_catalog (this table)
--                                                    →  rule_metadata      (existing)
--                                                    →  rule_checks        (existing)
--                                                    →  rule_discoveries   (existing)
--
-- Rule lifecycle:
--   CREATE rule  = INSERT into rule_metadata + rule_checks (check_config JSONB)
--   DELETE rule  = UPDATE rule_checks SET is_active = FALSE
--   LIST fields  = SELECT from csp_field_catalog WHERE service = ?
--   SCAN time    = SELECT from rule_checks + rule_discoveries (unchanged engine path)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- for fast text search on field_path

-- ============================================================================
-- CSP FIELD CATALOG
-- ============================================================================
-- One row per (csp, service, field_path).
-- Stores discovery chain + field type + operator metadata.
-- Used by: rule builder UI (field picker, operator options, value guidance).

CREATE TABLE IF NOT EXISTS csp_field_catalog (
    id                   BIGSERIAL       PRIMARY KEY,

    -- Identity
    csp                  VARCHAR(20)     NOT NULL,           -- oci, aws, azure, gcp
    service              VARCHAR(100)    NOT NULL,           -- e.g. object_storage
    field_path           VARCHAR(300)    NOT NULL,           -- e.g. bucket.kms_key_id
    item_var_path        VARCHAR(300)    NOT NULL,           -- e.g. item.bucket.kms_key_id

    -- Field metadata
    field_type           VARCHAR(30),                        -- string, boolean, object, array
    is_id                BOOLEAN         DEFAULT FALSE,      -- true = this IS an identifier field

    -- Resource context
    resource_type        VARCHAR(100),                       -- e.g. bucket, autonomous_database
    resource_id_field    VARCHAR(100)    DEFAULT 'ocid',     -- field that is the resource key
    resource_id_param    VARCHAR(150),                       -- SDK param for get_ op (e.g. bucket_id)

    -- Discovery / producing operation
    producing_op         VARCHAR(250),                       -- e.g. oci.object_storage.get_bucket
    op_kind              VARCHAR(20),                        -- read_list, read_get, read_describe
    is_independent       BOOLEAN         DEFAULT TRUE,       -- true = only needs compartment_id

    -- Dependency chain (how to reach this field)
    root_op              VARCHAR(250),                       -- root independent op (for_each target)
    chain_ops            TEXT,                               -- 'oci.svc.list_X → oci.svc.get_X'
    chain_length         SMALLINT        DEFAULT 1,
    hop_distance         SMALLINT        DEFAULT 0,

    -- SDK call details
    python_call          TEXT,                               -- e.g. BucketClient().list_buckets(...)
    http_path            VARCHAR(300),                       -- e.g. /n/{namespaceName}/b

    -- Operator metadata (drives UI field picker validation)
    operators            TEXT,                               -- 'equals, exists, not_equals'
    operators_no_value   TEXT,                               -- operators that need no value
    operators_select_list TEXT,                              -- operators requiring enum select
    operators_manual_input TEXT,                             -- operators requiring free text

    -- Timestamps
    created_at           TIMESTAMPTZ     DEFAULT NOW(),
    updated_at           TIMESTAMPTZ     DEFAULT NOW(),

    UNIQUE (csp, service, field_path)
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Primary access patterns for rule builder UI
CREATE INDEX IF NOT EXISTS idx_field_catalog_service
    ON csp_field_catalog(csp, service);

CREATE INDEX IF NOT EXISTS idx_field_catalog_resource
    ON csp_field_catalog(csp, service, resource_type);

-- Field search (user types partial field name)
CREATE INDEX IF NOT EXISTS idx_field_catalog_path_trgm
    ON csp_field_catalog USING gin(field_path gin_trgm_ops);

-- Dependency chain lookups (build discovery YAML)
CREATE INDEX IF NOT EXISTS idx_field_catalog_root_op
    ON csp_field_catalog(csp, service, root_op)
    WHERE root_op IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_field_catalog_independent
    ON csp_field_catalog(csp, service, is_independent);

-- ============================================================================
-- RULE BUILDER VIEW
-- ============================================================================
-- Convenience view: for each field, show what rule conditions are valid.
-- Used by UI to populate the "add rule" form.

CREATE OR REPLACE VIEW v_rule_builder_fields AS
SELECT
    fc.csp,
    fc.service,
    fc.resource_type,
    fc.field_path,
    fc.item_var_path,
    fc.field_type,
    fc.is_id,
    fc.operators,
    fc.operators_no_value,
    fc.operators_select_list,
    fc.operators_manual_input,
    fc.resource_id_field,
    fc.resource_id_param,
    fc.root_op              AS check_for_each,   -- auto-fill in rule builder
    fc.chain_ops,
    fc.chain_length,
    -- Count existing active rules on this field (shows if field is already covered)
    COUNT(rc.id)            AS existing_rule_count
FROM csp_field_catalog fc
LEFT JOIN rule_checks rc
    ON  rc.service    = fc.service
    AND rc.provider   = fc.csp
    AND rc.is_active  = TRUE
    AND (rc.check_config->>'var') = fc.item_var_path
GROUP BY fc.id;

-- ============================================================================
-- RULE BUILDER HELPER: auto-fill for_each and var from field selection
-- ============================================================================
-- When user picks a field, engine calls:
--   SELECT check_for_each, item_var_path, operators, field_type
--   FROM v_rule_builder_fields
--   WHERE csp = ? AND service = ? AND field_path = ?
-- Then pre-fills for_each and var in the rule form.

COMMENT ON TABLE csp_field_catalog IS
    'Field-level discovery catalog for all CSPs. '
    'Source: oci_field_rule_catalog.csv (and equivalent for AWS/Azure/GCP). '
    'Used by rule builder UI and to generate rule_checks + rule_discoveries records. '
    'NOT used directly by scan engines — engines read rule_checks + rule_discoveries.';

COMMENT ON VIEW v_rule_builder_fields IS
    'Rule builder UI field picker. Shows all fields with auto-fill values '
    'for check_for_each (= root_op) and check_var (= item_var_path).';
