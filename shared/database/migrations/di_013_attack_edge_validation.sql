-- di_013_attack_edge_validation.sql
-- Adds attack-edge validation columns to asset_relationships and resource_relationship_catalog.
-- Part of VAL-01 sprint: validated attack edges (is_attack_edge=true) are written by
-- validators in engine-attack-path; pg_graph will later filter on is_attack_edge=true
-- instead of the hardcoded _ATTACK_RELEVANT_TYPES set.

BEGIN;

-- ── 1. asset_relationships: 5 new validation columns ────────────────────────
ALTER TABLE asset_relationships
    ADD COLUMN IF NOT EXISTS is_attack_edge     BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS attack_edge_type   VARCHAR(64),
    ADD COLUMN IF NOT EXISTS validation_status  VARCHAR(32) NOT NULL DEFAULT 'unvalidated',
    ADD COLUMN IF NOT EXISTS validation_rule_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS attack_evidence    JSONB;

-- Partial index — only attack edges; keeps graph traversal query fast
CREATE INDEX IF NOT EXISTS idx_ar_attack_edge
    ON asset_relationships (tenant_id, scan_run_id, is_attack_edge)
    WHERE is_attack_edge = TRUE;

-- Index for validator reads (find existing structural edges by type)
CREATE INDEX IF NOT EXISTS idx_ar_relation_type_lower
    ON asset_relationships (tenant_id, LOWER(relation_type));

-- ── 2. resource_relationship_catalog: 4 classification columns ───────────────
ALTER TABLE resource_relationship_catalog
    ADD COLUMN IF NOT EXISTS attack_edge_class        VARCHAR(32),
    ADD COLUMN IF NOT EXISTS validation_required      BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS derived_attack_edge_type VARCHAR(64),
    ADD COLUMN IF NOT EXISTS validator_name           VARCHAR(64);

-- ── 3. Seed attack_edge_class for all known relation types ───────────────────

-- direct_capability: these edges ARE the attack movement (IAM engine validated them)
UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'direct_capability',
    validation_required      = TRUE,
    derived_attack_edge_type = 'CAN_ASSUME',
    validator_name           = 'validate_assume_role'
WHERE LOWER(relation_type) IN ('can_assume', 'assumes');

UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'direct_capability',
    validation_required      = TRUE,
    derived_attack_edge_type = 'CAN_INVOKE',
    validator_name           = 'validate_service_chain'
WHERE LOWER(relation_type) IN ('invokes', 'triggers');

UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'direct_capability',
    validation_required      = TRUE,
    derived_attack_edge_type = 'CAN_READ',
    validator_name           = 'validate_data_access'
WHERE LOWER(relation_type) IN ('grants_access_to', 'reads_from');

-- candidate: structural edge that enables a derived attack edge after validation
UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'candidate',
    validation_required      = TRUE,
    derived_attack_edge_type = 'CAN_REACH',
    validator_name           = 'validate_service_chain'
WHERE LOWER(relation_type) IN ('routes_to', 'has_integration', 'forwards_to', 'serves_traffic_for');

UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'candidate',
    validation_required      = TRUE,
    derived_attack_edge_type = 'CAN_REACH',
    validator_name           = 'validate_internet_reachability'
WHERE LOWER(relation_type) IN ('governed_by', 'placed_in', 'in_subnet', 'in_vpc', 'in_vnet', 'in_vcn', 'in_network');

UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'candidate',
    validation_required      = TRUE,
    derived_attack_edge_type = 'CAN_USE_IDENTITY',
    validator_name           = 'validate_identity_usage'
WHERE LOWER(relation_type) IN ('has_profile', 'has_role', 'has_identity', 'has_sa', 'uses_identity');

UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'candidate',
    validation_required      = TRUE,
    derived_attack_edge_type = 'CAN_DECRYPT',
    validator_name           = 'validate_data_access'
WHERE LOWER(relation_type) IN ('encrypted_by');

-- context: useful evidence, not attack traversal
UPDATE resource_relationship_catalog SET
    attack_edge_class        = 'context',
    validation_required      = FALSE,
    derived_attack_edge_type = NULL,
    validator_name           = NULL
WHERE LOWER(relation_type) IN (
    'belongs_to', 'contains', 'resolves_to', 'attached_to',
    'has_eni', 'has_nsg', 'has_firewall', 'has_route_table',
    'logging_enabled_to', 'logs_to', 'replicates_to',
    'stores_artifacts_in', 'protected_by'
);

-- context default for anything unclassified
UPDATE resource_relationship_catalog SET
    attack_edge_class   = 'context',
    validation_required = FALSE
WHERE attack_edge_class IS NULL;

COMMIT;

-- Verify
SELECT attack_edge_class, COUNT(*) FROM resource_relationship_catalog GROUP BY attack_edge_class ORDER BY attack_edge_class;
