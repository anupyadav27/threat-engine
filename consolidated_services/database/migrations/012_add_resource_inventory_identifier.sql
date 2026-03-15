-- =============================================================================
-- Migration 012: Add resource_inventory_identifier table
-- =============================================================================
-- Database:  threat_engine_inventory
-- Purpose:   Static step5 resource catalog - ARN entity paths, identifier
--            patterns, root/enrich ops per (csp, service, resource_type).
--
-- Apply with:
--   psql -h <RDS_HOST> -U postgres -d threat_engine_inventory \
--     -f 012_add_resource_inventory_identifier.sql
--
-- Safe to re-run: all DDL uses IF NOT EXISTS / DROP IF EXISTS.
-- =============================================================================

-- Ensure the updated_at trigger function exists (created in inventory_schema.sql)
CREATE OR REPLACE FUNCTION update_inventory_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ── Main table ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resource_inventory_identifier (
    id                    BIGSERIAL PRIMARY KEY,

    -- Resource identity
    csp                   VARCHAR(50)   NOT NULL,   -- aws | azure | gcp | alicloud | ibm | k8s | oci
    service               VARCHAR(100)  NOT NULL,   -- appsync | s3 | ec2 | lambda | …
    resource_type         VARCHAR(255)  NOT NULL,   -- api | bucket | instance | function | …
    classification        VARCHAR(50)   NOT NULL,   -- PRIMARY_RESOURCE | SUB_RESOURCE | CONFIGURATION | EPHEMERAL

    -- Identifier / ARN metadata
    has_arn               BOOLEAN       NOT NULL DEFAULT TRUE,
    arn_entity            VARCHAR(500),             -- dot-path to ARN in emitted_fields: "appsync.graphql_api_arn"
    identifier_type       VARCHAR(50)   DEFAULT 'arn',  -- arn | id | name
    primary_param         VARCHAR(255),             -- AWS API field carrying the ARN: "GraphqlApiArn"
    identifier_pattern    VARCHAR(1000),            -- ARN template with placeholders:
                                                    --   "arn:${Partition}:appsync:${Region}:${Account}:api/${GraphqlApiArn}"
                                                    -- Resolved at scan time from discovery_findings:
                                                    --   ${Region}    ← discovery_findings.region
                                                    --   ${Account}   ← discovery_findings.hierarchy_id
                                                    --   ${Partition} ← "aws" (default)

    -- Inventory classification flags
    can_inventory_from_roots  BOOLEAN NOT NULL DEFAULT TRUE,
    should_inventory          BOOLEAN NOT NULL DEFAULT TRUE,

    -- Operations (from step5 inventory.ops and inventory_enrich.ops)
    root_ops              JSONB NOT NULL DEFAULT '[]',
    -- [{"operation": "ListGraphqlApis",           "independent": true,  "required_params": [], "python_method": "list_graphql_apis"}]
    enrich_ops            JSONB NOT NULL DEFAULT '[]',
    -- [{"operation": "ListSourceApiAssociations", "independent": false, "required_params": ["apiId"], "python_method": "list_source_api_associations"}]

    -- Full step5 resource block (for future extensibility)
    raw_catalog           JSONB,

    -- Housekeeping
    loaded_at             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT rii_unique UNIQUE (csp, service, resource_type)
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_rii_csp_service
    ON resource_inventory_identifier(csp, service);

CREATE INDEX IF NOT EXISTS idx_rii_csp
    ON resource_inventory_identifier(csp);

CREATE INDEX IF NOT EXISTS idx_rii_classification
    ON resource_inventory_identifier(classification);

CREATE INDEX IF NOT EXISTS idx_rii_should_inventory
    ON resource_inventory_identifier(should_inventory)
    WHERE should_inventory = TRUE;

CREATE INDEX IF NOT EXISTS idx_rii_arn_entity
    ON resource_inventory_identifier(arn_entity)
    WHERE arn_entity IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rii_root_ops_gin
    ON resource_inventory_identifier USING GIN(root_ops);

CREATE INDEX IF NOT EXISTS idx_rii_enrich_ops_gin
    ON resource_inventory_identifier USING GIN(enrich_ops);

-- ── Trigger ───────────────────────────────────────────────────────────────────
DROP TRIGGER IF EXISTS update_rii_updated_at ON resource_inventory_identifier;
CREATE TRIGGER update_rii_updated_at
    BEFORE UPDATE ON resource_inventory_identifier
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();

-- ── Comment ───────────────────────────────────────────────────────────────────
COMMENT ON TABLE resource_inventory_identifier IS
    'Static step5 resource catalog: ARN entity paths, identifier patterns, root/enrich ops per csp.service.resource_type. '
    'Loaded once from data_pythonsdk; read at scan time to extract ARNs and classify discovery records.';

COMMENT ON COLUMN resource_inventory_identifier.root_ops IS
    'Independent operations that LIST/describe resources (no external params needed). '
    'Each record: {operation, independent:true, required_params:[], python_method, yaml_action}';

COMMENT ON COLUMN resource_inventory_identifier.enrich_ops IS
    'Dependent operations that enrich assets (require params from root resource). '
    'Each record: {operation, independent:false, required_params:[...], python_method, yaml_action}. '
    'required_params are field names that must be resolved from the parent asset emitted_fields at runtime.';

COMMENT ON COLUMN resource_inventory_identifier.identifier_pattern IS
    'ARN template with runtime placeholders. '
    'Resolved during inventory scan from discovery_findings: '
    '${Region}←region, ${Account}←hierarchy_id, ${Partition}←"aws".';
