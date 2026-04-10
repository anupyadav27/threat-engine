-- ============================================================================
-- Inventory Engine Database Schema
-- ============================================================================
-- Database: threat_engine_inventory
-- Purpose: Store cloud resource inventory, relationships, drift, and asset metadata
-- Used by: engine_inventory
-- Tables: tenants, inventory_report, inventory_scans, inventory_findings,
--         inventory_relationships, inventory_asset_history, inventory_asset_tags_index,
--         inventory_asset_collections, inventory_asset_collection_membership,
--         inventory_asset_metrics, inventory_drift,
--         resource_inventory_identifier

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Inventory Report (scan-level metadata)
CREATE TABLE IF NOT EXISTS inventory_report (
    inventory_scan_id VARCHAR(255) PRIMARY KEY,
    orchestration_id VARCHAR(255),  -- PLANNED: not yet deployed to RDS
    execution_id VARCHAR(255),      -- exists in RDS
    tenant_id VARCHAR(255) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL,
    total_assets INTEGER NOT NULL DEFAULT 0,
    total_relationships INTEGER NOT NULL DEFAULT 0,
    assets_by_provider JSONB DEFAULT '{}',
    assets_by_resource_type JSONB DEFAULT '{}',
    assets_by_region JSONB DEFAULT '{}',
    providers_scanned JSONB DEFAULT '[]',
    accounts_scanned JSONB DEFAULT '[]',
    regions_scanned JSONB DEFAULT '[]',
    errors_count INTEGER NOT NULL DEFAULT 0,
    scan_metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    discovery_scan_id VARCHAR(255),
    customer_id VARCHAR(255),

    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Inventory Scans (lightweight scan tracking)
CREATE TABLE IF NOT EXISTS inventory_scans (
    scan_run_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    discovery_scan_id VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    total_assets INTEGER DEFAULT 0,
    total_relationships INTEGER DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_tenant_scan FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- INVENTORY FINDINGS (asset-level data)
-- ============================================================================

CREATE TABLE IF NOT EXISTS inventory_findings (
    asset_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    resource_uid TEXT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    display_name VARCHAR(500),
    description TEXT,
    tags JSONB DEFAULT '{}',
    labels JSONB DEFAULT '{}',
    properties JSONB DEFAULT '{}',
    configuration JSONB DEFAULT '{}',
    compliance_status VARCHAR(50),  -- 'compliant', 'non_compliant', 'unknown'
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    criticality VARCHAR(20),  -- 'low', 'medium', 'high', 'critical'
    environment VARCHAR(50),  -- 'production', 'staging', 'development', 'test'
    cost_center VARCHAR(100),
    owner VARCHAR(255),
    business_unit VARCHAR(100),
    latest_scan_run_id VARCHAR(255),
    first_discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_modified_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    inventory_scan_id VARCHAR(255),
    customer_id VARCHAR(255),

    CONSTRAINT fk_tenant_asset FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(resource_uid, tenant_id)
);

-- ============================================================================
-- RELATIONSHIPS
-- ============================================================================

CREATE TABLE IF NOT EXISTS inventory_relationships (
    relationship_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    inventory_scan_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    relation_type VARCHAR(100) NOT NULL,  -- 'attached_to', 'member_of', 'depends_on', 'contains'
    from_uid TEXT NOT NULL,
    to_uid TEXT NOT NULL,
    from_resource_type VARCHAR(255),
    to_resource_type VARCHAR(255),
    relationship_strength VARCHAR(20) DEFAULT 'strong',  -- 'weak', 'medium', 'strong'
    bidirectional BOOLEAN DEFAULT FALSE,
    properties JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    first_discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_confirmed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    source_resource_uid TEXT,
    target_resource_uid TEXT,
    relationship_type VARCHAR(100),

    CONSTRAINT fk_tenant_rel FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- HISTORY & DRIFT
-- ============================================================================

CREATE TABLE IF NOT EXISTS inventory_asset_history (
    history_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    resource_uid TEXT NOT NULL,
    inventory_scan_id VARCHAR(255),
    change_type VARCHAR(50) NOT NULL,  -- 'created', 'modified', 'deleted', 'discovered'
    previous_state JSONB,
    current_state JSONB NOT NULL,
    changes_summary JSONB DEFAULT '{}',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_asset_history FOREIGN KEY (asset_id) REFERENCES inventory_findings(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_history FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS inventory_drift (
    id SERIAL PRIMARY KEY,
    drift_id UUID DEFAULT uuid_generate_v4(),
    inventory_scan_id VARCHAR(255) NOT NULL,
    previous_scan_id VARCHAR(255),
    tenant_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    asset_id UUID,
    resource_uid TEXT NOT NULL,
    provider VARCHAR(50),
    resource_type VARCHAR(255),
    change_type VARCHAR(50) NOT NULL,  -- 'added', 'removed', 'modified'
    previous_state JSONB,
    current_state JSONB,
    changes_summary JSONB DEFAULT '{}'::jsonb,
    severity VARCHAR(20) DEFAULT 'info',
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_tenant_drift FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- TAGS & COLLECTIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS inventory_asset_tags_index (
    tag_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    tag_key VARCHAR(255) NOT NULL,
    tag_value VARCHAR(500),
    tag_source VARCHAR(50) DEFAULT 'provider',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resource_uid TEXT,
    inventory_scan_id VARCHAR(255),

    CONSTRAINT fk_asset_tag FOREIGN KEY (asset_id) REFERENCES inventory_findings(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_tag FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(asset_id, tag_key)
);

CREATE TABLE IF NOT EXISTS inventory_asset_collections (
    collection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    collection_type VARCHAR(50) NOT NULL,  -- 'application', 'service', 'environment', 'team'
    description TEXT,
    collection_criteria JSONB,            -- nullable in RDS
    is_dynamic BOOLEAN DEFAULT TRUE,
    owner VARCHAR(255),
    business_criticality VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    filters JSONB DEFAULT '{}'::jsonb,
    auto_assign BOOLEAN DEFAULT false,

    CONSTRAINT fk_tenant_collection FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(tenant_id, name)
);

CREATE TABLE IF NOT EXISTS inventory_asset_collection_membership (
    membership_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    collection_id UUID NOT NULL,
    asset_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    membership_reason VARCHAR(100),
    added_by VARCHAR(255),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_collection_membership FOREIGN KEY (collection_id) REFERENCES inventory_asset_collections(collection_id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_membership FOREIGN KEY (asset_id) REFERENCES inventory_findings(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_membership FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(collection_id, asset_id)
);

-- ============================================================================
-- METRICS
-- ============================================================================

CREATE TABLE IF NOT EXISTS inventory_asset_metrics (
    metric_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255),
    metric_type VARCHAR(50) NOT NULL,  -- 'cpu', 'memory', 'storage', 'network', 'cost'
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(20,6),
    metric_unit VARCHAR(20),
    metric_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    aggregation_period VARCHAR(20),  -- 'instant', 'hour', 'day', 'week', 'month'
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_asset_metric FOREIGN KEY (asset_id) REFERENCES inventory_findings(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_metric FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_ir_tenant ON inventory_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ir_completed_at ON inventory_report(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_ir_status ON inventory_report(status);
CREATE INDEX IF NOT EXISTS idx_ir_discovery_scan ON inventory_report(discovery_scan_id);

CREATE INDEX IF NOT EXISTS idx_is_tenant ON inventory_scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_is_discovery_scan ON inventory_scans(discovery_scan_id);

CREATE INDEX IF NOT EXISTS idx_if_tenant ON inventory_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_if_resource_uid ON inventory_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_if_provider ON inventory_findings(provider);
CREATE INDEX IF NOT EXISTS idx_if_resource_type ON inventory_findings(resource_type);
CREATE INDEX IF NOT EXISTS idx_if_region ON inventory_findings(region);
CREATE INDEX IF NOT EXISTS idx_if_account ON inventory_findings(account_id);
CREATE INDEX IF NOT EXISTS idx_if_environment ON inventory_findings(environment);
CREATE INDEX IF NOT EXISTS idx_if_criticality ON inventory_findings(criticality);
CREATE INDEX IF NOT EXISTS idx_if_compliance ON inventory_findings(compliance_status);
CREATE INDEX IF NOT EXISTS idx_if_risk_score ON inventory_findings(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_if_owner ON inventory_findings(owner);
CREATE INDEX IF NOT EXISTS idx_if_inventory_scan ON inventory_findings(inventory_scan_id);

CREATE INDEX IF NOT EXISTS idx_iah_asset ON inventory_asset_history(asset_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_iah_tenant ON inventory_asset_history(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_iah_change_type ON inventory_asset_history(change_type, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_irel_tenant ON inventory_relationships(tenant_id);
CREATE INDEX IF NOT EXISTS idx_irel_from_uid ON inventory_relationships(from_uid);
CREATE INDEX IF NOT EXISTS idx_irel_to_uid ON inventory_relationships(to_uid);
CREATE INDEX IF NOT EXISTS idx_irel_type ON inventory_relationships(relation_type);
CREATE INDEX IF NOT EXISTS idx_irel_scan ON inventory_relationships(inventory_scan_id);
CREATE INDEX IF NOT EXISTS idx_irel_tenant_scan ON inventory_relationships(tenant_id, inventory_scan_id);

CREATE INDEX IF NOT EXISTS idx_itag_asset ON inventory_asset_tags_index(asset_id);
CREATE INDEX IF NOT EXISTS idx_itag_key_value ON inventory_asset_tags_index(tag_key, tag_value);
CREATE INDEX IF NOT EXISTS idx_itag_tenant ON inventory_asset_tags_index(tenant_id);

CREATE INDEX IF NOT EXISTS idx_idrift_tenant ON inventory_drift(tenant_id);
CREATE INDEX IF NOT EXISTS idx_idrift_scan ON inventory_drift(inventory_scan_id);
CREATE INDEX IF NOT EXISTS idx_idrift_severity ON inventory_drift(severity);

CREATE INDEX IF NOT EXISTS idx_icol_tenant ON inventory_asset_collections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_icol_type ON inventory_asset_collections(collection_type);
CREATE INDEX IF NOT EXISTS idx_icol_criticality ON inventory_asset_collections(business_criticality);

CREATE INDEX IF NOT EXISTS idx_imem_collection ON inventory_asset_collection_membership(collection_id);
CREATE INDEX IF NOT EXISTS idx_imem_asset ON inventory_asset_collection_membership(asset_id);

CREATE INDEX IF NOT EXISTS idx_imet_asset ON inventory_asset_metrics(asset_id, metric_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_imet_type ON inventory_asset_metrics(metric_type, metric_name);
CREATE INDEX IF NOT EXISTS idx_imet_timestamp ON inventory_asset_metrics(metric_timestamp DESC);

-- Composite indexes
CREATE INDEX IF NOT EXISTS idx_if_tenant_type ON inventory_findings(tenant_id, resource_type);
CREATE INDEX IF NOT EXISTS idx_if_tenant_region ON inventory_findings(tenant_id, region);
CREATE INDEX IF NOT EXISTS idx_if_tenant_provider ON inventory_findings(tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_if_criticality_compliance ON inventory_findings(criticality, compliance_status);

-- JSONB GIN indexes
CREATE INDEX IF NOT EXISTS idx_if_tags_gin ON inventory_findings USING gin(tags);
CREATE INDEX IF NOT EXISTS idx_if_labels_gin ON inventory_findings USING gin(labels);
CREATE INDEX IF NOT EXISTS idx_if_properties_gin ON inventory_findings USING gin(properties);
CREATE INDEX IF NOT EXISTS idx_if_configuration_gin ON inventory_findings USING gin(configuration);
CREATE INDEX IF NOT EXISTS idx_ir_assets_by_provider_gin ON inventory_report USING gin(assets_by_provider);
CREATE INDEX IF NOT EXISTS idx_ir_assets_by_type_gin ON inventory_report USING gin(assets_by_resource_type);
CREATE INDEX IF NOT EXISTS idx_iah_changes_gin ON inventory_asset_history USING gin(changes_summary);
CREATE INDEX IF NOT EXISTS idx_irel_properties_gin ON inventory_relationships USING gin(properties);
CREATE INDEX IF NOT EXISTS idx_icol_criteria_gin ON inventory_asset_collections USING gin(collection_criteria);

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_if_name_trgm ON inventory_findings USING gin(name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_if_display_name_trgm ON inventory_findings USING gin(display_name gin_trgm_ops);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_inventory_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_inventory_findings_updated_at ON inventory_findings;
CREATE TRIGGER update_inventory_findings_updated_at BEFORE UPDATE ON inventory_findings
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();

DROP TRIGGER IF EXISTS update_inventory_collections_updated_at ON inventory_asset_collections;
CREATE TRIGGER update_inventory_collections_updated_at BEFORE UPDATE ON inventory_asset_collections
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE inventory_report IS 'Inventory scan metadata and summary';
COMMENT ON TABLE inventory_scans IS 'Lightweight scan tracking';
COMMENT ON TABLE inventory_findings IS 'Cloud resource inventory (latest state per resource_uid)';
COMMENT ON TABLE inventory_relationships IS 'Connections between cloud resources';
COMMENT ON TABLE inventory_asset_history IS 'Asset change history';
COMMENT ON TABLE inventory_drift IS 'Configuration drift between scans';
COMMENT ON TABLE inventory_asset_tags_index IS 'Efficient tag-based queries';
COMMENT ON TABLE inventory_asset_collections IS 'Business logic asset grouping';
COMMENT ON TABLE inventory_asset_collection_membership IS 'Asset-to-collection mapping';
COMMENT ON TABLE inventory_asset_metrics IS 'Asset performance and utilization metrics';

-- ============================================================================
-- STEP5 RESOURCE CATALOG
-- ============================================================================
-- Static metadata loaded from data_pythonsdk resource_inventory_identifier_inventory_enrich.json files.
-- Used by the inventory engine at scan-time to:
--   1. Identify the ARN/identifier field in emitted_fields (arn_entity)
--   2. Construct the full ARN from identifier_pattern + discovery context (account, region)
--   3. Classify discovery operations as root (independent) or dependent (enrichment)
--   4. Understand the dependency chain (which dependent ops need which required_params)
--
-- Runtime context (account_id, region, tenant_id) comes from discovery_findings.
-- This table provides STATIC service/resource metadata independent of any specific scan.

CREATE TABLE IF NOT EXISTS resource_inventory_identifier (
    id                    BIGSERIAL PRIMARY KEY,
    csp                   VARCHAR(50)   NOT NULL,  -- aws | azure | gcp | alicloud | ibm | k8s | oci
    service               VARCHAR(100)  NOT NULL,  -- appsync | s3 | ec2 | lambda | ...
    resource_type         VARCHAR(255)  NOT NULL,  -- api | bucket | instance | function | ...
    classification        VARCHAR(50)   NOT NULL,  -- PRIMARY_RESOURCE | SUB_RESOURCE | CONFIGURATION | EPHEMERAL

    -- Identifier / ARN metadata
    has_arn               BOOLEAN       NOT NULL DEFAULT TRUE,
    arn_entity            VARCHAR(500),            -- dot-path to ARN in emitted_fields: "appsync.graphql_api_arn"
    identifier_type       VARCHAR(50)   DEFAULT 'arn',  -- arn | id | name
    primary_param         VARCHAR(255),            -- AWS API field name carrying the ARN: "GraphqlApiArn"
    identifier_pattern    VARCHAR(1000),           -- ARN template with placeholders:
                                                  --   "arn:${Partition}:appsync:${Region}:${Account}:api/${GraphqlApiArn}"
                                                  -- Placeholders resolved from discovery_findings at runtime:
                                                  --   ${Region}    → discovery_findings.region
                                                  --   ${Account}   → discovery_findings.hierarchy_id (account_id)
                                                  --   ${Partition} → "aws" (default)

    -- Inventory classification flags
    can_inventory_from_roots  BOOLEAN NOT NULL DEFAULT TRUE,
                                                  -- TRUE  = resource appears in root/independent op output
                                                  -- FALSE = resource only reachable via dependent (enrich) ops
    should_inventory          BOOLEAN NOT NULL DEFAULT TRUE,
                                                  -- FALSE = skip this resource type (EPHEMERAL, CONFIG-only)

    -- Parent resource relationship (for SUB_RESOURCE types)
    -- Tells the inventory engine: "to find/enrich this resource, first locate the parent"
    parent_service        VARCHAR(100),           -- Service name of the parent resource (NULL for root resources)
                                                  -- e.g. "s3" for bucket_versioning, "ec2" for security_group
    parent_resource_type  VARCHAR(255),           -- resource_type of the parent (NULL for root resources)
                                                  -- e.g. "bucket" for bucket_versioning, "vpc" for security_group
    -- param_sources lives inside each enrich_op entry (see enrich_ops below)

    -- Operations
    root_ops              JSONB NOT NULL DEFAULT '[]',
                                                  -- Root/independent operations that produce this resource
                                                  -- [{
                                                  --   operation:      "list_buckets",
                                                  --   independent:    true,
                                                  --   required_params: [],
                                                  --   python_method:  "list_buckets"
                                                  -- }]
    enrich_ops            JSONB NOT NULL DEFAULT '[]',
                                                  -- Dependent/enrichment operations that add detail
                                                  -- [{
                                                  --   operation:       "get_bucket_versioning",
                                                  --   independent:     false,
                                                  --   required_params: ["Bucket"],
                                                  --   python_method:   "get_bucket_versioning",
                                                  --   param_sources: {
                                                  --     "Bucket": {
                                                  --       "from_field":         "resource_id",
                                                  --       "from_asset_field":   "name",
                                                  --       "parent_resource_type": "bucket"
                                                  --     }
                                                  --   }
                                                  -- }]
                                                  -- param_sources tells the engine how to extract
                                                  -- each required_param from the parent asset's fields

    -- Raw catalog (full step5 resource block for extensibility)
    raw_catalog           JSONB,

    -- Housekeeping
    loaded_at             TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT rii_unique UNIQUE (csp, service, resource_type)
);

-- ── Indexes ──────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_rii_csp_service      ON resource_inventory_identifier(csp, service);
CREATE INDEX IF NOT EXISTS idx_rii_csp              ON resource_inventory_identifier(csp);
CREATE INDEX IF NOT EXISTS idx_rii_classification   ON resource_inventory_identifier(classification);
CREATE INDEX IF NOT EXISTS idx_rii_should_inventory ON resource_inventory_identifier(should_inventory)
    WHERE should_inventory = TRUE;
CREATE INDEX IF NOT EXISTS idx_rii_arn_entity       ON resource_inventory_identifier(arn_entity)
    WHERE arn_entity IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rii_root_ops_gin     ON resource_inventory_identifier USING GIN(root_ops);
CREATE INDEX IF NOT EXISTS idx_rii_enrich_ops_gin   ON resource_inventory_identifier USING GIN(enrich_ops);
-- Parent relationship index: look up all sub-resources owned by a given parent type
CREATE INDEX IF NOT EXISTS idx_rii_parent           ON resource_inventory_identifier(csp, parent_service, parent_resource_type)
    WHERE parent_resource_type IS NOT NULL;

-- ── Updated-at trigger ───────────────────────────────────────────────────────
DROP TRIGGER IF EXISTS update_rii_updated_at ON resource_inventory_identifier;
CREATE TRIGGER update_rii_updated_at
    BEFORE UPDATE ON resource_inventory_identifier
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();

-- ── Comment ──────────────────────────────────────────────────────────────────
-- ── Architecture display columns (added separately from discovery metadata) ──
-- show_in_architecture: gates whether this resource type can ever appear in
--   the architecture diagram. FALSE for sub-resources, config-only, ephemeral.
--   Overrides architecture_resource_placement entirely when FALSE.
-- diagram_zone: where the resource lives in the landscape diagram.
--   internet_edge  = global strip at top   (S3, CloudFront, Route53, API GW)
--   network        = Region card layer 1   (VPC container, IGW, NAT, RT, NACL, subnet container)
--   compute        = Region card layer 2   (EC2, RDS, EKS, ALB — subnet-scoped)
--   services       = Region card layer 3   (Lambda, DynamoDB, SQS — regional, no subnet)
--   supporting     = bottom strip          (IAM, KMS, CloudWatch, security groups, EBS)
--   hidden         = never shown           (sub-resources, config-only, ephemeral)
ALTER TABLE resource_inventory_identifier
    ADD COLUMN IF NOT EXISTS show_in_architecture BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS diagram_zone         VARCHAR(30) DEFAULT 'services';

-- Default rules derived from classification:
--   SUB_RESOURCE  → hidden  (sg-rule, policy-version, bucket-acl, listener-rule …)
--   CONFIGURATION → hidden  (config-rule, health-check, parameter-store entry …)
--   EPHEMERAL     → hidden  (spot-request, import-job, pending-task …)
UPDATE resource_inventory_identifier
    SET show_in_architecture = FALSE,
        diagram_zone         = 'hidden'
    WHERE classification IN ('SUB_RESOURCE', 'CONFIGURATION', 'EPHEMERAL');

CREATE INDEX IF NOT EXISTS idx_rii_show_in_arch
    ON resource_inventory_identifier(csp, show_in_architecture)
    WHERE show_in_architecture = TRUE;

CREATE INDEX IF NOT EXISTS idx_rii_diagram_zone
    ON resource_inventory_identifier(csp, diagram_zone);

COMMENT ON COLUMN resource_inventory_identifier.show_in_architecture IS
    'FALSE = never render in architecture diagram (sub-resources, config-only, ephemeral).';
COMMENT ON COLUMN resource_inventory_identifier.diagram_zone IS
    'Landscape diagram zone: internet_edge | network | compute | services | supporting | hidden.';

COMMENT ON TABLE resource_inventory_identifier IS
    'Static step5 resource catalog: ARN entity paths, identifier patterns, root/enrich ops per csp.service.resource_type.';

-- ============================================================================
-- ARCHITECTURE DIAGRAM TABLES
-- ============================================================================
-- architecture_resource_placement: one row per (csp, resource_type) defining
--   how to render that resource type in the landscape architecture diagram.
--   Seeded by: scripts/create_architecture_tables.py
--   Consumed by: /api/v1/inventory/architecture endpoint
-- ============================================================================

CREATE TABLE IF NOT EXISTS architecture_resource_placement (
    id               SERIAL PRIMARY KEY,
    csp              VARCHAR(20)  NOT NULL,  -- aws | azure | gcp | oci | ibm | alicloud | k8s
    resource_type    VARCHAR(200) NOT NULL,  -- e.g. ec2.instance, lambda.function

    -- Diagram zone (overrides resource_inventory_identifier.diagram_zone if present)
    diagram_zone     VARCHAR(30)  NOT NULL DEFAULT 'services',
    --   internet_edge  = global/public top strip
    --   network        = Region card — Network layer  (containers + gateway icons)
    --   compute        = Region card — Compute layer  (subnet-scoped resources)
    --   services       = Region card — Services layer (regional, outside VPC)
    --   supporting     = bottom strip (IAM, KMS, monitoring, security)
    --   hidden         = excluded from diagram

    -- Placement detail (used by the builder for precise positioning)
    arch_layer       INTEGER      NOT NULL DEFAULT 3,
    --   2 = network topology  3 = compute/services  4 = supporting/control
    placement_scope  VARCHAR(50),
    --   global | regional | vpc | az | subnet | multi-subnet | multi-az
    placement_parent VARCHAR(200),
    --   account | region | ec2.vpc | ec2.subnet (for builder routing)
    placement_zone   VARCHAR(30)  DEFAULT 'center',
    --   center | right | bottom  (legacy sub-positioning within a zone)

    -- Visual grouping
    visual_group     VARCHAR(100) NOT NULL DEFAULT 'other',
    --   network | compute | compute-container | compute-database | compute-serverless
    --   storage-object | identity | encryption | monitoring | messaging | public | security
    visual_subgroup  VARCHAR(100),
    --   vpc | subnet | igw | natgw | ec2 | rds | eks | ecs | lambda | s3 | iam | kms | cw …

    -- Container / nesting
    is_container     BOOLEAN      DEFAULT FALSE,
    container_depth  INTEGER      DEFAULT 0,

    -- Detail level (P1–P5 slider)
    display_priority INTEGER      DEFAULT 3,
    --   1 = always show (VPC, Subnet, EC2, ALB)
    --   2 = important   (RDS, IGW, NAT, KMS, IAM role)
    --   3 = extended    (SG, ElastiCache, VPC endpoint)
    --   4 = operational (CloudWatch, CloudTrail, log groups)
    --   5 = all         (ENI, EBS, policy docs, listeners)

    -- Render style
    show_as          VARCHAR(50)  DEFAULT 'box',
    --   box    = full resource chip (default)
    --   icon   = small inline pill  (gateways, NAT)
    --   badge  = count badge on parent (RT, NACL)
    --   count  = number only          (security groups in supporting)
    --   hidden = never render

    icon_type        VARCHAR(100),
    created_at       TIMESTAMPTZ  DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  DEFAULT NOW(),

    UNIQUE(csp, resource_type)
);

CREATE INDEX IF NOT EXISTS idx_arp_csp_zone     ON architecture_resource_placement(csp, diagram_zone);
CREATE INDEX IF NOT EXISTS idx_arp_csp_layer    ON architecture_resource_placement(csp, arch_layer);
CREATE INDEX IF NOT EXISTS idx_arp_visual_group ON architecture_resource_placement(csp, visual_group);
CREATE INDEX IF NOT EXISTS idx_arp_priority     ON architecture_resource_placement(csp, display_priority);

COMMENT ON TABLE architecture_resource_placement IS
    'Per-(csp, resource_type) diagram placement rules for the landscape architecture view. '
    'diagram_zone drives which strip/layer a resource renders in. '
    'display_priority (P1-P5) controls detail level visibility. '
    'Seeded by scripts/create_architecture_tables.py.';

-- ── Architecture Relationship Rules ─────────────────────────────────────────
-- Defines visual edges to draw between resource types in the diagram.
-- Seeded by scripts/create_architecture_tables.py

CREATE TABLE IF NOT EXISTS architecture_relationship_rules (
    id               SERIAL PRIMARY KEY,
    csp              VARCHAR(20)  NOT NULL,
    rel_category     VARCHAR(50)  NOT NULL,
    --   topology | placement | composition | dependency | flow
    rel_type         VARCHAR(100) NOT NULL,
    from_resource_type VARCHAR(200) NOT NULL,
    to_resource_type   VARCHAR(200) NOT NULL,
    source_field     VARCHAR(200),
    source_field_item VARCHAR(200),
    target_uid_pattern VARCHAR(500),
    arch_layer       INTEGER      NOT NULL DEFAULT 3,
    line_style       VARCHAR(50)  DEFAULT 'solid',   -- solid | dashed | dotted
    line_color       VARCHAR(50),
    line_label       VARCHAR(100),
    bidirectional    BOOLEAN      DEFAULT FALSE,
    is_active        BOOLEAN      DEFAULT TRUE,
    created_at       TIMESTAMPTZ  DEFAULT NOW(),
    updated_at       TIMESTAMPTZ  DEFAULT NOW(),

    UNIQUE(csp, rel_category, from_resource_type, to_resource_type, rel_type)
);

CREATE INDEX IF NOT EXISTS idx_arr_csp_category ON architecture_relationship_rules(csp, rel_category);
CREATE INDEX IF NOT EXISTS idx_arr_from_type    ON architecture_relationship_rules(csp, from_resource_type);
CREATE INDEX IF NOT EXISTS idx_arr_layer        ON architecture_relationship_rules(csp, arch_layer);

COMMENT ON TABLE architecture_relationship_rules IS
    'Visual edge rules for the architecture diagram: defines which resource types '
    'are connected and how (line style, label, direction). '
    'Seeded by scripts/create_architecture_tables.py.';

-- ============================================================================
-- RELATIONSHIP RULES  (single DB-driven source of truth, no local JSON files)
-- ============================================================================
--
-- Stores the relationship extraction rules for every (csp, resource_type) pair.
-- Rules are auto-generated from resource_inventory_identifier (contained_by from
-- parent_resource_type; uses/depends_on from enrich_ops.param_sources) and
-- supplemented with curated cross-service rules for AWS, Azure, GCP, OCI, IBM,
-- AliCloud and K8s.
--
-- Consumed by: RelationshipBuilder._load_rules_from_db()  (no local cache)
-- Populated by: engine_inventory/scripts/load_relationship_rules_to_db.py
--

CREATE TABLE IF NOT EXISTS resource_relationship_rules (
    rule_id           BIGSERIAL PRIMARY KEY,

    -- Identity
    csp               VARCHAR(20)  NOT NULL,  -- aws | azure | gcp | oci | ibm | alicloud | k8s
    service           VARCHAR(100),            -- source service (e.g. ec2, lambda)  — nullable for cross-service rules

    -- Rule definition
    from_resource_type VARCHAR(200) NOT NULL,  -- e.g. ec2.instance
    relation_type      VARCHAR(100) NOT NULL,  -- contained_by | attached_to | uses | encrypted_by …
    to_resource_type   VARCHAR(200) NOT NULL,  -- e.g. ec2.vpc

    -- Field extraction
    source_field       VARCHAR(500) NOT NULL,  -- dot-path in raw_response / emitted_fields
    source_field_item  VARCHAR(200),           -- for array fields: sub-field to extract per item
    target_uid_pattern TEXT         NOT NULL,  -- pattern to build target UID, e.g. arn:aws:ec2:{region}:{account_id}:vpc/{VpcId}

    -- Control
    is_active         BOOLEAN      NOT NULL DEFAULT TRUE,
    rule_source       VARCHAR(50)  NOT NULL DEFAULT 'auto',  -- auto | curated | migrated

    -- Metadata
    rule_metadata     JSONB        NOT NULL DEFAULT '{}',
    created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_resource_rel_rule
        UNIQUE (csp, from_resource_type, relation_type, to_resource_type, source_field)
);

-- Indexes for fast lookup at scan time
CREATE INDEX IF NOT EXISTS idx_rrr_csp_from_type
    ON resource_relationship_rules(csp, from_resource_type)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_rrr_csp
    ON resource_relationship_rules(csp)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_rrr_service
    ON resource_relationship_rules(csp, service)
    WHERE is_active = TRUE AND service IS NOT NULL;

-- Auto-update timestamp trigger
DROP TRIGGER IF EXISTS update_rrr_updated_at ON resource_relationship_rules;
CREATE TRIGGER update_rrr_updated_at
    BEFORE UPDATE ON resource_relationship_rules
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();

COMMENT ON TABLE resource_relationship_rules IS
    'DB-driven relationship extraction rules: one row per (csp, from_resource_type, relation_type, to_resource_type, source_field). '
    'No local JSON file cache — RelationshipBuilder loads directly from this table at scan start.';
