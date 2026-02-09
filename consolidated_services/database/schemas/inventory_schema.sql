-- ============================================================================
-- Inventory Engine Database Schema
-- ============================================================================
-- Database: threat_engine_inventory
-- Purpose: Store cloud resource inventory, relationships, drift, and asset metadata
-- Used by: engine_inventory
-- Tables: tenants, inventory_report, inventory_scans, inventory_findings,
--         inventory_relationships, inventory_asset_history, inventory_asset_tags_index,
--         inventory_asset_collections, inventory_asset_collection_membership,
--         inventory_asset_metrics, inventory_drift

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
