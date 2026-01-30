-- Inventory Engine Database Schema
-- PostgreSQL DDL for inventory indexes and asset management

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Minimal tenants table for FK (split-DB: no cross-DB refs)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Inventory Run Index
CREATE TABLE IF NOT EXISTS inventory_run_index (
    scan_run_id VARCHAR(255) PRIMARY KEY,
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
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Asset Index Latest (latest state per resource_uid)
CREATE TABLE IF NOT EXISTS asset_index_latest (
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
    security_groups JSONB DEFAULT '[]',
    network_interfaces JSONB DEFAULT '[]',
    iam_roles JSONB DEFAULT '[]',
    encryption_details JSONB DEFAULT '{}',
    compliance_status VARCHAR(50),  -- 'compliant', 'non_compliant', 'unknown'
    risk_score INTEGER CHECK (risk_score >= 0 AND risk_score <= 100),
    criticality VARCHAR(20),  -- 'low', 'medium', 'high', 'critical'
    environment VARCHAR(50),  -- 'production', 'staging', 'development', 'test'
    cost_center VARCHAR(100),
    owner VARCHAR(255),
    business_unit VARCHAR(100),
    latest_scan_run_id VARCHAR(255) NOT NULL,
    first_discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_modified_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_asset FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run FOREIGN KEY (latest_scan_run_id) REFERENCES inventory_run_index(scan_run_id) ON DELETE CASCADE,
    UNIQUE(resource_uid, tenant_id)
);

-- Asset History (for tracking changes over time)
CREATE TABLE IF NOT EXISTS asset_history (
    history_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    resource_uid TEXT NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    change_type VARCHAR(50) NOT NULL,  -- 'created', 'modified', 'deleted', 'discovered'
    previous_state JSONB,
    current_state JSONB NOT NULL,
    changes_summary JSONB DEFAULT '{}',  -- Summary of what changed
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_asset_history FOREIGN KEY (asset_id) REFERENCES asset_index_latest(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_history FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run_history FOREIGN KEY (scan_run_id) REFERENCES inventory_run_index(scan_run_id) ON DELETE CASCADE
);

-- Relationship Index Latest (connections between resources)
CREATE TABLE IF NOT EXISTS relationship_index_latest (
    relationship_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
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
    
    CONSTRAINT fk_tenant_rel FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run_rel FOREIGN KEY (scan_run_id) REFERENCES inventory_run_index(scan_run_id) ON DELETE CASCADE
);

-- Asset Tags Index (for efficient tag-based queries)
CREATE TABLE IF NOT EXISTS asset_tags_index (
    tag_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    tag_key VARCHAR(255) NOT NULL,
    tag_value VARCHAR(500),
    tag_source VARCHAR(50) DEFAULT 'provider',  -- 'provider', 'user', 'system'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_asset_tag FOREIGN KEY (asset_id) REFERENCES asset_index_latest(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_tag FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(asset_id, tag_key)
);

-- Asset Dependencies (critical path analysis)
CREATE TABLE IF NOT EXISTS asset_dependencies (
    dependency_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    dependent_asset_id UUID NOT NULL,  -- Asset that depends on something
    dependency_asset_id UUID NOT NULL,  -- Asset being depended upon
    dependency_type VARCHAR(50) NOT NULL,  -- 'critical', 'important', 'optional'
    dependency_reason TEXT,
    impact_level VARCHAR(20) DEFAULT 'medium',  -- 'low', 'medium', 'high', 'critical'
    validated BOOLEAN DEFAULT FALSE,
    validation_method VARCHAR(100),
    last_validated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_dependent_asset FOREIGN KEY (dependent_asset_id) REFERENCES asset_index_latest(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_dependency_asset FOREIGN KEY (dependency_asset_id) REFERENCES asset_index_latest(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_dependency FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(dependent_asset_id, dependency_asset_id)
);

-- Asset Collections (grouping for business logic)
CREATE TABLE IF NOT EXISTS asset_collections (
    collection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    collection_name VARCHAR(255) NOT NULL,
    collection_type VARCHAR(50) NOT NULL,  -- 'application', 'service', 'environment', 'team'
    description TEXT,
    collection_criteria JSONB NOT NULL,  -- Rules for automatic inclusion
    is_dynamic BOOLEAN DEFAULT TRUE,  -- Whether membership is automatically managed
    owner VARCHAR(255),
    business_criticality VARCHAR(20),  -- 'low', 'medium', 'high', 'critical'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_collection FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(tenant_id, collection_name)
);

-- Asset Collection Membership
CREATE TABLE IF NOT EXISTS asset_collection_membership (
    membership_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    collection_id UUID NOT NULL,
    asset_id UUID NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    membership_reason VARCHAR(100),  -- 'automatic', 'manual', 'inherited'
    added_by VARCHAR(255),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_collection_membership FOREIGN KEY (collection_id) REFERENCES asset_collections(collection_id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_membership FOREIGN KEY (asset_id) REFERENCES asset_index_latest(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_membership FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(collection_id, asset_id)
);

-- Asset Metrics (performance and utilization)
CREATE TABLE IF NOT EXISTS asset_metrics (
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
    
    CONSTRAINT fk_asset_metric FOREIGN KEY (asset_id) REFERENCES asset_index_latest(asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_metric FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_run_tenant ON inventory_run_index(tenant_id);
CREATE INDEX IF NOT EXISTS idx_run_completed_at ON inventory_run_index(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_run_status ON inventory_run_index(status);

CREATE INDEX IF NOT EXISTS idx_asset_tenant ON asset_index_latest(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_resource_uid ON asset_index_latest(resource_uid);
CREATE INDEX IF NOT EXISTS idx_asset_provider ON asset_index_latest(provider);
CREATE INDEX IF NOT EXISTS idx_asset_resource_type ON asset_index_latest(resource_type);
CREATE INDEX IF NOT EXISTS idx_asset_region ON asset_index_latest(region);
CREATE INDEX IF NOT EXISTS idx_asset_account ON asset_index_latest(account_id);
CREATE INDEX IF NOT EXISTS idx_asset_environment ON asset_index_latest(environment);
CREATE INDEX IF NOT EXISTS idx_asset_criticality ON asset_index_latest(criticality);
CREATE INDEX IF NOT EXISTS idx_asset_compliance ON asset_index_latest(compliance_status);
CREATE INDEX IF NOT EXISTS idx_asset_risk_score ON asset_index_latest(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_asset_owner ON asset_index_latest(owner);

CREATE INDEX IF NOT EXISTS idx_history_asset ON asset_history(asset_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_tenant ON asset_history(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_history_change_type ON asset_history(change_type, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_rel_tenant ON relationship_index_latest(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rel_from_uid ON relationship_index_latest(from_uid);
CREATE INDEX IF NOT EXISTS idx_rel_to_uid ON relationship_index_latest(to_uid);
CREATE INDEX IF NOT EXISTS idx_rel_type ON relationship_index_latest(relation_type);
CREATE INDEX IF NOT EXISTS idx_rel_bidirectional ON relationship_index_latest(from_uid, to_uid) WHERE bidirectional = true;

CREATE INDEX IF NOT EXISTS idx_tags_asset ON asset_tags_index(asset_id);
CREATE INDEX IF NOT EXISTS idx_tags_key_value ON asset_tags_index(tag_key, tag_value);
CREATE INDEX IF NOT EXISTS idx_tags_tenant ON asset_tags_index(tenant_id);

CREATE INDEX IF NOT EXISTS idx_dependency_dependent ON asset_dependencies(dependent_asset_id);
CREATE INDEX IF NOT EXISTS idx_dependency_target ON asset_dependencies(dependency_asset_id);
CREATE INDEX IF NOT EXISTS idx_dependency_type ON asset_dependencies(dependency_type, impact_level);

CREATE INDEX IF NOT EXISTS idx_collection_tenant ON asset_collections(tenant_id);
CREATE INDEX IF NOT EXISTS idx_collection_type ON asset_collections(collection_type);
CREATE INDEX IF NOT EXISTS idx_collection_criticality ON asset_collections(business_criticality);

CREATE INDEX IF NOT EXISTS idx_membership_collection ON asset_collection_membership(collection_id);
CREATE INDEX IF NOT EXISTS idx_membership_asset ON asset_collection_membership(asset_id);

CREATE INDEX IF NOT EXISTS idx_metrics_asset ON asset_metrics(asset_id, metric_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_type ON asset_metrics(metric_type, metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON asset_metrics(metric_timestamp DESC);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_asset_tenant_type ON asset_index_latest(tenant_id, resource_type);
CREATE INDEX IF NOT EXISTS idx_asset_tenant_region ON asset_index_latest(tenant_id, region);
CREATE INDEX IF NOT EXISTS idx_asset_tenant_provider ON asset_index_latest(tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_asset_criticality_compliance ON asset_index_latest(criticality, compliance_status);

-- JSONB GIN indexes for flexible JSON queries
CREATE INDEX IF NOT EXISTS idx_asset_tags_gin ON asset_index_latest USING gin(tags);
CREATE INDEX IF NOT EXISTS idx_asset_labels_gin ON asset_index_latest USING gin(labels);
CREATE INDEX IF NOT EXISTS idx_asset_properties_gin ON asset_index_latest USING gin(properties);
CREATE INDEX IF NOT EXISTS idx_asset_configuration_gin ON asset_index_latest USING gin(configuration);
CREATE INDEX IF NOT EXISTS idx_run_assets_by_provider_gin ON inventory_run_index USING gin(assets_by_provider);
CREATE INDEX IF NOT EXISTS idx_run_assets_by_type_gin ON inventory_run_index USING gin(assets_by_resource_type);
CREATE INDEX IF NOT EXISTS idx_history_changes_gin ON asset_history USING gin(changes_summary);
CREATE INDEX IF NOT EXISTS idx_relationship_properties_gin ON relationship_index_latest USING gin(properties);
CREATE INDEX IF NOT EXISTS idx_collection_criteria_gin ON asset_collections USING gin(collection_criteria);

-- Full-text search indexes
CREATE INDEX IF NOT EXISTS idx_asset_name_trgm ON asset_index_latest USING gin(name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_asset_display_name_trgm ON asset_index_latest USING gin(display_name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_asset_description_trgm ON asset_index_latest USING gin(description gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_collection_name_trgm ON asset_collections USING gin(collection_name gin_trgm_ops);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_inventory_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_asset_index_updated_at ON asset_index_latest;
CREATE TRIGGER update_asset_index_updated_at BEFORE UPDATE ON asset_index_latest
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();

DROP TRIGGER IF EXISTS update_asset_dependencies_updated_at ON asset_dependencies;
CREATE TRIGGER update_asset_dependencies_updated_at BEFORE UPDATE ON asset_dependencies
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();

DROP TRIGGER IF EXISTS update_asset_collections_updated_at ON asset_collections;
CREATE TRIGGER update_asset_collections_updated_at BEFORE UPDATE ON asset_collections
    FOR EACH ROW EXECUTE FUNCTION update_inventory_updated_at_column();