-- Inventory Engine Database Schema
-- PostgreSQL DDL for inventory indexes

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Minimal tenants table (needed for FK constraints in this DB)
-- Note: other engines have their own tenants tables; inventory DB is standalone.
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255),
    provider VARCHAR(50),
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Asset Index Latest (latest state per resource_uid)
CREATE TABLE IF NOT EXISTS asset_index_latest (
    asset_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    resource_uid TEXT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    tags JSONB DEFAULT '{}',
    latest_scan_run_id VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_asset FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run FOREIGN KEY (latest_scan_run_id) REFERENCES inventory_run_index(scan_run_id) ON DELETE CASCADE
);

-- Relationship Index Latest (optional - for quick lookups)
CREATE TABLE IF NOT EXISTS relationship_index_latest (
    relationship_id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    scan_run_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    relation_type VARCHAR(100) NOT NULL,
    from_uid TEXT NOT NULL,
    to_uid TEXT NOT NULL,
    properties JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT fk_tenant_rel FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_scan_run_rel FOREIGN KEY (scan_run_id) REFERENCES inventory_run_index(scan_run_id) ON DELETE CASCADE
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
CREATE INDEX IF NOT EXISTS idx_asset_tags_gin ON asset_index_latest USING gin(tags);

CREATE INDEX IF NOT EXISTS idx_rel_tenant ON relationship_index_latest(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rel_from_uid ON relationship_index_latest(from_uid);
CREATE INDEX IF NOT EXISTS idx_rel_to_uid ON relationship_index_latest(to_uid);
CREATE INDEX IF NOT EXISTS idx_rel_type ON relationship_index_latest(relation_type);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_asset_tenant_type ON asset_index_latest(tenant_id, resource_type);
CREATE INDEX IF NOT EXISTS idx_asset_tenant_region ON asset_index_latest(tenant_id, region);
CREATE INDEX IF NOT EXISTS idx_asset_tenant_provider ON asset_index_latest(tenant_id, provider);

