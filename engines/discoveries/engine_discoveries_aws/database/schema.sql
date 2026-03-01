-- Discoveries Engine Database Schema
-- PostgreSQL DDL for discoveries storage
-- Tables: discovery_report, discovery_findings, discovery_history

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Customers (shared schema - engine_shared)
CREATE TABLE IF NOT EXISTS customers (
    customer_id VARCHAR(255) PRIMARY KEY,
    customer_name VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tenants (shared schema - engine_shared)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    tenant_name VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);

-- Discovery Report (scan metadata)
CREATE TABLE IF NOT EXISTS discovery_report (
    discovery_scan_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    provider VARCHAR(50),
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    region VARCHAR(100),
    service VARCHAR(100),
    scan_type VARCHAR(50) DEFAULT 'discovery',
    status VARCHAR(50) DEFAULT 'running',
    metadata JSONB DEFAULT '{}',
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_tenant_scan FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Discovery Findings Table
CREATE TABLE IF NOT EXISTS discovery_findings (
    id SERIAL PRIMARY KEY,
    discovery_scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    provider VARCHAR(50),
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    discovery_id VARCHAR(255) NOT NULL,
    resource_uid TEXT,  -- Primary identifier (ARN for AWS, Resource ID for Azure/GCP)
    resource_arn TEXT,  -- AWS-specific (for backward compatibility)
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    service VARCHAR(100),
    region VARCHAR(50),
    emitted_fields JSONB,
    raw_response JSONB,
    config_hash VARCHAR(64),
    version INTEGER DEFAULT 1,
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_discovery FOREIGN KEY (discovery_scan_id) REFERENCES discovery_report(discovery_scan_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_discovery FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Discovery History (for drift detection)
CREATE TABLE IF NOT EXISTS discovery_history (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    provider VARCHAR(50),
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    discovery_id VARCHAR(255) NOT NULL,
    resource_arn TEXT,
    resource_uid TEXT,  -- Primary identifier
    discovery_scan_id VARCHAR(255) NOT NULL,
    config_hash VARCHAR(64),
    raw_response JSONB,
    emitted_fields JSONB,
    version INTEGER DEFAULT 1,
    change_type VARCHAR(50),  -- 'created', 'modified', 'unchanged'
    previous_hash VARCHAR(64),
    diff_summary JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_history FOREIGN KEY (discovery_scan_id) REFERENCES discovery_report(discovery_scan_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_history FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_df_scan_id ON discovery_findings(discovery_scan_id);
CREATE INDEX IF NOT EXISTS idx_df_tenant_id ON discovery_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_df_discovery_id ON discovery_findings(discovery_id);
CREATE INDEX IF NOT EXISTS idx_df_resource_uid ON discovery_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_df_resource_arn ON discovery_findings(resource_arn);
CREATE INDEX IF NOT EXISTS idx_df_service ON discovery_findings(service);
CREATE INDEX IF NOT EXISTS idx_df_tenant_uid ON discovery_findings(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_df_scan_timestamp ON discovery_findings(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_df_lookup ON discovery_findings(discovery_id, tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_df_latest ON discovery_findings(resource_uid, discovery_id, tenant_id, hierarchy_id, scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_dh_scan_id ON discovery_history(discovery_scan_id);
CREATE INDEX IF NOT EXISTS idx_dh_resource_uid ON discovery_history(resource_uid);
CREATE INDEX IF NOT EXISTS idx_dh_change_type ON discovery_history(change_type);
