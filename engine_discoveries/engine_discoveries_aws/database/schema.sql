-- Discoveries Engine Database Schema
-- PostgreSQL DDL for discoveries storage

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

-- Scans (shared schema - engine_shared)
CREATE TABLE IF NOT EXISTS scans (
    scan_id VARCHAR(255) PRIMARY KEY,
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

-- Discoveries Table
CREATE TABLE IF NOT EXISTS discoveries (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
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
    CONSTRAINT fk_scan_discovery FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
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
    scan_id VARCHAR(255) NOT NULL,
    config_hash VARCHAR(64),
    raw_response JSONB,
    emitted_fields JSONB,
    version INTEGER DEFAULT 1,
    change_type VARCHAR(50),  -- 'created', 'modified', 'unchanged'
    previous_hash VARCHAR(64),
    diff_summary JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_history FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_history FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_discoveries_scan_id ON discoveries(scan_id);
CREATE INDEX IF NOT EXISTS idx_discoveries_tenant_id ON discoveries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_discoveries_discovery_id ON discoveries(discovery_id);
CREATE INDEX IF NOT EXISTS idx_discoveries_resource_uid ON discoveries(resource_uid);
CREATE INDEX IF NOT EXISTS idx_discoveries_resource_arn ON discoveries(resource_arn);
CREATE INDEX IF NOT EXISTS idx_discoveries_service ON discoveries(service);
CREATE INDEX IF NOT EXISTS idx_discoveries_tenant_uid ON discoveries(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_discoveries_scan_timestamp ON discoveries(scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_discovery_history_scan_id ON discovery_history(scan_id);
CREATE INDEX IF NOT EXISTS idx_discovery_history_resource_uid ON discovery_history(resource_uid);
CREATE INDEX IF NOT EXISTS idx_discovery_history_change_type ON discovery_history(change_type);
