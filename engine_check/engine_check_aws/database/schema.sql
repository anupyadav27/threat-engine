-- Check Engine Database Schema
-- PostgreSQL DDL for check results storage

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
    scan_type VARCHAR(50) DEFAULT 'check',
    status VARCHAR(50) DEFAULT 'running',
    metadata JSONB DEFAULT '{}',
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_tenant_scan FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Check Results Table
CREATE TABLE IF NOT EXISTS check_results (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255),
    tenant_id VARCHAR(255),
    provider VARCHAR(50),
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    rule_id VARCHAR(255) NOT NULL,
    resource_uid TEXT,  -- Primary identifier (ARN for AWS, Resource ID for Azure/GCP)
    resource_arn TEXT,  -- AWS-specific (for backward compatibility)
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    status VARCHAR(50),  -- PASS, FAIL, ERROR
    checked_fields JSONB,
    finding_data JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_scan_check FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    CONSTRAINT fk_tenant_check FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_check_results_scan_id ON check_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_check_results_tenant_id ON check_results(tenant_id);
CREATE INDEX IF NOT EXISTS idx_check_results_rule_id ON check_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_check_results_resource_uid ON check_results(resource_uid);
CREATE INDEX IF NOT EXISTS idx_check_results_resource_arn ON check_results(resource_arn);
CREATE INDEX IF NOT EXISTS idx_check_results_status ON check_results(status);
CREATE INDEX IF NOT EXISTS idx_check_results_tenant_uid ON check_results(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_check_results_created_at ON check_results(created_at DESC);
