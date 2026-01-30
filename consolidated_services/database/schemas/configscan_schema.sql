-- PostgreSQL Schema for Multi-Tenant CSPM SaaS Platform
-- Supports: Customer → Tenant (per CSP) → Hierarchy (Account/Project/etc.) → Resources

-- Customers Table
CREATE TABLE IF NOT EXISTS customers (
    customer_id VARCHAR(255) PRIMARY KEY,
    customer_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB
);

-- Tenants Table (per CSP)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    tenant_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE
);

-- CSP Hierarchies Table (Account, Project, Subscription, Org, Resource Group, etc.)
CREATE TABLE IF NOT EXISTS csp_hierarchies (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_type VARCHAR(50) NOT NULL,  -- 'account', 'project', 'subscription', 'org', 'resource_group'
    hierarchy_id VARCHAR(255) NOT NULL,    -- AWS account_id, GCP project_id, Azure subscription_id, etc.
    hierarchy_name VARCHAR(255),
    parent_id INTEGER,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES csp_hierarchies(id) ON DELETE SET NULL,
    UNIQUE(tenant_id, provider, hierarchy_type, hierarchy_id)
);

-- Scans Table
CREATE TABLE IF NOT EXISTS scans (
    scan_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    region VARCHAR(50),
    service VARCHAR(100),
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    scan_type VARCHAR(50),  -- 'discovery', 'check', 'full'
    status VARCHAR(50),    -- 'running', 'completed', 'failed', 'partial'
    metadata JSONB,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Discoveries Table
CREATE TABLE IF NOT EXISTS discoveries (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    discovery_id VARCHAR(255) NOT NULL,  -- 'aws.s3.get_bucket_encryption'
    region VARCHAR(50),
    service VARCHAR(100) NOT NULL,
    resource_arn TEXT,
    resource_id VARCHAR(255),
    raw_response JSONB,                  -- Full API response
    emitted_fields JSONB,                 -- Extracted/emitted fields
    config_hash VARCHAR(64),              -- SHA256 hash for drift detection
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER DEFAULT 1,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Discovery History Table (for drift detection)
CREATE TABLE IF NOT EXISTS discovery_history (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    discovery_id VARCHAR(255) NOT NULL,
    resource_arn TEXT,
    scan_id VARCHAR(255) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    raw_response JSONB,
    emitted_fields JSONB,
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER NOT NULL,
    change_type VARCHAR(50),              -- 'created', 'modified', 'deleted', 'unchanged'
    previous_hash VARCHAR(64),
    diff_summary JSONB,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Checks Table (metadata about checks)
CREATE TABLE IF NOT EXISTS checks (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(255) NOT NULL,
    service VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    check_type VARCHAR(50) DEFAULT 'default',  -- 'default' or 'custom'
    customer_id VARCHAR(255),                 -- NULL for default, customer_id for custom
    tenant_id VARCHAR(255),
    check_config JSONB NOT NULL,              -- Full check YAML config
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    UNIQUE(rule_id, customer_id, tenant_id)
);

-- Check Results Table
CREATE TABLE IF NOT EXISTS check_results (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    rule_id VARCHAR(255) NOT NULL,
    resource_arn TEXT,
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    status VARCHAR(50) NOT NULL,             -- 'PASS', 'FAIL', 'ERROR'
    checked_fields JSONB,                    -- Fields checked
    finding_data JSONB NOT NULL,             -- Full finding data
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Drift Detections Table
CREATE TABLE IF NOT EXISTS drift_detections (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    resource_arn TEXT,
    discovery_id VARCHAR(255) NOT NULL,
    baseline_scan_id VARCHAR(255),
    current_scan_id VARCHAR(255),
    drift_type VARCHAR(50),                   -- 'configuration', 'deletion', 'addition'
    severity VARCHAR(50),                     -- 'low', 'medium', 'high', 'critical'
    change_summary JSONB,
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (customer_id) REFERENCES customers(customer_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Indexes for Performance
CREATE INDEX IF NOT EXISTS idx_tenants_customer ON tenants(customer_id);
CREATE INDEX IF NOT EXISTS idx_tenants_provider ON tenants(provider);
CREATE INDEX IF NOT EXISTS idx_hierarchies_tenant ON csp_hierarchies(tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_hierarchies_id ON csp_hierarchies(hierarchy_id, hierarchy_type);

CREATE INDEX IF NOT EXISTS idx_scans_customer_tenant ON scans(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_scans_hierarchy ON scans(hierarchy_id, hierarchy_type);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_discoveries_arn ON discoveries(resource_arn);
CREATE INDEX IF NOT EXISTS idx_discoveries_scan ON discoveries(scan_id, discovery_id);
CREATE INDEX IF NOT EXISTS idx_discoveries_tenant ON discoveries(tenant_id, hierarchy_id, provider);
CREATE INDEX IF NOT EXISTS idx_discoveries_hash ON discoveries(config_hash);
CREATE INDEX IF NOT EXISTS idx_discoveries_service ON discoveries(service, region);

CREATE INDEX IF NOT EXISTS idx_history_tenant ON discovery_history(tenant_id, resource_arn, discovery_id);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON discovery_history(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_history_hash ON discovery_history(config_hash, previous_hash);

CREATE INDEX IF NOT EXISTS idx_checks_service ON checks(service, provider, check_type);
CREATE INDEX IF NOT EXISTS idx_checks_customer ON checks(customer_id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_check_results_scan ON check_results(scan_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_check_results_tenant ON check_results(tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_check_results_status ON check_results(status, scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_check_results_rule ON check_results(rule_id, status);

CREATE INDEX IF NOT EXISTS idx_drift_tenant ON drift_detections(tenant_id, resource_arn, discovery_id);
CREATE INDEX IF NOT EXISTS idx_drift_detected ON drift_detections(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_drift_severity ON drift_detections(severity, detected_at DESC);

-- GIN Indexes for JSONB columns (for efficient JSON queries)
CREATE INDEX IF NOT EXISTS idx_discoveries_raw_response_gin ON discoveries USING gin(raw_response);
CREATE INDEX IF NOT EXISTS idx_discoveries_emitted_fields_gin ON discoveries USING gin(emitted_fields);
CREATE INDEX IF NOT EXISTS idx_check_results_finding_data_gin ON check_results USING gin(finding_data);
CREATE INDEX IF NOT EXISTS idx_drift_change_summary_gin ON drift_detections USING gin(change_summary);

