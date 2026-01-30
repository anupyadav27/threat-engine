-- =============================================================================
-- Single PostgreSQL Database Consolidation - Init Script
-- DB: postgres (default). All engine data in engine_* schemas.
-- engine_shared.tenants + engine_shared.customers are canonical.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- -----------------------------------------------------------------------------
-- Schemas
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS engine_shared;
CREATE SCHEMA IF NOT EXISTS engine_onboarding;
CREATE SCHEMA IF NOT EXISTS engine_configscan;
CREATE SCHEMA IF NOT EXISTS engine_compliance;
CREATE SCHEMA IF NOT EXISTS engine_inventory;
CREATE SCHEMA IF NOT EXISTS engine_userportal;
CREATE SCHEMA IF NOT EXISTS engine_adminportal;
CREATE SCHEMA IF NOT EXISTS engine_secops;
CREATE SCHEMA IF NOT EXISTS engine_threat;

-- -----------------------------------------------------------------------------
-- engine_shared: tenants, customers (canonical; Decision 1.A)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_shared.customers (
    customer_id VARCHAR(255) PRIMARY KEY,
    customer_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS engine_shared.tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255) REFERENCES engine_shared.customers(customer_id) ON DELETE CASCADE,
    tenant_name VARCHAR(255),
    provider VARCHAR(50),
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_shared_tenants_customer ON engine_shared.tenants(customer_id);
CREATE INDEX IF NOT EXISTS idx_shared_tenants_provider ON engine_shared.tenants(provider);
CREATE INDEX IF NOT EXISTS idx_shared_tenants_status ON engine_shared.tenants(status);

-- update_updated_at helper (used by engine_onboarding etc.)
CREATE OR REPLACE FUNCTION engine_shared.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON engine_shared.tenants
    FOR EACH ROW EXECUTE FUNCTION engine_shared.update_updated_at_column();

-- -----------------------------------------------------------------------------
-- engine_configscan: discoveries, check_results, csp_hierarchies, scans
-- FK to engine_shared.tenants / engine_shared.customers. No local customers.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_configscan.scans (
    scan_id VARCHAR(255) PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL REFERENCES engine_shared.customers(customer_id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    region VARCHAR(50),
    service VARCHAR(100),
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    scan_type VARCHAR(50),
    status VARCHAR(50),
    metadata JSONB
);

CREATE TABLE IF NOT EXISTS engine_configscan.csp_hierarchies (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    hierarchy_type VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255) NOT NULL,
    hierarchy_name VARCHAR(255),
    parent_id INTEGER REFERENCES engine_configscan.csp_hierarchies(id) ON DELETE SET NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, provider, hierarchy_type, hierarchy_id)
);

CREATE TABLE IF NOT EXISTS engine_configscan.discoveries (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL REFERENCES engine_configscan.scans(scan_id) ON DELETE CASCADE,
    customer_id VARCHAR(255) NOT NULL REFERENCES engine_shared.customers(customer_id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    discovery_id VARCHAR(255) NOT NULL,
    region VARCHAR(50),
    service VARCHAR(100) NOT NULL,
    resource_arn TEXT,
    resource_id VARCHAR(255),
    raw_response JSONB,
    emitted_fields JSONB,
    config_hash VARCHAR(64),
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS engine_configscan.check_results (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL REFERENCES engine_configscan.scans(scan_id) ON DELETE CASCADE,
    customer_id VARCHAR(255) NOT NULL REFERENCES engine_shared.customers(customer_id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255),
    hierarchy_type VARCHAR(50),
    rule_id VARCHAR(255) NOT NULL,
    resource_arn TEXT,
    resource_id VARCHAR(255),
    resource_type VARCHAR(100),
    status VARCHAR(50) NOT NULL,
    checked_fields JSONB,
    finding_data JSONB NOT NULL,
    scan_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cfg_scans_customer_tenant ON engine_configscan.scans(customer_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_cfg_scans_timestamp ON engine_configscan.scans(scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_cfg_hierarchies_tenant ON engine_configscan.csp_hierarchies(tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_cfg_discoveries_scan ON engine_configscan.discoveries(scan_id, discovery_id);
CREATE INDEX IF NOT EXISTS idx_cfg_discoveries_tenant ON engine_configscan.discoveries(tenant_id, hierarchy_id, provider);
CREATE TABLE IF NOT EXISTS engine_configscan.discovery_history (
    id SERIAL PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL REFERENCES engine_shared.customers(customer_id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
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
    change_type VARCHAR(50),
    previous_hash VARCHAR(64),
    diff_summary JSONB
);

CREATE INDEX IF NOT EXISTS idx_cfg_history_tenant ON engine_configscan.discovery_history(tenant_id, resource_arn, discovery_id);
CREATE INDEX IF NOT EXISTS idx_cfg_history_timestamp ON engine_configscan.discovery_history(scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_cfg_check_results_scan ON engine_configscan.check_results(scan_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_cfg_check_results_tenant ON engine_configscan.check_results(tenant_id, hierarchy_id);
CREATE INDEX IF NOT EXISTS idx_cfg_check_results_status ON engine_configscan.check_results(status, scan_timestamp DESC);

-- -----------------------------------------------------------------------------
-- engine_onboarding: providers, accounts, schedules, executions, scan_results
-- FK to engine_shared.tenants only (no local tenants)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_onboarding.providers (
    provider_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    provider_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, provider_type)
);

CREATE TABLE IF NOT EXISTS engine_onboarding.accounts (
    account_id VARCHAR(255) PRIMARY KEY,
    provider_id VARCHAR(255) NOT NULL REFERENCES engine_onboarding.providers(provider_id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    account_name VARCHAR(255) NOT NULL,
    account_number VARCHAR(50),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    onboarding_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    onboarding_id VARCHAR(255),
    last_validated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engine_onboarding.schedules (
    schedule_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    account_id VARCHAR(255) NOT NULL REFERENCES engine_onboarding.accounts(account_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    schedule_type VARCHAR(50) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    cron_expression VARCHAR(255),
    interval_seconds INTEGER DEFAULT 0,
    regions JSONB DEFAULT '[]'::jsonb,
    services JSONB DEFAULT '[]'::jsonb,
    exclude_services JSONB DEFAULT '[]'::jsonb,
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    run_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    notify_on_success BOOLEAN NOT NULL DEFAULT FALSE,
    notify_on_failure BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engine_onboarding.executions (
    execution_id VARCHAR(255) PRIMARY KEY,
    schedule_id VARCHAR(255) NOT NULL REFERENCES engine_onboarding.schedules(schedule_id) ON DELETE CASCADE,
    account_id VARCHAR(255) NOT NULL REFERENCES engine_onboarding.accounts(account_id) ON DELETE CASCADE,
    scan_id VARCHAR(255),
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    triggered_by VARCHAR(50) NOT NULL DEFAULT 'scheduler',
    total_checks INTEGER,
    passed_checks INTEGER,
    failed_checks INTEGER,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engine_onboarding.scan_results (
    scan_id VARCHAR(255) PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL REFERENCES engine_onboarding.accounts(account_id) ON DELETE CASCADE,
    provider_type VARCHAR(50) NOT NULL,
    scan_type VARCHAR(50) NOT NULL DEFAULT 'scheduled',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    total_checks INTEGER,
    passed_checks INTEGER,
    failed_checks INTEGER,
    error_checks INTEGER,
    result_storage_path TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_onb_providers_tenant ON engine_onboarding.providers(tenant_id, provider_type);
CREATE INDEX IF NOT EXISTS idx_onb_accounts_tenant ON engine_onboarding.accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_onb_schedules_tenant ON engine_onboarding.schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_onb_schedules_enabled ON engine_onboarding.schedules(enabled, next_run_at);
CREATE INDEX IF NOT EXISTS idx_onb_executions_schedule ON engine_onboarding.executions(schedule_id, started_at);
CREATE INDEX IF NOT EXISTS idx_onb_scan_results_account ON engine_onboarding.scan_results(account_id, started_at);

-- Triggers for updated_at
CREATE TRIGGER update_providers_updated_at BEFORE UPDATE ON engine_onboarding.providers
    FOR EACH ROW EXECUTE FUNCTION engine_shared.update_updated_at_column();
CREATE TRIGGER update_accounts_updated_at BEFORE UPDATE ON engine_onboarding.accounts
    FOR EACH ROW EXECUTE FUNCTION engine_shared.update_updated_at_column();
CREATE TRIGGER update_schedules_updated_at BEFORE UPDATE ON engine_onboarding.schedules
    FOR EACH ROW EXECUTE FUNCTION engine_shared.update_updated_at_column();

-- -----------------------------------------------------------------------------
-- engine_compliance: report_index, finding_index; FK to engine_shared.tenants
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_compliance.report_index (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    scan_run_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL,
    collection_mode VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    total_controls INTEGER NOT NULL DEFAULT 0,
    controls_passed INTEGER NOT NULL DEFAULT 0,
    controls_failed INTEGER NOT NULL DEFAULT 0,
    total_findings INTEGER NOT NULL DEFAULT 0,
    report_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engine_compliance.finding_index (
    finding_id VARCHAR(255) PRIMARY KEY,
    report_id UUID NOT NULL REFERENCES engine_compliance.report_index(report_id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    scan_run_id VARCHAR(255) NOT NULL,
    rule_id VARCHAR(255) NOT NULL,
    rule_version VARCHAR(50),
    category VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    region VARCHAR(50),
    finding_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comp_report_tenant_scan ON engine_compliance.report_index(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_comp_report_completed ON engine_compliance.report_index(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_comp_finding_tenant_scan ON engine_compliance.finding_index(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_comp_finding_severity ON engine_compliance.finding_index(severity);
CREATE INDEX IF NOT EXISTS idx_comp_finding_status ON engine_compliance.finding_index(status);
CREATE INDEX IF NOT EXISTS idx_comp_finding_rule ON engine_compliance.finding_index(rule_id);

-- -----------------------------------------------------------------------------
-- engine_inventory: run index, assets, relationships; FK to engine_shared.tenants
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_inventory.inventory_run_index (
    scan_run_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engine_inventory.asset_index_latest (
    asset_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    resource_uid TEXT NOT NULL,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    resource_type VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    tags JSONB DEFAULT '{}',
    latest_scan_run_id VARCHAR(255) NOT NULL REFERENCES engine_inventory.inventory_run_index(scan_run_id) ON DELETE CASCADE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engine_inventory.relationship_index_latest (
    relationship_id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    scan_run_id VARCHAR(255) NOT NULL REFERENCES engine_inventory.inventory_run_index(scan_run_id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    relation_type VARCHAR(100) NOT NULL,
    from_uid TEXT NOT NULL,
    to_uid TEXT NOT NULL,
    properties JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_run_tenant ON engine_inventory.inventory_run_index(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_run_completed ON engine_inventory.inventory_run_index(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_inv_asset_tenant ON engine_inventory.asset_index_latest(tenant_id);
CREATE INDEX IF NOT EXISTS idx_inv_asset_resource_uid ON engine_inventory.asset_index_latest(resource_uid);
CREATE INDEX IF NOT EXISTS idx_inv_asset_provider ON engine_inventory.asset_index_latest(provider);
CREATE INDEX IF NOT EXISTS idx_inv_rel_tenant ON engine_inventory.relationship_index_latest(tenant_id);

-- -----------------------------------------------------------------------------
-- engine_secops: secops_scans, secops_findings; scan_id, customer_id, tenant_id
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_secops.secops_scans (
    scan_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    customer_id VARCHAR(255) REFERENCES engine_shared.customers(customer_id) ON DELETE SET NULL,
    project_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    provider VARCHAR(50) DEFAULT 'secops',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engine_secops.secops_findings (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL REFERENCES engine_secops.secops_scans(scan_id) ON DELETE CASCADE,
    tenant_id VARCHAR(255) NOT NULL REFERENCES engine_shared.tenants(tenant_id) ON DELETE CASCADE,
    customer_id VARCHAR(255) REFERENCES engine_shared.customers(customer_id) ON DELETE SET NULL,
    rule_id VARCHAR(255),
    severity VARCHAR(50),
    file_path TEXT,
    message TEXT,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_secops_scans_tenant ON engine_secops.secops_scans(tenant_id);
CREATE INDEX IF NOT EXISTS idx_secops_scans_customer ON engine_secops.secops_scans(customer_id);
CREATE INDEX IF NOT EXISTS idx_secops_scans_started ON engine_secops.secops_scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_secops_findings_scan ON engine_secops.secops_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_secops_findings_tenant ON engine_secops.secops_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_secops_findings_severity ON engine_secops.secops_findings(severity);

-- -----------------------------------------------------------------------------
-- engine_threat: threat_reports (Threat engine output when THREAT_USE_DB=true)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS engine_threat.threat_reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_run_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    cloud VARCHAR(50) NOT NULL,
    trigger_type VARCHAR(50) NOT NULL,
    report_data JSONB NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, scan_run_id)
);
CREATE INDEX IF NOT EXISTS idx_threat_reports_tenant_scan ON engine_threat.threat_reports(tenant_id, scan_run_id);
CREATE INDEX IF NOT EXISTS idx_threat_reports_generated_at ON engine_threat.threat_reports(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_reports_data_gin ON engine_threat.threat_reports USING gin(report_data);

-- engine_userportal, engine_adminportal: schemas only; tables via Django migrations
-- (Already created above.)
