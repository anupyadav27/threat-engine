-- ============================================================================
-- Onboarding Engine Database Schema
-- ============================================================================
-- Database: threat_engine_onboarding
-- Purpose: Manage tenant onboarding, cloud provider accounts, scan schedules,
--          execution tracking, and scan results
-- Used by: engine_onboarding
-- Tables: tenants, providers, accounts, schedules, executions, scan_results

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- CORE TABLES
-- ============================================================================

-- Multi-tenant organization/customer tracking
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Cloud service provider configurations per tenant
CREATE TABLE IF NOT EXISTS providers (
    provider_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    provider_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT providers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- Individual cloud accounts to be scanned
CREATE TABLE IF NOT EXISTS accounts (
    account_id VARCHAR(255) PRIMARY KEY,
    provider_id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    account_name VARCHAR(255) NOT NULL,
    account_number VARCHAR(50),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    onboarding_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    onboarding_id VARCHAR(255),
    last_validated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    auth_method VARCHAR(50),
    credential_reference VARCHAR(500),
    external_id VARCHAR(255),

    CONSTRAINT accounts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT accounts_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES providers(provider_id) ON DELETE CASCADE
);

-- Automated scan schedules with cron/interval support
CREATE TABLE IF NOT EXISTS schedules (
    schedule_id VARCHAR(255) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
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
    enabled BOOLEAN NOT NULL DEFAULT true,
    next_run_at TIMESTAMP WITH TIME ZONE,
    run_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    notify_on_success BOOLEAN NOT NULL DEFAULT false,
    notify_on_failure BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT schedules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    CONSTRAINT schedules_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
);

-- Scan execution tracking and status
CREATE TABLE IF NOT EXISTS executions (
    execution_id VARCHAR(255) PRIMARY KEY,
    schedule_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    scan_id VARCHAR(255),
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    triggered_by VARCHAR(50) NOT NULL DEFAULT 'scheduler',
    total_checks INTEGER,
    passed_checks INTEGER,
    failed_checks INTEGER,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT executions_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id) ON DELETE CASCADE,
    CONSTRAINT executions_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
);

-- Overall scan results and metadata storage
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id VARCHAR(255) PRIMARY KEY,
    account_id VARCHAR(255) NOT NULL,
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
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT scan_results_account_id_fkey FOREIGN KEY (account_id) REFERENCES accounts(account_id) ON DELETE CASCADE
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Tenant indexes
CREATE INDEX IF NOT EXISTS idx_tenants_name ON tenants(tenant_name);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- Provider indexes
CREATE INDEX IF NOT EXISTS idx_providers_tenant ON providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_providers_type ON providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_providers_status ON providers(status);

-- Account indexes
CREATE INDEX IF NOT EXISTS idx_accounts_tenant ON accounts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(provider_id);
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
CREATE INDEX IF NOT EXISTS idx_accounts_onboarding_status ON accounts(onboarding_status);
CREATE INDEX IF NOT EXISTS idx_accounts_auth_method ON accounts(auth_method);

-- Schedule indexes
CREATE INDEX IF NOT EXISTS idx_schedules_tenant ON schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_schedules_account ON schedules(account_id);
CREATE INDEX IF NOT EXISTS idx_schedules_type ON schedules(schedule_type);
CREATE INDEX IF NOT EXISTS idx_schedules_status ON schedules(status);
CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON schedules(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run_at) WHERE enabled = true;

-- Execution indexes
CREATE INDEX IF NOT EXISTS idx_executions_schedule ON executions(schedule_id);
CREATE INDEX IF NOT EXISTS idx_executions_account ON executions(account_id);
CREATE INDEX IF NOT EXISTS idx_executions_scan ON executions(scan_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON executions(status);
CREATE INDEX IF NOT EXISTS idx_executions_started ON executions(started_at);

-- Scan results indexes
CREATE INDEX IF NOT EXISTS idx_scan_results_account ON scan_results(account_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_type ON scan_results(scan_type);
CREATE INDEX IF NOT EXISTS idx_scan_results_status ON scan_results(status);
CREATE INDEX IF NOT EXISTS idx_scan_results_started ON scan_results(started_at);

-- ============================================================================
-- COMMENTS
-- ============================================================================

COMMENT ON TABLE tenants IS 'Multi-tenant organization/customer tracking';
COMMENT ON TABLE providers IS 'Cloud service provider configurations per tenant';
COMMENT ON TABLE accounts IS 'Individual cloud accounts to be scanned';
COMMENT ON TABLE schedules IS 'Automated scan schedules with cron/interval support';
COMMENT ON TABLE executions IS 'Scan execution tracking and status';
COMMENT ON TABLE scan_results IS 'Overall scan results and metadata storage';
