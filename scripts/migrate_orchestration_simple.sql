-- Create scan_orchestration table in threat_engine_onboarding
-- Based on live RDS schema from threat_engine_shared.scan_orchestration

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS scan_orchestration (
    orchestration_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id VARCHAR(255) NOT NULL,
    scan_name VARCHAR(255),
    scan_type VARCHAR(50) NOT NULL DEFAULT 'full',
    trigger_type VARCHAR(50) NOT NULL DEFAULT 'scheduled',
    engines_requested JSONB NOT NULL DEFAULT '["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"]',
    engines_completed JSONB DEFAULT '[]',
    overall_status VARCHAR(50) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    results_summary JSONB DEFAULT '{}',
    error_details JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    execution_id UUID,
    customer_id VARCHAR(255),
    provider VARCHAR(50) NOT NULL,
    hierarchy_id VARCHAR(255) NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    include_services JSONB,
    include_regions JSONB,
    discovery_scan_id VARCHAR(255),
    check_scan_id VARCHAR(255),
    inventory_scan_id VARCHAR(255),
    threat_scan_id VARCHAR(255),
    compliance_scan_id VARCHAR(255),
    iam_scan_id VARCHAR(255),
    datasec_scan_id VARCHAR(255),
    credential_type VARCHAR(50) NOT NULL,
    credential_ref VARCHAR(255) NOT NULL,
    exclude_services JSONB,
    exclude_regions JSONB,
    schedule_id VARCHAR(255)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_orchestration_tenant ON scan_orchestration(tenant_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_status ON scan_orchestration(overall_status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_orchestration_execution ON scan_orchestration(execution_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_schedule ON scan_orchestration(schedule_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_discovery ON scan_orchestration(discovery_scan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_check ON scan_orchestration(check_scan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_inventory ON scan_orchestration(inventory_scan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_threat ON scan_orchestration(threat_scan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_compliance ON scan_orchestration(compliance_scan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_iam ON scan_orchestration(iam_scan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_datasec ON scan_orchestration(datasec_scan_id);
CREATE INDEX IF NOT EXISTS idx_orchestration_engines_gin ON scan_orchestration USING gin(engines_requested);
CREATE INDEX IF NOT EXISTS idx_orchestration_results_gin ON scan_orchestration USING gin(results_summary);