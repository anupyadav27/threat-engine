-- ============================================================================
-- Shared Database Schema
-- ============================================================================
-- Database: threat_engine_shared
-- Status:   DEPRECATED - kept for backward compatibility only
--
-- RDS actual tables (as of 2026-02-20):
--   scan_orchestration - only table remaining (scan_orchestration is authoritative
--                        in threat_engine_onboarding; this copy is legacy)
--
-- History:
--   Originally held: tenants, customers, accounts, schedules, executions,
--   engine_status, notifications, audit_log, global_config, tenant_config,
--   data_lineage. All of these were removed from RDS in production.
--   scan_orchestration was moved to threat_engine_onboarding (authoritative).
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- SCAN ORCHESTRATION (LEGACY COPY)
-- ============================================================================
-- This is a legacy copy. Authoritative scan_orchestration is in
-- threat_engine_onboarding.scan_orchestration.
-- Kept in shared DB for backward compatibility with older engine code.

CREATE TABLE IF NOT EXISTS scan_orchestration (
    orchestration_id    UUID            NOT NULL DEFAULT uuid_generate_v4(),
    tenant_id           VARCHAR(255)    NOT NULL,
    customer_id         VARCHAR(255),
    provider            VARCHAR(50),
    hierarchy_id        VARCHAR(255),
    account_id          VARCHAR(255),
    credential_type     VARCHAR(50)     NOT NULL,
    credential_ref      VARCHAR(255)    NOT NULL,
    scan_name           VARCHAR(255),
    scan_type           VARCHAR(50)     NOT NULL,
    trigger_type        VARCHAR(50)     NOT NULL,
    include_services    JSONB,
    include_regions     JSONB,
    exclude_services    JSONB,
    exclude_regions     JSONB,
    discovery_scan_id   VARCHAR(255),
    check_scan_id       VARCHAR(255),
    inventory_scan_id   VARCHAR(255),
    threat_scan_id      VARCHAR(255),
    compliance_scan_id  VARCHAR(255),
    iam_scan_id         VARCHAR(255),
    datasec_scan_id     VARCHAR(255),
    engines_requested   JSONB           NOT NULL,
    engines_completed   JSONB           DEFAULT '[]'::jsonb,
    overall_status      VARCHAR(50)     NOT NULL DEFAULT 'pending',
    execution_id        VARCHAR(255),
    schedule_id         VARCHAR(255),
    started_at          TIMESTAMP WITH TIME ZONE    NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMP WITH TIME ZONE,
    created_at          TIMESTAMP WITH TIME ZONE    DEFAULT NOW(),
    results_summary     JSONB           DEFAULT '{}'::jsonb,
    error_details       JSONB           DEFAULT '{}'::jsonb,

    CONSTRAINT scan_orchestration_pkey PRIMARY KEY (orchestration_id)
);

COMMENT ON TABLE scan_orchestration IS 'DEPRECATED: Legacy copy. Authoritative table is threat_engine_onboarding.scan_orchestration';

-- Indexes
CREATE INDEX IF NOT EXISTS idx_orchestration_tenant
    ON scan_orchestration(tenant_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_status
    ON scan_orchestration(overall_status, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_orchestration_type
    ON scan_orchestration(scan_type, trigger_type);

CREATE INDEX IF NOT EXISTS idx_orchestration_execution
    ON scan_orchestration(execution_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_schedule
    ON scan_orchestration(schedule_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_discovery
    ON scan_orchestration(discovery_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_check
    ON scan_orchestration(check_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_inventory
    ON scan_orchestration(inventory_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_engines_gin
    ON scan_orchestration USING gin(engines_requested);

CREATE INDEX IF NOT EXISTS idx_orchestration_results_gin
    ON scan_orchestration USING gin(results_summary);
