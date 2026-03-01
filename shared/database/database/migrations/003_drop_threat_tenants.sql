-- Migration 003: Drop local tenants table from threat_engine_threat
-- Reason: Tenant master lives in shared DB. Local tenants table is redundant.
-- tenant_id remains as plain VARCHAR on all tables (no FK enforcement).
--
-- Run against: threat_engine_threat database
-- ==========================================================================

BEGIN;

-- 1. Drop all FK constraints referencing tenants
ALTER TABLE IF EXISTS threat_report DROP CONSTRAINT IF EXISTS fk_tenant_report;
ALTER TABLE IF EXISTS threat_report DROP CONSTRAINT IF EXISTS fk_tenant_threat_report;
ALTER TABLE IF EXISTS threat_findings DROP CONSTRAINT IF EXISTS fk_tenant_finding;
ALTER TABLE IF EXISTS threat_findings DROP CONSTRAINT IF EXISTS fk_tenant_threat_findings;
ALTER TABLE IF EXISTS threat_intelligence DROP CONSTRAINT IF EXISTS fk_tenant_intel;
ALTER TABLE IF EXISTS threat_detections DROP CONSTRAINT IF EXISTS fk_tenant_detection;
ALTER TABLE IF EXISTS threat_analysis DROP CONSTRAINT IF EXISTS fk_tenant_analysis;
ALTER TABLE IF EXISTS threat_hunt_queries DROP CONSTRAINT IF EXISTS fk_tenant_hunt;
ALTER TABLE IF EXISTS threat_hunt_results DROP CONSTRAINT IF EXISTS fk_tenant_hunt_result;

-- 2. Drop the tenants table
DROP TABLE IF EXISTS tenants;

-- 3. Verify all tables still have tenant_id column (no data loss)
-- SELECT table_name, column_name FROM information_schema.columns
-- WHERE column_name = 'tenant_id' AND table_schema = 'public';

COMMIT;
