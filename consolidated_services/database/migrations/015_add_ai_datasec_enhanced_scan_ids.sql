-- ============================================================================
-- Migration 015: Add AI Security & DataSec Enhanced Engine Scan IDs
-- ============================================================================
--
-- Extends scan_orchestration with 2 new scan_id columns for the AI Security
-- and DataSec Enhanced engines, following the exact same pattern as migration
-- 014 which added container, network, supplychain, api, and risk scan IDs.
--
-- Idempotent: All ALTER TABLE ADD COLUMN IF NOT EXISTS
-- Rollback:   DROP COLUMN for each added column
-- ============================================================================


-- ============================================================================
-- PART 1: New engine scan_id columns on scan_orchestration
-- ============================================================================

ALTER TABLE scan_orchestration
  ADD COLUMN IF NOT EXISTS ai_security_scan_id       VARCHAR(255),
  ADD COLUMN IF NOT EXISTS datasec_enhanced_scan_id  VARCHAR(255);

COMMENT ON COLUMN scan_orchestration.ai_security_scan_id IS 'AI Security engine scan ID — written when engine starts (Port 8032)';
COMMENT ON COLUMN scan_orchestration.datasec_enhanced_scan_id IS 'DataSec Enhanced engine scan ID — written when engine starts (Port 8033)';


-- ============================================================================
-- PART 2: Indexes for new scan_id columns
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_orchestration_ai_security
    ON scan_orchestration(ai_security_scan_id);

CREATE INDEX IF NOT EXISTS idx_orchestration_datasec_enhanced
    ON scan_orchestration(datasec_enhanced_scan_id);


-- ============================================================================
-- PART 3: Add new engine DB passwords to Secrets Manager reference
-- ============================================================================
-- The following keys need to be added to threat-engine/rds-credentials in
-- AWS Secrets Manager (manual step):
--
--   AI_SECURITY_DB_PASSWORD       → password for threat_engine_ai_security DB
--   DATASEC_ENHANCED_DB_PASSWORD  → password for threat_engine_datasec_enhanced DB
--   LOG_COLLECTOR_DB_PASSWORD     → password for threat_engine_logs DB
--   EXTERNAL_COLLECTOR_DB_PASSWORD → password for threat_engine_external DB
--
-- These are referenced in external-secret-db-passwords.yaml
