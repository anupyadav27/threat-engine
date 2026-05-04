-- =============================================================================
-- Migration: ENG-13 — Risk Engine FAIR model + Neo4j blast radius columns
-- Database:  threat_engine_risk
-- Table:     risk_scenarios
-- Date:      2026-05-02
-- =============================================================================
-- Adds ENG-13 columns to risk_scenarios for the FAIR model upgrade:
--   finding_id      — deterministic sha256[:16] idempotency key (AC-S4)
--   scan_run_id     — pipeline scan_run_id (was orchestration_id)
--   fair_lef        — Loss Event Frequency
--   fair_lm         — Loss Magnitude
--   fair_risk_score — LEF × LM (canonical FAIR score)
--   regulatory_flags — JSONB regulations inferred from resource region
-- Also adds blast_radius_score CHECK constraint (AC-S7).
-- Safe to run multiple times (IF NOT EXISTS / idempotent).
-- =============================================================================

BEGIN;

-- 1. Add finding_id — deterministic idempotency key (AC-S4)
ALTER TABLE risk_scenarios
    ADD COLUMN IF NOT EXISTS finding_id VARCHAR(16);

-- Unique constraint on finding_id for ON CONFLICT upserts
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_risk_scenarios_finding_id'
          AND conrelid = 'risk_scenarios'::regclass
    ) THEN
        ALTER TABLE risk_scenarios
            ADD CONSTRAINT uq_risk_scenarios_finding_id UNIQUE (finding_id);
    END IF;
END
$$;

-- 2. Add scan_run_id (pipeline UUID — replaces orchestration_id in new rows)
ALTER TABLE risk_scenarios
    ADD COLUMN IF NOT EXISTS scan_run_id UUID;

-- 3. Add canonical FAIR score columns
ALTER TABLE risk_scenarios
    ADD COLUMN IF NOT EXISTS fair_lef        DECIMAL(8,5)  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fair_lm         DECIMAL(14,2) NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fair_risk_score DECIMAL(14,2) NOT NULL DEFAULT 0;

-- 4. Add regulatory_flags JSONB column (region-inferred regulations, AC-F7)
ALTER TABLE risk_scenarios
    ADD COLUMN IF NOT EXISTS regulatory_flags JSONB DEFAULT '[]';

-- 5. Add CHECK constraint on blast_radius_score 0-100 (AC-S7)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_blast_radius_score_range'
          AND conrelid = 'risk_scenarios'::regclass
    ) THEN
        ALTER TABLE risk_scenarios
            ADD CONSTRAINT chk_blast_radius_score_range
            CHECK (blast_radius_score >= 0 AND blast_radius_score <= 100);
    END IF;
END
$$;

-- 6. Change data_types and applicable_regulations from TEXT[] to JSONB if needed
--    (new rows insert JSONB; old rows keep TEXT[] — both coexist in PostgreSQL)
--    Skip if already JSONB.
-- NOTE: This migration does NOT convert existing TEXT[] columns to avoid data loss.
-- New rows from the engine will always use the new JSONB parameter binding.

-- 7. Add index on (tenant_id, risk_scan_id) for AC-S2 tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_risk_scenarios_tenant_scan
    ON risk_scenarios (tenant_id, risk_scan_id);

-- 8. Add index on finding_id for upsert lookups
CREATE INDEX IF NOT EXISTS idx_risk_scenarios_finding_id
    ON risk_scenarios (finding_id)
    WHERE finding_id IS NOT NULL;

COMMIT;
