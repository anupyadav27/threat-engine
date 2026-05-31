-- Migration: di_017_rsp_risk_scores
-- Database:  threat_engine_di
-- Purpose:   Add FAIR financial risk output columns to resource_security_posture.
--            Written by risk engine (Stage 3 reporter) after FAIR computation.
--            Enables BFF + UI to show per-resource dollar exposure without
--            querying threat_engine_risk directly.
--
-- Columns added:
--   total_exposure_likely  — SUM of FAIR exposure across all scenarios for this resource (USD)
--   risk_tier              — worst tier across all scenarios (critical/high/medium/low)
--   fair_risk_score        — SUM of FAIR risk scores across all scenarios
--   risk_scan_id           — UUID of the risk scan that produced these values

BEGIN;

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS total_exposure_likely  NUMERIC(18,2)  DEFAULT 0   NOT NULL,
    ADD COLUMN IF NOT EXISTS risk_tier              VARCHAR(20),
    ADD COLUMN IF NOT EXISTS fair_risk_score        NUMERIC(14,4)  DEFAULT 0   NOT NULL,
    ADD COLUMN IF NOT EXISTS risk_scan_id           UUID;

CREATE INDEX IF NOT EXISTS idx_rsp_risk_tier
    ON resource_security_posture (tenant_id, risk_tier)
    WHERE risk_tier IN ('critical', 'high');

CREATE INDEX IF NOT EXISTS idx_rsp_exposure
    ON resource_security_posture (tenant_id, total_exposure_likely DESC)
    WHERE total_exposure_likely > 0;

COMMIT;
