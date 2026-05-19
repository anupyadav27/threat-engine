-- =============================================================================
-- Migration: 20260519_vuln_mitre_tactic_cache
-- Target DB: vulnerability_db
--
-- Purpose:  Engine-local MITRE ATT&CK T-code → tactic lookup cache.
--           Populated at engine startup and refreshed every 90 days by the
--           reference_data background task in the vulnerability engine.
--           Allows security_findings rows to carry mitre_tactic without a
--           cross-DB join to threat_engine_threat at scan time.
--
-- Rollback:
--   BEGIN;
--   DROP TABLE IF EXISTS mitre_tactic_cache;
--   COMMIT;
-- =============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS mitre_tactic_cache (
    technique_id  VARCHAR(20)   PRIMARY KEY,        -- e.g. T1190, T1078.004
    tactic        VARCHAR(50)   NOT NULL,            -- e.g. Initial Access
    refreshed_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE mitre_tactic_cache IS
    'MITRE ATT&CK T-code → tactic mapping cache local to vulnerability_db. '
    'Seeded and refreshed every 90 days by reference_data._mitre_loop().';

COMMIT;
