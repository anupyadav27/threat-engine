-- apisec_003: Add composite posture flags for API Security on resource_security_posture
-- These boolean columns are written by the attack-path engine (posture_updater.py)
-- and consumed by the attack-path BFS scoring to detect high-risk exposed assets.
--
-- Depends on: apisec_002_posture_columns.sql (api_auth_type, api_security_score, etc.)
-- Applied to: threat_engine_inventory DB (resource_security_posture table)

BEGIN;

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS api_public_no_waf   BOOLEAN DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_public_no_auth  BOOLEAN DEFAULT FALSE;

COMMENT ON COLUMN resource_security_posture.api_public_no_waf IS
    'True when api_publicly_accessible=true AND api_has_waf=false — set by attack-path posture_updater';
COMMENT ON COLUMN resource_security_posture.api_public_no_auth IS
    'True when api_publicly_accessible=true AND api_auth_type=none — set by attack-path posture_updater';

-- Partial index to accelerate attack-path BFS queries on exposed APIs
CREATE INDEX IF NOT EXISTS idx_rsp_api_public_no_waf
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE api_public_no_waf = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_api_public_no_auth
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE api_public_no_auth = TRUE;

COMMIT;

-- Verification
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'resource_security_posture'
          AND column_name = 'api_public_no_waf'
    ) THEN
        RAISE EXCEPTION 'MIGRATION FAILED: api_public_no_waf column missing';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'resource_security_posture'
          AND column_name = 'api_public_no_auth'
    ) THEN
        RAISE EXCEPTION 'MIGRATION FAILED: api_public_no_auth column missing';
    END IF;
    RAISE NOTICE 'apisec_003 MIGRATION COMPLETE';
END $$;
