-- =============================================================================
-- API Security Posture Columns
-- Target DB: threat_engine_inventory
-- =============================================================================

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS api_auth_type                 VARCHAR(50),
    ADD COLUMN IF NOT EXISTS api_has_waf                   BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_has_rate_limit            BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_publicly_accessible       BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_deprecated_version_active BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS api_security_score            SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS api_detail                    JSONB;

CREATE INDEX IF NOT EXISTS idx_rsp_api_public_nowaf
    ON resource_security_posture(tenant_id, scan_run_id)
    WHERE api_publicly_accessible = TRUE AND api_has_waf = FALSE;

CREATE INDEX IF NOT EXISTS idx_rsp_api_score
    ON resource_security_posture(tenant_id, api_security_score)
    WHERE api_security_score IS NOT NULL;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: apisec_002_posture_columns'; END; $$;
