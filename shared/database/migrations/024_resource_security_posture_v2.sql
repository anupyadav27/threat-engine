-- Migration 024: Extend resource_security_posture with Container, Vulnerability,
-- AI-Security, and Cross-Engine Composite Signal Columns
-- Target DB: threat_engine_inventory
-- Depends on: 023_resource_security_posture.sql (table must exist)

BEGIN;

-- ============================================================================
-- Container Security dimension (written by container-security engine)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS has_privileged_container         BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS image_has_critical_cve           BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS k8s_rbac_overpermissive          BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS container_network_policy_missing BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS container_security_score         SMALLINT NOT NULL DEFAULT 0;

-- ============================================================================
-- Vulnerability dimension (written by vulnerability engine)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS vuln_critical_count  INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS vuln_high_count      INTEGER      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS has_known_exploit    BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS epss_max             NUMERIC(5,4) NOT NULL DEFAULT 0;

-- ============================================================================
-- AI Security dimension (written by ai-security engine)
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS has_shadow_ai_service        BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ai_model_publicly_accessible BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS ai_training_data_has_pii     BOOLEAN NOT NULL DEFAULT FALSE;

-- ============================================================================
-- Cross-engine composite flags (computed by attack-path engine post-merge)
-- Each flag encodes a dangerous multi-dimension combination.
-- ============================================================================
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS unencrypted_pii_store       BOOLEAN NOT NULL DEFAULT FALSE,
    -- data_classification IN ('pii','phi','pci') AND NOT is_encrypted_at_rest
    ADD COLUMN IF NOT EXISTS internet_exposed_with_pii   BOOLEAN NOT NULL DEFAULT FALSE,
    -- is_internet_exposed = TRUE AND data_classification IN ('pii','phi','pci')
    ADD COLUMN IF NOT EXISTS admin_role_without_mfa      BOOLEAN NOT NULL DEFAULT FALSE,
    -- is_admin_role = TRUE AND mfa_enforced = FALSE
    ADD COLUMN IF NOT EXISTS exploitable_exposed_resource BOOLEAN NOT NULL DEFAULT FALSE,
    -- is_internet_exposed = TRUE AND has_known_exploit = TRUE
    ADD COLUMN IF NOT EXISTS cdr_active_on_unencrypted   BOOLEAN NOT NULL DEFAULT FALSE;
    -- has_active_cdr_actor = TRUE AND is_encrypted_at_rest = FALSE

-- ============================================================================
-- Partial indexes on new high-value boolean columns
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_rsp_privileged_container
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE has_privileged_container = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_known_exploit
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE has_known_exploit = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_unencrypted_pii
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE unencrypted_pii_store = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_internet_pii
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE internet_exposed_with_pii = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_admin_no_mfa
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE admin_role_without_mfa = TRUE;

COMMIT;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: 024_resource_security_posture_v2'; END; $$;
