BEGIN;

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS has_priv_escalation_path      BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS priv_escalation_hop_count     SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS priv_escalation_cdr_confirmed BOOLEAN  NOT NULL DEFAULT FALSE;

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS ecr_scan_on_push_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS eks_node_ami_outdated     BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_rsp_priv_escalation
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE has_priv_escalation_path = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_priv_escalation_cdr
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE priv_escalation_cdr_confirmed = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_ecr_no_scan
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE ecr_scan_on_push_enabled = FALSE;

CREATE INDEX IF NOT EXISTS idx_rsp_eks_ami_outdated
    ON resource_security_posture (tenant_id, scan_run_id)
    WHERE eks_node_ami_outdated = TRUE;

COMMIT;

DO $$ BEGIN RAISE NOTICE 'MIGRATION COMPLETE: 027_posture_depth_columns'; END; $$;
