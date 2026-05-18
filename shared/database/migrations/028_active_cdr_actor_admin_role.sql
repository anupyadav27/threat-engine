-- Migration 028: active_cdr_actor_on_admin_role composite flag column
-- Target DB: threat_engine_inventory (resource_security_posture table)
-- Cross-engine flag: is_admin_role AND has_active_cdr_actor

BEGIN;

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS active_cdr_actor_on_admin_role BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_rsp_cdr_admin_role
    ON resource_security_posture (tenant_id, active_cdr_actor_on_admin_role)
    WHERE active_cdr_actor_on_admin_role = TRUE;

COMMIT;

DO $$ BEGIN
    RAISE NOTICE 'MIGRATION COMPLETE: 028_active_cdr_actor_admin_role';
END $$;
