-- UP Migration
-- Adds threat_flags JSONB column to rule_metadata.
-- Populated by scripts/bootstrap_threat_flags.py (keyword bootstrap)
-- and maintained via rule YAML metadata going forward.
-- FlagMapper reads this column at scan time instead of hardcoded keywords.

BEGIN;

ALTER TABLE rule_metadata
    ADD COLUMN IF NOT EXISTS threat_flags JSONB DEFAULT '[]'::jsonb;

COMMENT ON COLUMN rule_metadata.threat_flags IS
    'Array of threat-signal flag names this rule contributes to when status=FAIL. '
    'E.g. ["internet_exposed"], ["has_no_mfa"], ["has_no_audit_trail"]. '
    'Valid values: internet_exposed | is_admin_role | has_imdsv1 | has_no_mfa | '
    'has_stale_credentials | has_no_audit_trail | has_no_rotation';

COMMIT;

-- DOWN Migration
BEGIN;
ALTER TABLE rule_metadata DROP COLUMN IF EXISTS threat_flags;
COMMIT;
