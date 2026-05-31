-- UP: Add compliance posture columns to resource_security_posture and security_findings
-- Written by: compliance engine post-assessment write-back
BEGIN;

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS compliance_score           NUMERIC(5,2)    DEFAULT 0,
    ADD COLUMN IF NOT EXISTS compliance_frameworks_violated TEXT[]       DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS compliance_controls_failed INTEGER          DEFAULT 0;

ALTER TABLE security_findings
    ADD COLUMN IF NOT EXISTS compliance_frameworks      TEXT[]           DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_rsp_compliance_score
    ON resource_security_posture(compliance_score)
    WHERE compliance_score > 0;

CREATE INDEX IF NOT EXISTS idx_sf_compliance_frameworks
    ON security_findings USING GIN(compliance_frameworks)
    WHERE array_length(compliance_frameworks, 1) > 0;

COMMIT;
