-- di_011: Add per-severity check finding counts to resource_security_posture
-- The check engine will upsert these after each scan so the BFF can read
-- severity summaries directly from posture without calling the check engine API.

ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS check_critical  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS check_high      INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS check_medium    INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS check_low       INTEGER NOT NULL DEFAULT 0;
