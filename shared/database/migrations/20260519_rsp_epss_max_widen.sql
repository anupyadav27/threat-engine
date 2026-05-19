-- Widen resource_security_posture.epss_max from NUMERIC(5,4) to NUMERIC(4,1)
-- The posture writer stores CVSS scores (0-10) not EPSS probability (0-1).
-- NUMERIC(5,4) overflows on score=10.0 — NUMERIC(4,1) holds 0.0-999.9.
-- Target DB: threat_engine_inventory

ALTER TABLE resource_security_posture
    ALTER COLUMN epss_max TYPE NUMERIC(4,1);
