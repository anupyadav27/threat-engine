-- Migration 027: CISA KEV catalog table + kev_listed column on scan_vulnerabilities
-- Target DB: threat_engine_vulnerability (same DB as scan_vulnerabilities)
-- Run this on the vulnerability DB pod.

BEGIN;

-- KEV reference table (global, no tenant_id — public catalog data)
CREATE TABLE IF NOT EXISTS kev_catalog (
    cve_id              VARCHAR(50)   PRIMARY KEY,
    vendor_project      VARCHAR(255),
    product             VARCHAR(255),
    vulnerability_name  VARCHAR(512),
    date_added          DATE,
    short_description   TEXT,
    required_action     TEXT,
    due_date            DATE,
    known_ransomware    BOOLEAN       NOT NULL DEFAULT FALSE,
    synced_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kev_catalog_date_added
    ON kev_catalog (date_added);

CREATE INDEX IF NOT EXISTS idx_kev_catalog_known_ransomware
    ON kev_catalog (known_ransomware) WHERE known_ransomware = TRUE;

-- Add kev_listed flag to scan_vulnerabilities
ALTER TABLE scan_vulnerabilities
    ADD COLUMN IF NOT EXISTS kev_listed BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_sv_kev_listed
    ON scan_vulnerabilities (scan_run_id, kev_listed) WHERE kev_listed = TRUE;

COMMIT;

DO $$ BEGIN
    RAISE NOTICE 'MIGRATION COMPLETE: 027_kev_catalog';
END $$;
