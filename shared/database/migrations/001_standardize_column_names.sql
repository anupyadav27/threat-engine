-- ============================================================================
-- Migration 001: Standardize column names across all engine finding tables
-- ============================================================================
-- Standard columns (same name in every finding table):
--   finding_id, scan_run_id, tenant_id, account_id, credential_ref,
--   credential_type, provider, region, resource_uid, resource_type,
--   severity, status, rule_id, first_seen_at, last_seen_at
--
-- Drops: {engine}_scan_id (redundant with scan_run_id)
-- Renames: hierarchy_id → account_id, id → finding_id, etc.
-- ============================================================================

-- ============================================================================
-- 1. DISCOVERY FINDINGS  (threat_engine_discoveries)
-- ============================================================================
-- Current: id (serial PK), discovery_scan_id, hierarchy_id, no scan_run_id/severity/status/account_id
-- Target:  finding_id (varchar PK), scan_run_id, account_id, + add missing standard cols

\connect threat_engine_discoveries;

BEGIN;

-- Rename discovery_scan_id → scan_run_id
ALTER TABLE discovery_findings RENAME COLUMN discovery_scan_id TO scan_run_id;

-- Rename hierarchy_id → account_id
ALTER TABLE discovery_findings RENAME COLUMN hierarchy_id TO account_id;

-- Rename scan_timestamp → first_seen_at
ALTER TABLE discovery_findings RENAME COLUMN scan_timestamp TO first_seen_at;

-- Convert id (serial) → finding_id (varchar)
-- Step 1: Add finding_id varchar column
ALTER TABLE discovery_findings ADD COLUMN finding_id varchar(64);
-- Step 2: Populate from existing id
UPDATE discovery_findings SET finding_id = 'disc-' || id::text WHERE finding_id IS NULL;
-- Step 3: Drop old PK, make finding_id the PK
ALTER TABLE discovery_findings DROP CONSTRAINT IF EXISTS discovery_findings_pkey;
ALTER TABLE discovery_findings ALTER COLUMN finding_id SET NOT NULL;
ALTER TABLE discovery_findings ADD PRIMARY KEY (finding_id);
-- Step 4: Drop old id column
ALTER TABLE discovery_findings DROP COLUMN id;

-- Add missing standard columns
ALTER TABLE discovery_findings ADD COLUMN IF NOT EXISTS scan_run_id_old varchar(255);
-- scan_run_id already renamed above
ALTER TABLE discovery_findings ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE discovery_findings ADD COLUMN IF NOT EXISTS credential_type varchar(64);
ALTER TABLE discovery_findings ADD COLUMN IF NOT EXISTS severity varchar(20) DEFAULT 'info';
ALTER TABLE discovery_findings ADD COLUMN IF NOT EXISTS status varchar(20) DEFAULT 'DISCOVERED';
ALTER TABLE discovery_findings ADD COLUMN IF NOT EXISTS last_seen_at timestamptz DEFAULT NOW();
ALTER TABLE discovery_findings ADD COLUMN IF NOT EXISTS resource_type varchar(255);

-- Drop scan_run_id_old if accidentally created
ALTER TABLE discovery_findings DROP COLUMN IF EXISTS scan_run_id_old;

-- Update FK references on report table
ALTER TABLE discovery_report RENAME COLUMN discovery_scan_id TO scan_run_id;

COMMIT;


-- ============================================================================
-- 2. CHECK FINDINGS  (threat_engine_check)
-- ============================================================================
-- Current: id (serial PK), check_scan_id, hierarchy_id, no scan_run_id/severity/account_id
-- Target:  finding_id, scan_run_id, account_id, + add missing standard cols

\connect threat_engine_check;

BEGIN;

-- Rename check_scan_id → scan_run_id
ALTER TABLE check_findings RENAME COLUMN check_scan_id TO scan_run_id;

-- Rename hierarchy_id → account_id
ALTER TABLE check_findings RENAME COLUMN hierarchy_id TO account_id;

-- Rename created_at → first_seen_at
ALTER TABLE check_findings RENAME COLUMN created_at TO first_seen_at;

-- Convert id (serial) → finding_id (varchar)
ALTER TABLE check_findings ADD COLUMN finding_id varchar(64);
UPDATE check_findings SET finding_id = 'chk-' || id::text WHERE finding_id IS NULL;
ALTER TABLE check_findings DROP CONSTRAINT IF EXISTS check_findings_pkey;
ALTER TABLE check_findings ALTER COLUMN finding_id SET NOT NULL;
ALTER TABLE check_findings ADD PRIMARY KEY (finding_id);
ALTER TABLE check_findings DROP COLUMN id;

-- Add missing standard columns
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS credential_type varchar(64);
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS severity varchar(20);
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS last_seen_at timestamptz DEFAULT NOW();

-- Populate severity from rule_metadata where possible
UPDATE check_findings cf
SET severity = COALESCE(
    (SELECT rm.severity FROM rule_metadata rm WHERE rm.rule_id = cf.rule_id LIMIT 1),
    'medium'
)
WHERE cf.severity IS NULL;

-- Update FK references on report table
ALTER TABLE check_report RENAME COLUMN check_scan_id TO scan_run_id;

COMMIT;


-- ============================================================================
-- 3. INVENTORY FINDINGS  (threat_engine_inventory)
-- ============================================================================
-- Current: asset_id (uuid PK), inventory_scan_id, no scan_run_id/severity/status/rule_id
-- Target:  finding_id, scan_run_id, + add missing standard cols

\connect threat_engine_inventory;

BEGIN;

-- Rename asset_id → finding_id
ALTER TABLE inventory_findings RENAME COLUMN asset_id TO finding_id;

-- Rename inventory_scan_id → scan_run_id
ALTER TABLE inventory_findings RENAME COLUMN inventory_scan_id TO scan_run_id;

-- Rename first_discovered_at → first_seen_at
ALTER TABLE inventory_findings RENAME COLUMN first_discovered_at TO first_seen_at;

-- Rename last_modified_at → last_seen_at
ALTER TABLE inventory_findings RENAME COLUMN last_modified_at TO last_seen_at;

-- Add missing standard columns
ALTER TABLE inventory_findings ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE inventory_findings ADD COLUMN IF NOT EXISTS credential_type varchar(64);
ALTER TABLE inventory_findings ADD COLUMN IF NOT EXISTS severity varchar(20) DEFAULT 'info';
ALTER TABLE inventory_findings ADD COLUMN IF NOT EXISTS status varchar(20) DEFAULT 'ACTIVE';

-- Rename in relationships table too
ALTER TABLE inventory_relationships RENAME COLUMN inventory_scan_id TO scan_run_id;

-- Update FK references on report table
ALTER TABLE inventory_report RENAME COLUMN inventory_scan_id TO scan_run_id;

COMMIT;


-- ============================================================================
-- 4. THREAT FINDINGS  (threat_engine_threat)
-- ============================================================================
-- Current: id (serial) + finding_id (varchar UNIQUE), threat_scan_id, scan_run_id exists, no provider
-- Target:  finding_id as PK, scan_run_id only, drop threat_scan_id, add provider

\connect threat_engine_threat;

BEGIN;

-- Drop old serial id, promote finding_id to PK
ALTER TABLE threat_findings DROP CONSTRAINT IF EXISTS threat_findings_pkey;
ALTER TABLE threat_findings DROP CONSTRAINT IF EXISTS threat_findings_finding_id_key;
ALTER TABLE threat_findings ALTER COLUMN finding_id SET NOT NULL;
ALTER TABLE threat_findings ADD PRIMARY KEY (finding_id);
ALTER TABLE threat_findings DROP COLUMN IF EXISTS id;

-- Drop redundant threat_scan_id (scan_run_id already exists)
ALTER TABLE threat_findings DROP COLUMN IF EXISTS threat_scan_id;

-- Add missing standard columns
ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS provider varchar(20) DEFAULT 'aws';
ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE threat_findings ADD COLUMN IF NOT EXISTS credential_type varchar(64);

-- Rename in report table
ALTER TABLE threat_report RENAME COLUMN threat_scan_id TO scan_run_id;

-- threat_detections: same treatment
ALTER TABLE threat_detections DROP COLUMN IF EXISTS threat_scan_id;
ALTER TABLE threat_detections ADD COLUMN IF NOT EXISTS provider varchar(20) DEFAULT 'aws';
ALTER TABLE threat_detections ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE threat_detections ADD COLUMN IF NOT EXISTS credential_type varchar(64);

COMMIT;


-- ============================================================================
-- 5. COMPLIANCE FINDINGS  (threat_engine_compliance)
-- ============================================================================
-- Current: finding_id (varchar PK), compliance_scan_id, scan_run_id exists, no provider
-- Target:  drop compliance_scan_id, add provider + credential cols

\connect threat_engine_compliance;

BEGIN;

-- Drop redundant compliance_scan_id
ALTER TABLE compliance_findings DROP COLUMN IF EXISTS compliance_scan_id;

-- Add missing standard columns
ALTER TABLE compliance_findings ADD COLUMN IF NOT EXISTS provider varchar(20) DEFAULT 'aws';
ALTER TABLE compliance_findings ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE compliance_findings ADD COLUMN IF NOT EXISTS credential_type varchar(64);

-- Rename in report table
ALTER TABLE compliance_report RENAME COLUMN compliance_scan_id TO scan_run_id;

COMMIT;


-- ============================================================================
-- 6. IAM FINDINGS  (threat_engine_iam)
-- ============================================================================
-- Current: finding_id (varchar PK), iam_scan_id, scan_run_id exists
-- Target:  drop iam_scan_id, add credential cols

\connect threat_engine_iam;

BEGIN;

-- Drop redundant iam_scan_id
ALTER TABLE iam_findings DROP COLUMN IF EXISTS iam_scan_id;

-- Rename hierarchy_id → account_id (if exists)
ALTER TABLE iam_findings RENAME COLUMN hierarchy_id TO account_id;

-- Add missing standard columns
ALTER TABLE iam_findings ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE iam_findings ADD COLUMN IF NOT EXISTS credential_type varchar(64);

-- Rename in report table
ALTER TABLE iam_report RENAME COLUMN iam_scan_id TO scan_run_id;

-- iam_policy_statements: same treatment
ALTER TABLE iam_policy_statements DROP COLUMN IF EXISTS iam_scan_id;
ALTER TABLE iam_policy_statements ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE iam_policy_statements ADD COLUMN IF NOT EXISTS credential_type varchar(64);

COMMIT;


-- ============================================================================
-- 7. DATASEC FINDINGS  (threat_engine_datasec)
-- ============================================================================
-- Current: finding_id (varchar PK), datasec_scan_id, scan_run_id exists, no provider
-- Target:  drop datasec_scan_id, add provider + credential cols

\connect threat_engine_datasec;

BEGIN;

-- Drop redundant datasec_scan_id
ALTER TABLE datasec_findings DROP COLUMN IF EXISTS datasec_scan_id;

-- Add missing standard columns
ALTER TABLE datasec_findings ADD COLUMN IF NOT EXISTS provider varchar(20) DEFAULT 'aws';
ALTER TABLE datasec_findings ADD COLUMN IF NOT EXISTS account_id varchar(64);
ALTER TABLE datasec_findings ADD COLUMN IF NOT EXISTS credential_ref varchar(512);
ALTER TABLE datasec_findings ADD COLUMN IF NOT EXISTS credential_type varchar(64);

-- Rename in report table
ALTER TABLE datasec_report RENAME COLUMN datasec_scan_id TO scan_run_id;

COMMIT;
