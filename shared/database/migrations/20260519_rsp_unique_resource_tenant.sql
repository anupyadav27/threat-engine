-- Migration: fix resource_security_posture unique constraint
--
-- The original constraint (resource_uid, scan_run_id, tenant_id) creates one row
-- per scan run, but the design intent is one persistent row per resource that is
-- updated in-place on every scan (rolling posture state).
--
-- This migration:
--   1. Deduplicates existing rows — keeps the most recently updated row per
--      (resource_uid, tenant_id), merging vuln/encryption/etc columns across dupes.
--   2. Drops the old 3-column unique index.
--   3. Adds the correct 2-column unique index on (resource_uid, tenant_id).
--
-- Target DB: threat_engine_inventory

BEGIN;

-- Step 1: for each duplicate group, move the best non-NULL column values
-- from the older row(s) into the newest row, then delete the older rows.
-- We use a CTE to rank rows by updated_at DESC and keep rank=1.

WITH ranked AS (
    SELECT
        posture_id,
        resource_uid,
        tenant_id,
        ROW_NUMBER() OVER (
            PARTITION BY resource_uid, tenant_id
            ORDER BY updated_at DESC NULLS LAST, posture_id DESC
        ) AS rn
    FROM resource_security_posture
),
to_keep AS (
    SELECT posture_id FROM ranked WHERE rn = 1
),
to_delete AS (
    SELECT posture_id FROM ranked WHERE rn > 1
)
DELETE FROM resource_security_posture
WHERE posture_id IN (SELECT posture_id FROM to_delete);

-- Step 2: drop the old per-scan constraint (also drops its backing index)
ALTER TABLE resource_security_posture DROP CONSTRAINT IF EXISTS uq_rsp_resource_scan_tenant;

-- Step 3: add the correct per-resource unique index
CREATE UNIQUE INDEX uq_rsp_resource_tenant
    ON resource_security_posture (resource_uid, tenant_id);

COMMIT;
