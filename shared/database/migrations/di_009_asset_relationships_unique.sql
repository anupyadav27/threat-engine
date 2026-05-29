-- UP Migration: Add unique constraint on asset_relationships
-- Prevents duplicate edges when multiple writers (DI, network, IAM, encryption) write the same edge.
-- ON CONFLICT DO UPDATE in writers ensures richer metadata from later-running engines wins.

BEGIN;

-- Deduplicate: keep earliest row per logical edge, remove later duplicates
DELETE FROM asset_relationships a
USING asset_relationships b
WHERE a.scan_run_id = b.scan_run_id
  AND a.tenant_id    = b.tenant_id
  AND a.source_uid   = b.source_uid
  AND a.relation_type = b.relation_type
  AND a.target_uid   = b.target_uid
  AND a.id > b.id;

ALTER TABLE asset_relationships
    ADD CONSTRAINT uq_asset_relationships_edge
    UNIQUE (scan_run_id, tenant_id, source_uid, relation_type, target_uid);

COMMIT;


-- DOWN Migration
-- BEGIN;
-- ALTER TABLE asset_relationships DROP CONSTRAINT IF EXISTS uq_asset_relationships_edge;
-- COMMIT;
