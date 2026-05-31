-- di_016: Add graph_role to resource_relationship_catalog + is_attack_edge to asset_relationships
--
-- graph_role classifies how each catalog rule participates in attack graph traversal:
--   attack_traversal  — BFS traverses unconditionally; is_attack_edge=TRUE set at write time
--   validated_traversal — needs a validator to confirm; validator sets is_attack_edge=TRUE
--   context           — structural/topological; useful for display but never in BFS
--
-- is_attack_edge on asset_relationships is the BFS gate:
--   TRUE  → pg_graph BFS may traverse this edge
--   FALSE → edge exists only for context (PLACED_IN, GOVERNED_BY, ENCRYPTED_BY, etc.)

BEGIN;

-- 1. Add graph_role to resource_relationship_catalog
ALTER TABLE resource_relationship_catalog
    ADD COLUMN IF NOT EXISTS graph_role VARCHAR(32) NOT NULL DEFAULT 'context';

-- Backfill known attack_traversal relations from existing catalog data
UPDATE resource_relationship_catalog
SET graph_role = 'attack_traversal'
WHERE relation_type IN (
    'HAS_PROFILE',      -- EC2 → IAM Instance Profile
    'HAS_ROLE',         -- Lambda → IAM Role
    'TRIGGERS',         -- EventSource → Lambda
    'INVOKES',          -- API Gateway → Lambda
    'HAS_INTEGRATION',  -- API Gateway → Integration (part of INVOKES chain)
    'ROUTES_TO',        -- LB/TargetGroup → EC2/Lambda (internet entry traversal)
    'CONTAINS',         -- EKS Cluster → NodeGroup, NodeGroup → EC2
    'CAN_ASSUME',       -- IAM Role → IAM Role (privilege escalation via chaining)
    'MANAGED_BY_AGENT', -- SSM/Arc/OSConfig agent → EC2 (agent-based entry)
    'USES_IDENTITY'     -- GCE/CloudFunction/CloudRun → ServiceAccount (GCP)
);

-- INTERNET_ACCESSIBLE is promoted by the internet_reachability validator at scan time,
-- so it stays 'context' in the catalog but becomes is_attack_edge=TRUE during scans.

-- 2. Ensure is_attack_edge column exists on asset_relationships
-- (added by di_013, but guard with IF NOT EXISTS for idempotency)
ALTER TABLE asset_relationships
    ADD COLUMN IF NOT EXISTS is_attack_edge BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill existing attack-traversal edges for all live scans
UPDATE asset_relationships
SET is_attack_edge = TRUE
WHERE relation_type IN (
    'HAS_PROFILE', 'HAS_ROLE', 'TRIGGERS', 'INVOKES', 'HAS_INTEGRATION',
    'ROUTES_TO', 'CONTAINS', 'CAN_ASSUME', 'MANAGED_BY_AGENT', 'USES_IDENTITY',
    'CAN_REACH'  -- created directly by validators with is_attack_edge=TRUE intent
);

-- Index to make BFS filter cheap
CREATE INDEX IF NOT EXISTS idx_asset_rel_attack_edge
    ON asset_relationships (tenant_id, scan_run_id, is_attack_edge)
    WHERE is_attack_edge = TRUE;

COMMIT;

-- Verification
SELECT relation_type, graph_role, COUNT(*) AS rule_count
FROM resource_relationship_catalog
GROUP BY relation_type, graph_role
ORDER BY graph_role, relation_type;
