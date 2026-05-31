# DI-S1-01 — threat_engine_di Database Schema
**Sprint**: DI-S1 | **Points**: 5 | **Status**: Ready for Dev

## Goal
Create the `threat_engine_di` PostgreSQL database on the shared RDS instance and apply the full schema:
`asset_inventory` (partitioned), `asset_relationships`, `di_scan_errors`, and all indexes.
This is the foundation story — nothing else in the DI sprint starts until this is done.

## Context
engine-di replaces `engine-discoveries` (port 8001, DB: threat_engine_discoveries) and
`engine-inventory` (port 8022, DB: threat_engine_inventory). It writes to a single unified DB
with canonical resource UIDs (ARN/OCID/ARM ID/CRN) built before any row is written.

## Files to Create / Modify
- `shared/database/migrations/di_001_initial_schema.sql` — CREATE DATABASE + all tables + indexes
- `shared/database/schemas/di_schema.sql` — schema reference copy (same DDL, no `CREATE DATABASE`)

## Schema DDL

```sql
-- di_001_initial_schema.sql
-- Run once on RDS; psycopg2 isolation_level=AUTOCOMMIT for CREATE DATABASE

CREATE DATABASE threat_engine_di;
\c threat_engine_di

-- ── asset_inventory ───────────────────────────────────────────────────────────
CREATE TABLE asset_inventory (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id           UUID NOT NULL,
    tenant_id             VARCHAR(255) NOT NULL,
    account_id            VARCHAR(512) NOT NULL,
    provider              VARCHAR(50) NOT NULL,
    region                VARCHAR(100) NOT NULL DEFAULT 'global',
    credential_ref        TEXT,
    credential_type       VARCHAR(100),
    resource_uid          VARCHAR(2048) NOT NULL,   -- always canonical ARN/OCID/ARM/CRN
    resource_type         VARCHAR(255) NOT NULL,    -- e.g. ec2.instance, s3.bucket
    resource_name         VARCHAR(512),             -- display name (Tags.Name, etc.)
    service               VARCHAR(100) NOT NULL,
    discovery_id          VARCHAR(255),             -- maps to rule_discoveries.discovery_id
    phase                 SMALLINT NOT NULL DEFAULT 0,  -- 0=enumerated, 1=enriched
    emitted_fields        JSONB DEFAULT '{}',
    raw_response          JSONB DEFAULT '{}',
    config_hash           VARCHAR(64),
    previous_config_hash  VARCHAR(64),
    drift_detected        BOOLEAN DEFAULT FALSE,
    severity              VARCHAR(20) DEFAULT 'informational',
    status                VARCHAR(50) DEFAULT 'active',
    first_seen_at         TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT ak_asset_uid_scan_tenant UNIQUE (resource_uid, scan_run_id, tenant_id)
) PARTITION BY LIST (provider);

-- 7 partitions — one per CSP
CREATE TABLE asset_inventory_aws     PARTITION OF asset_inventory FOR VALUES IN ('aws');
CREATE TABLE asset_inventory_azure   PARTITION OF asset_inventory FOR VALUES IN ('azure');
CREATE TABLE asset_inventory_gcp     PARTITION OF asset_inventory FOR VALUES IN ('gcp');
CREATE TABLE asset_inventory_oci     PARTITION OF asset_inventory FOR VALUES IN ('oci');
CREATE TABLE asset_inventory_ibm     PARTITION OF asset_inventory FOR VALUES IN ('ibm');
CREATE TABLE asset_inventory_alicloud PARTITION OF asset_inventory FOR VALUES IN ('alicloud');
CREATE TABLE asset_inventory_k8s     PARTITION OF asset_inventory FOR VALUES IN ('k8s');

-- Indexes for common query patterns
CREATE INDEX idx_ai_tenant_scan     ON asset_inventory (tenant_id, scan_run_id);
CREATE INDEX idx_ai_resource_uid    ON asset_inventory (resource_uid);
CREATE INDEX idx_ai_discovery_id    ON asset_inventory (discovery_id);
CREATE INDEX idx_ai_resource_type   ON asset_inventory (resource_type);
CREATE INDEX idx_ai_service         ON asset_inventory (service);
CREATE INDEX idx_ai_provider_region ON asset_inventory (provider, region);
CREATE INDEX idx_ai_drift           ON asset_inventory (drift_detected) WHERE drift_detected = TRUE;

-- ── asset_relationships ────────────────────────────────────────────────────────
-- Identical column names to inventory_relationships — zero logic changes in attack-path/network/threat-v1
CREATE TABLE asset_relationships (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id       UUID NOT NULL,
    tenant_id         VARCHAR(255) NOT NULL,
    from_uid          VARCHAR(2048) NOT NULL,
    to_uid            VARCHAR(2048) NOT NULL,
    relation_type     VARCHAR(100) NOT NULL,   -- e.g. internet_connected, routes_to, CONTAINS
    from_resource_type VARCHAR(255),
    to_resource_type  VARCHAR(255),
    properties        JSONB DEFAULT '{}',
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT ak_rel_unique UNIQUE (from_uid, to_uid, relation_type, scan_run_id, tenant_id)
);

CREATE INDEX idx_ar_tenant_scan  ON asset_relationships (tenant_id, scan_run_id);
CREATE INDEX idx_ar_from_uid     ON asset_relationships (from_uid);
CREATE INDEX idx_ar_to_uid       ON asset_relationships (to_uid);
CREATE INDEX idx_ar_relation     ON asset_relationships (relation_type);

-- ── di_scan_errors ────────────────────────────────────────────────────────────
-- Error audit trail — one row per API call failure or ResourceIdMissingError.
-- Not a fallback; never used to recover bad data. Used for diagnosis + alerts only.
CREATE TABLE di_scan_errors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id     UUID NOT NULL,
    tenant_id       VARCHAR(255) NOT NULL,
    account_id      VARCHAR(512),
    provider        VARCHAR(50),
    region          VARCHAR(100),
    service         VARCHAR(100),
    discovery_id    VARCHAR(255),
    error_type      VARCHAR(100) NOT NULL,  -- ResourceIdMissingError, APICallError, AuthError
    error_message   TEXT,
    item_keys       JSONB DEFAULT '[]',     -- first 15 keys of the failed item
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_dse_tenant_scan ON di_scan_errors (tenant_id, scan_run_id);
CREATE INDEX idx_dse_error_type  ON di_scan_errors (error_type);
CREATE INDEX idx_dse_service     ON di_scan_errors (service);
```

## Apply Instructions
```bash
# DB access via kubectl exec (RDS not publicly accessible)
kubectl cp /tmp/di_001_initial_schema.sql \
  threat-engine-engines/$(kubectl get pods -n threat-engine-engines -l app=engine-check -o jsonpath='{.items[0].metadata.name}'):/tmp/di_001_initial_schema.sql

# Apply via psycopg2 (no psql CLI in pods)
kubectl exec -n threat-engine-engines deployment/engine-check -- python3 -c "
import psycopg2, os
conn = psycopg2.connect(host=os.getenv('DB_HOST'), user=os.getenv('DB_USER'),
                        password=os.getenv('DB_PASSWORD'), database='postgres')
conn.autocommit = True
with conn.cursor() as cur:
    cur.execute(open('/tmp/di_001_initial_schema.sql').read())
print('MIGRATION COMPLETE')
"
```

## Acceptance Criteria

### Functional
- [ ] `threat_engine_di` database exists on RDS with owner `postgres`
- [ ] `asset_inventory` table has all columns (no `resource_id` column — intentionally absent)
- [ ] All 7 CSP partitions exist and accept INSERT for their respective `provider` value
- [ ] `asset_relationships` column names identical to `inventory_relationships` (verified by diff)
- [ ] `di_scan_errors` table accepts an INSERT with a sample `ResourceIdMissingError` row
- [ ] All 12 indexes created and verified via `\d+ asset_inventory`
- [ ] `UNIQUE (resource_uid, scan_run_id, tenant_id)` constraint: duplicate INSERT raises IntegrityError

### Security
- [ ] `threat_engine_di` DB has no PUBLIC schema grants beyond `postgres` role
- [ ] `raw_response` JSONB stores cloud API responses — sensitive fields (credentials, tokens)
  must be scrubbed by the Phase 2 writer before reaching this column (AC verified by Phase 2
  story DI-S1-05, not this story)
- [ ] DB not accessible from outside EKS VPC; RDS security group unchanged

### Error Handling
- [ ] Applying migration twice is idempotent: second run exits cleanly (use `IF NOT EXISTS`)
- [ ] Migration job pod logs must end with `MIGRATION COMPLETE`
- [ ] Pod in `Failed` state → migration did NOT apply; check logs before assuming success

## Testing Requirements

**Schema validation** (run after migration):
```sql
-- Verify all tables
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public' AND table_catalog = 'threat_engine_di'
ORDER BY table_name;
-- Expected: asset_inventory, asset_inventory_aws, asset_inventory_azure, asset_inventory_gcp,
--           asset_inventory_oci, asset_inventory_ibm, asset_inventory_alicloud, asset_inventory_k8s,
--           asset_relationships, di_scan_errors

-- Verify no resource_id column
SELECT column_name FROM information_schema.columns
WHERE table_name = 'asset_inventory' AND column_name = 'resource_id';
-- Expected: 0 rows

-- Verify index count
SELECT count(*) FROM pg_indexes WHERE tablename = 'asset_inventory';
-- Expected: >= 7
```

**Unit test** (`tests/database/test_di_schema.py`):
- Connect to threat_engine_di; verify table list
- Insert a row per partition; verify routing
- Insert duplicate → IntegrityError
- Coverage ≥ 80% on migration SQL path

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev design review | bmad-security-architect | dev start (mandatory — new DB) |
| Migration review | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] Migration SQL committed to `shared/database/migrations/di_001_initial_schema.sql`
- [ ] Schema reference committed to `shared/database/schemas/di_schema.sql`
- [ ] `threat_engine_di` exists on prod RDS with all tables + indexes
- [ ] Migration apply log ends with `MIGRATION COMPLETE`
- [ ] Schema validation queries pass
- [ ] Unit tests passing
- [ ] bmad-security-architect design review signed off
- [ ] MEMORY.md updated: add `threat_engine_di` DB to infrastructure table

## Dependencies
- None (foundation story — first in sprint)

## Rollback
```bash
# Drop DB if migration applied incorrectly (only if no data yet)
kubectl exec -n threat-engine-engines deployment/engine-check -- python3 -c "
import psycopg2, os
conn = psycopg2.connect(host=os.getenv('DB_HOST'), user=os.getenv('DB_USER'),
                        password=os.getenv('DB_PASSWORD'), database='postgres')
conn.autocommit = True
with conn.cursor() as cur:
    cur.execute('DROP DATABASE IF EXISTS threat_engine_di')
print('ROLLBACK COMPLETE')
"
```