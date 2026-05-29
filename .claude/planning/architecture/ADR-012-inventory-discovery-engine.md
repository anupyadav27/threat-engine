# ADR-012: Replace engine-discoveries + engine-inventory with engine-di

| Field | Value |
|-------|-------|
| Status | Proposed |
| Date | 2026-05-23 |
| Deciders | Platform Architect, Engine Lead |
| Supersedes | ADR-003 (discovery scan architecture), ADR-007 (inventory normalization) |
| Affected engines | All 16 downstream engines that read DISCOVERIES_DB or INVENTORY_DB |

---

## 1. Status

Proposed — pending sprint planning approval before implementation begins.

---

## 2. Context

### 2.1 Problem: Synthetic UIDs at the source

engine-discoveries (port 8001, DB: threat_engine_discoveries, table: discovery_findings) attempts to reconstruct ARNs after the fact from raw API responses. This fails for 65% of resources, producing synthetic UIDs (`region:name` format) instead of real cloud identifiers (ARN/OCID/ARM ID/CRN). Before the 2026-05 cleanup:

- 107K rows had synthetic resource_uid values
- 59K rows were pure catalog noise (no real resource behind them) and were deleted

engine-inventory (port 8022, DB: threat_engine_inventory, tables: inventory_findings, inventory_relationships) normalizes discovery data but cannot fix what discovery gets wrong at the source. The canonical UID problem must be solved before the write, not after.

### 2.2 Problem: Two engines for one logical function

The discovery-to-inventory pipeline is two sequential engines (discovery → inventory) with separate DBs, separate scan triggers, separate Argo steps, and 17 reader files across downstream engines that must connect to both. This doubles the integration surface for no architectural benefit: every downstream engine needs the same data, just canonically identified and normalized.

### 2.3 Downstream impact of bad UIDs

- resource_security_posture joins on resource_uid — synthetic UIDs produce posture orphans
- Neo4j graph nodes keyed on resource_uid — mismatches break attack-path BFS edges
- security_findings UNIQUE constraint on (source_engine, source_finding_id, tenant_id) — deduplication breaks when UIDs are unstable across scans
- attack-path internet-exposure queries join discovery_findings on resource_uid — wrong node labels produced the `(origin:Resource)` vs `:Internet` BFS bug fixed in 2026-05-17

### 2.4 Why not fix engine-discoveries in place

The root cause is architectural: discovery reads raw API payloads and then tries to derive a canonical identifier from them. The correct model is to enumerate resources using a known identifier pattern first, then use that canonical UID as the primary key for all subsequent enrichment. This inversion cannot be retrofitted into the existing two-engine pipeline without rebuilding it.

---

## 3. Decision

Replace engine-discoveries and engine-inventory with a single engine: **engine-di** (Discovery + Inventory, port 8025).

engine-di runs a deterministic 3-phase scan:

- **Phase 0 — Enumerate**: Call root_ops from resource_inventory_identifier to get resource list. Build canonical resource_uid (ARN/OCID/ARM ID/CRN) from identifier_pattern BEFORE writing any data. If a canonical UID cannot be constructed, raise ResourceIdMissingError, log to di_scan_errors, and skip. No synthetic UIDs are written under any circumstance.
- **Phase 1 — Enrich**: For each service×region pair where Phase 0 found resources, run the rule_discoveries operations. This is server-side filtered — operations are only called for pairs that produced Phase 0 resources, not for the full catalog.
- **Phase 2 — Write**: Upsert to asset_inventory with the guaranteed canonical resource_uid from Phase 0. ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO UPDATE sets last_seen_at and emitted_fields.

All errors are explicit: ResourceIdMissingError and API call failures are written to di_scan_errors with enough context to diagnose and re-run. No silent swallowing.

---

## 4. New DB: threat_engine_di

### 4.1 Schema SQL

```sql
-- Primary asset table (replaces discovery_findings + inventory_findings)
CREATE TABLE asset_inventory (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id           UUID NOT NULL,
    tenant_id             VARCHAR(255) NOT NULL,
    account_id            VARCHAR(512) NOT NULL,
    provider              VARCHAR(50) NOT NULL,
    region                VARCHAR(100) NOT NULL,
    credential_ref        TEXT,
    credential_type       VARCHAR(100),
    resource_uid          VARCHAR(2048) NOT NULL,
    resource_type         VARCHAR(255) NOT NULL,
    resource_name         VARCHAR(512),
    service               VARCHAR(100) NOT NULL,
    discovery_id          VARCHAR(255),
    phase                 SMALLINT NOT NULL,          -- 0=enumerated, 1=enriched
    emitted_fields        JSONB DEFAULT '{}',
    raw_response          JSONB DEFAULT '{}',
    config_hash           VARCHAR(64),
    previous_config_hash  VARCHAR(64),
    drift_detected        BOOLEAN DEFAULT FALSE,
    severity              VARCHAR(20) DEFAULT 'informational',
    status                VARCHAR(50) DEFAULT 'active',
    first_seen_at         TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT uq_asset_per_scan UNIQUE (resource_uid, scan_run_id, tenant_id)
);
-- NOTE: NO resource_id column. Derivable from resource_uid suffix when needed.

CREATE INDEX idx_ai_tenant_provider ON asset_inventory (tenant_id, provider);
CREATE INDEX idx_ai_scan_run ON asset_inventory (scan_run_id);
CREATE INDEX idx_ai_resource_uid ON asset_inventory (resource_uid);
CREATE INDEX idx_ai_service_region ON asset_inventory (service, region);
CREATE INDEX idx_ai_drift ON asset_inventory (tenant_id, drift_detected) WHERE drift_detected = TRUE;

-- Relationship table (replaces inventory_relationships — same column names for zero eval-logic changes)
CREATE TABLE asset_relationships (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id       UUID NOT NULL,
    tenant_id         VARCHAR(255) NOT NULL,
    source_uid        VARCHAR(2048) NOT NULL,
    target_uid        VARCHAR(2048) NOT NULL,
    relationship_type VARCHAR(100) NOT NULL,
    provider          VARCHAR(50) NOT NULL,
    metadata          JSONB DEFAULT '{}',
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ar_tenant ON asset_relationships (tenant_id);
CREATE INDEX idx_ar_source ON asset_relationships (source_uid);
CREATE INDEX idx_ar_scan_run ON asset_relationships (scan_run_id);

-- Phase tracking
CREATE TABLE di_scan_runs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id       UUID NOT NULL UNIQUE,
    tenant_id         VARCHAR(255) NOT NULL,
    provider          VARCHAR(50) NOT NULL,
    account_id        VARCHAR(512),
    status            VARCHAR(50) DEFAULT 'running',   -- running|phase0_complete|phase1_complete|complete|failed
    phase0_count      INTEGER DEFAULT 0,
    phase1_count      INTEGER DEFAULT 0,
    error_count       INTEGER DEFAULT 0,
    started_at        TIMESTAMPTZ DEFAULT NOW(),
    completed_at      TIMESTAMPTZ
);

-- Error log (no silent fallbacks)
CREATE TABLE di_scan_errors (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   UUID NOT NULL,
    tenant_id     VARCHAR(255) NOT NULL,
    error_type    VARCHAR(100) NOT NULL,   -- ResourceIdMissingError|APICallError|EnrichError
    service       VARCHAR(100),
    region        VARCHAR(100),
    resource_type VARCHAR(255),
    raw_context   JSONB DEFAULT '{}',      -- raw API response fragment for diagnosis
    error_message TEXT,
    created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_errors_scan ON di_scan_errors (scan_run_id);
CREATE INDEX idx_errors_type ON di_scan_errors (error_type, tenant_id);
```

### 4.2 resource_inventory_identifier addition

Add column to existing table (in threat_engine_inventory DB — this table stays there):

```sql
ALTER TABLE resource_inventory_identifier
    ADD COLUMN used_by_engines JSONB DEFAULT '[]';

CREATE INDEX idx_rii_engines ON resource_inventory_identifier USING GIN (used_by_engines);
```

Downstream engines replace hardcoded discovery_id lists with:

```sql
-- Before (hardcoded in 17 files):
WHERE discovery_id IN ('ec2-vpc', 'ec2-subnet', ...)

-- After:
WHERE 'network' = ANY(SELECT jsonb_array_elements_text(used_by_engines))
-- or in Python using psycopg2:
WHERE used_by_engines ? 'network'   -- JSONB contains-key operator
```

---

## 5. used_by_engines Mapping (authoritative — from code audit)

| Resource category | used_by_engines |
|-------------------|----------------|
| iam.* (all IAM resources) | ["check","iam"] |
| ec2.vpc, subnet, sg, nacl, route_table, igw, nat, vpc_endpoint, vpc_peering, transit_gw | ["check","network","attack-path","datasec"] |
| ec2.flow_logs | ["check","network","cdr"] |
| elbv2.load_balancer, listener, target_group | ["check","network","api-sec"] |
| elb.load_balancer | ["check","network","cdr"] |
| wafv2.web_acl | ["check","network","api-sec"] |
| networkfirewall.firewall | ["check","network"] |
| s3.bucket | ["check","datasec","cdr","encryption"] |
| rds.instance, cluster | ["check","datasec","dbsec","cdr"] |
| dynamodb.table | ["check","datasec","dbsec"] |
| redshift.cluster | ["check","datasec","dbsec"] |
| elasticache.cluster | ["check","datasec","dbsec"] |
| efs.file_system | ["check","datasec","encryption"] |
| kms.key | ["check","encryption","datasec"] |
| secretsmanager.secret | ["check","encryption","datasec"] |
| acm.certificate | ["check","encryption"] |
| sagemaker.*, bedrock.* | ["check","ai-security"] |
| eks.cluster | ["check","container-security","cdr","attack-path"] |
| ecr.repository | ["check","container-security","datasec"] |
| apigateway.*, apigatewayv2.* | ["check","api-sec","attack-path"] |
| cloudtrail.trail | ["check","cdr"] |
| guardduty.detector | ["check","cdr"] |
| lambda.function | ["check","attack-path","cdr","datasec"] |
| ec2.instance | ["check","attack-path","vulnerability"] |
| vpc_peering, transit_gateway_attachment, egress_igw (topology-only) | ["network","attack-path"] |

---

## 6. Integration Map

### 6.1 K8s manifests — env var replacement

16 manifests must replace DISCOVERIES_DB_* and/or INVENTORY_DB_* with DI_DB_*. During parallel-run transition, keep legacy vars alongside DI vars and gate on DI_ENGINE_ENABLED.

| Manifest | Has DISCOVERIES_DB | Has INVENTORY_DB | Action |
|----------|--------------------|------------------|--------|
| engine-ai-security.yaml | Yes | Yes | Add DI_DB_* |
| engine-api-security.yaml | Yes | Yes | Add DI_DB_* |
| engine-attack-path.yaml | Yes | Yes | Add DI_DB_* |
| engine-container-sec.yaml | Yes | No | Add DI_DB_* |
| engine-dbsec.yaml | Yes | No | Add DI_DB_* |
| engine-encryption.yaml | Yes | Yes | Add DI_DB_* |
| engine-iam.yaml | Yes | No | Add DI_DB_* |
| engine-network.yaml | Yes | Yes | Add DI_DB_* |
| engine-pipeline-monitor.yaml | Yes | Yes | Add DI_DB_* |
| engine-platform-admin.yaml | No | Yes | Add DI_DB_* |
| engine-risk.yaml | Yes | Yes | Add DI_DB_* |
| engine-threat-narrative.yaml | Yes | No | Add DI_DB_* |
| engine-threat-v1.yaml | No | Yes | Add DI_DB_* |
| engine-vulnerability.yaml | No | Yes | Add DI_DB_* |
| log-collector-worker.yaml | Yes | No | Add DI_DB_* |
| log-collector.yaml | Yes | No | Add DI_DB_* |

### 6.2 Python reader files — connection + table name replacement

17 files must update DB connection string (DISCOVERIES_DB → DI_DB or INVENTORY_DB → DI_DB) and table names (discovery_findings → asset_inventory, inventory_findings → asset_inventory, inventory_relationships → asset_relationships).

| File | Reads from | Table(s) changed |
|------|-----------|-----------------|
| engines/iam/iam_engine/input/discovery_db_reader.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/network-security/network_security_engine/input/discovery_db_reader.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/network-security/network_security_engine/input/inventory_reader.py | INVENTORY_DB | inventory_relationships → asset_relationships |
| engines/datasec/data_security_engine/input/discovery_db_reader.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/datasec/data_security_engine/input/inventory_reader.py | INVENTORY_DB | inventory_findings → asset_inventory |
| engines/encryption-security/encryption_security_engine/input/inventory_reader.py | INVENTORY_DB | inventory_findings → asset_inventory |
| engines/database-security/database_security_engine/providers/base.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/ai-security/ai_security_engine/input/discovery_reader.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/attack-path/attack_path_engine/run_scan.py | DISCOVERIES_DB | internet exposure query → asset_inventory |
| engines/attack-path/attack_path_engine/graph/pg_graph.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/container-security/container_security_engine/providers/base.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/threat_v1/threat_v1/graph/resource_resolver.py | INVENTORY_DB | inventory_findings → asset_inventory |
| engines/threat_v1/threat_v1/graph/edge_builder.py | INVENTORY_DB | inventory_relationships → asset_relationships |
| engines/cdr/cdr_engine/source_discovery/log_source_finder.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/api-security/api_security_engine/input/discovery_reader.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/dbsec/run_scan.py | DISCOVERIES_DB | discovery_findings → asset_inventory |
| engines/dbsec/dbsec_engine/providers/base.py | DISCOVERIES_DB | discovery_findings → asset_inventory |

### 6.3 API Gateway

File: `shared/api_gateway/main.py`

```python
# Remove:
"discoveries": {"url": DISCOVERIES_ENGINE_URL, "prefix": "/api/v1/discoveries", ...}
"inventory":   {"url": INVENTORY_ENGINE_URL,   "prefix": "/api/v1/inventory", ...}

# Add:
"di": {"url": DI_ENGINE_URL, "prefix": "/api/v1/di", "prefixes": ["/api/v1/di"]}
```

### 6.4 BFF files

Three BFF files connect directly to INVENTORY_DB for posture data. Update DB connection to DI_DB for asset_inventory reads only. resource_security_posture remains in threat_engine_inventory (see section 7).

- `shared/api_gateway/bff/asset_posture.py`
- `shared/api_gateway/bff/asset_findings.py`
- `shared/api_gateway/bff/_shared.py`

### 6.5 Argo pipeline

File: `deployment/aws/eks/argo/cspm-pipeline.yaml`

```yaml
# Remove steps:
- name: discovery
  trigger: http://engine-discoveries/api/v1/discovery

- name: inventory
  depends: discovery
  trigger: http://engine-inventory/api/v1/inventory/scan/discovery

# Add step:
- name: di
  trigger: http://engine-di/api/v1/di/scan
  poll:    http://engine-di/api/v1/di/scan/{scan_run_id}/status

# Update all downstream depends:
# Before: depends: inventory
# After:  depends: di
```

Affected downstream steps: check, threat, compliance, iam, datasec, network, cdr, container-security, encryption, dbsec, ai-security, api-security, vulnerability, attack-path.

### 6.6 ConfigMap and Secret

```yaml
# threat-engine-db-config — add:
DI_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
DI_DB_PORT: "5432"
DI_DB_NAME: threat_engine_di
DI_DB_USER: cspm_di_user

# threat-engine-db-passwords — add:
DI_DB_PASSWORD: <rotated-secret>

# Keep during parallel run (remove after cutover):
DISCOVERIES_DB_*: <existing values>
INVENTORY_DB_*: <existing values>
```

---

## 7. What Stays in threat_engine_inventory

These tables have too many writers and are not moved to threat_engine_di:

| Table | Reason to keep |
|-------|---------------|
| resource_security_posture | 12+ engine writers; changing DB connection for all writers is out of scope for DI sprint |
| resource_inventory_identifier | Static lookup; stays here, gains used_by_engines column via migration |
| resource_security_relationship_rules | Referenced by network engine eval logic |
| security_findings | Unified findings layer; 12 source engines write here |
| All posture-related tables | Same as resource_security_posture |

The BFF files that read from threat_engine_inventory for posture data continue to use INVENTORY_DB. Only the asset data reads (inventory_findings, inventory_relationships) move to DI_DB.

---

## 8. Error Handling Rules (no exceptions to these)

| Error condition | Action | Silent? |
|-----------------|--------|---------|
| ResourceIdMissingError in Phase 0 | Log to di_scan_errors, skip row | No |
| API call fails in Phase 0 or 1 | Log to di_scan_errors, skip service×region, continue | No |
| Enrich op fails in Phase 1 | Keep Phase 0 row (canonical UID already written), log error | No |
| Synthetic UID would be written | Raise ResourceIdMissingError, never write | Never allowed |
| Mock data fallback | Not implemented | Never allowed |

di_scan_errors provides full diagnosis context: error_type, service, region, resource_type, raw_context JSONB, error_message.

---

## 9. Rollback Plan

A 2-week parallel-run window ensures zero-downtime rollback.

### Phase: Parallel run (week 1-2 after DI go-live)

1. Keep engine-discoveries and engine-inventory deployed and running
2. All 16 downstream engine manifests carry both legacy env vars (DISCOVERIES_DB_*, INVENTORY_DB_*) and new DI_DB_* vars
3. Each manifest has feature flag: `DI_ENGINE_ENABLED: "false"` (default)
4. Argo pipeline runs DI step alongside legacy steps during validation
5. Downstream engines read from DI_DB only when DI_ENGINE_ENABLED=true

### Rollback trigger

If any of the following occur during parallel run, rollback immediately:

- asset_inventory row count < 80% of discovery_findings row count for same scan_run_id
- Downstream engine error rate increases by >5% after switching to DI_DB
- resource_security_posture orphan count (resource_uid not in asset_inventory) exceeds 1%
- Attack-path BFS produces zero paths when paths existed before cutover

### Rollback steps

```bash
# Set flag back to false on affected engine(s)
kubectl set env deployment/engine-network DI_ENGINE_ENABLED=false -n threat-engine-engines
# Repeat for each engine

# Revert Argo pipeline to discovery → inventory steps
kubectl apply -f deployment/aws/eks/argo/cspm-pipeline-rollback.yaml

# engine-discoveries and engine-inventory continue serving — no data loss
```

### Cutover (week 3)

After 2 weeks with DI_ENGINE_ENABLED=true and zero rollback triggers fired:

1. Set DI_ENGINE_ENABLED=true in all 16 manifests permanently
2. Remove DISCOVERIES_DB_* and INVENTORY_DB_* env vars from all manifests (except BFF posture reads)
3. Scale down engine-discoveries and engine-inventory to 0 replicas (do not delete for 30 days)
4. Remove legacy Argo steps
5. Remove DI_ENGINE_ENABLED feature flag from manifests

---

## 10. Sprint Breakdown

4 sprints, 22 stories. Each sprint is independently deployable.

| Sprint | Focus | Stories | Key deliverable |
|--------|-------|---------|----------------|
| DI-S1 | Foundation | 6 | DB created, Phase 0 scan working, 0 synthetic UIDs written |
| DI-S2 | Enrichment + write | 5 | Phase 1+2 complete, asset_inventory populated, Argo step live |
| DI-S3 | Downstream migration | 7 | All 17 reader files migrated, 16 manifests updated, parallel run active |
| DI-S4 | Cutover + cleanup | 4 | Parallel run complete, legacy engines scaled down, used_by_engines seeded |

### Sprint DI-S1: Foundation

| Story | Title | Points |
|-------|-------|--------|
| DI-S1-01 | Create threat_engine_di DB and schema (asset_inventory, asset_relationships, di_scan_runs, di_scan_errors) | 3 |
| DI-S1-02 | engine-di scaffold: FastAPI app, port 8025, health endpoints, RBAC wiring | 3 |
| DI-S1-03 | Phase 0 enumerator: root_ops loop, identifier_pattern resolution, canonical UID builder per CSP (ARN/OCID/ARM/CRN) | 8 |
| DI-S1-04 | ResourceIdMissingError: define, raise in Phase 0, write to di_scan_errors, zero synthetic UIDs guarantee | 3 |
| DI-S1-05 | di_scan_runs status tracking: phase transitions, count updates, error_count | 2 |
| DI-S1-06 | unit tests: Phase 0 for AWS (>90% UID coverage), ResourceIdMissingError path, di_scan_errors row structure | 3 |

Sprint DI-S1 total: 22 points

### Sprint DI-S2: Enrichment and Write

| Story | Title | Points |
|-------|-------|--------|
| DI-S2-01 | Phase 1 enricher: rule_discoveries ops scoped to service×region pairs from Phase 0 results only | 5 |
| DI-S2-02 | Phase 2 writer: upsert to asset_inventory, ON CONFLICT update, config_hash diff → drift_detected flag | 5 |
| DI-S2-03 | asset_relationships builder: port relationship_builder.py logic to DI engine using asset_inventory UIDs | 5 |
| DI-S2-04 | Argo pipeline: add "di" step, remove "discovery"+"inventory" steps, update all depends references | 3 |
| DI-S2-05 | integration test: full 3-phase scan against AWS sandbox, row count check, 0 synthetic UIDs in output | 3 |

Sprint DI-S2 total: 21 points

### Sprint DI-S3: Downstream Migration

| Story | Title | Points |
|-------|-------|--------|
| DI-S3-01 | Migrate network engine readers (discovery_db_reader.py, inventory_reader.py) to DI_DB + used_by_engines filter | 3 |
| DI-S3-02 | Migrate attack-path readers (run_scan.py internet query, pg_graph.py) to DI_DB | 3 |
| DI-S3-03 | Migrate IAM, CDR, threat_v1 readers (5 files) to DI_DB | 3 |
| DI-S3-04 | Migrate datasec, encryption, dbsec, container-sec readers (6 files) to DI_DB | 3 |
| DI-S3-05 | Migrate ai-security, api-security readers (2 files) to DI_DB | 2 |
| DI-S3-06 | Update 16 K8s manifests: add DI_DB_* env vars, add DI_ENGINE_ENABLED=false feature flag | 3 |
| DI-S3-07 | Update API gateway routing + BFF asset reads (main.py, asset_posture.py, asset_findings.py, _shared.py) | 3 |

Sprint DI-S3 total: 20 points

### Sprint DI-S4: Cutover and Cleanup

| Story | Title | Points |
|-------|-------|--------|
| DI-S4-01 | Seed used_by_engines values in resource_inventory_identifier (migration + seed script for all resource types in mapping table) | 5 |
| DI-S4-02 | Parallel run validation: DI_ENGINE_ENABLED=true for all engines, compare row counts and posture orphan rate against thresholds | 3 |
| DI-S4-03 | Cutover: remove legacy env vars from all manifests, scale engine-discoveries+inventory to 0, remove Argo legacy steps | 3 |
| DI-S4-04 | Post-cutover: 30-day stability log, update CLAUDE.md engine routing table, update agents.ndjson, update DATABASE-SCHEMA.md | 2 |

Sprint DI-S4 total: 13 points

Total: 22 stories, 76 points across 4 sprints.

---

## 11. Consequences

### Positive

- Canonical resource_uid guaranteed from Phase 0 — no synthetic UIDs can enter the pipeline
- Single DB (threat_engine_di) replaces two separate DBs, halving connection overhead for downstream engines
- used_by_engines column replaces 17 copies of hardcoded discovery_id lists — one source of truth for which engines read which resources
- asset_inventory UNIQUE constraint on (resource_uid, scan_run_id, tenant_id) makes upserts idempotent by design
- di_scan_errors table makes every failure observable and diagnosable — no silent degradation
- Phase 1 enrichment is scoped to service×region pairs that Phase 0 confirmed have resources — eliminates catalog noise calls
- resource_security_posture join correctness improves proportionally with UID canonicality
- Attack-path BFS node label mismatches are structurally prevented (root cause of the 2026-05-17 bug)

### Negative / Risks

- 17 reader files and 16 manifests must be updated in DI-S3 — high coordination cost; regression risk in each downstream engine
- used_by_engines seed data (DI-S4-01) must be accurate; wrong values cause downstream engines to miss resources
- 2-week parallel-run extends infra cost (both old and new engines running simultaneously)
- Phase 0 coverage depends on identifier_pattern quality in resource_inventory_identifier — any gaps produce di_scan_errors rows that must be fixed before cutover
- BFF posture reads stay on INVENTORY_DB for resource_security_posture — dual-DB pattern in BFF persists until posture tables are migrated in a future ADR

### Non-changes (explicitly out of scope)

- resource_security_posture and all posture-related tables: remain in threat_engine_inventory
- security_findings table: remains in threat_engine_inventory
- check engine: reads rule_discoveries and check_findings — no change
- threat engine (port 8020): reads check_findings — no change
- compliance, risk engines: read check_findings and security_findings — no change

---

## 12. Infrastructure Reference

| Item | Value |
|------|-------|
| RDS host | postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432 |
| New DB name | threat_engine_di |
| EKS namespace | threat-engine-engines |
| Engine image | yadavanup84/engine-di:{tag} |
| Engine port | 8025 (K8s service port 80) |
| Health endpoints | GET /api/v1/di/health/live, GET /api/v1/di/health/ready |
| Scan trigger | POST /api/v1/di/scan |
| Scan status | GET /api/v1/di/scan/{scan_run_id}/status |

---

## 13. Security Threat Model

### 13.1 STRIDE Analysis

| Component | Threat | Category | Severity | Mitigation | Gate |
|-----------|--------|----------|----------|------------|------|
| API server | Attacker spoofs tenant in POST /di/scan body | Spoofing | BLOCKER | tenant_id always from AuthContext; never from request body | bmad-security-architect |
| API server | Pod reachable directly (bypass gateway auth) | Spoofing | BLOCKER | NetworkPolicy: only allow ingress from gateway pod selector | bmad-security-architect |
| Phase 0 Enumerator | Attacker crafts account_id to scan another tenant's account | Spoofing | BLOCKER | Two-param cred lookup: `WHERE account_id = %s AND tenant_id = %s` | bmad-security-architect |
| Phase 0 Enumerator | API response pagination causes OOM → DoS | Denial of Service | WARNING | Page size cap 1000 per API call; memory limit 4Gi | DI-S1-03 review |
| Phase 1 Enricher | SSRF via crafted enrich_op calling internal endpoint | SSRF | BLOCKER | Only SDK-based API calls via scanner classes; no HTTP to arbitrary URL | bmad-security-architect |
| Phase 1 Enricher | enrich_ops field in identifier table poisoned → code exec | Tampering | BLOCKER | enrich_ops is a structured list of op names; never eval'd as code; identifier table update requires DB access | bmad-security-reviewer |
| Phase 2 Writer | raw_response leaks credentials (MasterUserPassword, AccessKeyId) | Information Disclosure | BLOCKER | `sensitive_scrubber.py` removes known sensitive keys before any write | bmad-security-reviewer |
| Phase 2 Writer | Tenant A row written with Tenant B's tenant_id | Elevation of Privilege | BLOCKER | tenant_id comes from orchestration record, not API body; verified in run_scan.py | bmad-security-architect |
| Phase 2 Writer | Drift detection config_hash collision → false drift | Tampering | WARNING | MD5 used for non-security deduplication only; SHA-256 if security-relevant | DI-S1-05 review |
| K8s Job Creator | Job injection via malformed account_id in pod spec | Tampering | BLOCKER | account_id sanitized (alphanumeric + hyphens only) before use in Job name | bmad-security-architect |
| K8s Job Creator | Scanner Job runs as root → container escape | Elevation of Privilege | BLOCKER | `runAsNonRoot: true`, `runAsUser: 1000` in K8s manifest | DI-S1-06 review |
| Credential Loader | AWS credentials cached in env vars logged by debug | Information Disclosure | BLOCKER | Log scrubber strips AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY from log output | bmad-security-reviewer |
| DB Writer | `asset_inventory` missing RLS → tenant data leak | Information Disclosure | BLOCKER | RLS policy: `USING (tenant_id = current_setting('app.tenant_id'))` — applied in DI-S1-01 | bmad-security-architect |
| DB Writer | di_scan_errors exposes resource keys from other tenants | Information Disclosure | WARNING | di_scan_errors scoped by tenant_id; BFF endpoint requires discoveries:read | DI-S2-03 review |
| API Server | JWT token replay attack (expired token reused) | Spoofing | WARNING | Gateway AuthMiddleware validates exp claim; engine re-validates X-Auth-Context | Existing auth layer |

### 13.2 PASTA Attack Trees (Stages 5–6)

**Attack Tree 1: Credential Exfiltration via raw_response**
- Goal: Steal AWS credentials stored in `asset_inventory.raw_response`
- Path: Exploit missing sensitive_scrubber → `raw_response.MasterUserPassword` written → SQL injection on `GET /di/assets` endpoint → extract password
- MITRE: T1552 (Unsecured Credentials)
- Mitigation: `sensitive_scrubber.py` BLOCKER gate; SQL parameterization; `discoveries:read` required

**Attack Tree 2: Tenant Data Leakage via Missing tenant_id Filter**
- Goal: Read another tenant's cloud inventory
- Path: Craft request without tenant_id → missing WHERE clause → returns all tenants' assets
- MITRE: T1530 (Data from Cloud Storage Object)
- Mitigation: tenant_id always from AuthContext; RLS on asset_inventory; unit test verifies WHERE clause

**Attack Tree 3: SSRF via Crafted enrich_op**
- Goal: Reach internal K8s services via Phase 1 API call
- Path: Poison identifier table enrich_ops with `http://169.254.169.254/latest/meta-data/` → Phase 1 calls it
- MITRE: T1190 (Exploit Public-Facing Application), T1552.005 (Cloud Instance Metadata API)
- Mitigation: All Phase 1 calls go through SDK client factories (boto3/Azure SDK/etc.) — no raw HTTP

**Attack Tree 4: Unauthorized Scan via Stolen Credentials**
- Goal: Trigger DI scan for another tenant's account using stolen onboarding credentials
- Path: Stolen credential_ref → POST /di/scan with victim account_id → exfiltrate inventory data
- MITRE: T1078 (Valid Accounts)
- Mitigation: account_id ownership verified against tenant_id in onboarding DB before scan starts

**Attack Tree 5: K8s Job Injection**
- Goal: Inject malicious command via account_id in K8s Job metadata
- Path: account_id=`; rm -rf /` passed to Job name/label → command injection in Job spec
- MITRE: T1036 (Masquerading), T1059 (Command and Scripting Interpreter)
- Mitigation: account_id sanitized to `[a-zA-Z0-9\-]{1,512}` before Job creation; label values quoted

### 13.3 MITRE ATT&CK Coverage Matrix

| Technique | Tactic | Covered By | Status |
|-----------|--------|------------|--------|
| T1552 — Unsecured Credentials | Credential Access | sensitive_scrubber.py; BLOCKER gate | Covered |
| T1530 — Data from Cloud Storage | Collection | tenant_id RLS + AuthContext | Covered |
| T1190 — Exploit Public-Facing App | Initial Access | NetworkPolicy; SDK-only calls | Covered |
| T1552.005 — Cloud Instance Metadata | Credential Access | No raw HTTP in Phase 1 | Covered |
| T1078 — Valid Accounts | Defense Evasion | account_id×tenant_id join in onboarding | Covered |
| T1036 — Masquerading | Defense Evasion | account_id sanitization | Covered |
| T1059 — Command Scripting Interpreter | Execution | No shell exec; SDK calls only | Covered |
| T1570 — Lateral Tool Transfer | Lateral Movement | No file write to shared volumes | Covered |
| T1485 — Data Destruction | Impact | RDS automated backups enabled | Covered |
| T1489 — Service Stop | Impact | liveness probe auto-restart | Covered |
| T1040 — Network Sniffing | Collection | TLS on all RDS + inter-pod comms | Gap: verify RDS SSL enforced |

### 13.4 Security Requirements to Story Mapping

| Requirement | Story | Gate |
|-------------|-------|------|
| RLS policy on asset_inventory | DI-S1-01 | bmad-security-architect pre-review |
| Two-param credential lookup (account_id + tenant_id) | DI-S1-03 | bmad-security-architect |
| SDK-only allowlist for enrich_ops (no raw HTTP) | DI-S1-04 | bmad-security-architect |
| sensitive_scrubber.py (8 key classes) | DI-S1-05 | bmad-security-reviewer PR gate |
| account_id sanitization before K8s Job name | DI-S1-06 | bmad-security-reviewer |
| NetworkPolicy: gateway→engine-di only ingress | DI-S1-06 | bmad-security-architect |
| runAsNonRoot + runAsUser 1000 | DI-S1-06 | DI-S1-06 review |
| No DI_DB credentials in any log line | DI-S1-06 | bmad-security-reviewer |
| tenant_id in every DI DB query (all 16 adapters) | DI-S3-01 to DI-S3-07 | bmad-security-reviewer |
| LIKE → ANY(%s) parameterized (CDR adapter) | DI-S3-07 | bmad-security-reviewer |
| ILIKE → discovery_id = ANY(%s) (Encryption) | DI-S3-04 | bmad-security-reviewer |
| source_conn closed in finally (attack-path) | DI-S3-06 | bmad-security-reviewer |
| Migration non-destructive; discovery_findings untouched | DI-S4-01 | bmad-security-reviewer |
| Pre-cutover validation: sensitive fields = 0 | DI-S4-02 | cspm-qa + bmad-sm sign-off |
| Post-cutover: AuthError count = 0 | DI-S4-03 | cspm-post-deploy |
| Legacy credentials removed from manifests | DI-S4-04 | bmad-security-reviewer |

### 13.5 NIST CSF 2.0 Coverage

| Function | Category | Coverage |
|----------|----------|----------|
| IDENTIFY | ID.AM-1/2/3 — Asset inventory | Core deliverable of engine-di |
| PROTECT | PR.AA-01 — Credential protection | sensitive_scrubber; SDK-only calls |
| PROTECT | PR.AA-05 — Access control | tenant_id RLS; AuthContext scoping |
| PROTECT | PR.DS-01 — Data-at-rest protection | RDS encryption (existing) |
| DETECT | DE.CM-01 — Network activity monitoring | di_scan_errors spike alerting (gap — DI-DEBT-01) |
| RESPOND | RS.CO-02 — Communication (Gap) | No alert on di_scan_errors spike → DI-DEBT-01 |

Gap filed: **DI-DEBT-01** — Add CloudWatch alarm on `di_scan_errors.error_type = 'AuthError'` count > 0.

### 13.6 CSA CCM v4 Domain Mapping

| Control ID | Domain | How engine-di addresses it |
|------------|--------|---------------------------|
| IAM-01 | Identity & Access Management | tenant_id from AuthContext; RLS on asset_inventory |
| DSP-07 | Data Security & Privacy | sensitive_scrubber removes credentials from raw_response |
| IVS-01 | Infrastructure & Virtualization | Container non-root; resource limits; NetworkPolicy |
| IVS-06 | Network Security | SDK-only calls (no SSRF vector); no arbitrary HTTP |
| SEF-05 | Security Incident Management | di_scan_errors audit trail; health endpoints |
| AIS-01 | Application & Interface Security | AuthMiddleware validates JWT; engine re-validates AuthContext |
| GRC-05 | Governance & Risk Management | ADR approved before implementation; security gates in every story |

### 13.7 Security Gate Checklist (bmad-security-architect sign-off — required before DI-S1 dev starts)

- [ ] RLS policy on `asset_inventory` confirmed in DI-S1-01 DDL
- [ ] NetworkPolicy YAML drafted for engine-di pod (gateway→engine-di only)
- [ ] credential lookup pattern reviewed: `WHERE account_id = %s AND tenant_id = %s`
- [ ] SDK-only enrich_op allowlist architecture approved
- [ ] sensitive_scrubber key list reviewed and approved
- [ ] account_id sanitization regex confirmed
- [ ] K8s security context (runAsNonRoot, runAsUser 1000, readOnlyRootFilesystem) in manifest

**bmad-security-reviewer PR checklist (every story PR in all 4 sprints)**:
- [ ] No DI_DB credentials in any log statement
- [ ] tenant_id in every parameterized WHERE clause on DI DB queries
- [ ] No raw HTTP calls in Phase 1 (SDK client factory only)
- [ ] sensitive_scrubber called before any raw_response write
- [ ] No `DEV_BYPASS_AUTH` or hardcoded passwords
- [ ] Table name in f-string only from controlled constant (not user input)
- [ ] source_conn/conn closed in finally block in all changed files