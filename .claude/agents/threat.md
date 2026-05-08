---
name: threat-engine
description: Full-context agent for the Threat engine — MITRE ATT&CK detection, attack paths, toxic combinations, Neo4j graph, blast radius. Covers DB schema, all API endpoints, BFF views, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Threat Engine specialist. You know every detail of this engine's DB, API, BFF, pipeline role, and Neo4j graph.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 4 — runs after check, before parallel domain engines.
**Reads:** `check_findings` from `threat_engine_check` + `inventory_findings` from `threat_engine_inventory`
**Writes:** `threat_findings`, `threat_detections`, `threat_report` in `threat_engine_threat` + Neo4j graph
**Feeds downstream:** compliance, IAM, datasec, network, risk (all read threat data), BFF threat views
**Credentials:** NONE — reads DB, writes DB + Neo4j
**Execution:** K8s Job
**Timeout:** 14400s (4 hours)

---

## 2. Database

### PostgreSQL — `threat_engine_threat`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

**`threat_findings`** — main detection table
```
id                  SERIAL PK
threat_scan_id      UUID               (job-level — use scan_run_id for cross-engine joins)
scan_run_id         UUID               (cross-engine link — USE THIS for joins)
finding_id          VARCHAR(32) UNIQUE (sha256(rule_id|resource_uid|account|region)[:16] — stable)
tenant_id           UUID
rule_id             VARCHAR
resource_uid        TEXT               -- join to inventory_findings on resource_uid
resource_type, service, region VARCHAR
account_id          VARCHAR(512)
severity            VARCHAR            -- critical|high|medium|low
risk_score          INTEGER            -- common buckets: 22, 38, 50, 77
mitre_technique     VARCHAR            -- T#### format
mitre_tactic        VARCHAR
finding_data        JSONB              -- ALREADY A DICT
first_seen_at, last_seen_at TIMESTAMP
status              VARCHAR
credential_ref      TEXT               -- stripped from viewer responses
```

**`threat_detections`** — aggregated per MITRE technique
```
id                  SERIAL PK
scan_run_id         UUID               (USE THIS — NOT threat_scan_id)
detection_id        UUID
tenant_id           UUID
technique_id        VARCHAR            -- T#### MITRE technique
tactic, severity    VARCHAR
affected_resources  JSONB              -- list of resource_uids
description         TEXT
```
**CRITICAL:** `threat_detections` uses `scan_run_id`, NOT `threat_scan_id`.

**`threat_report`** — scan summary
```
threat_scan_id      UUID PK
orchestration_id    UUID
tenant_id, account_id, provider
total_threats, critical_threats, high_threats, medium_threats, low_threats INTEGER
threat_summary      JSONB
started_at, completed_at TIMESTAMP
status              VARCHAR
```

**`threat_analysis`** — enrichment (blast_radius|attack_path|toxic_combo)
**`threat_intel`** — threat intelligence data
**`tenants`** — FK target (MUST upsert before writing threat_findings)

### Neo4j — Aura
**URL:** `neo4j+s://17ec5cbb.databases.neo4j.io`
Labels: `Resource`, `Internet`
Relationships: `HAS_THREAT`, `EXPOSES`, `CONNECTS_TO`, `ASSUMES`, `IN_VPC`, `PROTECTED_BY`, `LOGS_TO`, `CONTAINS`, `HOSTS`

Powers: attack path visualization, reachability-based blast radius, security graph.
NOT the same as `blast_radius_score` from risk engine (that is numeric risk, not graph reachability).

### Common Queries

```sql
-- Threat summary for a scan
SELECT severity, COUNT(*) c FROM threat_findings
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY severity;

-- Top MITRE techniques
SELECT mitre_technique, mitre_tactic, COUNT(*) affected_resources
FROM threat_findings
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY mitre_technique, mitre_tactic ORDER BY affected_resources DESC;

-- Threats for a specific resource
SELECT finding_id, rule_id, severity, mitre_technique, finding_data
FROM threat_findings
WHERE resource_uid = $1 AND tenant_id = $2
ORDER BY severity, risk_score DESC;
```

---

## 3. API Endpoints

**Service URL:** `http://engine-threat` (port 80 → targetPort 8020)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `scan_run_id`, `tenant_id`, `account_id`, `csp` | Trigger threat scan |
| GET | `/api/v1/threat/{scan_run_id}/status` | path | Poll status |
| GET | `/api/v1/threat/summary` | `tenant_id` | Aggregated posture |
| GET | `/api/v1/threat/list` | `tenant_id`, `?severity`, `?limit` | Paginated threat list |
| GET | `/api/v1/threat/{threat_id}` | path | Single threat detail |
| GET | `/api/v1/threat/{threat_id}/misconfig-findings` | path | Linked check findings |
| GET | `/api/v1/threat/{threat_id}/assets` | path | Affected resources |
| PATCH | `/api/v1/threat/{threat_id}` | status, notes | Update threat |
| POST | `/api/v1/threat/analysis/run` | `tenant_id`, `analysis_types[]` | Trigger blast radius / attack path / toxic combo |
| GET | `/api/v1/threat/analysis/blast-radius` | `resource_uid`, `tenant_id` | Neo4j reachability blast radius |
| GET | `/api/v1/threat/analysis/attack-paths` | `tenant_id` | Attack chain analysis |
| GET | `/api/v1/threat/analysis/toxic-combinations` | `tenant_id` | Toxic combo detection |
| GET | `/api/v1/threat/analysis/prioritized` | `tenant_id` | AI-sorted prioritized threats |
| GET | `/api/v1/threat/analysis/{detection_id}` | path | Detection detail |
| GET | `/api/v1/threat/detections/{detection_id}/check-findings` | path | Mapped check findings |
| GET | `/api/v1/threat/analytics/trend` | `tenant_id`, `?days=30` | Time-series trends |
| GET | `/api/v1/threat/drift` | `tenant_id` | Drift vs previous scan |
| POST | `/api/v1/graph/build` | `tenant_id`, `scan_run_id` | Trigger Neo4j graph build; returns 202 + `job_id` |
| GET | `/api/v1/graph/build/status/{job_id}` | path | Poll graph build status (completed/failed/running) |
| GET | `/api/v1/graph/explore` | `tenant_id`, `?resource_uid`, `?depth` | Cytoscape graph explorer data |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 4. BFF Views I Feed

`threat_detail.py`, `threat_blast_radius.py`, `threat_attack_paths.py`, `threat_toxic_combos.py`, `threat_command_room.py`, `threat_scenario_detail.py`, `threat_posture_delta.py`, `threat_timeline.py` — all in `shared/api_gateway/bff/`

Also: `inventory.py` calls `http://engine-threat:8020/api/v1/threat/ui-data` for per-resource severity counts used in the inventory list view.

---

## 5. UI Pages I Power

- **`/threats`** — KPI cards, MITRE heatmap, threat list
- **`/threats/{threat_id}`** — threat detail, affected resources, remediation
- **`/threats/attack-paths`** — attack path graph visualization
- **`/threats/blast-radius`** — blast radius graph
- **`/threats/toxic-combos`** — toxic combination detections
- **`/dashboard`** — threat KPI card, risk score trend
- **`/inventory`** — severity badge per asset uses threat finding counts

---

## 6. K8s Service

```yaml
name: engine-threat
namespace: threat-engine-engines
image: yadavanup84/engine-threat:v-graph-sprint5
containerPort: 8020
service: ClusterIP port 80 → targetPort 8020
replicas: 1
resources:
  requests: 200m CPU, 512Mi memory
  limits: 1 CPU, 2Gi memory
liveness:  GET /api/v1/health/live  initialDelay=30  period=15  failThreshold=20
readiness: GET /api/v1/health/ready initialDelay=10  period=10  failThreshold=3
```

---

## 7. Engine-Specific Gotchas

**finding_id is stable and deterministic** — `sha256(rule_id|resource_uid|account|region)[:16]`. Always use `ON CONFLICT (finding_id) DO UPDATE` — never INSERT without conflict handling.

**ALWAYS upsert tenants table first** — FK constraint blocks INSERT into threat_findings if tenant row is missing. Call `_ensure_tenant(conn, tenant_id)` before any write.

**threat_detections uses scan_run_id NOT threat_scan_id** — always join on `scan_run_id` for cross-engine work.

**Risk scores cluster at 22/38/50/77** — preconfigured severity buckets, not continuous distribution.

**102 MITRE techniques** — all pre-loaded in DB. Format: `T####` (e.g., T1190, T1078).

**Neo4j blast radius ≠ risk blast_radius_score** — `/api/v1/threat/analysis/blast-radius` is graph reachability via Neo4j. `blast_radius_score` in risk engine is a numeric calculation. They are different concepts.

**Upsert pattern (mandatory):**
```sql
INSERT INTO threat_findings (finding_id, scan_run_id, threat_scan_id, tenant_id, ...)
VALUES ($1, $2, $3, $4, ...)
ON CONFLICT (finding_id) DO UPDATE SET
  scan_run_id = EXCLUDED.scan_run_id,
  threat_scan_id = EXCLUDED.threat_scan_id,
  last_seen_at = NOW();
```

---

## 8. Common Workflows

### Debug zero threat findings
1. Confirm check ran: `SELECT COUNT(*) FROM check_findings WHERE scan_run_id = $1 AND status = 'FAIL'` in check DB
2. Verify tenants row: `SELECT * FROM tenants WHERE tenant_id = $1` in threat DB
3. Check logs: `kubectl logs -l app=engine-threat -n threat-engine-engines --tail=200`
4. Check Neo4j connectivity in logs — Neo4j failures affect attack paths but not findings writes

### Port-forward for local testing
```bash
kubectl port-forward svc/engine-threat 8020:80 -n threat-engine-engines
```
