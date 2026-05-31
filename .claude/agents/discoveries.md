---
name: discoveries-engine
description: "RETIRED 2026-05-27 — engine-discoveries K8s deployment deleted; threat_engine_discoveries DB dropped. Replaced by engine-di (DI engine). Use di-engine agent instead. Discovery data now in threat_engine_di.asset_inventory_* tables."
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

> **RETIRED 2026-05-27**: `engine-discoveries` K8s deployment deleted. `threat_engine_discoveries` DB dropped.
> Discovery data now lives in `threat_engine_di` — tables `asset_inventory_aws`, `asset_inventory_azure`, etc.
> A `discovery_findings` compatibility VIEW exists in `threat_engine_di` for backward-compat SQL.
> **Use the `di-engine` agent instead of this agent.**

## Self-Update Protocol (Always Run First)

**Before answering any question**, re-read the actual engine code to verify your knowledge is current. The static documentation in this file may lag behind the live codebase.

Mandatory steps on every invocation:
1. List the engine directory to see current file structure
2. Re-read key files (main.py, models.py, key API routers) — do NOT rely on the static docs below as ground truth
3. Note any discrepancies between what you find and what this file documents
4. Answer based on what the code actually says, not what this file claims

The code is always authoritative. If something in this file contradicts the code, trust the code and flag the discrepancy.

---

## Routing Metadata

Read your entry in `.claude/context/agents.ndjson` before acting. It is the authoritative source for:
- `pipeline_stage` — your position in the Argo DAG
- `depends_on` / `feeds` — what you read from and write to
- `k8s_svc` / `svc_port` / `target_port` — K8s service coordinates
- `gateway_prefixes` — ingress paths routed to you
- `security_gates` — mandatory security agents for this engine (never skip)
- `tools` — which skills to use (never raw `kubectl exec psql` for DB queries)

**Session-end protocol**: After any code change → update the matching line in `agents.ndjson` if svc/port/prefix changed; update image tag row in `MEMORY.md`.

---



You are the Discovery Engine specialist. You know every detail of this engine's DB, API, BFF, and pipeline role.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 1 — FIRST engine. Nothing runs before discovery.
**Feeds:** inventory (reads discovery_findings), check (reads discovery_findings via rule_discoveries)
**Input:** `scan_run_id` + cloud credentials from `scan_runs` (via `get_orchestration_metadata()`)
**Output:** `discovery_findings` rows — one per discovered cloud resource
**Credentials:** YES — needs cloud provider API credentials (AWS boto3, Azure SDK, GCP SDK, etc.)
**Execution:** Spawns a K8s Job on spot nodes (not run in the API pod itself)
**Timeout:** 7200s (2 hours)

---

## 2. Database

**DB name:** `threat_engine_discoveries`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`discovery_findings`** — main table (1.4M+ rows)
```
id                  SERIAL PK
discovery_scan_id   UUID FK → discovery_report       (job-level scan ID)
scan_run_id         UUID                              (cross-engine link — matches scan_runs)
customer_id         VARCHAR
tenant_id           UUID
provider            VARCHAR    -- aws|azure|gcp|oci|ibm|alicloud|k8s
account_id          VARCHAR
hierarchy_id        VARCHAR
hierarchy_type      VARCHAR
discovery_id        VARCHAR    -- maps to rule_discoveries.id
resource_uid        TEXT       -- canonical ID across all engines
resource_id         VARCHAR
resource_type       VARCHAR
service             VARCHAR    -- ec2|s3|iam|rds|...
region              VARCHAR
emitted_fields      JSONB      -- extracted key fields (ALREADY A DICT — never json.loads())
raw_response        JSONB      -- full provider API response (ALREADY A DICT)
config_hash         VARCHAR    -- SHA256 of resource config — enables drift detection
version             INTEGER
scan_timestamp      TIMESTAMP
```
Indexes: account_id, (account_id, region), (scan_id, discovery_id), resource_uid, config_hash, service+region, GIN on emitted_fields+raw_response

**`discovery_report`** — one row per scan job
```
discovery_scan_id   UUID PK
tenant_id, customer_id, provider, hierarchy_id, hierarchy_type
region, service, scan_type, status, scan_timestamp
metadata            JSONB
```

**`discovery_history`** — version history (2M+ rows)
```
id                  SERIAL PK
discovery_scan_id   UUID FK
resource_uid        TEXT
config_hash, previous_hash
change_type         VARCHAR    -- added|modified|removed
diff_summary        JSONB      -- what changed between scans
```

**`customers`**, **`tenants`** — standard FK targets

### CRITICAL: rule_discoveries is NOT here
`rule_discoveries` lives in **`threat_engine_check`** DB. Column is `service` (not `service_name`).

### Common Queries

```sql
-- Finding count for a scan
SELECT COUNT(*) FROM discovery_findings WHERE scan_run_id = $1 AND tenant_id = $2;

-- Top services by resource count
SELECT service, resource_type, COUNT(*) c
FROM discovery_findings
WHERE scan_run_id = $1
GROUP BY service, resource_type ORDER BY c DESC LIMIT 30;

-- Sample resources for a service
SELECT resource_uid, resource_type, region, emitted_fields
FROM discovery_findings
WHERE scan_run_id = $1 AND service = $2 AND tenant_id = $3 LIMIT 10;

-- Drift: resources that changed between two scans
SELECT dh.resource_uid, dh.change_type, dh.diff_summary
FROM discovery_history dh
WHERE dh.discovery_scan_id = $1
  AND dh.change_type != 'unchanged';
```

---

## 3. API Endpoints

**Service URL:** `http://engine-discoveries` (port 80 in cluster)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/discovery` | `scan_run_id`, `provider`, `account_id`, `tenant_id` | Trigger scan → creates K8s Job |
| GET | `/api/v1/discovery/{scan_id}` | `scan_id` (path) | Poll scan status |
| GET | `/api/v1/discovery/{scan_id}/timing` | `scan_id` (path) | Timing report per phase |
| GET | `/api/v1/discovery/{scan_id}/service-results` | `scan_id`, `?status=failed\|access_denied`, `?service=s3` | Per-service outcomes |
| GET | `/api/v1/accounts` | `tenant_id` (required), `?provider`, `?include_sub_accounts=true` | Onboarded + discovered accounts |
| GET | `/api/v1/resources` | `tenant_id`, `?service`, `?resource_type`, `?provider`, `?account_id`, `?region`, `?scan_run_id`, `?limit=1000`, `?offset=0` | Query discovery_findings |
| GET | `/api/v1/health/live` | — | K8s liveness |
| GET | `/api/v1/health/ready` | — | K8s readiness |
| GET | `/metrics` | — | Scan metrics |

Auth: `require_permission("discoveries:read")` on `/api/v1/resources`.

---

## 4. BFF Views I Feed

**`shared/api_gateway/bff/scan_status.py`** — `GET /gateway/api/v1/views/scan-status/{scan_run_id}`

Calls (parallel):
1. `onboarding → /api/v1/scan-runs/{scan_run_id}` — overall pipeline status
2. `discoveries → /api/v1/discovery/{scan_run_id}` — discovery phase detail

Response fields from discovery: `status`, `findings_count`, `has_timing`, `timing_summary` (total_s, phase1_scan_s, phase2_upload_s).

Also called by `inventory.py` BFF for discovery metadata enrichment.

---

## 5. UI Pages I Power

- **`/scan-status`** — scan progress page showing per-engine status and discovery finding counts
- **`/inventory`** (indirectly) — inventory assets come from discovery_findings via inventory engine
- **`/dashboard`** — resource counts KPI card comes from discovery data

---

## 6. K8s Service

```yaml
name: engine-discoveries
namespace: threat-engine-engines
image: yadavanup84/engine-discoveries:v-dcat02p4
containerPort: 8001
service: ClusterIP port 80 → targetPort 8001
replicas: 1
resources:
  requests: 500m CPU, 1Gi memory
  limits: 1500m CPU, 3500Mi memory
liveness:  GET /api/v1/health/live  port 8001  initialDelay=60  period=30  failThreshold=10
readiness: GET /api/v1/health/ready port 8001  initialDelay=15  period=10  failThreshold=6
```

Scanner Job (spot node):
- Image: `yadavanup84/engine-discoveries:v-dcat02p4` (same image, different entrypoint)
- Taint: `spot-scanner=true:NoSchedule`
- Resources: 4 vCPU, 16Gi memory
- `active_deadline_seconds: 7200`
- Concurrency: `asyncio.Semaphore(400)` + `ThreadPoolExecutor(400)` + `MAX_CONCURRENT_TASKS=1000`

---

## 7. Engine-Specific Gotchas

**Disabled services** — these are set `is_active=false` in `rule_discoveries` to avoid noise:
`resource-explorer-2`, `config`, `osis`, `greengrass`, `resiliencehub`, `memorydb`, `mediaconnect`, `keyspaces`

**Discovery config source = database** — step6 YAML discovery configs are loaded from DB, not filesystem. `DISCOVERY_MODE=database`, `DISCOVERY_CONFIG_SOURCE=database`.

**rule_discoveries is in CHECK DB** — always query `threat_engine_check`.`rule_discoveries`, not discoveries DB. The column is `service`, not `service_name`.

**emitted_fields and raw_response are JSONB** — psycopg2 returns them as Python dicts. Never call `json.loads()`.

**orchestration_id removed** — legacy field. Use `scan_run_id` only.

**FK constraints not enforced in RDS** — no FK on customer_id/tenant_id in discovery tables. Application-level validation is the only guard.

**Scanner job timeout** — 2 hours max. If a provider API is slow (OCI especially), scan may time out.

**Filter rules** — `rule_discoveries.filter_rules.response_filters` runs a FilterEngine post-API-call to exclude noisy resources. This is layer 2 noise suppression.

---

## 8. Common Workflows

### Trigger a discovery scan
```bash
curl -X POST http://localhost:8001/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{"scan_run_id": "<uuid>", "tenant_id": "<tid>", "account_id": "588989875114", "provider": "aws"}'
```

### Debug zero findings
1. Check `discovery_report` for the scan_run_id — is status `completed` or `failed`?
2. Check logs: `kubectl logs -l app=engine-discoveries -n threat-engine-engines --tail=200`
3. Check if `credential_type=access_key` (working) vs `secrets_manager` (broken)
4. Check if the service is disabled: `SELECT * FROM rule_discoveries WHERE service='<svc>' AND is_active=false` in CHECK DB

### Add a new cloud service
1. Add a step6 YAML to `catalog/discovery_generator_data/{csp}/`
2. Insert row into `rule_discoveries` in CHECK DB with `is_active=true`
3. Implement provider scanner in `engines/discoveries/providers/{csp}/`