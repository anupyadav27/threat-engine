---
name: cdr-engine
description: Full-context agent for the CDR engine — Cloud Detection & Response. Independent CronWorkflow (not main scan pipeline). L1/L2/L3 behavioral detection from cloud logs. Covers DB schema, API endpoints, BFF views, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the CDR Engine specialist. You know every detail of this engine's behavioral detection model, log source architecture, DB, API, BFF, and pipeline role.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** INDEPENDENT — runs as a K8s CronWorkflow, NOT part of the main CSPM scan pipeline.
**Pipeline:** `ciem-cron-pipeline.yaml` in Argo (separate from `cspm-pipeline.yaml`)
**Reads:** Cloud logs from CloudTrail (AWS), Activity Logs (Azure), Cloud Audit Logs (GCP), etc.
**Writes:** `cdr_findings`, `cdr_report`, `ciem_identities`, `ciem_collection_watermark`, `cdr_actor_daily_stats`, `cdr_baselines` in `threat_engine_cdr`
**Feeds downstream:** BFF ciem views, risk engine (identity-related scenarios)
**Credentials:** YES — needs log API access (CloudTrail, S3, etc.)
**Execution:** K8s CronWorkflow (Argo)

**Key difference from other engines:** CIEM does NOT use `scan_run_id` from scan_orchestration. It runs independently on a schedule, collecting and analyzing log events.

---

## 2. Detection Architecture

CIEM has 3 detection layers:

| Layer | What | Method |
|-------|------|--------|
| **L1** | Known-bad patterns | Rule-based evaluation on log events (overprivileged, admin actions, service account misuse) |
| **L2** | Behavioral anomalies | Statistical deviation from `cdr_baselines` (actor_daily_stats vs baseline) |
| **L3** | Correlation | Cross-event correlation (privilege escalation chains, lateral movement via assume role) |

**No raw events stored** — only processed findings and aggregated stats are persisted. Raw CloudTrail events are evaluated in-memory and discarded.

---

## 3. Database

**DB name:** `threat_engine_cdr`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`cdr_findings`** — per-identity findings
```
finding_id          UUID PK
tenant_id           VARCHAR
scan_run_id         VARCHAR    -- ciem job ID (not main pipeline scan_run_id)
rule_id             VARCHAR
severity            VARCHAR    -- critical | high | medium | low
resource_uid        TEXT
resource_type       VARCHAR    -- iam_user | iam_role | service_account | managed_identity
finding_data        JSONB      -- identity detail, actions performed, risk indicators
status              VARCHAR
first_seen_at, last_seen_at TIMESTAMP
```

**`cdr_report`** — scan-level summary
```
scan_run_id         VARCHAR PK (ciem job ID)
tenant_id           VARCHAR
status              VARCHAR    -- running | completed | failed
total_findings, critical_count, high_count INTEGER
findings_by_type    JSONB
started_at, completed_at TIMESTAMP
```

**`ciem_identities`** — identity catalog with entitlement posture
```
identity_id         UUID PK
tenant_id           VARCHAR
identity_uid        TEXT       -- ARN, service account path, etc.
identity_type       VARCHAR    -- iam_user | iam_role | service_account | group
provider            VARCHAR
account_id          VARCHAR
is_privileged       BOOLEAN
is_unused           BOOLEAN
last_activity_at    TIMESTAMP
entitlement_data    JSONB      -- permissions, policies, cross-account access
```

**`ciem_collection_watermark`** — log collection cursor (auto-created by event_writer.py)
```
tenant_id           VARCHAR
provider            VARCHAR
account_id          VARCHAR
last_collected_at   TIMESTAMP  -- high-water mark for incremental collection
log_source_type     VARCHAR    -- cloudtrail | azure_activity | gcp_audit
```

**`cdr_actor_daily_stats`** — rolling daily activity aggregates (auto-created by baseline_evaluator.py)
```
tenant_id, actor_arn TEXT
stat_date           DATE
event_count         INTEGER
unique_services     INTEGER
unique_actions      INTEGER
sensitive_actions   INTEGER
denied_actions      INTEGER
cross_account_calls INTEGER
```

**`cdr_baselines`** — behavioral baselines per actor (auto-created by baseline_evaluator.py)
```
tenant_id, actor_arn TEXT
metric_type         VARCHAR    -- event_count | sensitive_actions | cross_account | denied_actions
baseline_avg, baseline_p95, std_deviation NUMERIC
window_days         INTEGER    -- default 14
computed_at         TIMESTAMP
UNIQUE(tenant_id, actor_arn, metric_type)
```

### Common Queries

```sql
-- CIEM findings by severity
SELECT severity, COUNT(*) FROM cdr_findings
WHERE tenant_id = $1 GROUP BY severity;

-- Overprivileged identities
SELECT identity_uid, identity_type, entitlement_data->>'permission_count' as perms
FROM ciem_identities
WHERE tenant_id = $1 AND is_privileged = TRUE
ORDER BY (entitlement_data->>'permission_count')::int DESC;

-- Behavioral anomalies (actor vs baseline)
SELECT actor_arn, event_count, baseline_avg,
       ROUND(event_count / NULLIF(baseline_avg, 0), 2) AS deviation_factor
FROM cdr_actor_daily_stats ads
JOIN cdr_baselines b USING (tenant_id, actor_arn)
WHERE ads.tenant_id = $1 AND b.metric_type = 'event_count'
  AND event_count > baseline_p95 * 2;
```

---

## 4. API Endpoints

**Service URL:** `http://engine-cdr` (port 80 → targetPort 8025)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `scan_run_id`, `tenant_id`, `csp` | Trigger CIEM scan |
| POST | `/api/v1/scan/all` | `tenant_id` | Scan all accounts for tenant |
| POST | `/api/v1/internal/scan/all` | `tenant_id` | Internal: scan all (called by CronWorkflow) |
| GET | `/api/v1/cdr/findings` | `tenant_id`, `?severity`, `?limit` | Paginated findings |
| GET | `/api/v1/cdr/findings/{finding_id}` | path, `tenant_id` | Single finding detail |
| GET | `/api/v1/cdr/dashboard` | `tenant_id` | Aggregated posture KPIs |
| GET | `/api/v1/cdr/identities` | `tenant_id`, `?type`, `?is_privileged` | Identity catalog |
| GET | `/api/v1/cdr/top-rules` | `tenant_id` | Top triggered rules |
| GET | `/api/v1/cdr/log-sources` | `tenant_id` | Available log sources + status |
| GET | `/api/v1/cdr/report/{scan_run_id}` | path | Retrieve report |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 5. BFF Views I Feed

**`shared/api_gateway/bff/ciem.py`** — `GET /gateway/api/v1/views/ciem`
- URL: `http://engine-cdr`
- Parallel calls:
  1. `/api/v1/cdr/dashboard` — KPI counts
  2. `/api/v1/cdr/identities` — top identities
  3. `/api/v1/cdr/top-rules` — most-triggered rules
  4. `/api/v1/cdr/log-sources` — log source coverage

---

## 6. UI Pages I Power

- **`/ciem`** — identity posture overview, top overprivileged identities, behavioral anomalies
- **`/ciem/identities`** — full identity catalog with entitlement drill-down
- **`/ciem/findings`** — CIEM findings list
- **`/dashboard`** — CIEM KPI card (overprivileged count, anomalies)

---

## 7. K8s Service

```yaml
name: engine-cdr
namespace: threat-engine-engines
image: yadavanup84/engine-cdr:v-jny-a
containerPort: 8025
service: ClusterIP port 80 → targetPort 8025
replicas: 1
resources:
  requests: 100m CPU, 256Mi memory
  limits: 500m CPU, 512Mi memory
liveness:  GET /api/v1/health/live  port 8025  initialDelay=60  period=30  failThreshold=5
readiness: GET /api/v1/health/ready port 8025  initialDelay=30  period=10  failThreshold=5
env: ENGINE_NAME=ciem, LOG_LOOKBACK_HOURS=1, LOG_MAX_EVENTS=500000, LOG_EVENTS_RETAIN_DAYS=7
```

**Argo CronWorkflow:** `deployment/aws/eks/argo/ciem-cron-pipeline.yaml`
- Runs independently from the main `cspm-pipeline.yaml`
- Calls `/api/v1/internal/scan/all` on a schedule

---

## 8. Engine-Specific Gotchas

**Independent pipeline — no scan_run_id from orchestration** — CIEM uses its own job IDs. It does NOT use the `scan_run_id` from `scan_orchestration`. Never try to join CIEM findings to other engine tables using scan_run_id.

**No raw events stored** — Raw CloudTrail/log events are processed in-memory. Only aggregates (`cdr_actor_daily_stats`) and findings (`cdr_findings`) are persisted. Do not design storage for raw events.

**LOG_LOOKBACK_HOURS=1** — On first run with no watermark, only 1 hour of logs are fetched. After that, incremental collection uses `ciem_collection_watermark.last_collected_at` as the cursor.

**Behavioral baseline requires 14 days** — `cdr_baselines` needs 14 days of `cdr_actor_daily_stats` before L2 anomaly detection fires. New tenants will only get L1 findings for the first 2 weeks.

**CronWorkflow trigger vs API trigger** — The standard POST `/api/v1/scan` endpoint works for manual triggers. The CronWorkflow calls `/api/v1/internal/scan/all` which bypasses tenant filtering and scans all registered accounts.

**Log source discovery** — `GET /api/v1/cdr/log-sources` returns available log sources with connection status. A tenant with no CloudTrail configured will show 0 findings — check log sources first when debugging.

**Port-forward:**
```bash
kubectl port-forward svc/engine-cdr 8025:80 -n threat-engine-engines
```

---

## 9. Common Workflows

### Debug zero CIEM findings
1. Check log sources: `GET /api/v1/cdr/log-sources?tenant_id=$TENANT_ID`
2. Check watermark: `SELECT * FROM ciem_collection_watermark WHERE tenant_id = $1`
3. Check if baseline is populated: `SELECT COUNT(*) FROM cdr_actor_daily_stats WHERE tenant_id = $1`
4. Logs: `kubectl logs -l app=engine-cdr -n threat-engine-engines --tail=200`

### Trigger manual CIEM scan
```bash
kubectl port-forward svc/engine-cdr 8025:80 -n threat-engine-engines
# In another terminal:
curl -X POST http://localhost:8025/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"scan_run_id": "<uuid>", "tenant_id": "<tid>", "csp": "aws"}'
```