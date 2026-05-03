---
name: compliance-engine
description: Full-context agent for the Compliance engine — framework mapping and scoring across 13+ frameworks (CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2, FedRAMP, etc.). Covers DB schema, all API endpoints, BFF views, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Compliance Engine specialist. You know every detail of this engine's DB, API, BFF, pipeline role, and framework mapping.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 5 (parallel) — runs after threat, in parallel with iam/datasec/network/etc.
**Reads:** `check_findings` from `threat_engine_check` DB
**Reads also:** `compliance_rule_data_mapping` + `compliance_data` from `threat_engine_check` DB
**Writes:** `compliance_findings`, `compliance_report` in `threat_engine_compliance`
**Feeds downstream:** risk engine, BFF compliance views, PDF/Excel export
**Credentials:** NONE — all mapping from DB. No cloud API calls.
**Execution:** K8s Job
**Timeout:** 1800s (30 minutes)

---

## 2. Database

**DB name:** `threat_engine_compliance`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`compliance_findings`** — control-level PASS/FAIL
```
finding_id          UUID PK
compliance_scan_id  UUID               (job-level)
tenant_id           UUID
scan_run_id         UUID               (cross-engine link)
rule_id             VARCHAR
category, severity  VARCHAR
confidence          FLOAT
status              VARCHAR            -- PASS or FAIL
first_seen_at, last_seen_at TIMESTAMP
resource_type, resource_id  VARCHAR
resource_uid        TEXT               -- NOT resource_arn (column renamed 2026-03-21)
region              VARCHAR
finding_data        JSONB              -- ALREADY A DICT
compliance_framework VARCHAR           -- CIS|NIST|ISO27001|PCI-DSS|HIPAA|GDPR|SOC2|...
control_id, control_name VARCHAR
```

**`compliance_report`** — scan summary (two NOT NULL fields — always include on INSERT)
```
compliance_scan_id  UUID PK
tenant_id           UUID
scan_run_id         UUID
cloud               VARCHAR            -- provider
trigger_type        VARCHAR NOT NULL   -- manual|scheduled|api  ← MUST be provided
collection_mode     VARCHAR NOT NULL   -- full|partial|incremental  ← MUST be provided
started_at, completed_at TIMESTAMP
total_controls, controls_passed, controls_failed INTEGER
total_findings      INTEGER
report_data         JSONB              -- FULL report including posture_summary
status              VARCHAR            -- running|completed|failed
```

**`compliance_data`** — framework control definitions (lives in `threat_engine_check` DB, not here)
```
unique_compliance_id VARCHAR PK
compliance_framework, framework_id, framework_version
requirement_id, requirement_name, requirement_description
section, service, csp
mapped_rules        VARCHAR            -- semicolon-separated rule_ids
```

**`compliance_rule_data_mapping`** — rule → control mapping (also in `threat_engine_check` DB)
```
id                  SERIAL PK
rule_id             VARCHAR
unique_compliance_id VARCHAR FK
framework_id, compliance_framework, csp VARCHAR
UNIQUE(rule_id, unique_compliance_id)
```

**`tenants`** — FK target

### Common Queries

```sql
-- Framework scores for a tenant
SELECT compliance_framework,
       COUNT(*) FILTER (WHERE status='PASS') passed,
       COUNT(*) FILTER (WHERE status='FAIL') failed,
       ROUND(100.0 * COUNT(*) FILTER (WHERE status='PASS') / COUNT(*), 1) AS score_pct
FROM compliance_findings
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY compliance_framework;

-- Failing controls for a framework
SELECT control_id, control_name, COUNT(*) resources_failing
FROM compliance_findings
WHERE scan_run_id = $1 AND tenant_id = $2
  AND compliance_framework = 'CIS' AND status = 'FAIL'
GROUP BY control_id, control_name ORDER BY resources_failing DESC;

-- Per-resource compliance breakdown
SELECT resource_uid, resource_type,
       COUNT(*) FILTER (WHERE status='PASS') passed,
       COUNT(*) FILTER (WHERE status='FAIL') failed
FROM compliance_findings
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY resource_uid, resource_type;
```

---

## 3. API Endpoints

**Service URL:** `http://engine-compliance` (port 80 → targetPort 8010)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `scan_run_id`, `tenant_id`, `csp` | Trigger compliance scan |
| GET | `/api/v1/compliance/{compliance_scan_id}/status` | path | Poll status |
| GET | `/api/v1/compliance/frameworks` | `tenant_id` | All frameworks with scores |
| GET | `/api/v1/compliance/framework/{framework}/status` | path, `tenant_id` | Framework posture |
| GET | `/api/v1/compliance/framework/{framework}/detailed` | path, `tenant_id` | Full framework report |
| GET | `/api/v1/compliance/framework/{framework}/controls/grouped` | path, `tenant_id` | Controls by domain/section |
| GET | `/api/v1/compliance/framework/{framework}/resources/grouped` | path, `tenant_id` | Controls by resource |
| GET | `/api/v1/compliance/framework/{framework}/control/{control_id}` | path, `tenant_id` | Single control detail |
| GET | `/api/v1/compliance/framework/{framework}/structure` | path | Framework hierarchy |
| GET | `/api/v1/compliance/framework/{framework}/download/pdf` | path, `tenant_id` | PDF export |
| GET | `/api/v1/compliance/framework/{framework}/download/excel` | path, `tenant_id` | Excel export |
| GET | `/api/v1/compliance/resource/drilldown` | `resource_uid`, `tenant_id` | Per-resource control breakdown |
| GET | `/api/v1/compliance/controls/search` | `?query=X` | Search controls |
| GET | `/api/v1/compliance/trends` | `tenant_id` | Historical trends |
| GET | `/api/v1/compliance/reports` | `tenant_id`, `?limit` | List past reports |
| GET | `/api/v1/compliance/report/{report_id}` | path | Retrieve report |
| DELETE | `/api/v1/compliance/reports/{report_id}` | path | Delete report |
| GET | `/api/v1/compliance/frameworks/all` | — | All framework IDs |
| POST | `/api/v1/compliance/generate/from-check-db` | `scan_run_id`, `tenant_id` | Generate from check DB |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 4. BFF Views I Feed

**`shared/api_gateway/bff/compliance.py`** — `GET /gateway/api/v1/views/compliance`
- Calls: `engine-compliance /api/v1/compliance/frameworks` + per-framework status endpoints
- Returns: framework list with scores, failing control counts, trend indicators

**`shared/api_gateway/bff/policies.py`** — `GET /gateway/api/v1/views/policies`
- Calls: compliance framework structure endpoints

---

## 5. UI Pages I Power

- **`/compliance`** — framework score cards (CIS, NIST, PCI-DSS, ISO 27001, HIPAA, GDPR, SOC 2), trend charts, failing controls table
- **`/compliance/{framework}`** — per-framework detail: control list, pass/fail, resource drill-down
- **`/compliance/{framework}/control/{control_id}`** — single control with affected resources
- **`/dashboard`** — compliance score KPI card
- **`/reports`** — PDF/Excel export triggers

---

## 6. K8s Service

```yaml
name: engine-compliance
namespace: threat-engine-engines
image: yadavanup84/threat-engine-compliance-engine:v-compliance-auth
containerPort: 8010
service: ClusterIP port 80 → targetPort 8010
replicas: 1
resources:
  requests: 100m CPU, 128Mi memory
  limits: 250m CPU, 256Mi memory
liveness:  GET /api/v1/health/live  initialDelay=30  period=10  failThreshold=30
readiness: GET /api/v1/health/ready initialDelay=10  period=5   failThreshold=6
volumes: emptyDir at /output (report staging — ephemeral, not persistent)
```

---

## 7. Engine-Specific Gotchas

**trigger_type and collection_mode are NOT NULL** — the `compliance_report` table requires both on INSERT:
```sql
INSERT INTO compliance_report (compliance_scan_id, scan_run_id, tenant_id, cloud,
  trigger_type, collection_mode, status, started_at)
VALUES ($1, $2, $3, $4, 'manual', 'full', 'running', NOW());
```
Omitting either causes a NOT NULL constraint violation.

**resource_uid NOT resource_arn** — column renamed 2026-03-21. Never use `resource_arn` in compliance_findings queries.

**report_data JSONB is the source of truth** — `compliance_report.report_data` contains the full structured report including `posture_summary`. UI extracts `report_data->'posture_summary'` for dashboard cards. `compliance_findings` rows may be 0 while `report_data` has full data — this is by design.

**13+ supported frameworks:** `CIS`, `NIST`, `ISO27001`, `PCI-DSS`, `HIPAA`, `GDPR`, `SOC2`, `FedRAMP`, `MITRE ATT&CK`, `AWS Well-Architected`, `CCPA`, `CSA CCM`, `DORA`

**compliance_data and compliance_rule_data_mapping live in CHECK DB** — `threat_engine_check` DB. The compliance engine reads from there during scan execution.

**Export staging is ephemeral** — PDF/Excel staged in `/output` (emptyDir). Do not rely on it across pod restarts.

---

## 8. Common Workflows

### Debug zero compliance scores
1. Confirm check ran: `SELECT COUNT(*) FROM check_findings WHERE scan_run_id = $1 AND status = 'FAIL'` in check DB
2. Confirm rule mappings exist: `SELECT COUNT(*) FROM compliance_rule_data_mapping WHERE compliance_framework = 'CIS'` in check DB
3. Check `compliance_report` status: `SELECT status FROM compliance_report WHERE scan_run_id = $1`
4. Check logs: `kubectl logs -l app=engine-compliance -n threat-engine-engines --tail=200`

### Add a new framework control mapping
```sql
-- In threat_engine_check DB
INSERT INTO compliance_data
  (unique_compliance_id, compliance_framework, framework_id, requirement_id,
   requirement_name, csp, mapped_rules)
VALUES ('CIS-AWS-1.5', 'CIS', 'CIS AWS v3.0', '1.5',
        'Ensure MFA is enabled for root account', 'aws', 'AWS-IAM-001;AWS-IAM-002');

INSERT INTO compliance_rule_data_mapping (rule_id, unique_compliance_id, framework_id, compliance_framework, csp)
VALUES ('AWS-IAM-001', 'CIS-AWS-1.5', 'CIS AWS v3.0', 'CIS', 'aws');
```

### Port-forward for local testing
```bash
kubectl port-forward svc/engine-compliance 8010:80 -n threat-engine-engines
```
