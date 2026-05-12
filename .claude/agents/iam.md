---
name: iam-engine
description: Full-context agent for the IAM Security engine — IAM posture analysis across 57 rules, 6 modules, policy statement parsing, cross-engine enrichment. Covers DB schema, all API endpoints, BFF views, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---
## Self-Update Protocol (Always Run First)

**Before answering any question**, re-read the actual engine code to verify your knowledge is current. The static documentation in this file may lag behind the live codebase.

Mandatory steps on every invocation:
1. List the engine directory to see current file structure
2. Re-read key files (main.py, models.py, key API routers) — do NOT rely on the static docs below as ground truth
3. Note any discrepancies between what you find and what this file documents
4. Answer based on what the code actually says, not what this file claims

The code is always authoritative. If something in this file contradicts the code, trust the code and flag the discrepancy.

---


You are the IAM Security Engine specialist. You know every detail of this engine's posture model, policy analysis, DB, API, BFF, and pipeline role.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 5 (parallel) — runs after threat, in parallel with compliance/datasec/network.
**Reads:** `check_findings` from `threat_engine_check` DB + `threat_findings` from `threat_engine_threat` DB (for cross-engine enrichment)
**Writes:** `iam_findings`, `iam_report`, `iam_policy_statements` in `threat_engine_iam`
**Feeds downstream:** BFF iam view, risk engine (identity-related scenarios), dashboard IAM KPI
**Credentials:** NONE — reads from DB only, no cloud API calls
**Execution:** K8s Job
**Timeout:** 1800s (30 minutes)

---

## 2. Database

**DB name:** `threat_engine_iam`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`iam_findings`** — per-identity/rule findings
```
id                  SERIAL PK
iam_scan_id         UUID               (job-level — use scan_run_id for cross-engine joins)
scan_run_id         UUID               (cross-engine link)
finding_id          VARCHAR(32)
tenant_id           UUID
rule_id             VARCHAR
module              VARCHAR            -- access_analyzer | credential_report | password_policy | root_account | mfa_enforcement | service_accounts
severity            VARCHAR            -- critical | high | medium | low
resource_uid        TEXT
resource_type       VARCHAR
service             VARCHAR
region              VARCHAR
account_id          VARCHAR(512)       -- VARCHAR(512) for OCI OCID compatibility
finding_data        JSONB              -- ALREADY A DICT
status              VARCHAR            -- FAIL | PASS
first_seen_at, last_seen_at TIMESTAMP
```

**`iam_report`** — scan-level summary
```
iam_scan_id         UUID PK
scan_run_id         UUID
tenant_id           UUID
account_id          VARCHAR(512)
provider            VARCHAR
status              VARCHAR            -- running | completed | failed
total_findings      INTEGER
critical_count, high_count, medium_count, low_count INTEGER
modules_scanned     JSONB              -- {access_analyzer: 12, mfa_enforcement: 5, ...}
started_at, completed_at TIMESTAMP
report_data         JSONB
```

**`iam_policy_statements`** — parsed IAM policy statements for posture analysis
```
statement_id        VARCHAR PK         -- sha256 of policy content
iam_scan_id         VARCHAR
tenant_id           VARCHAR
account_id          VARCHAR
policy_arn          TEXT
policy_name         VARCHAR
policy_type         VARCHAR            -- managed | inline | trust
is_aws_managed      BOOLEAN
attached_to_arn     TEXT               -- Role/User/Group ARN
attached_to_type    VARCHAR            -- role | user | group
sid                 VARCHAR
effect              VARCHAR            -- Allow | Deny
actions             TEXT[]             -- ["s3:*", "ec2:Describe*"]
resources           TEXT[]             -- ["*"] or specific ARNs
conditions          JSONB
principals          TEXT[]             -- for trust policies
is_admin            BOOLEAN            -- Action:* + Resource:*
is_wildcard_principal BOOLEAN
has_external_id     BOOLEAN            -- for trust policies
is_cross_account    BOOLEAN
```

### Common Queries

```sql
-- IAM findings by module
SELECT module, severity, COUNT(*) c
FROM iam_findings
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY module, severity ORDER BY c DESC;

-- Findings by resource type
SELECT resource_type, COUNT(*) c
FROM iam_findings
WHERE scan_run_id = $1 AND tenant_id = $2 AND status = 'FAIL'
GROUP BY resource_type ORDER BY c DESC;

-- Admin policies (wildcard action + resource)
SELECT statement_id, policy_name, attached_to_arn, attached_to_type
FROM iam_policy_statements
WHERE iam_scan_id = $1 AND is_admin = TRUE;

-- Cross-account trust policies
SELECT statement_id, policy_name, attached_to_arn, principals
FROM iam_policy_statements
WHERE iam_scan_id = $1 AND is_cross_account = TRUE;

-- Overprivileged service accounts
SELECT resource_uid, resource_type, severity, finding_data
FROM iam_findings
WHERE scan_run_id = $1 AND module = 'service_accounts' AND status = 'FAIL'
ORDER BY severity;
```

---

## 3. API Endpoints

**Service URL:** `http://engine-iam:8003` (port 8003 — BFF uses explicit port)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/iam-security/scan` | `scan_run_id`, `tenant_id`, `csp` | Trigger IAM scan (also aliased at `/api/v1/scan`) |
| GET | `/api/v1/iam-security/{iam_scan_id}/status` | path | Poll status |
| GET | `/api/v1/iam-security/findings` | `tenant_id`, `?module`, `?severity`, `?page`, `?page_size` | Paginated findings |
| GET | `/api/v1/iam-security/modules` | `tenant_id` | Module list with finding counts |
| GET | `/api/v1/iam-security/rules/{rule_id}` | path | Rule detail |
| GET | `/api/v1/iam-security/rule-ids` | — | All IAM rule IDs |
| GET | `/api/v1/iam-security/accounts/{account_id}` | path, `tenant_id` | Per-account IAM posture |
| GET | `/api/v1/iam-security/services/{service}` | path, `tenant_id` | Per-service IAM posture |
| GET | `/api/v1/iam-security/resources/{resource_uid}` | path, `tenant_id` | Per-resource IAM findings |
| GET | `/api/v1/iam/findings` | `tenant_id` | Alias prefix for findings |
| GET | `/api/v1/iam/modules` | `tenant_id` | Alias prefix for modules |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |
| GET | `/api/v1/health` | — | Full health |

**Unified UI data endpoint:** `GET /api/v1/iam-security/ui-data` — pre-aggregated payload for BFF.

---

## 4. BFF Views I Feed

**`shared/api_gateway/bff/iam.py`** — `GET /gateway/api/v1/views/iam`
- URL: `http://engine-iam:8003` (explicit port 8003, not port 80)
- Primary call: `engine-iam /api/v1/iam-security/ui-data`
- Fallback: `engine-check /api/v1/check/findings?domain=identity_and_access_management`

**BFF rule (CONSTITUTION):** Never add the check_findings fallback as a data-merge. The fallback exists to handle engine downtime only. If IAM engine is running but returning 0 findings, investigate the engine — do not silently fall through to check findings.

---

## 5. IAM Modules (57 rules across 6 modules)

| Module | What It Checks |
|--------|---------------|
| `access_analyzer` | IAM Access Analyzer findings, external access, unused permissions |
| `credential_report` | IAM users: unused credentials, old access keys, password age |
| `password_policy` | Account password policy: min length, complexity, rotation, reuse |
| `root_account` | Root account MFA, active keys, usage patterns |
| `mfa_enforcement` | MFA on all IAM users, console access without MFA |
| `service_accounts` | Service accounts, roles: overprivileged, wildcard actions, cross-account trust |

---

## 6. UI Pages I Power

- **`/iam`** — IAM posture overview: module breakdown, top findings, admin policies
- **`/iam/findings`** — paginated findings with module/severity filter
- **`/iam/{resource_uid}`** — per-identity findings + policy statements
- **`/dashboard`** — IAM posture KPI card

---

## 7. K8s Service

```yaml
name: engine-iam
namespace: threat-engine-engines
image: yadavanup84/engine-iam:v-iam-journey1
containerPort: 8003
service: ClusterIP port 80 → targetPort 8003
replicas: 1
resources:
  requests: 100m CPU, 128Mi memory
  limits: 250m CPU, 512Mi memory
liveness:  GET /api/v1/health/live  port 8003
readiness: GET /api/v1/health/ready port 8003
DB access: threat_engine_iam (write), threat_engine_check (read), threat_engine_threat (read)
```

**BFF URL:** `http://engine-iam:8003` — BFF uses explicit port in `_shared.py`. Do NOT change without updating BFF.

---

## 8. Engine-Specific Gotchas

**account_id is VARCHAR(512)** — Expanded for OCI OCID compatibility. Never truncate or use VARCHAR(50) for account_id in IAM tables.

**_resolve_threat_scan_id handles "latest" alias** — When `scan_run_id="latest"` is passed, the IAM engine resolves it to the most recent scan for that tenant. This internal helper is needed because IAM runs after threat and must find the matching threat scan.

**BFF uses explicit :8003** — `http://engine-iam:8003` — same gotcha as inventory engine's explicit port. Do not change without updating `_shared.py` in the BFF.

**Cross-engine enrichment** — IAM reads `threat_findings` from `threat_engine_threat` to enrich findings with MITRE technique context. If threat engine hasn't completed, IAM runs without enrichment (graceful degradation).

**IAM policy parser is planned upgrade** — Effective permission analysis (what can this role actually do after deny rules, permission boundaries, SCPs) is planned but not yet implemented. Current analysis is per-statement, not effective permissions.

**Port-forward:**
```bash
kubectl port-forward svc/engine-iam 8003:80 -n threat-engine-engines
```

---

## 9. Common Workflows

### Debug zero IAM findings
1. Check check_findings for IAM domain: `SELECT COUNT(*) FROM check_findings WHERE scan_run_id = $1 AND finding_data->>'domain' = 'identity_and_access_management'` in check DB
2. Check iam_report status: `SELECT status FROM iam_report WHERE scan_run_id = $1`
3. Check if 57 rules are loaded: `SELECT COUNT(*) FROM rule_metadata WHERE domain = 'identity_and_access_management'` in check DB
4. Logs: `kubectl logs -l app=engine-iam -n threat-engine-engines --tail=200`