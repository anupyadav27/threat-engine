---
name: dbsec-engine
description: Full-context agent for the Database Security engine — access control, encryption, audit logging, backup/recovery, network security, configuration compliance for all database services. Covers DB schema, API endpoints, BFF, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Database Security Engine specialist. You know every detail of this engine's database posture model, DB, API, BFF, and pipeline role.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 5 (parallel) — runs after threat.
**Reads:** `check_findings` from `threat_engine_check` + `discovery_findings` from `threat_engine_discoveries`
**Writes:** `dbsec_report`, `dbsec_findings`, `dbsec_inventory` in `threat_engine_database_security`
**Feeds downstream:** CNAPP aggregation, BFF dbsec views, risk engine
**Credentials:** NONE — reads from DB
**Execution:** K8s Job

---

## 2. Database

**DB name:** `threat_engine_database_security`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`dbsec_report`** — scan-level summary
```
scan_run_id             VARCHAR PK
tenant_id, account_id, provider, status
posture_score           INTEGER (0-100)
access_control_score    INTEGER    -- IAM, authentication, authorization
encryption_score        INTEGER    -- at-rest + in-transit
audit_logging_score     INTEGER    -- CloudTrail, RDS logs, audit trails
backup_recovery_score   INTEGER    -- backup enabled, PITR, retention
network_security_score  INTEGER    -- VPC, SGs, public accessibility
configuration_score     INTEGER    -- parameter groups, maintenance windows

total_databases         INTEGER
total_findings, critical_findings, high_findings, medium_findings, low_findings INTEGER
pass_count, fail_count  INTEGER
findings_by_service, findings_by_domain, coverage_by_service JSONB
severity_breakdown, service_breakdown, domain_breakdown JSONB
report_data             JSONB
started_at, completed_at TIMESTAMP
```

**`dbsec_findings`** — per-resource findings (standard 15 columns)
```
finding_id              VARCHAR PK
scan_run_id, tenant_id, account_id, credential_ref, credential_type
provider, region, resource_uid, resource_type
severity, status
domain                  VARCHAR    -- access_control | encryption | audit_logging | backup_recovery | network_security | configuration
service                 VARCHAR    -- rds | aurora | dynamodb | redshift | elasticache | documentdb | neptune
rule_id, title, description, remediation TEXT
finding_data            JSONB
first_seen_at, last_seen_at TIMESTAMP
```

**`dbsec_inventory`** — database catalog
```
id BIGSERIAL, scan_run_id, tenant_id, account_id, provider, region
resource_uid, resource_type, resource_id, resource_name TEXT
is_publicly_accessible  BOOLEAN
encryption_at_rest      BOOLEAN
encryption_in_transit   BOOLEAN
backup_enabled          BOOLEAN
multi_az                BOOLEAN
deletion_protection     BOOLEAN
engine_type             VARCHAR    -- mysql | postgresql | aurora | oracle | sqlserver
engine_version          VARCHAR
properties              JSONB
```

### Common Queries

```sql
-- DB posture by domain
SELECT domain, COUNT(*) FILTER (WHERE status='FAIL') failed,
       COUNT(*) FILTER (WHERE status='PASS') passed
FROM dbsec_findings
WHERE scan_run_id = $1 AND tenant_id = $2
GROUP BY domain ORDER BY failed DESC;

-- Publicly accessible databases
SELECT resource_uid, resource_type, service, region
FROM dbsec_inventory
WHERE scan_run_id = $1 AND tenant_id = $2 AND is_publicly_accessible = TRUE;
```

---

## 3. API Endpoints

**Service URL:** `http://engine-dbsec` (port 80 → targetPort 8007)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `scan_run_id`, `tenant_id`, `csp` | Trigger scan |
| GET | `/api/v1/dbsec/{scan_id}/status` | path | Poll status |
| GET | `/api/v1/dbsec/findings` | `tenant_id`, `?domain`, `?severity` | Paginated findings |
| GET | `/api/v1/dbsec/summary` | `tenant_id` | Posture summary |
| GET | `/api/v1/dbsec/inventory` | `tenant_id` | Database inventory |
| GET | `/api/v1/dbsec/ui-data` | `tenant_id` | Pre-aggregated UI payload |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 4. BFF Views I Feed

**`shared/api_gateway/bff/dbsec.py`** (if exists) — `GET /gateway/api/v1/views/dbsec`
- URL: `http://engine-dbsec`
- Calls: `engine-dbsec /api/v1/dbsec/ui-data`

---

## 5. UI Pages I Power

- **`/dbsec`** — database security posture, domain scores, publicly accessible DBs
- **`/dashboard`** — database security KPI card

---

## 6. K8s Service

```yaml
name: engine-dbsec
namespace: threat-engine-engines
image: yadavanup84/engine-dbsec:v-dbsec-enterprise
containerPort: 8007
service: ClusterIP port 80 → targetPort 8007
replicas: 1
liveness:  GET /api/v1/health/live  port 8007
readiness: GET /api/v1/health/ready port 8007
```

---

## 7. Engine-Specific Gotchas

**viewer role = 403** — Per RBAC constitution, viewer role cannot access dbsec endpoints.

**containerPort 8007 also used by vul_fix** — Both dbsec (8007) and vul_fix (8007) use the same internal port. Different K8s deployments.

**is_publicly_accessible is a critical flag** — Surface this prominently. A publicly accessible RDS instance is a critical finding regardless of other posture scores.

**Port-forward:**
```bash
kubectl port-forward svc/engine-dbsec 8007:80 -n threat-engine-engines
```
