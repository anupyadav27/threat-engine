---
name: encryption-engine
description: Full-context agent for the Encryption Security engine — KMS key management, certificate lifecycle, secrets rotation, per-resource encryption coverage. Aggregates from discovery, check, datasec, and inventory engines. Covers DB schema, API endpoints, BFF, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the Encryption Security Engine specialist. You know every detail of this engine's coverage model, DB, API, BFF, and pipeline role.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** Stage 5 (parallel) — runs after threat.
**Reads:** `check_findings` from `threat_engine_check` + `discovery_findings` from `threat_engine_discoveries` + `datasec_findings` from `threat_engine_datasec` + `inventory_findings` from `threat_engine_inventory`
**Writes:** `encryption_report`, `encryption_findings`, `key_inventory`, `cert_inventory`, `secrets_inventory` in `threat_engine_encryption`
**Feeds downstream:** CNAPP aggregation, BFF encryption views
**Credentials:** NONE — reads from DB
**Execution:** K8s Job

---

## 2. Database

**DB name:** `threat_engine_encryption`
**Host:** `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

### Tables

**`encryption_report`** — scan-level summary
```
scan_run_id             VARCHAR PK
tenant_id, account_id, provider, status
posture_score           INTEGER (0-100, composite)
coverage_score          INTEGER    -- % of resources encrypted
rotation_score          INTEGER    -- key rotation compliance
algorithm_score         INTEGER    -- weak algorithm detection
transit_score           INTEGER    -- TLS/HTTPS enforcement

total_resources, encrypted_resources, unencrypted_resources INTEGER
total_keys, total_certificates, total_secrets INTEGER
total_findings, critical_findings, high_findings, medium_findings, low_findings INTEGER
coverage_by_service     JSONB      -- {s3: 0.95, rds: 0.88, ec2: 0.70}
severity_breakdown, domain_breakdown JSONB
report_data             JSONB
started_at, completed_at TIMESTAMP
```

**`encryption_findings`** — per-resource findings (standard 15 columns)
```
finding_id              VARCHAR PK
scan_run_id, tenant_id, account_id, credential_ref, credential_type
provider, region, resource_uid, resource_type
severity, status
domain                  VARCHAR    -- encryption_at_rest | encryption_in_transit | key_management | certificate | secrets
rule_id, title, description, remediation TEXT
finding_data            JSONB
first_seen_at, last_seen_at TIMESTAMP
```

**`key_inventory`** — KMS key catalog
```
id BIGSERIAL, scan_run_id, tenant_id, account_id, provider, region
key_id, key_arn TEXT
key_state       VARCHAR    -- enabled | disabled | pending_deletion
key_type        VARCHAR    -- symmetric | asymmetric | hmac
rotation_enabled BOOLEAN
key_age_days    INTEGER
last_used_at    TIMESTAMP
key_policy      JSONB
managed_by      VARCHAR    -- aws | customer
```

**`cert_inventory`** — certificate catalog
```
id BIGSERIAL, scan_run_id, tenant_id, account_id, provider, region
cert_arn, domain_name TEXT
expiry_date     TIMESTAMP
days_to_expiry  INTEGER
is_expired      BOOLEAN
key_algorithm   VARCHAR    -- RSA_2048 | EC_prime256v1 | RSA_1024 (weak)
issuer          VARCHAR
cert_type       VARCHAR    -- acm | self_signed | imported
```

**`secrets_inventory`** — secrets manager catalog
```
id BIGSERIAL, scan_run_id, tenant_id, account_id, provider, region
secret_arn, secret_name TEXT
last_rotated_at TIMESTAMP
rotation_enabled BOOLEAN
days_since_rotation INTEGER
is_in_use       BOOLEAN
secret_type     VARCHAR    -- db_credentials | api_key | oauth_token | custom
```

### Common Queries

```sql
-- Encryption coverage by service
SELECT resource_type, 
       COUNT(*) FILTER (WHERE status='PASS') encrypted,
       COUNT(*) FILTER (WHERE status='FAIL') unencrypted
FROM encryption_findings
WHERE scan_run_id = $1 AND tenant_id = $2 AND domain = 'encryption_at_rest'
GROUP BY resource_type;

-- Expiring certificates (next 30 days)
SELECT cert_arn, domain_name, days_to_expiry
FROM cert_inventory
WHERE tenant_id = $1 AND scan_run_id = $2 AND days_to_expiry <= 30
ORDER BY days_to_expiry ASC;
```

---

## 3. API Endpoints

**Service URL:** `http://engine-encryption` (port 80 → targetPort 8006)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| POST | `/api/v1/scan` | `scan_run_id`, `tenant_id`, `csp` | Trigger scan |
| GET | `/api/v1/encryption/{scan_id}/status` | path | Poll status |
| GET | `/api/v1/encryption/findings` | `tenant_id`, `?domain`, `?severity` | Paginated findings |
| GET | `/api/v1/encryption/summary` | `tenant_id` | Posture summary |
| GET | `/api/v1/encryption/certificates` | `tenant_id` | Certificate inventory |
| GET | `/api/v1/encryption/keys` | `tenant_id` | Key inventory |
| GET | `/api/v1/encryption/ui-data` | `tenant_id` | Pre-aggregated UI payload |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 4. BFF Views I Feed

**`shared/api_gateway/bff/encryption.py`** — `GET /gateway/api/v1/views/encryption`
- URL: `http://engine-encryption`
- Calls: `engine-encryption /api/v1/encryption/ui-data`

---

## 5. UI Pages I Power

- **`/encryption`** — encryption posture overview, coverage by service, expiring certs, unrotated keys
- **`/dashboard`** — encryption posture KPI card

---

## 6. K8s Service

```yaml
name: engine-encryption
namespace: threat-engine-engines
image: yadavanup84/engine-encryption:v-encryption-mapfix2
containerPort: 8006
service: ClusterIP port 80 → targetPort 8006
replicas: 1
liveness:  GET /api/v1/health/live  port 8006
readiness: GET /api/v1/health/ready port 8006
```

---

## 7. Engine-Specific Gotchas

**viewer role = 403** — Per RBAC constitution, viewer role cannot access encryption endpoints.

**containerPort 8006 also used by secops_fix** — Both encryption (8006) and secops_fix (8006) use the same internal port. They are different K8s deployments.

**days_to_expiry is computed at scan time** — `cert_inventory.days_to_expiry` is calculated when the scan runs, not dynamically. Certificates expire silently between scans if no alert is triggered.

**Port-forward:**
```bash
kubectl port-forward svc/engine-encryption 8006:80 -n threat-engine-engines
```
