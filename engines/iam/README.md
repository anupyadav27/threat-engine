# IAM Security Engine (`engine_iam`)

Identity & Access Management posture engine for CSPM — filters threat findings by IAM-relevant rules, enriches with IAM security modules, and surfaces identity/access misconfigurations across AWS, Azure, GCP, and other CSPs.

**Port:** `8003` | **Database:** `threat_engine_iam` | **Image:** `yadavanup84/engine-iam:v2-fixes`

---

## Overview

The IAM Security Engine reads **threat findings** from the `threat_findings` table (written by the Threat Engine), identifies IAM-relevant findings using rule_id pattern matching, and generates a structured `iam_report`.

Pipeline position:

```
discoveries → check → threat → IAM
                       (8020)   (8003)
```

No new YAML rules are created — the engine reuses the full threat findings corpus and classifies findings by IAM module (least_privilege, policy_analysis, mfa, role_management, password_policy, access_control).

---

## Architecture

```
Threat DB (threat_findings)
        ↓
  ThreatDBReader           ← resolves scan_run_id, loads findings by tenant/scan
        ↓
  FindingEnricher          ← tags each finding with is_iam_relevant + iam_security_modules[]
        ↓
  IAMReporter              ← builds full report: findings + module summaries + posture score
        ↓
  iam_db_writer            ← writes iam_report + iam_findings rows to threat_engine_iam DB
```

**IAM Rule Identification** uses regex pattern matching on `rule_id` — no DB lookup needed.

---

## Key Components

| File | Purpose |
|------|---------|
| `iam_engine/api_server.py` | FastAPI app — all endpoints |
| `input/threat_db_reader.py` | Reads `threat_findings`, resolves `scan_run_id`, supports resource-level queries |
| `enricher/finding_enricher.py` | Tags findings: `is_iam_relevant`, `iam_security_modules[]` |
| `mapper/rule_to_module_mapper.py` | 15 IAM regex patterns + 6-module keyword mapping |
| `reporter/iam_reporter.py` | Assembles full IAM report with per-module summaries |
| `storage/iam_db_writer.py` | Writes to `iam_report` + `iam_findings` tables |
| `storage/report_storage.py` | Writes JSON report to `/output/` for S3 sync sidecar |

---

## IAM Rule Identification

IAM relevance is determined purely by matching `rule_id` against 15 compiled regex patterns:

| Pattern | Catches |
|---------|---------|
| `\.iam\.` | AWS IAM rules (`aws.iam.role.*`, `aws.iam.policy.*`) |
| `\.iam_` | IAM fine-grained access rules |
| `\.mfa[._]` | MFA enforcement rules |
| `\.password[._]` | Password policy rules |
| `\.root[._]` | Root account usage rules |
| `\.sso[._]` | SSO configuration rules |
| `\.entraid\.` | Azure Entra ID (formerly AAD) |
| `\.aad\.` | Azure Active Directory rules |
| `\.managedidentity\.` | Azure Managed Identity |
| `\.serviceprincipal\.` | Azure Service Principal |
| `\.rbac\.` | Azure RBAC rules |
| `\.pim\.` | Azure Privileged Identity Management |
| `\.serviceaccount\.` | GCP Service Account rules |
| `\.workloadidentity\.` | GCP Workload Identity |
| `\.orgpolicy\.` | GCP Organization Policy |

---

## IAM Security Modules

| Module | Description | Example Rule Patterns |
|--------|-------------|----------------------|
| `least_privilege` | Over-permission, RBAC, privilege escalation | `wildcard_admin`, `full_admin`, `fine_grained_access` |
| `policy_analysis` | IAM policy evaluation and versioning | `managed_policy`, `inline_policies`, `conditions_used` |
| `mfa` | Multi-factor authentication enforcement | `mfa`, `multi_factor`, `hardware_mfa` |
| `role_management` | Role trust and session management | `role`, `trust_principals`, `max_session_duration` |
| `password_policy` | Account password strength/rotation | `password`, `minimum_length`, `expires_passwords` |
| `access_control` | Console access, root usage, key rotation | `root_usage`, `console_access`, `key_rotation` |

---

## API Endpoints

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Basic health check (returns `{"status":"healthy"}`) |
| `GET` | `/api/v1/health/live` | Kubernetes liveness probe |
| `GET` | `/api/v1/health/ready` | Kubernetes readiness probe |

### Scan

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/iam-security/scan` | Generate full IAM security report |

**Scan request body:**
```json
{
  "csp": "aws",
  "scan_run_id": "337a7425-...",
  "tenant_id": "5a8b072b-...",
  "max_findings": 1000
}
```

Supports two modes:
- **Pipeline mode** (recommended): provide `scan_run_id` — engine looks up `scan_run_id` + `tenant_id` + `csp` from `scan_orchestration`
- **Ad-hoc mode**: provide `scan_id` (direct `scan_run_id` value, must also provide `tenant_id`)

### Query Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/iam-security/rule-ids` | IAM rule identification patterns (15 regex patterns) |
| `GET` | `/api/v1/iam-security/modules` | List all IAM security modules (6 modules) |
| `GET` | `/api/v1/iam-security/rules/{rule_id}` | Check if a rule is IAM-relevant + which modules it maps to |
| `GET` | `/api/v1/iam-security/findings` | All IAM findings with filters |
| `GET` | `/api/v1/iam-security/accounts/{account_id}` | IAM posture per account |
| `GET` | `/api/v1/iam-security/services/{service}` | IAM posture per service (e.g. `iam`, `sts`, `cognito`) |
| `GET` | `/api/v1/iam-security/resources/{resource_uid}` | IAM findings for a specific resource |

All query endpoints require query params: `csp`, `scan_id`, `tenant_id`.

**Findings endpoint filters:** `account_id`, `account_id`, `service`, `module`, `status` (PASS/FAIL), `resource_id`

---

## Database Tables (`threat_engine_iam`)

| Table | Description |
|-------|-------------|
| `tenants` | Tenant registry (FK for other tables) |
| `iam_report` | One row per scan — summary, counts, full report JSONB |
| `iam_findings` | Individual FAIL findings with `resource_type`, `resource_arn`, `iam_modules[]` |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IAM_DB_HOST` | `localhost` | IAM DB host |
| `IAM_DB_PORT` | `5432` | IAM DB port |
| `IAM_DB_NAME` | `threat_engine_iam` | IAM database name |
| `IAM_DB_USER` | `postgres` | DB user |
| `IAM_DB_PASSWORD` | — | DB password (from K8s secret) |
| `THREAT_DB_HOST` | `localhost` | Threat DB host (read-only) |
| `THREAT_DB_PORT` | `5432` | Threat DB port |
| `THREAT_DB_NAME` | `threat_engine_threat` | Threat DB name |
| `THREAT_DB_PASSWORD` | — | Threat DB password |
| `IAM_ENGINE_PORT` | `8003` | Server port |
| `OUTPUT_DIR` | `/output` | Directory for JSON report (synced to S3) |
| `LOG_LEVEL` | `INFO` | Log verbosity |

---

## Running Locally

```bash
cd engine_iam
pip install -r iam_engine/requirements.txt

export IAM_DB_HOST=localhost
export IAM_DB_PASSWORD=your_password
export THREAT_DB_HOST=localhost
export THREAT_DB_PASSWORD=your_password
export PYTHONPATH=$(pwd)/..

python -m uvicorn iam_engine.api_server:app --host 0.0.0.0 --port 8003 --reload
```

---

## Docker

```bash
# Build (from repo root)
docker build -t yadavanup84/engine-iam:latest -f engine_iam/Dockerfile .

# Run
docker run -p 8003:8003 \
  -e IAM_DB_HOST=host.docker.internal \
  -e IAM_DB_PASSWORD=your_password \
  -e THREAT_DB_HOST=host.docker.internal \
  -e THREAT_DB_PASSWORD=your_password \
  yadavanup84/engine-iam:latest
```

---

## Kubernetes Deployment

Manifest: `deployment/aws/eks/engines/engine-iam.yaml`

```bash
kubectl apply -f deployment/aws/eks/engines/engine-iam.yaml
kubectl rollout status deployment/engine-iam -n threat-engine-engines
kubectl logs -f -l app=engine-iam -n threat-engine-engines
```

The pod runs two containers:
- `engine-iam` — FastAPI app on port 8003
- `s3-sync` — syncs `/output/` to S3 every 30s

---

## Triggering a Scan (Pipeline Mode)

```bash
# Via scan_run_id (preferred in pipeline)
curl -X POST http://engine-iam/api/v1/iam-security/scan \
  -H "Content-Type: application/json" \
  -d '{
    "csp": "aws",
    "scan_run_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3"
  }'
```

The engine will:
1. Look up `scan_run_id` + `tenant_id` from `scan_orchestration`
2. Load all threat findings from `threat_findings` table
3. Filter to IAM-relevant findings using regex pattern matching
4. Enrich each finding with `is_iam_relevant` + `iam_security_modules[]`
5. Write report to `iam_report` + `iam_findings` tables
6. Write `scan_run_id` back to `scan_orchestration`

---

## Verified Scan Results (2026-02-22)

- **825** IAM-relevant findings (from 3,900 total threat findings)
- **100%** `resource_type` fill rate in `iam_findings`
- Supports AWS, Azure, GCP, OCI, IBM, AliCloud (pattern matching is CSP-agnostic)
