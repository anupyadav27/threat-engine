# Data Security Engine (`engine_datasec`)

Data security posture engine for CSPM — discovers data stores, classifies sensitive data (PII/PCI/PHI), and surfaces data-security-relevant misconfigurations from the Threat DB.

**Port:** `8004` | **Database:** `threat_engine_datasec` | **Image:** `yadavanup84/engine-datasec:v3-fixes`

---

## Overview

The Data Security Engine reads **threat findings** from the `threat_findings` table (written by the Threat Engine), enriches them with data-security module tags, filters to data-security-relevant resources (S3, RDS, DynamoDB, etc.), and generates a structured `datasec_report`.

Pipeline position:

```
discoveries → check → threat → IAM  →  DataSec
                              (8020)   (8004)
```

No new YAML rules are created — the engine reuses the full threat findings corpus and classifies findings by data-security module (encryption, access control, logging, backup, lifecycle).

---

## Architecture

```
Threat DB (threat_findings)
        ↓
  ThreatDBReader           ← resolves threat_scan_id, filters by data store resource types
        ↓
  FindingEnricher          ← tags each finding with is_data_security_relevant + data_security_modules[]
        ↓
  DataSecurityReporter     ← builds full report: findings + classification + lineage + residency + activity
        ↓
  datasec_db_writer        ← writes datasec_report + datasec_findings rows to threat_engine_datasec DB
```

**Data Store Service Types** are loaded from `datasec_data_store_services` DB table (multi-CSP aware — `aws`, `azure`, `gcp`, `oci`, `ibm`, `alicloud`). No hardcoded lists.

**IAM relevance** for filtering: resource_type must be in the DB-driven service list per CSP.

---

## Key Components

| File | Purpose |
|------|---------|
| `iam_engine/api_server.py` | FastAPI app — all endpoints |
| `input/threat_db_reader.py` | Reads `threat_findings`, resolves `threat_scan_id`, loads data stores |
| `input/rule_db_reader.py` | Reads rule metadata from `check_engine_check` DB for module mapping |
| `enricher/finding_enricher.py` | Tags findings: `is_data_security_relevant`, `data_security_modules[]` |
| `mapper/rule_to_module_mapper.py` | Maps rule_id to modules; loads service types from `datasec_data_store_services` |
| `reporter/data_security_reporter.py` | Assembles full report with sub-analyses |
| `analyzer/classification_analyzer.py` | S3 content sampling — PII/PCI/PHI regex detection |
| `analyzer/lineage_analyzer.py` | Data flow graph across services |
| `analyzer/residency_analyzer.py` | Geographic location compliance |
| `analyzer/activity_analyzer.py` | CloudTrail-based access anomaly detection |
| `storage/datasec_db_writer.py` | Writes to `datasec_report` + `datasec_findings` tables |
| `storage/report_storage.py` | Writes JSON report to `/output/` for S3 sync sidecar |

---

## Data Security Modules

| Module | Description | Example Rules |
|--------|-------------|---------------|
| `data_protection_encryption` | Encryption at rest / in transit | S3 bucket encryption, RDS storage encrypted |
| `data_access_control` | IAM policies, public access | S3 public access block, bucket ACL |
| `data_logging_monitoring` | Audit logging for data access | S3 server access logging, CloudTrail |
| `data_backup_recovery` | Backup policies and retention | RDS automated backups, S3 versioning |
| `data_lifecycle` | Retention and lifecycle policies | S3 lifecycle rules, Glacier transition |

---

## API Endpoints

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Basic health check |
| `GET` | `/api/v1/health/live` | Kubernetes liveness probe |
| `GET` | `/api/v1/health/ready` | Kubernetes readiness probe |

### Scan

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/data-security/scan` | Generate full data security report |

**Scan request body:**
```json
{
  "csp": "aws",
  "orchestration_id": "337a7425-...",
  "tenant_id": "5a8b072b-...",
  "include_classification": true,
  "include_lineage": true,
  "include_residency": true,
  "include_activity": true,
  "allowed_regions": ["ap-south-1"],
  "max_findings": 500
}
```

Supports two modes:
- **Pipeline mode** (recommended): provide `orchestration_id` — engine looks up `threat_scan_id` + `tenant_id` + `csp` from `scan_orchestration`
- **Ad-hoc mode**: provide `scan_id` (direct `threat_scan_id` value)

### Query Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/data-security/catalog` | List data stores with optional filters (`account_id`, `service`, `region`) |
| `GET` | `/api/v1/data-security/governance/{resource_id}` | Access governance findings for a resource |
| `GET` | `/api/v1/data-security/protection/{resource_id}` | Encryption/protection findings for a resource |
| `GET` | `/api/v1/data-security/classification` | PII/PCI/PHI classification results |
| `GET` | `/api/v1/data-security/lineage` | Data flow lineage graph |
| `GET` | `/api/v1/data-security/residency` | Geographic residency compliance |
| `GET` | `/api/v1/data-security/activity` | Data access activity and anomalies |
| `GET` | `/api/v1/data-security/compliance` | Compliance findings (GDPR/HIPAA/PCI) |
| `GET` | `/api/v1/data-security/findings` | All data security findings with filters |
| `GET` | `/api/v1/data-security/accounts/{account_id}` | Data security posture per account |
| `GET` | `/api/v1/data-security/services/{service}` | Data security posture per service |
| `GET` | `/api/v1/data-security/modules` | List all data security modules |
| `GET` | `/api/v1/data-security/modules/{module}/rules` | Rules for a specific module |
| `GET` | `/api/v1/data-security/rules/{rule_id}` | Data security metadata for a rule |

All query endpoints require query params: `csp`, `scan_id`, `tenant_id`.

---

## Database Tables (`threat_engine_datasec`)

| Table | Description |
|-------|-------------|
| `tenants` | Tenant registry (FK for other tables) |
| `datasec_report` | One row per scan — summary, counts, full report JSONB |
| `datasec_findings` | Individual FAIL findings with `resource_type`, `resource_arn`, `datasec_modules[]`, `data_classification[]` |
| `datasec_data_store_services` | Seed table — maps `(csp, service_name)` to is_active; drives data store filtering |

### `datasec_data_store_services` — adding new services

To add a new data store service without code changes:
```sql
INSERT INTO datasec_data_store_services (csp, service_name)
VALUES ('aws', 'memorydb');
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATASEC_DB_HOST` | `localhost` | DataSec DB host |
| `DATASEC_DB_PORT` | `5432` | DataSec DB port |
| `DATASEC_DB_NAME` | `threat_engine_datasec` | DataSec database name |
| `DATASEC_DB_USER` | `postgres` | DB user |
| `DATASEC_DB_PASSWORD` | — | DB password (from K8s secret) |
| `THREAT_DB_HOST` | `localhost` | Threat DB host (read-only) |
| `THREAT_DB_PORT` | `5432` | Threat DB port |
| `THREAT_DB_NAME` | `threat_engine_threat` | Threat DB name |
| `OUTPUT_DIR` | `/output` | Directory for JSON report (synced to S3) |
| `LOG_LEVEL` | `INFO` | Log verbosity |

---

## Running Locally

```bash
cd engine_datasec
pip install -r engine_datasec_aws/requirements.txt

export DATASEC_DB_HOST=localhost
export DATASEC_DB_PASSWORD=your_password
export THREAT_DB_HOST=localhost
export THREAT_DB_PASSWORD=your_password
export PYTHONPATH=$(pwd)/..

python -m uvicorn data_security_engine.api_server:app --host 0.0.0.0 --port 8004 --reload
```

---

## Docker

```bash
# Build (from repo root)
docker build -t yadavanup84/engine-datasec:latest -f engine_datasec/Dockerfile .

# Run
docker run -p 8004:8004 \
  -e DATASEC_DB_HOST=host.docker.internal \
  -e DATASEC_DB_PASSWORD=your_password \
  -e THREAT_DB_HOST=host.docker.internal \
  -e THREAT_DB_PASSWORD=your_password \
  yadavanup84/engine-datasec:latest
```

---

## Kubernetes Deployment

Manifest: `deployment/aws/eks/engines/engine-datasec.yaml`

```bash
kubectl apply -f deployment/aws/eks/engines/engine-datasec.yaml
kubectl rollout status deployment/engine-datasec -n threat-engine-engines
kubectl logs -f -l app=engine-datasec -n threat-engine-engines
```

The pod runs two containers:
- `engine-datasec` — FastAPI app on port 8004
- `s3-sync` — syncs `/output/` to S3 every 30s

---

## Triggering a Scan (Pipeline Mode)

```bash
# Via orchestration_id (preferred in pipeline)
curl -X POST http://engine-datasec/api/v1/data-security/scan \
  -H "Content-Type: application/json" \
  -d '{
    "csp": "aws",
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
    "include_classification": false,
    "max_findings": 500
  }'
```

The engine will:
1. Look up `threat_scan_id` + `tenant_id` from `scan_orchestration`
2. Load all threat findings from `threat_findings` table
3. Enrich and filter to data-security-relevant findings
4. Write report to `datasec_report` + `datasec_findings` tables
5. Write `datasec_scan_id` back to `scan_orchestration`

---

## Verified Scan Results (2026-02-22)

- **21** unique data stores identified (S3 buckets, Lambda functions)
- **500** data-security-relevant findings (from 3,900 total threat findings)
- **100%** `resource_type` fill rate in `datasec_findings`
- Module breakdown: `data_access_control` (216), `data_protection_encryption` (190), `data_backup_recovery` (130), `data_lifecycle` (35), `data_logging_monitoring` (21)
