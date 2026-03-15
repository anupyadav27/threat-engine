# Check Engine (`engine_check`)

Compliance check engine for CSPM — evaluates discovered cloud resources against YAML-defined security rules and produces PASS/FAIL findings stored in PostgreSQL.

**Port:** `8002` | **Database:** `threat_engine_check` | **Image:** `yadavanup84/engine-check:latest`

---

## Overview

The Check Engine is **Phase 2** of the scan pipeline. It takes discovery results from the `engine_discoveries` DB and evaluates each resource against security rules loaded from the `rule_discoveries` table. Results are stored in `check_findings` and referenced by downstream engines (threat, compliance, IAM, datasec).

Pipeline position:

```
discoveries → check → threat / compliance / inventory
  (8001)       (8002)    (8020 / 8010 / 8022)
```

---

## Architecture

```
discoveries DB (discovery_findings)
        ↓
  DiscoveryReader          ← loads resources for a discovery_scan_id
        ↓
  CheckEngine              ← loads rules from rule_discoveries table, evaluates per resource
        ↓
  DatabaseManager          ← writes check_findings rows to threat_engine_check DB
        ↓
  scan_orchestration       ← updates check_scan_id for downstream engines
```

Rules are loaded from the `rule_discoveries` table in `threat_engine_check` DB. The `is_active` column controls which services are scanned — set `is_active = FALSE` to suppress a service without code changes.

---

## Key Components

| File | Purpose |
|------|---------|
| `engine_check_aws/api_server.py` | FastAPI app — all endpoints |
| `engine/check_engine.py` | Core check execution — loads rules, evaluates findings |
| `engine/database_manager.py` | DB read/write for check findings |
| `engine/discovery_reader.py` | Reads discovery findings (DB or NDJSON fallback) |
| `engine/service_scanner.py` | Per-service scanning with enabled-service list |
| `utils/metadata_loader.py` | Loads rule metadata from YAML files |
| `utils/reporting_manager.py` | Builds check result summaries |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scan` | Run compliance check scan |
| `GET` | `/api/v1/check/{check_scan_id}/status` | Get check scan status |
| `GET` | `/api/v1/checks` | List all check scans |
| `GET` | `/api/v1/health` | Health check with DB connection status |
| `GET` | `/api/v1/health/ready` | Kubernetes readiness probe (checks DB connectivity) |
| `GET` | `/api/v1/health/live` | Kubernetes liveness probe |
| `GET` | `/api/v1/metrics` | Engine metrics (total/success/failed scans) |

### Run Check Scan

```bash
# Pipeline mode (recommended) — all metadata resolved from orchestration table
curl -X POST http://engine-check/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0"
  }'

# Ad-hoc mode — direct discovery_scan_id
curl -X POST http://engine-check/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "discovery_scan_id": "disc-scan-uuid",
    "tenant_id": "your-tenant",
    "provider": "aws",
    "hierarchy_id": "123456789012",
    "include_services": ["s3", "iam", "ec2"]
  }'
```

**Request body fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `orchestration_id` | One of these | Orchestration ID (pipeline mode — resolves all metadata automatically) |
| `discovery_scan_id` | One of these | Direct discovery scan ID (ad-hoc mode) |
| `tenant_id` | Ad-hoc only | Tenant ID |
| `provider` | No | Cloud provider (`aws`, `azure`, etc.) — defaults to `aws` |
| `hierarchy_id` | No | Account/hierarchy ID |
| `include_services` | No | List of services to check; if omitted, all active services |
| `check_source` | No | Rule source — defaults to `default` |

**Response:**
```json
{
  "check_scan_id": "bfed9ebc-68e7-4f9d-83e1-24ce75e21d01",
  "status": "running",
  "message": "Check scan started"
}
```

The scan runs asynchronously in the background. Poll `/api/v1/check/{check_scan_id}/status` to track progress.

### Get Scan Status

```bash
curl http://engine-check/api/v1/check/bfed9ebc-68e7-4f9d-83e1-24ce75e21d01/status
```

```json
{
  "check_scan_id": "bfed9ebc-...",
  "status": "completed",
  "discovery_scan_id": "disc-uuid",
  "started_at": "2026-02-22T10:00:00Z",
  "completed_at": "2026-02-22T10:15:00Z",
  "progress": {
    "services_completed": 414,
    "services_total": 414,
    "checks_completed": 42000,
    "percentage": 100
  }
}
```

---

## Database Schema (`threat_engine_check`)

| Table | Description |
|-------|-------------|
| `rule_discoveries` | Rules loaded from YAML — `is_active` column controls which services scan |
| `check_findings` | PASS/FAIL findings with `rule_id`, `resource_type`, `resource_arn`, `status`, `severity` |
| `check_report` | One row per check_scan — summary counts by status/severity |
| `tenants` | Tenant registry |

### `rule_discoveries` — controlling scan scope

```sql
-- Suppress a noisy service without code changes
UPDATE rule_discoveries SET is_active = FALSE
WHERE boto3_client_name = 'savingsplans';

-- Re-enable a service
UPDATE rule_discoveries SET is_active = TRUE
WHERE boto3_client_name = 'savingsplans';

-- Check which services are active
SELECT DISTINCT boto3_client_name, COUNT(*),
       SUM(CASE WHEN is_active THEN 1 ELSE 0 END) AS active_rules
FROM rule_discoveries
GROUP BY boto3_client_name
ORDER BY boto3_client_name;
```

Key columns in `rule_discoveries`:

| Column | Description |
|--------|-------------|
| `rule_id` | Unique rule identifier (`aws.s3.bucket.public_access_blocked`) |
| `boto3_client_name` | AWS SDK client name (`s3`, `ec2`, `iam`) |
| `arn_identifier` | ARN field path for resource identification |
| `arn_identifier_independent_methods[]` | Methods that list resources independently |
| `arn_identifier_dependent_methods[]` | Methods that require parent resource context |
| `is_active` | Set `FALSE` to suppress this rule from scans |
| `filter_rules` | JSONB — `response_filters` for post-call noise suppression |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CHECK_DB_HOST` | `localhost` | PostgreSQL host |
| `CHECK_DB_PORT` | `5432` | PostgreSQL port |
| `CHECK_DB_NAME` | `threat_engine_check` | Database name |
| `CHECK_DB_USER` | `postgres` | Database user |
| `CHECK_DB_PASSWORD` | — | Database password (from K8s secret) |
| `DISCOVERIES_DB_HOST` | `localhost` | Discoveries DB host (read-only) |
| `DISCOVERIES_DB_PASSWORD` | — | Discoveries DB password |
| `MAX_CHECK_WORKERS` | `50` | Parallel check threads |
| `FOR_EACH_MAX_WORKERS` | `50` | Workers for for-each operations |
| `CHECK_MODE` | — | Set to `ndjson` to force file-based mode |
| `LOG_LEVEL` | `INFO` | Log verbosity |

---

## Running Locally

```bash
cd engine_check/engine_check_aws

pip install -r requirements.txt

export CHECK_DB_HOST=localhost
export CHECK_DB_PASSWORD=your_password
export DISCOVERIES_DB_HOST=localhost
export DISCOVERIES_DB_PASSWORD=your_password
export PYTHONPATH=$(pwd)/../..

uvicorn api_server:app --host 0.0.0.0 --port 8002 --reload
```

---

## Docker

```bash
# Build (from repo root)
docker build -t yadavanup84/engine-check:latest -f engine_check/engine_check_aws/Dockerfile engine_check/

# Run
docker run -p 8002:8002 \
  -e CHECK_DB_HOST=host.docker.internal \
  -e CHECK_DB_PASSWORD=your_password \
  yadavanup84/engine-check:latest
```

---

## Kubernetes Deployment

Manifest: `deployment/aws/eks/engines/engine-check.yaml`

```bash
kubectl apply -f deployment/aws/eks/engines/engine-check.yaml
kubectl rollout status deployment/engine-check -n threat-engine-engines
kubectl logs -f -l app=engine-check -n threat-engine-engines
```

---

## Rule Structure

Rules are defined per-service in YAML files under `engine_check_aws/services/` and loaded into the `rule_discoveries` table:

```
services/{service}/
├── checks/default/{service}.checks.yaml   # Check definitions
├── discoveries/{service}.discoveries.yaml # Discovery call definitions
├── rules/{service}.yaml                   # Rule logic
└── metadata/                              # Per-check metadata YAML files
```

Each rule evaluates a specific configuration property and returns `PASS`, `FAIL`, or `ERROR`.

---

## Noise Control (DB-Driven)

The check engine supports three layers of DB-driven noise suppression — no code changes required:

1. **`rule_discoveries.is_active = FALSE`** — suppresses entire service from scan
2. **`rule_discoveries.filter_rules.response_filters`** — FilterEngine excludes items post-call
3. **`resource_inventory_identifier.should_inventory = FALSE`** — skips asset creation in inventory engine

These controls apply across all CSPs (AWS, Azure, GCP, OCI) via the `provider` column in each table.
