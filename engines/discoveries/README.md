# Discoveries Engine (`engine_discoveries`)

Multi-CSP resource discovery engine for CSPM — discovers all cloud resources across AWS, Azure, GCP, and OCI using provider-native APIs, stores findings in PostgreSQL, and feeds downstream engines (check, inventory, threat).

**Port:** `8001` | **Database:** `threat_engine_discoveries` | **Image:** `yadavanup84/engine-discoveries:v10-multicloud`

---

## Overview

The Discovery Engine is **Phase 1** of the scan pipeline — the entry point for all cloud security assessments. It connects to cloud accounts via Secrets Manager credentials, discovers resources across all active services and regions in parallel, and writes findings to the discoveries DB.

Pipeline position:

```
onboarding → discoveries → check → inventory → threat / compliance / IAM / datasec
  (8008)        (8001)      (8002)    (8022)         (8020 / 8010 / 8003 / 8004)
```

---

## Architecture

```
scan_orchestration (onboarding DB)
        ↓
  api_server.py (POST /api/v1/discovery)
        ↓ scan_run_id lookup
  SecretsManagerStorage    ← retrieves CSP credentials from AWS Secrets Manager
        ↓
  CSP Scanner (per provider)  ← AWSDiscoveryScanner / AzureDiscoveryScanner / GCPDiscoveryScanner / OCIDiscoveryScanner
        ↓
  DiscoveryEngine          ← parallel scan across services × regions
        ↓
  DatabaseManager          ← writes discovery_report + discovery_findings to discoveries DB
        ↓
  scan_orchestration       ← updates scan_run_id for downstream engines
```

**Service configuration** is loaded from the `rule_discoveries` table in `threat_engine_check` DB. Set `is_active = FALSE` to suppress a service without code changes.

---

## Multi-CSP Architecture

```
engine_discoveries/
├── common/
│   └── api_server.py              # Entry point — CSP-agnostic FastAPI app
├── providers/
│   ├── aws/
│   │   ├── auth/aws_auth.py       # AWS authentication (access key, IAM role, IRSA)
│   │   ├── scanner/
│   │   │   └── service_scanner.py # AWSDiscoveryScanner
│   │   └── config/                # AWS-specific scan config
│   ├── azure/
│   │   ├── auth/                  # Azure authentication (service principal, managed identity)
│   │   └── scanner/
│   │       └── service_scanner.py # AzureDiscoveryScanner
│   ├── gcp/
│   │   ├── auth/                  # GCP authentication (service account key)
│   │   └── scanner/
│   │       └── service_scanner.py # GCPDiscoveryScanner
│   └── oci/
│       ├── auth/                  # OCI authentication (API key)
│       └── scanner/
│           └── service_scanner.py # OCIDiscoveryScanner
└── engine_discoveries_aws/
    ├── Dockerfile                 # Container build
    ├── requirements.txt           # Python dependencies
    └── database/                  # Legacy DB utilities
```

**Supported providers:** `aws`, `azure`, `gcp`, `oci`

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/discovery` | Run discovery scan (async — returns scan_id immediately) |
| `GET` | `/api/v1/discovery/{scan_id}` | Get scan status and result |
| `GET` | `/health` | Health check with DB connection status |
| `GET` | `/api/v1/health/live` | Kubernetes liveness probe |
| `GET` | `/api/v1/health/ready` | Kubernetes readiness probe |
| `GET` | `/metrics` | Engine metrics (total/success/failed scans) |

### Run Discovery Scan

```bash
# Pipeline mode (recommended) — all metadata pulled from orchestration table
curl -X POST http://engine-discoveries/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{
    "scan_run_id": "337a7425-5a53-4664-8569-04c1f0d6abf0"
  }'

# Ad-hoc mode — provide credentials and account info directly
curl -X POST http://engine-discoveries/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "tenant_id": "tenant-uuid",
    "account_id": "588989875114",
    "include_services": ["s3", "ec2", "iam"],
    "include_regions": ["ap-south-1"],
    "credentials": {
      "credential_type": "access_key",
      "aws_access_key_id": "AKIA...",
      "aws_secret_access_key": "..."
    }
  }'
```

**Request fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `scan_run_id` | One of these | Pipeline mode — resolves tenant, account, credentials, CSP automatically |
| `provider` | One of these | Ad-hoc mode — CSP (`aws`, `azure`, `gcp`, `oci`) |
| `account_id` | Ad-hoc | Account/subscription/project ID |
| `tenant_id` | Ad-hoc | Tenant identifier |
| `include_services` | No | Services to scan; if omitted, all active services |
| `include_regions` | No | Regions to scan; if omitted, all regions |
| `exclude_regions` | No | Regions to skip |
| `credentials` | Ad-hoc | CSP credentials (access key, role ARN, service principal, etc.) |

**Response:**
```json
{
  "scan_run_id": "a1b2c3d4-...",
  "status": "running",
  "message": "Discovery scan started for provider: aws",
  "scan_run_id": "337a7425-...",
  "provider": "aws"
}
```

The scan runs asynchronously. Poll `GET /api/v1/discovery/{scan_id}` to check completion.

### Pipeline Mode Flow

When `scan_run_id` is provided:
1. Reads `cloud_accounts` from onboarding DB to get `account_id`, `provider`, `credential_ref`
2. Retrieves CSP credentials from AWS Secrets Manager using `credential_ref`
3. Selects CSP-specific scanner based on provider
4. Runs discovery across all active services and regions in parallel
5. Writes `discovery_report` + `discovery_findings` to discoveries DB
6. Updates `scan_orchestration.scan_run_id` for downstream engines

---

## Database Tables (`threat_engine_discoveries`)

| Table | Description |
|-------|-------------|
| `discovery_report` | One row per scan — status, provider, tenant, hierarchy |
| `discovery_findings` | One row per discovered resource — raw_response + emitted_fields |
| `discovery_history` | Historical snapshots for drift detection — config_hash, diff_summary |
| `tenants` | Tenant registry |
| `customers` | Customer registry |

### `discovery_findings` key columns

| Column | Description |
|--------|-------------|
| `scan_run_id` | Links to discovery_report |
| `resource_uid` | Unique resource identifier (ARN-derived) |
| `resource_arn` | Full resource ARN |
| `resource_type` | Service resource type (e.g. `ec2.instance`, `s3.bucket`) |
| `service` | AWS/CSP service name (e.g. `ec2`, `s3`) |
| `region` | Resource region |
| `emitted_fields` | JSONB — explicitly extracted fields per rule YAML `emit:` block |
| `raw_response` | JSONB — full API response from CSP SDK |
| `config_hash` | SHA-256 of raw_response — used for drift detection |

---

## Rule Configuration (DB-Driven)

Services to scan and their API call sequences are loaded from the `rule_discoveries` table in `threat_engine_check` DB:

```sql
-- Suppress a noisy service without code changes
UPDATE rule_discoveries SET is_active = FALSE
WHERE boto3_client_name = 'savingsplans';

-- Check active service counts
SELECT boto3_client_name, COUNT(*) AS rules,
       SUM(CASE WHEN is_active THEN 1 ELSE 0 END) AS active
FROM rule_discoveries
GROUP BY boto3_client_name
ORDER BY active DESC;
```

Key `rule_discoveries` columns used by discoveries engine:

| Column | Description |
|--------|-------------|
| `boto3_client_name` | AWS SDK client (`ec2`, `s3`, `iam`) |
| `arn_identifier` | Field path to extract the ARN |
| `arn_identifier_independent_methods[]` | API calls that list resources (no parent needed) |
| `arn_identifier_dependent_methods[]` | API calls that need a parent resource |
| `is_active` | `FALSE` = skip this service entirely |
| `filter_rules.response_filters` | JSONB — post-call item exclusion rules |

---

## Parallelism Configuration

The discovery engine uses three levels of parallelism for maximum throughput:

```
Level 1: Services (asyncio semaphore, MAX_SERVICE_WORKERS=10)
  └── Level 2: Regions per service (asyncio semaphore, MAX_REGION_WORKERS=5)
        └── Level 3: Sub-discoveries (thread pool, MAX_DISCOVERY_WORKERS=20)
              └── for_each expansions (nested threads, FOR_EACH_MAX_WORKERS=5)

Peak concurrent API calls: 10 × 5 × 20 = 1,000
Peak boto3 threads: 10 × 20 = 200
```

**Boto3 timeout tuning** prevents unsupported-region calls from blocking the pool:

| Variable | Value | Purpose |
|----------|-------|---------|
| `BOTO_READ_TIMEOUT` | `10s` | Fast-fail on unavailable endpoints (was 120s) |
| `BOTO_CONNECT_TIMEOUT` | `5s` | Connection timeout |
| `BOTO_MAX_ATTEMPTS` | `2` | 1 attempt + 1 retry only |
| `OPERATION_TIMEOUT` | `60s` | Hard cap per API call |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCOVERY_DB_HOST` | `localhost` | Discoveries DB host |
| `DISCOVERY_DB_PORT` | `5432` | Discoveries DB port |
| `DISCOVERY_DB_NAME` | `threat_engine_discoveries` | Discoveries database name |
| `DISCOVERY_DB_USER` | `postgres` | DB user |
| `DISCOVERY_DB_PASSWORD` | — | DB password (from K8s secret) |
| `ONBOARDING_DB_HOST` | `localhost` | Onboarding DB host (for orchestration lookup) |
| `ONBOARDING_DB_NAME` | `threat_engine_onboarding` | Onboarding database name |
| `ONBOARDING_DB_PASSWORD` | — | Onboarding DB password |
| `CHECK_DB_HOST` | `localhost` | Check DB host (for rule_discoveries config) |
| `CHECK_DB_NAME` | `threat_engine_check` | Check database name |
| `CHECK_DB_PASSWORD` | — | Check DB password |
| `MAX_SERVICE_WORKERS` | `10` | Concurrent services (asyncio) |
| `MAX_REGION_WORKERS` | `5` | Concurrent regions per service (asyncio) |
| `MAX_DISCOVERY_WORKERS` | `20` | Sub-discovery thread pool size |
| `FOR_EACH_MAX_WORKERS` | `5` | for_each expansion threads |
| `SCAN_EXECUTOR_THREADS` | `100` | Total thread pool for scans |
| `BOTO_READ_TIMEOUT` | `10` | boto3 read timeout (seconds) |
| `BOTO_CONNECT_TIMEOUT` | `5` | boto3 connect timeout (seconds) |
| `BOTO_MAX_ATTEMPTS` | `2` | boto3 retry attempts |
| `DB_POOL_MIN` | `5` | Min DB connections |
| `DB_POOL_MAX` | `60` | Max DB connections |
| `ORCHESTRATION_ENABLED` | `true` | Enable orchestration mode |
| `OUTPUT_DIR` | `/output` | Directory for output files (synced to S3) |
| `LOG_LEVEL` | `INFO` | Log verbosity |

---

## Running Locally

```bash
cd engine_discoveries

pip install -r engine_discoveries_aws/requirements.txt

export DISCOVERY_DB_HOST=localhost
export DISCOVERY_DB_PASSWORD=your_password
export CHECK_DB_HOST=localhost
export CHECK_DB_PASSWORD=your_password
export ONBOARDING_DB_HOST=localhost
export ONBOARDING_DB_PASSWORD=your_password
export PYTHONPATH=$(pwd)/..

python -m uvicorn common.api_server:app --host 0.0.0.0 --port 8001 --reload
```

---

## Docker

```bash
# Build (from repo root)
docker build -t yadavanup84/engine-discoveries:latest \
  -f engine_discoveries/engine_discoveries_aws/Dockerfile .

# Run
docker run -p 8001:8001 \
  -e DISCOVERY_DB_HOST=host.docker.internal \
  -e DISCOVERY_DB_PASSWORD=your_password \
  -e CHECK_DB_HOST=host.docker.internal \
  -e CHECK_DB_PASSWORD=your_password \
  yadavanup84/engine-discoveries:latest
```

---

## Kubernetes Deployment

Manifest: `deployment/aws/eks/engines/engine-discoveries.yaml`

```bash
kubectl apply -f deployment/aws/eks/engines/engine-discoveries.yaml
kubectl rollout status deployment/engine-discoveries -n threat-engine-engines
kubectl logs -f -l app=engine-discoveries -n threat-engine-engines
```

**Spot node scanning:** The manifest has spot affinity rules commented out. Uncomment the `affinity`, `tolerations`, and `topologySpreadConstraints` blocks to run discovery scans on spot instances (`vulnerability-spot-scanners` node group) for cost savings.

---

## Triggering a Scan

```bash
# Pipeline mode (scan_run_id resolves all context)
curl -X POST http://engine-discoveries/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{"scan_run_id": "337a7425-5a53-4664-8569-04c1f0d6abf0"}'

# Poll for completion
curl http://engine-discoveries/api/v1/discovery/a1b2c3d4-.../
```

---

## Typical Scan Performance

| Metric | Value |
|--------|-------|
| Services scanned | 414 active AWS services |
| Scan speed | ~2 services/min = ~3–4h full scan |
| Concurrent API calls (peak) | ~1,000 |
| boto3 threads | up to 200 |
| DB pool | 5–60 connections |
| Discovery findings per account | 5,000–50,000+ rows |
