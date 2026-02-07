# Engine Discoveries (AWS Resource Discovery Engine)

> Discovers and inventories AWS resources across 40+ services and multiple regions using the AWS SDK.

---

## Overview

The Discovery Engine is **Phase 1** of the scan pipeline — the entry point for all cloud security assessments. It connects to AWS accounts via IAM cross-account roles, access keys, or IRSA, then systematically discovers all resources across configured services and regions.

**Port:** `8001`
**Database:** `threat_engine_check` (shared with check engine)
**Docker Image:** `yadavanup84/engine-discoveries:latest`

---

## Architecture

```
AWS Account (via STS AssumeRole)
        |
        v
  +----------------------------+
  |   Discovery Engine          |
  |                              |
  |  1. Authenticate to AWS      |
  |  2. Scan services in parallel|
  |  3. Extract resource fields  |
  |  4. Store discoveries        |
  +----------------------------+
        |
        v
  PostgreSQL (discoveries table)
  + NDJSON files (engine_output/)
```

---

## Directory Structure

```
engine_discoveries/
└── engine_discoveries_aws/
    ├── api_server.py              # FastAPI application (port 8001)
    ├── Dockerfile                 # Container definition
    ├── requirements.txt           # Python dependencies
    ├── auth/
    │   └── aws_auth.py            # AWS authentication (IAM/IRSA/keys)
    ├── config/
    │   ├── service_list.json      # 40+ supported AWS services
    │   ├── scan_config.json       # Scan behavior configuration
    │   ├── parameter_name_mapping.json
    │   ├── actions.yaml           # API action definitions
    │   ├── actions_selection.yaml # Action selection rules
    │   └── check_exceptions.yaml  # Exception handling
    ├── database/
    │   ├── schema.sql             # PostgreSQL schema
    │   ├── setup_database.sh      # Database initialization
    │   ├── connection/
    │   │   └── database_config.py # Connection pool config
    │   └── migrations/
    │       ├── 002_add_resource_uid.sql
    │       └── run_migration_002.py
    ├── engine/
    │   ├── discovery_engine.py    # Core discovery execution logic
    │   ├── database_manager.py    # DB read/write operations
    │   ├── service_scanner.py     # Per-service scanning logic
    │   └── discovery_helper.py    # Discovery data helpers
    ├── utils/
    │   ├── metadata_loader.py     # Service metadata loading
    │   ├── exception_manager.py   # Exception handling
    │   ├── service_feature_manager.py
    │   ├── reporting_manager.py   # Result reporting
    │   ├── phase_logger.py        # Phase-specific logging
    │   ├── progressive_output.py  # Incremental file writing
    │   ├── action_runner.py       # AWS API action executor
    │   ├── progress_monitor.py    # Scan progress tracking
    │   ├── discovery_resource_mapper.py
    │   └── organizations_scanner.py # AWS Organizations scanning
    └── services/                  # Per-service discovery definitions
        ├── codebuild/
        │   ├── discoveries/codebuild.discoveries.yaml
        │   ├── checks/default/codebuild.checks.yaml
        │   ├── rules/codebuild.yaml
        │   └── metadata/
        ├── edr/
        ├── kinesis/
        └── [40+ AWS services...]
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/discovery` | Create a discovery scan |
| `GET` | `/api/v1/discovery/{discovery_scan_id}/status` | Get scan status |
| `GET` | `/api/v1/discoveries` | List all discovery scans |
| `GET` | `/api/v1/services` | List available AWS services |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/metrics` | Engine metrics |

### Create Discovery Scan

```bash
curl -X POST http://localhost:8001/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant",
    "customer_id": "your-customer",
    "account_id": "123456789012",
    "role_arn": "arn:aws:iam::123456789012:role/CSPMReadOnlyRole",
    "services": ["s3", "iam", "ec2", "rds"],
    "regions": ["ap-south-1"]
  }'
```

### Get Scan Status

```bash
curl http://localhost:8001/api/v1/discovery/{discovery_scan_id}/status
```

---

## Supported AWS Services (40+)

```
s3, iam, ec2, rds, lambda, dynamodb, sns, sqs, cloudfront, cloudtrail,
cloudwatch, config, efs, elasticache, elasticsearch, elb, elbv2, glacier,
kms, redshift, route53, secretsmanager, ses, ssm, vpc, waf, backup,
codebuild, codepipeline, ecr, ecs, eks, guardduty, inspector, kinesis,
macie, organizations, sagemaker, and more
```

---

## Database Schema

**Database:** `threat_engine_check` (shared with check engine)

| Table | Description |
|-------|-------------|
| `customers` | Customer records |
| `tenants` | Tenant records (per CSP) |
| `scans` | Scan metadata and status |
| `discoveries` | Discovered resources with emitted_fields, raw_response |
| `discovery_history` | Historical discoveries for drift detection |

### Key Indexes

```sql
CREATE INDEX idx_discoveries_scan ON discoveries(scan_id);
CREATE INDEX idx_discoveries_tenant ON discoveries(tenant_id);
CREATE INDEX idx_discoveries_service ON discoveries(service);
CREATE INDEX idx_discoveries_resource ON discoveries(resource_uid);
```

---

## Storage Modes

| Mode | Output | Description |
|------|--------|-------------|
| **Database** (default) | PostgreSQL | Stores discoveries in `discoveries` table |
| **NDJSON** | File system | Writes to `engine_output/` as NDJSON files |
| **Hybrid** | Both | Writes to both database and NDJSON (recommended) |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8001` | Server port |
| `DISCOVERY_DB_HOST` | `localhost` | PostgreSQL host |
| `DISCOVERY_DB_PORT` | `5432` | PostgreSQL port |
| `DISCOVERY_DB_NAME` | `threat_engine_check` | Database name |
| `DISCOVERY_DB_USER` | `postgres` | Database user |
| `DISCOVERY_DB_PASSWORD` | - | Database password |
| `MAX_DISCOVERY_WORKERS` | `50` | Parallel service discovery threads |
| `MAX_SERVICE_WORKERS` | `10` | Workers per service |
| `MAX_REGION_WORKERS` | `5` | Workers per region |
| `BOTO_MAX_POOL_CONNECTIONS` | `100` | AWS API connection pool size |
| `BOTO_RETRY_MODE` | `standard` | AWS retry mode (`standard` or `adaptive`) |
| `OPERATION_TIMEOUT` | `600` | Per-operation timeout (seconds) |

---

## Service Discovery Definitions

Each service has YAML definitions that describe how to discover resources:

```
services/{service}/discoveries/{service}.discoveries.yaml
```

These YAML files define:
- AWS API actions to call (e.g., `ListBuckets`, `DescribeInstances`)
- Fields to extract from API responses
- Resource identifier mapping
- Pagination handling
- Region-specific behavior

---

## Running Locally

```bash
cd engine_discoveries/engine_discoveries_aws

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
export AWS_PROFILE=your-profile
# OR
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

# Set database connection
export DISCOVERY_DB_HOST=localhost
export DISCOVERY_DB_PASSWORD=your_password

# Run server
uvicorn api_server:app --host 0.0.0.0 --port 8001 --reload
```

---

## Docker

```bash
# Build
docker build -t engine-discoveries -f engine_discoveries/engine_discoveries_aws/Dockerfile engine_discoveries/engine_discoveries_aws/

# Run
docker run -p 8001:8001 \
  -e DISCOVERY_DB_HOST=host.docker.internal \
  -e DISCOVERY_DB_PASSWORD=your_password \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  engine-discoveries
```

---

## Pipeline Integration

```
engine_discoveries (Phase 1) -----> discoveries table
    |
    | discovery_scan_id
    v
engine_check (Phase 2) -----> check_results table
    |
    v
engine_inventory / engine_threat / engine_compliance (Phases 3-5)
```

The discovery engine is the first step in every scan pipeline. It produces a `discovery_scan_id` that all downstream engines reference to access the discovered resources.

---

## Typical Performance

| Metric | Value |
|--------|-------|
| Full scan (all services) | 2-5 minutes |
| Resources discovered | ~280 per account |
| Services scanned | 40+ |
| Parallel threads | Up to 50 |
