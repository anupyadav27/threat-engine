# Engine Check (AWS Compliance Check Engine)

> Evaluates discovered AWS resources against security rules and compliance policies, producing PASS/FAIL findings.

---

## Overview

The Check Engine is **Phase 2** of the scan pipeline. It takes discovery results (from `engine_discoveries`) and evaluates each resource against YAML-defined security rules. Results are stored in PostgreSQL and can be consumed by downstream engines (inventory, threat, compliance).

**Port:** `8002`
**Database:** `threat_engine_check`
**Docker Image:** `yadavanup84/engine-check:latest`

---

## Architecture

```
Discovery Results (DB or NDJSON)
        |
        v
  +---------------------+
  |   Check Engine       |
  |                      |
  |  1. Load discoveries |
  |  2. Load rules/YAML  |
  |  3. Evaluate checks  |
  |  4. Store findings   |
  +---------------------+
        |
        v
  PostgreSQL (check_results)
```

---

## Directory Structure

```
engine_check/
└── engine_check_aws/
    ├── api_server.py              # FastAPI application (port 8002)
    ├── Dockerfile                 # Container definition
    ├── requirements.txt           # Python dependencies
    ├── auth/
    │   └── aws_auth.py            # AWS credential management
    ├── config/
    │   ├── service_list.json      # Supported AWS services
    │   ├── scan_config.json       # Scan behavior settings
    │   ├── parameter_name_mapping.json
    │   ├── actions.yaml           # Action definitions
    │   ├── actions_selection.yaml # Action selection rules
    │   └── check_exceptions.yaml  # Exception handling rules
    ├── database/
    │   ├── schema.sql             # PostgreSQL schema
    │   ├── setup_database.sh      # DB initialization
    │   ├── connection/
    │   │   └── database_config.py # Connection pool config
    │   └── migrations/
    │       ├── 002_add_resource_uid.sql
    │       └── run_migration_002.py
    ├── engine/
    │   ├── check_engine.py        # Core check execution logic
    │   ├── database_manager.py    # DB read/write operations
    │   ├── service_scanner.py     # Per-service scanning
    │   ├── discovery_helper.py    # Discovery data utilities
    │   └── discovery_reader.py    # Read from DB or NDJSON
    ├── utils/
    │   ├── metadata_loader.py     # Rule metadata loading
    │   ├── exception_manager.py   # Check exception handling
    │   ├── service_feature_manager.py
    │   ├── reporting_manager.py   # Result reporting
    │   ├── phase_logger.py        # Phase-specific logging
    │   ├── progressive_output.py  # Incremental output writer
    │   ├── action_runner.py       # Action executor
    │   ├── progress_monitor.py    # Scan progress tracking
    │   ├── discovery_resource_mapper.py
    │   └── organizations_scanner.py
    └── services/                  # Per-service check definitions
        ├── codebuild/
        │   ├── checks/default/codebuild.checks.yaml
        │   ├── discoveries/codebuild.discoveries.yaml
        │   ├── rules/codebuild.yaml
        │   ├── metadata/
        │   └── metadata_mapping.json
        ├── edr/
        ├── kinesis/
        └── [40+ AWS services...]
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/check` | Create a check scan |
| `GET` | `/api/v1/check/{check_scan_id}/status` | Get scan status |
| `GET` | `/api/v1/checks` | List all check scans |
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/metrics` | Engine metrics |

### Create Check Scan

```bash
curl -X POST http://localhost:8002/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "your-tenant",
    "customer_id": "your-customer",
    "account_id": "123456789012",
    "discovery_scan_id": "disc-scan-uuid",
    "services": ["s3", "iam", "ec2"],
    "regions": ["ap-south-1"]
  }'
```

### Get Scan Status

```bash
curl http://localhost:8002/api/v1/check/{check_scan_id}/status
```

---

## Database Schema

**Database:** `threat_engine_check`

| Table | Description |
|-------|-------------|
| `customers` | Customer records |
| `tenants` | Tenant records (per CSP) |
| `scans` | Scan metadata and status |
| `check_results` | Check findings (PASS/FAIL/ERROR) |
| `check_findings` | Detailed findings with resource context |

### Key Indexes

```sql
CREATE INDEX idx_check_results_scan ON check_results(scan_id);
CREATE INDEX idx_check_results_tenant ON check_results(tenant_id);
CREATE INDEX idx_check_results_status ON check_results(status);
CREATE INDEX idx_check_results_resource ON check_results(resource_uid);
```

---

## Storage Modes

The check engine supports two storage modes:

| Mode | Source | Description |
|------|--------|-------------|
| **Database** (default) | PostgreSQL | Reads discoveries from `threat_engine_check.discoveries` table |
| **NDJSON** | File system | Reads from `engine_output/` NDJSON files |

Set via environment variable or scan request payload.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8002` | Server port |
| `CHECK_DB_HOST` | `localhost` | PostgreSQL host |
| `CHECK_DB_PORT` | `5432` | PostgreSQL port |
| `CHECK_DB_NAME` | `threat_engine_check` | Database name |
| `CHECK_DB_USER` | `postgres` | Database user |
| `CHECK_DB_PASSWORD` | - | Database password |
| `MAX_CHECK_WORKERS` | `50` | Parallel check threads |
| `FOR_EACH_MAX_WORKERS` | `50` | Workers for for-each operations |

---

## Rule Structure

Rules are defined per-service in YAML format:

```
services/{service}/checks/default/{service}.checks.yaml  # Check definitions
services/{service}/rules/{service}.yaml                    # Rule logic
services/{service}/metadata/                               # Per-check metadata
```

Each check evaluates a specific configuration property and returns PASS, FAIL, or ERROR.

---

## Running Locally

```bash
cd engine_check/engine_check_aws

# Install dependencies
pip install -r requirements.txt

# Set environment
export CHECK_DB_HOST=localhost
export CHECK_DB_PASSWORD=your_password

# Run server
uvicorn api_server:app --host 0.0.0.0 --port 8002 --reload
```

---

## Docker

```bash
# Build
docker build -t engine-check -f engine_check/engine_check_aws/Dockerfile engine_check/engine_check_aws/

# Run
docker run -p 8002:8002 \
  -e CHECK_DB_HOST=host.docker.internal \
  -e CHECK_DB_PASSWORD=your_password \
  engine-check
```

---

## Pipeline Integration

```
engine_discoveries (Phase 1)
    |
    | discovery_scan_id
    v
engine_check (Phase 2) -----> check_results table
    |
    | check_scan_id
    v
engine_inventory (Phase 3)
engine_threat (Phase 4)
engine_compliance (Phase 5)
```

The check engine receives a `discovery_scan_id`, loads the discovered resources, runs all applicable checks, and stores findings. Downstream engines reference the `check_scan_id` to access results.
