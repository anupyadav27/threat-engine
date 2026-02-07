# engine_check — Compliance Check Engine (AWS)

> Port: **8001** | Docker: `yadavanup84/check-engine:latest`
> Database: PostgreSQL (threat_engine_check)

---

## Folder Structure

```
engine_check/engine_check_aws/
├── api_server.py                       # FastAPI (7 endpoints)
├── auth/
│   └── aws_auth.py                     # AWS credential management
├── database/
│   ├── connection/
│   │   └── database_config.py          # DB connection factory
│   └── migrations/
│       └── run_migration_002.py        # Schema migrations
├── engine/
│   ├── check_engine.py                 # Core check execution engine
│   ├── database_manager.py             # DB operations for scans
│   ├── discovery_helper.py             # Discovery data access
│   ├── discovery_reader.py             # Read discovery results
│   └── service_scanner.py              # Per-service check scanner
├── services/
│   └── {40+ AWS services}/             # Per-service validation rules
│       ├── validate_yaml_rules.py      # Rule executor
│       └── analyze_metadata_review.py  # Metadata analysis
└── utils/
    ├── action_runner.py                # Execute check actions
    ├── discovery_resource_mapper.py    # Map discoveries to resources
    ├── exception_manager.py            # Error handling
    ├── metadata_loader.py              # Load rule metadata from DB
    ├── organizations_scanner.py        # AWS Organizations scanner
    ├── phase_logger.py                 # Phase-based logging
    ├── progress_monitor.py             # Scan progress tracking
    ├── progressive_output.py           # Streaming output
    ├── reporting_manager.py            # Report generation
    └── service_feature_manager.py      # Feature flag management
```

---

## UI Page Mapping

| UI Page | API Endpoints | Description |
|---------|--------------|-------------|
| **Run Scan** | `POST /api/v1/check` | Trigger a compliance check scan |
| **Scan Status** | `GET /api/v1/check/{id}/status` | Real-time scan progress |
| **Scan History** | `GET /api/v1/checks` | List past scans with status |
| **Health** | `GET /api/v1/health` | Engine health status |
| **Metrics** | `GET /api/v1/metrics` | Prometheus-format metrics |

---

## Endpoint Reference

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/check` | Create and run a check scan |
| GET | `/api/v1/check/{check_scan_id}/status` | Get check scan status |
| GET | `/api/v1/checks` | List all check scans |
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/health/ready` | Readiness probe |
| GET | `/api/v1/health/live` | Liveness probe |
| GET | `/api/v1/metrics` | Prometheus metrics |

### POST /api/v1/check
Create a compliance check scan against discovery results.

**Request:**
```json
{
  "tenant_id": "588989875114",
  "scan_run_id": "ece8c3a6-ca19-46d2-83bb-2691dfbc4641",
  "cloud": "aws",
  "accounts": ["588989875114"],
  "regions": ["ap-south-1"],
  "services": ["s3", "iam", "ec2"]
}
```

**Response:**
```json
{
  "check_scan_id": "a1b2c3d4-...",
  "status": "running",
  "tenant_id": "588989875114",
  "created_at": "2026-02-07T..."
}
```

### GET /api/v1/check/{check_scan_id}/status

**Response:**
```json
{
  "check_scan_id": "a1b2c3d4-...",
  "status": "completed",
  "total_checks": 764,
  "passed": 0,
  "failed": 764,
  "services_scanned": 40,
  "duration_seconds": 45.2
}
```

### Database Tables

| Table | Description |
|-------|-------------|
| `check_scans` | Scan metadata (id, tenant, status, timing) |
| `check_findings` | Individual check results (rule_id, resource_uid, status, evidence) |
| `rule_metadata` | Rule definitions (rule_id, service, domain, severity, MITRE mappings) |
