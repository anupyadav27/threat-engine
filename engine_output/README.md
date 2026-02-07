# Engine Output (Centralized Output Storage)

> Shared file storage directory for scan results, reports, and artifacts across all engines.

---

## Overview

`engine_output` is **not a service** — it's a centralized storage directory used by all engines to write and read scan artifacts. When engines operate in file-based (NDJSON) mode, this directory serves as the shared filesystem for inter-engine data exchange.

In production, this directory is typically backed by an S3 bucket or a Kubernetes PersistentVolume.

---

## Directory Structure

```
engine_output/
├── compliance/
│   └── reports/           # Compliance assessment reports
│       └── .gitkeep
├── datasec/
│   └── reports/           # Data security scan reports
│       └── .gitkeep
├── iam/
│   └── reports/           # IAM analysis reports
│       └── .gitkeep
└── latest/                # Symlink to most recent scan output
```

### Runtime Structure (populated during scans)

```
engine_output/
├── {scan_id}/
│   ├── discoveries.ndjson       # Discovered resources
│   ├── check_results.ndjson     # Check findings (PASS/FAIL)
│   ├── inventory.ndjson         # Inventory assets
│   ├── threat_detections.ndjson # Threat findings
│   └── summary.json             # Scan summary
├── compliance/
│   └── reports/
│       └── {report_id}.json     # Compliance reports
├── datasec/
│   └── reports/
│       └── {report_id}.json     # Data security reports
├── iam/
│   └── reports/
│       └── {report_id}.json     # IAM analysis reports
└── latest/ -> {most_recent_scan_id}
```

---

## Storage Backends

| Backend | Configuration | Use Case |
|---------|--------------|----------|
| **Local filesystem** | `STORAGE_TYPE=local` | Development, Docker Compose |
| **AWS S3** | `STORAGE_TYPE=s3` | Production (EKS) |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_TYPE` | `local` | Storage backend (`local` or `s3`) |
| `S3_BUCKET` | - | S3 bucket name |
| `S3_PREFIX` | `scans/` | S3 key prefix |
| `WORKSPACE_ROOT` | `./engine_output` | Local base path |

---

## File Formats

### NDJSON (Newline-Delimited JSON)

Scan results are stored as NDJSON — one JSON object per line for efficient streaming:

```json
{"resource_uid": "arn:aws:s3:::my-bucket", "service": "s3", "resource_type": "bucket", "region": "us-east-1", ...}
{"resource_uid": "arn:aws:s3:::other-bucket", "service": "s3", "resource_type": "bucket", "region": "ap-south-1", ...}
```

### Summary JSON

Each scan produces a summary with metadata:

```json
{
  "scan_id": "uuid",
  "tenant_id": "tenant-123",
  "status": "completed",
  "started_at": "2024-01-15T10:00:00Z",
  "completed_at": "2024-01-15T10:03:00Z",
  "total_resources": 280,
  "services_scanned": 40
}
```

---

## Usage by Engines

| Engine | Reads | Writes |
|--------|-------|--------|
| `engine_discoveries` | - | discoveries.ndjson |
| `engine_check` | discoveries.ndjson | check_results.ndjson |
| `engine_inventory` | discoveries.ndjson, check_results.ndjson | inventory.ndjson |
| `engine_compliance` | check_results.ndjson | compliance reports |
| `engine_datasec` | - | datasec reports |
| `engine_iam` | - | iam reports |

---

## Path Resolution

Paths are resolved by `engine_common/storage_paths.py`:

```python
from engine_common.storage_paths import StoragePathResolver

resolver = StoragePathResolver()

# Returns: engine_output/{scan_id}/discoveries.ndjson
path = resolver.get_scan_results_path(scan_id="scan-123")
```

---

## Docker Volume Mounting

When running engines in Docker Compose, mount `engine_output` as a shared volume:

```yaml
services:
  engine-discoveries:
    volumes:
      - ./engine_output:/app/engine_output

  engine-check:
    volumes:
      - ./engine_output:/app/engine_output
```

---

## S3 Structure (Production)

```
s3://threat-engine-results/
├── scans/
│   ├── {tenant_id}/{scan_id}/
│   │   ├── discoveries.ndjson
│   │   ├── check_results.ndjson
│   │   └── summary.json
│   └── ...
├── reports/
│   ├── compliance/{report_id}.json
│   ├── datasec/{report_id}.json
│   └── iam/{report_id}.json
└── exports/
    └── {export_id}.csv
```
