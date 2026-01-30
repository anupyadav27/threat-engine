# Threat Engine - Input/Output Guide

**Date:** 2026-01-25

## Overview

The Threat Engine analyzes misconfiguration scan results from ConfigScan engines to detect security threats and generate comprehensive threat reports.

---

## Architecture

```
Threat Engine Flow:
┌─────────────────────┐
│ ConfigScan Engine   │ → Generates NDJSON scan results
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Input: NDJSON Files  │ → Read from local filesystem or S3
│ - results.ndjson     │
│ - findings.ndjson    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Threat Engine       │
│ 1. Normalize        │ → Convert NDJSON to findings
│ 2. Detect Threats   │ → Pattern matching & correlation
│ 3. Generate Report  │ → Create threat report
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ Output: Threat      │ → Store threat reports
│ Reports (JSON)      │
└─────────────────────┘
```

---

## Input Paths

### 1. Local Filesystem (Default)

**Base Directory:**
- Environment variable: `SCAN_RESULTS_DIR`
- Default: `{project_root}/engine_output`

**Full Path Structure:**
```
{SCAN_RESULTS_DIR}/
└── engine_configscan_{csp}/
    └── output/
        └── {scan_run_id}/
            └── results.ndjson  ← Threat engine reads this
```

**Example Paths:**

**AWS:**
```
engine_output/engine_configscan_aws/output/{scan_run_id}/results.ndjson
```

**Azure:**
```
engine_output/engine_configscan_azure/output/{scan_run_id}/results.ndjson
```

**GCP:**
```
engine_output/engine_configscan_gcp/output/{scan_run_id}/results.ndjson
```

**Code Reference:**
```python
# api_server.py - load_scan_results_from_local()
base = os.getenv("SCAN_RESULTS_DIR")
if not base:
    base = str(get_project_root() / "engine_output")
csp_path = get_csp_s3_path(csp)  # e.g., "engine_configscan_aws"
file_path = os.path.join(base, csp_path, "output", scan_run_id, "results.ndjson")
```

### 2. S3 Storage (Production)

**S3 Path Structure:**
```
s3://{bucket}/
└── engine_configscan_{csp}/
    └── output/
        └── {scan_run_id}/
            └── results.ndjson
```

**Default Bucket:** `cspm-lgtech`

**Code Reference:**
```python
# api_server.py - load_scan_results_from_s3()
bucket = "cspm-lgtech"
s3_path = get_csp_s3_path(csp)  # e.g., "engine_configscan_aws"
key = f"{s3_path}/output/{scan_run_id}/results.ndjson"
```

### 3. Direct NDJSON Content

**API Endpoint:** `POST /api/v1/threat/generate/from-ndjson`

**Usage:**
- Pass NDJSON content directly in request body
- Useful for testing or when results are already in memory

---

## Input Format

The engine expects **NDJSON** (Newline Delimited JSON) format from ConfigScan engines:

**Each line is a JSON object:**
```json
{
  "inventory": {
    "account": "123456789012",
    "region": "us-east-1",
    "service": "s3"
  },
  "checks": [
    {
      "rule_id": "aws.s3.bucket_public_access",
      "result": "FAIL",
      "severity": "high",
      "region": "us-east-1",
      "resource_uid": "arn:aws:s3:::my-bucket",
      "resource_arn": "arn:aws:s3:::my-bucket",
      "resource_id": "my-bucket",
      "resource_type": "bucket",
      "_checked_fields": ["PublicAccessBlockConfiguration"]
    }
  ],
  "service": "s3",
  "scope": "regional",
  "region": "us-east-1",
  "account": "123456789012"
}
```

**Key Fields:**
- `checks[]` - Array of check results (misconfigurations)
- `rule_id` - Rule identifier (e.g., `aws.s3.bucket_public_access`)
- `result` - Check result (`PASS`, `FAIL`, `ERROR`)
- `severity` - Severity level (`critical`, `high`, `medium`, `low`)
- `resource_uid` / `resource_arn` - Resource identifiers
- `resource_type` - Type of resource (e.g., `bucket`, `security_group`)

---

## Output Paths

### Threat Report Storage

**Base Directory:**
- Environment variable: `THREAT_REPORTS_DIR`
- Default: `./threat_reports`

**Full Path Structure:**
```
{THREAT_REPORTS_DIR}/
└── {tenant_id}/
    └── {scan_run_id}.json  ← Threat report stored here
```

**Example:**
```
threat_reports/
└── tenant-123/
    ├── scan-abc-001.json
    ├── scan-abc-002.json
    └── scan-xyz-001.json
```

**Code Reference:**
```python
# storage/threat_storage.py
storage_dir = os.getenv("THREAT_REPORTS_DIR", "./threat_reports")
tenant_dir = storage_dir / tenant_id
report_file = tenant_dir / f"{scan_run_id}.json"
```

---

## Output Format

### Threat Report Schema

**File:** `threat_engine/schemas/threat_report_schema.py`

**Structure:**
```json
{
  "schema_version": "cspm_threat_report.v1",
  "generated_at": "2026-01-25T10:00:00Z",
  "tenant": {
    "tenant_id": "tenant-123",
    "tenant_name": "Acme Corp"
  },
  "scan_context": {
    "scan_run_id": "scan-abc-001",
    "trigger_type": "scheduled",
    "cloud": "aws",
    "accounts": ["123456789012"],
    "regions": ["us-east-1"],
    "services": ["s3", "iam"],
    "started_at": "2026-01-25T09:00:00Z",
    "completed_at": "2026-01-25T10:00:00Z"
  },
  "threat_summary": {
    "total_threats": 10,
    "threats_by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 3
    },
    "threats_by_category": {
      "exposure": 4,
      "identity": 3,
      "data_exfiltration": 2,
      "lateral_movement": 1
    }
  },
  "threats": [
    {
      "threat_id": "thr_abc123...",
      "threat_type": "exposure",
      "severity": "high",
      "confidence": "high",
      "status": "open",
      "title": "Public S3 Bucket with Sensitive Data",
      "description": "...",
      "affected_assets": [...],
      "correlations": {
        "misconfig_finding_refs": ["finding-1", "finding-2"]
      },
      "remediation": {...}
    }
  ],
  "misconfig_findings": [...],
  "asset_snapshots": [...]
}
```

---

## Processing Flow

### Step 1: Load Input

```python
# api_server.py
if use_s3:
    ndjson_lines = load_scan_results_from_s3(scan_run_id, csp)
else:
    ndjson_lines = load_scan_results_from_local(scan_run_id, csp)
```

### Step 2: Normalize Findings

```python
# schemas/misconfig_normalizer.py
findings = normalize_ndjson_to_findings(ndjson_lines, cloud)
```

**Converts NDJSON to normalized `MisconfigFinding` objects:**
- Extracts check results
- Normalizes resource identifiers
- Maps rule IDs to categories

### Step 3: Detect Threats

```python
# detector/threat_detector.py
detector = ThreatDetector()
threats = detector.detect_threats(findings)
```

**Threat Detection Patterns:**
- **Exposure**: Public access + internet reachability
- **Identity**: Permissive IAM + privileged access
- **Lateral Movement**: Open inbound rules + reachable subnets
- **Data Exfiltration**: Public storage + sensitive data + weak logging
- **Privilege Escalation**: IAM policies allowing escalation
- **Data Breach**: Database/public resource misconfigurations

### Step 4: Generate Report

```python
# reporter/threat_reporter.py
reporter = ThreatReporter()
report = reporter.generate_report(
    tenant=tenant,
    scan_context=scan_context,
    threats=threats,
    misconfig_findings=findings
)
```

### Step 5: Save Output

```python
# storage/threat_storage.py
storage.save_report(report)
# Saves to: {THREAT_REPORTS_DIR}/{tenant_id}/{scan_run_id}.json
```

---

## Environment Variables

### Input Configuration

```bash
# Local filesystem input
SCAN_RESULTS_DIR=/path/to/engine_output  # Default: {project_root}/engine_output

# S3 input
USE_S3=true  # Set to "true" to use S3 instead of local filesystem
S3_BUCKET=cspm-lgtech  # S3 bucket name (default: cspm-lgtech)
```

### Output Configuration

```bash
# Threat report storage
THREAT_REPORTS_DIR=./threat_reports  # Default: ./threat_reports
```

### API Configuration

```bash
PORT=8000  # API server port (default: 8000)
```

---

## API Endpoints

### Generate Threat Report

**POST** `/api/v1/threat/generate`

**Request:**
```json
{
  "tenant_id": "tenant-123",
  "scan_run_id": "scan-abc-001",
  "cloud": "aws",
  "trigger_type": "scheduled",
  "accounts": ["123456789012"],
  "regions": ["us-east-1"],
  "services": ["s3", "iam"],
  "started_at": "2026-01-25T09:00:00Z",
  "completed_at": "2026-01-25T10:00:00Z"
}
```

**Response:**
- Complete threat report (JSON)
- Saved to: `{THREAT_REPORTS_DIR}/{tenant_id}/{scan_run_id}.json`

### Get Threat Report

**GET** `/api/v1/threat/reports/{scan_run_id}?tenant_id={tenant_id}`

**Response:**
- Threat report from storage

### List Threats

**GET** `/api/v1/threat/list?scan_run_id={scan_run_id}&tenant_id={tenant_id}`

**Query Parameters:**
- `severity` - Filter by severity
- `threat_type` - Filter by threat type
- `status` - Filter by status
- `account` - Filter by account
- `region` - Filter by region

---

## File Structure

```
engine_threat/
├── threat_engine/
│   ├── api_server.py          # Main API server
│   ├── schemas/
│   │   ├── threat_report_schema.py    # Report schema
│   │   └── misconfig_normalizer.py    # NDJSON → findings
│   ├── detector/
│   │   └── threat_detector.py         # Threat detection logic
│   ├── reporter/
│   │   └── threat_reporter.py          # Report generation
│   └── storage/
│       └── threat_storage.py          # File-based storage
├── README.md
└── requirements.txt
```

---

## Example Usage

### Local Development

```bash
# Set input directory
export SCAN_RESULTS_DIR=/Users/apple/Desktop/threat-engine/engine_output

# Set output directory
export THREAT_REPORTS_DIR=./threat_reports

# Run engine
python -m uvicorn threat_engine.api_server:app --port 8000
```

### Generate Report

```bash
curl -X POST http://localhost:8000/api/v1/threat/generate \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-123",
    "scan_run_id": "check_check_20260122_172224_20260122_172225",
    "cloud": "aws",
    "trigger_type": "manual",
    "accounts": ["123456789012"],
    "regions": ["us-east-1"],
    "started_at": "2026-01-22T17:22:24Z",
    "completed_at": "2026-01-22T17:22:25Z"
  }'
```

**Input Read From:**
```
engine_output/engine_configscan_aws/output/check_check_20260122_172224_20260122_172225/results.ndjson
```

**Output Saved To:**
```
threat_reports/tenant-123/check_check_20260122_172224_20260122_172225.json
```

---

## Integration with Onboarding Engine

When onboarding engine triggers threat engine:

```python
# orchestrator/engine_orchestrator.py
await client.post(
    f"{self.threat_engine_url}/api/v1/threat/generate",
    json={
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
        "cloud": provider_type,
        "trigger_type": "orchestrated",
        "accounts": [],
        "regions": [],
        "services": [],
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": datetime.utcnow().isoformat()
    }
)
```

**Threat engine then:**
1. Reads input from: `engine_output/engine_configscan_{csp}/output/{scan_run_id}/results.ndjson`
2. Processes and detects threats
3. Saves output to: `threat_reports/{tenant_id}/{scan_run_id}.json`

---

## Summary

### Input
- **Source:** ConfigScan engine NDJSON output
- **Location:** `engine_output/engine_configscan_{csp}/output/{scan_run_id}/results.ndjson` (local) or S3
- **Format:** NDJSON (one JSON object per line)

### Output
- **Destination:** `threat_reports/{tenant_id}/{scan_run_id}.json`
- **Format:** JSON threat report (cspm_threat_report.v1 schema)
- **Content:** Threats, misconfig findings, asset snapshots, summaries

### Configuration
- `SCAN_RESULTS_DIR` - Input directory (default: `engine_output`)
- `THREAT_REPORTS_DIR` - Output directory (default: `./threat_reports`)
- `USE_S3` - Use S3 for input (default: `false`)

The threat engine reads ConfigScan results and generates threat reports!
