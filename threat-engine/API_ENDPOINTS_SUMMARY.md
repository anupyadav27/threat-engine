# Threat Engine API Endpoints Summary

## Overview

The threat engine API has been enhanced with comprehensive endpoints to support the UI mockup. All threat reports are now automatically saved to storage when generated, enabling retrieval and management.

## Storage

Threat reports are stored in a file-based storage system (can be enhanced with database later):
- Location: `./threat_reports/{tenant_id}/{scan_run_id}.json`
- Configurable via `THREAT_REPORTS_DIR` environment variable
- Reports are cached in memory for quick access
- Threat status updates are persisted

---

## API Endpoints

### Core Threat Report Generation

#### `POST /api/v1/threat/generate`
Generate threat report from scan results (S3 or local).

**Request Body:**
```json
{
  "tenant_id": "tenant-123",
  "tenant_name": "Acme Corp",
  "scan_run_id": "scan-456",
  "cloud": "aws",
  "trigger_type": "manual",
  "accounts": ["155052200811"],
  "regions": ["us-east-1"],
  "services": ["s3", "iam"],
  "started_at": "2025-01-18T00:00:00Z",
  "completed_at": "2025-01-18T01:00:00Z"
}
```

**Response:** Complete threat report (automatically saved to storage)

---

#### `POST /api/v1/threat/generate/from-ndjson`
Generate threat report directly from NDJSON content.

**Request Body:**
```json
{
  "tenant_id": "tenant-123",
  "scan_run_id": "scan-456",
  "cloud": "aws",
  "ndjson_content": "...",
  ...
}
```

**Response:** Complete threat report (automatically saved to storage)

---

### GET Endpoints - Retrieve Threat Reports

#### `GET /api/v1/threat/reports/{scan_run_id}?tenant_id={tenant_id}`
Get existing threat report by scan_run_id.

**Query Parameters:**
- `tenant_id` (required): Tenant identifier

**Response:** Complete threat report

---

#### `GET /api/v1/threat/summary?scan_run_id={scan_run_id}&tenant_id={tenant_id}`
Get threat summary only (lightweight).

**Query Parameters:**
- `scan_run_id` (required): Scan run identifier
- `tenant_id` (required): Tenant identifier

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "threat_summary": {
    "total_threats": 82,
    "threats_by_severity": {...},
    "threats_by_category": {...}
  },
  "generated_at": "2025-01-18T10:00:00Z"
}
```

---

#### `GET /api/v1/threat/list?scan_run_id={scan_run_id}&tenant_id={tenant_id}&severity={severity}&threat_type={type}&status={status}&account={account}&region={region}&confidence={confidence}`
Get filtered list of threats.

**Query Parameters:**
- `scan_run_id` (required): Scan run identifier
- `tenant_id` (required): Tenant identifier
- `severity` (optional): Filter by severity (critical, high, medium, low, info)
- `threat_type` (optional): Filter by threat type (exposure, identity, lateral_movement, etc.)
- `status` (optional): Filter by status (open, resolved, suppressed, false_positive)
- `account` (optional): Filter by account ID
- `region` (optional): Filter by region
- `confidence` (optional): Filter by confidence (high, medium, low)

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "total": 25,
  "threats": [...]
}
```

---

#### `GET /api/v1/threat/{threat_id}?tenant_id={tenant_id}`
Get single threat by ID with full details.

**Query Parameters:**
- `tenant_id` (required): Tenant identifier

**Response:**
```json
{
  "threat": {...},
  "report_context": {...},
  "misconfig_findings": [...]
}
```

---

#### `GET /api/v1/threat/{threat_id}/misconfig-findings?tenant_id={tenant_id}`
Get root cause misconfig findings for a threat.

**Response:**
```json
{
  "threat_id": "thr_abc123",
  "misconfig_findings": [...]
}
```

---

#### `GET /api/v1/threat/{threat_id}/assets?tenant_id={tenant_id}`
Get affected assets for a threat.

**Response:**
```json
{
  "threat_id": "thr_abc123",
  "affected_assets": [...]
}
```

---

#### `GET /api/v1/threat/reports?tenant_id={tenant_id}&limit={limit}`
List all threat reports for a tenant.

**Query Parameters:**
- `tenant_id` (required): Tenant identifier
- `limit` (optional): Maximum number of reports (default: 100)

**Response:**
```json
{
  "tenant_id": "tenant-123",
  "total": 10,
  "reports": [
    {
      "scan_run_id": "scan-456",
      "generated_at": "2025-01-18T10:00:00Z",
      "cloud": "aws",
      "total_threats": 82,
      "threats_by_severity": {...}
    }
  ]
}
```

---

### PATCH Endpoints - Update Threat Status

#### `PATCH /api/v1/threat/{threat_id}?tenant_id={tenant_id}`
Update threat status, notes, or assignee.

**Request Body:**
```json
{
  "status": "resolved",
  "notes": "Fixed by enabling S3 public access block",
  "assignee": "john@example.com"
}
```

**Query Parameters:**
- `tenant_id` (required): Tenant identifier

**Response:** Updated threat with full details

---

### Threat Map Endpoints

#### `GET /api/v1/threat/map/geographic?scan_run_id={scan_run_id}&tenant_id={tenant_id}`
Get threats grouped by region (geographic view).

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "regions": [
    {
      "region": "us-east-1",
      "threats": [...],
      "count": 12,
      "by_severity": {
        "critical": 5,
        "high": 4,
        "medium": 3
      }
    }
  ]
}
```

---

#### `GET /api/v1/threat/map/account?scan_run_id={scan_run_id}&tenant_id={tenant_id}`
Get threats grouped by account.

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "accounts": [
    {
      "account": "155052200811",
      "threats": [...],
      "count": 25,
      "by_severity": {...},
      "by_type": {...}
    }
  ]
}
```

---

#### `GET /api/v1/threat/map/service?scan_run_id={scan_run_id}&tenant_id={tenant_id}`
Get threats grouped by service.

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "services": [
    {
      "service": "s3",
      "threats": [...],
      "count": 8,
      "by_severity": {...}
    }
  ]
}
```

---

### Analytics Endpoints

#### `GET /api/v1/threat/analytics/patterns?scan_run_id={scan_run_id}&tenant_id={tenant_id}&limit={limit}`
Get common threat patterns (grouped by misconfig combinations).

**Query Parameters:**
- `limit` (optional): Number of patterns to return (default: 10)

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "patterns": [
    {
      "pattern": "mf_abc123|mf_def456|mf_ghi789",
      "misconfig_finding_refs": ["mf_abc123", "mf_def456", "mf_ghi789"],
      "count": 8,
      "threats": [...],
      "severity": "critical",
      "threat_type": "data_exfiltration"
    }
  ]
}
```

---

#### `GET /api/v1/threat/analytics/correlation?scan_run_id={scan_run_id}&tenant_id={tenant_id}`
Get threat correlation matrix.

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "correlation_matrix": {
    "exposure": {
      "exposure": 1.0,
      "identity": 0.3,
      "lateral_movement": 0.5,
      "data_exfiltration": 0.7
    },
    ...
  }
}
```

---

#### `GET /api/v1/threat/analytics/distribution?scan_run_id={scan_run_id}&tenant_id={tenant_id}`
Get threat distribution statistics.

**Response:**
```json
{
  "scan_run_id": "scan-456",
  "distribution": {
    "by_severity": {...},
    "by_category": {...},
    "by_status": {...},
    "top_categories": [...]
  }
}
```

---

### Remediation Endpoints

#### `GET /api/v1/threat/remediation/queue?tenant_id={tenant_id}&status={status}&limit={limit}`
Get remediation queue (all threats across all reports).

**Query Parameters:**
- `tenant_id` (required): Tenant identifier
- `status` (optional): Filter by status
- `limit` (optional): Maximum number of threats (default: 100)

**Response:**
```json
{
  "total": 150,
  "threats": [
    {
      "threat_id": "thr_abc123",
      "scan_run_id": "scan-456",
      ...
    }
  ]
}
```

---

#### `GET /api/v1/threat/{threat_id}/remediation?tenant_id={tenant_id}`
Get remediation workflow for a threat.

**Response:**
```json
{
  "threat_id": "thr_abc123",
  "threat": {...},
  "remediation": {
    "summary": "...",
    "steps": [...]
  },
  "steps": [
    {
      "step_id": "mf_abc123",
      "finding_id": "mf_abc123",
      "rule_id": "aws.s3.bucket.public_access_block_enabled",
      "description": "Remediate: aws.s3.bucket.public_access_block_enabled",
      "status": "pending",
      "severity": "high"
    }
  ],
  "total_steps": 3,
  "completed_steps": 0
}
```

---

## Implementation Notes

1. **Storage**: Reports are automatically saved when generated via POST endpoints
2. **Caching**: Reports are cached in memory for quick access
3. **Status Updates**: Threat status updates are persisted and applied to cached reports
4. **File-based**: Currently uses file-based storage, can be enhanced with PostgreSQL later
5. **Error Handling**: All endpoints return appropriate HTTP status codes (404 for not found, 400 for bad requests, 500 for server errors)

## Future Enhancements

- [ ] Database storage (PostgreSQL) for better querying and historical tracking
- [ ] Threat trend analysis over time (requires historical data)
- [ ] Remediation step tracking with completion status
- [ ] User assignment and workflow management
- [ ] WebSocket support for real-time threat updates
- [ ] Export functionality (PDF/CSV)



