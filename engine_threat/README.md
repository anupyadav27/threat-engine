# Threat Engine

Cloud Security Threat Detection and Reporting Engine.

## Overview

The Threat Engine analyzes misconfiguration scan results to detect security threats and generate comprehensive threat reports. It uses pattern matching and correlation to identify threats such as:

- **Exposure Threats**: Public access combined with internet reachability
- **Identity Threats**: Permissive IAM policies with privileged access
- **Lateral Movement**: Open inbound rules with reachable subnets
- **Data Exfiltration**: Public storage with sensitive data and weak logging
- **Privilege Escalation**: IAM policies allowing privilege escalation
- **Data Breach**: Database/public resource misconfigurations

## Architecture

```
threat-engine/
├── threat_engine/
│   ├── schemas/
│   │   ├── threat_report_schema.py      # cspm_threat_report.v1 schema
│   │   └── misconfig_normalizer.py     # NDJSON → normalized findings
│   ├── detector/
│   │   └── threat_detector.py          # Threat detection patterns
│   ├── reporter/
│   │   └── threat_reporter.py           # Report generation
│   └── api_server.py                    # FastAPI server
├── Dockerfile
├── requirements.txt
└── README.md
```

## Input Format

The engine expects NDJSON scan results from configScan engines with the following structure:

```json
{
  "inventory": {...},
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

**Note**: After the configScan engine enhancement, `resource_uid` and `resource_arn` should be present in check records.

## Output Format

The engine generates threat reports conforming to `cspm_threat_report.v1` schema:

```json
{
  "schema_version": "cspm_threat_report.v1",
  "tenant": {...},
  "scan_context": {...},
  "threat_summary": {
    "total_threats": 10,
    "threats_by_severity": {...},
    "threats_by_category": {...}
  },
  "threats": [...],
  "misconfig_findings": [...],
  "asset_snapshots": [...]
}
```

## API Endpoints

### POST `/api/v1/threat/generate`

Generate threat report from scan results (S3 or local).

**Request Body:**
```json
{
  "tenant_id": "tenant-123",
  "scan_run_id": "scan-456",
  "cloud": "aws",
  "trigger_type": "manual",
  "accounts": ["123456789012"],
  "regions": ["us-east-1"],
  "services": ["s3", "iam"],
  "started_at": "2024-01-01T00:00:00Z",
  "completed_at": "2024-01-01T01:00:00Z"
}
```

### POST `/api/v1/threat/generate/from-ndjson`

Generate threat report directly from NDJSON content.

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
python -m uvicorn threat_engine.api_server:app --reload --port 8000
```

## Docker

```bash
# Build image
docker build -t threat-engine:latest .

# Run container
docker run -p 8004:8000 \
  -e USE_S3=false \
  -e SCAN_RESULTS_DIR=/data \
  -v /path/to/engines-output:/data \
  threat-engine:latest
```

## Environment Variables

- `USE_S3`: Set to `"true"` to load results from S3 (default: `"false"`)
- `SCAN_RESULTS_DIR`: Local directory for scan results (default: `/Users/apple/Desktop/threat-engine/engines-output`)
- `PORT`: API server port (default: `8000`)

## Integration

The threat engine integrates with:

1. **ConfigScan Engines**: Reads NDJSON output from all CSP configScan engines
2. **Compliance Engine**: Can share findings for unified reporting
3. **S3 Storage**: Stores and retrieves scan results and reports

## Port Mapping

- **Local**: Port 8004 (host) → 8000 (container)
- **EKS**: Port 80 (service) → 8000 (container)

