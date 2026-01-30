# Compliance Engine Generator

A unified compliance reporting engine that processes scan results from all CSP engines (AWS, Azure, GCP, AliCloud, OCI, IBM) and generates comprehensive compliance reports across multiple frameworks.

## Overview

The Compliance Engine Generator:
- **Consumes** scan results from CSP compliance engines
- **Maps** security checks to compliance framework controls (CIS, ISO 27001, NIST, PCI-DSS, HIPAA, GDPR, etc.)
- **Aggregates** results by framework and calculates compliance scores
- **Generates** executive dashboards, framework reports, and audit-ready documentation
- **Tracks** compliance trends over time

## Architecture

```
CSP Engines (AWS/Azure/GCP/etc.) 
    ↓ (scan results JSON/NDJSON)
Compliance Engine Generator
    ├── Mapper: rule_id → compliance controls
    ├── Aggregator: Group by framework, calculate scores
    ├── Reporter: Generate reports (executive, framework, resource-level)
    ├── Exporter: Export to JSON/PDF/CSV/DB
    └── Storage: Track historical trends
    ↓
Compliance Reports (JSON/PDF/CSV/DB)
```

## Features

### Core Features
- ✅ Multi-framework compliance mapping (CIS, ISO, NIST, PCI-DSS, HIPAA, GDPR)
- ✅ Compliance score calculation (0-100% per framework)
- ✅ Multi-CSP aggregation (unified view across AWS/Azure/GCP/etc.)
- ✅ Historical tracking and trend analysis
- ✅ Evidence and audit trail
- ✅ Remediation prioritization

### Report Types
- **Executive Dashboard**: High-level compliance posture
- **Framework Reports**: Control-by-control status (audit-ready)
- **Resource Drill-down**: Per-resource compliance status
- **Remediation Roadmap**: Prioritized fix list

### Export Formats
- JSON API responses (for UI)
- PDF reports (executive + detailed)
- CSV exports (spreadsheet analysis)
- Database tables (PostgreSQL/DynamoDB)

## Quick Start

### 1. Install Dependencies

```bash
cd compliance-engine
pip install -r requirements.txt
```

### 2. Load Compliance Mappings

Place framework mapping files in `data/frameworks/`:
- `cis_aws_foundations_v2.0.csv`
- `iso27001_2022.csv`
- `nist_csf.csv`
- etc.

### 3. Run Compliance Engine

```bash
# Start API server
python -m compliance_engine.api_server

# Generate compliance report from scan results
curl -X POST http://localhost:8000/api/v1/compliance/generate \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "9c5ebb5b-5e68-4b9f-9851-6c5697f1d1f0",
    "csp": "aws",
    "frameworks": ["CIS", "ISO27001"]
  }'
```

## API Endpoints

- `POST /api/v1/compliance/generate` - Generate compliance report from scan results (S3/NDJSON)
- `POST /api/v1/compliance/generate/from-check-db` - Generate from **Check DB** (PostgreSQL). Use for Discovery → Check → Threat → Compliance flow. Requires `tenant_id`, `scan_id` (or `latest`). Env: `CHECK_DB_*`.
- `POST /api/v1/compliance/generate/from-threat-db` - Generate from **Threat DB** (PostgreSQL). Reads `threat_reports.report_data`, extracts `misconfig_findings`. Use when Threat writes to DB (`THREAT_USE_DB=true`). Env: `THREAT_DB_*`.
- `POST /api/v1/compliance/generate/from-threat-engine` - Generate from threat engine NDJSON output (file-based)
- `GET /api/v1/compliance/report/{report_id}` - Get compliance report
- `GET /api/v1/compliance/framework/{framework}/status` - Get framework compliance status
- `GET /api/v1/compliance/trends` - Get compliance trends
- `GET /api/v1/compliance/report/{report_id}/export?format=pdf` - Export report

### Generate from Check DB or Threat DB (table-based, SaaS-friendly)

**Check DB** (check_results from Discovery → Check):
```bash
curl -X POST "http://localhost:8000/api/v1/compliance/generate/from-check-db" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant-456", "scan_id": "latest", "csp": "aws"}'
```

**Threat DB** (threat_reports when Threat uses `THREAT_USE_DB=true`):
```bash
curl -X POST "http://localhost:8000/api/v1/compliance/generate/from-threat-db" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant-456", "scan_run_id": "check_xxx", "csp": "aws"}'
```

**Database:** Single-DB setup. Run `scripts/init-databases.sql` (creates `engine_*` schemas, including `engine_threat.threat_reports`, `engine_compliance.*`, etc.).

See `sample_output/README.md` and `sample_output/compliance_report_sample.json` for report structure.

## Data Structure

### Input: Scan Results (from CSP engines)
```json
{
  "scan_id": "uuid",
  "csp": "aws",
  "account_id": "588989875114",
  "scanned_at": "2026-01-13T07:27:00Z",
  "results": [
    {
      "service": "accessanalyzer",
      "region": "us-east-1",
      "checks": [
        {
          "rule_id": "aws.accessanalyzer.resource.access_analyzer_enabled",
          "result": "FAIL",
          "severity": "medium",
          "resource": {...}
        }
      ]
    }
  ]
}
```

### Output: Compliance Report
```json
{
  "compliance_report": {
    "frameworks": [
      {
        "framework": "CIS AWS Foundations Benchmark",
        "version": "2.0",
        "compliance_score": 78.5,
        "controls": [...]
      }
    ],
    "summary": {
      "overall_compliance_score": 78.5,
      "critical_findings": 12
    }
  }
}
```

## Framework Mappings

Compliance mappings are stored in:
- `data/frameworks/` - Framework control definitions (CSV)
- `data/mappings/` - Rule-to-framework mappings (YAML/CSV)

Format:
```csv
rule_id,framework,framework_version,control_id,control_title,control_category
aws.accessanalyzer.resource.access_analyzer_enabled,CIS AWS Foundations Benchmark,2.0,2.1.1,Ensure IAM Access Analyzer is enabled,Identity and Access Management
```

## Development

### Project Structure
```
compliance-engine/
├── compliance_engine/
│   ├── mapper/          # Framework mapping logic
│   ├── aggregator/      # Result aggregation and scoring
│   ├── reporter/        # Report generation
│   ├── exporter/        # Export formats
│   └── storage/         # Historical tracking
├── data/
│   ├── frameworks/      # Framework definitions
│   └── mappings/        # Rule-to-framework mappings
└── tests/               # Unit tests
```

### Running Tests
```bash
pytest tests/
```

## Deployment

### Docker
```bash
docker build -t compliance-engine:latest -f Dockerfile .
docker run -p 8000:8000 compliance-engine:latest
```

### Kubernetes
```bash
kubectl apply -f kubernetes/compliance-engine-deployment.yaml
```

## Integration with CSP Engines

The compliance engine consumes scan results from S3:

### S3 Structure

```
s3://cspm-lgtech/
├── aws-compliance-engine/output/{scan_id}/
│   ├── results.ndjson      # NDJSON format (one JSON per line)
│   └── summary.json       # Scan metadata
├── azure-compliance-engine/output/{scan_id}/
├── gcp-compliance-engine/output/{scan_id}/
├── alicloud-compliance-engine/output/{scan_id}/
├── oci-compliance-engine/output/{scan_id}/
└── ibm-compliance-engine/output/{scan_id}/
```

### Loading Scan Results

The compliance engine automatically:
1. **Loads from S3** using scan_id and CSP name
2. **Falls back to local filesystem** if S3 unavailable
3. **Parses NDJSON format** (one JSON object per line)

### CSP Engines Supported

- `aws` → `aws-compliance-engine/output`
- `azure` → `azure-compliance-engine/output`
- `gcp` → `gcp-compliance-engine/output`
- `alicloud` → `alicloud-compliance-engine/output`
- `oci` → `oci-compliance-engine/output`
- `ibm` → `ibm-compliance-engine/output`

All engines output a unified JSON format that the compliance engine processes.

## License

Same as parent project.

