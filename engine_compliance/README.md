# Compliance Engine (`engine_compliance`)

Compliance reporting engine for CSPM — maps check findings to 13+ regulatory frameworks, calculates per-control pass rates and compliance scores, and generates executive and audit-ready reports.

**Port:** `8010` | **Database:** `threat_engine_compliance` | **Image:** `yadavanup84/threat-engine-compliance-engine:v2-db-reports`

---

## Overview

The Compliance Engine reads **check findings** from the `threat_engine_check` DB (written by the Check Engine), maps each rule to its compliance framework controls, aggregates pass/fail rates per control, and generates structured compliance reports.

Pipeline position:

```
discoveries → check → compliance
                (8002)   (8010)
```

Supported frameworks: CIS AWS Foundations, CIS Azure, CIS GCP, ISO 27001, NIST CSF, NIST 800-53, PCI-DSS, HIPAA, GDPR, SOC 2, FedRAMP, MITRE ATT&CK, AWS Well-Architected.

---

## Architecture

```
Check DB (check_findings / rule_findings)
        ↓
  CheckDBLoader            ← reads findings for check_scan_id from threat_engine_check DB
        ↓
  RuleMapper               ← maps rule_id → compliance framework controls
        ↓
  ResultAggregator         ← groups by framework, control, resource; calculates pass rates
        ↓
  ScoreCalculator          ← computes compliance score (0-100%) per framework
        ↓
  EnterpriseReporter       ← assembles deduplicated findings + evidence + asset snapshots
        ↓
  DatabaseExporter         ← writes compliance_report + findings to threat_engine_compliance DB
```

---

## Key Components

| File | Purpose |
|------|---------|
| `compliance_engine/api_server.py` | FastAPI app — all endpoints |
| `loader/check_db_loader.py` | Reads check findings from `threat_engine_check` DB |
| `mapper/rule_mapper.py` | Maps `rule_id` to framework controls (CSV-driven) |
| `mapper/framework_loader.py` | Loads framework definitions and control hierarchies |
| `aggregator/result_aggregator.py` | Groups findings by framework/control/resource |
| `aggregator/score_calculator.py` | Calculates weighted compliance scores |
| `reporter/executive_dashboard.py` | High-level compliance posture summary |
| `reporter/framework_report.py` | Control-by-control framework report |
| `reporter/resource_drilldown.py` | Per-resource compliance status |
| `reporter/enterprise_reporter.py` | Full enterprise-grade report (cspm_misconfig_report.v1) |
| `exporter/json_exporter.py` | JSON export for API responses |
| `exporter/csv_exporter.py` | CSV export for spreadsheet analysis |
| `exporter/pdf_exporter.py` | PDF export (optional, requires `weasyprint`) |
| `exporter/excel_exporter.py` | Excel export (optional, requires `openpyxl`) |
| `storage/trend_tracker.py` | Historical compliance trend tracking |
| `storage/report_storage.py` | Local JSON report storage for S3 sync |

---

## API Endpoints

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check with DB connection status |

### Scan (Pipeline Entry Point)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/scan` | Run compliance scan — generates enterprise-grade report |
| `POST` | `/api/v1/compliance/generate` | Generate report from S3/NDJSON scan output |
| `POST` | `/api/v1/compliance/generate/direct` | Generate report with direct check results payload |
| `POST` | `/api/v1/compliance/generate/from-threat-engine` | Generate from Threat Engine NDJSON output |
| `POST` | `/api/v1/compliance/generate/from-check-db` | Generate from Check DB (legacy endpoint) |
| `POST` | `/api/v1/compliance/generate/from-threat-db` | Generate from Threat DB report data |
| `POST` | `/api/v1/compliance/generate/detailed` | Generate detailed report with extended control info |
| `POST` | `/api/v1/compliance/mock/generate` | Generate mock compliance report for UI development |

**Primary scan request body (`POST /api/v1/scan`):**
```json
{
  "orchestration_id": "337a7425-...",
  "tenant_id": "5a8b072b-...",
  "csp": "aws",
  "frameworks": ["CIS", "ISO27001", "NIST", "PCI-DSS", "HIPAA"],
  "include_passing": false,
  "max_findings": 1000
}
```

Supports two modes:
- **Pipeline mode** (recommended): provide `orchestration_id` — engine looks up `check_scan_id` + `tenant_id` + `csp` from `scan_orchestration`
- **Ad-hoc mode**: provide `scan_id` (direct `check_scan_id`, must also provide `csp` and `tenant_id`)

### Report Queries

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/report/{report_id}` | Get compliance report by ID |
| `GET` | `/api/v1/compliance/reports` | List all compliance reports |
| `GET` | `/api/v1/compliance/reports/{report_id}/status` | Get report generation status |
| `DELETE` | `/api/v1/compliance/reports/{report_id}` | Delete a compliance report |

### Framework Queries

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/frameworks` | List all supported frameworks with metadata |
| `GET` | `/api/v1/compliance/frameworks/all` | Extended framework list with control counts |
| `GET` | `/api/v1/compliance/framework/{framework}/status` | Compliance status for a framework |
| `GET` | `/api/v1/compliance/framework/{framework}/detailed` | Detailed framework report with per-control breakdown |
| `GET` | `/api/v1/compliance/framework/{framework}/structure` | Framework control hierarchy structure |
| `GET` | `/api/v1/compliance/framework/{framework}/controls/grouped` | Controls grouped by category |
| `GET` | `/api/v1/compliance/framework/{framework}/resources/grouped` | Resources grouped by compliance status |
| `GET` | `/api/v1/compliance/framework/{framework}/control/{control_id}` | Detail for a specific control |
| `GET` | `/api/v1/compliance/controls/search` | Search controls across frameworks |

### Dashboard & UI Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/dashboard` | Executive compliance dashboard (all frameworks summary) |
| `GET` | `/api/v1/compliance/trends` | Historical compliance trend data |
| `GET` | `/api/v1/compliance/accounts/{account_id}` | Compliance posture for a specific account |
| `GET` | `/api/v1/compliance/resource/drilldown` | Resource-level compliance details |
| `GET` | `/api/v1/compliance/resource/{resource_uid}/compliance` | All compliance findings for a resource |
| `GET` | `/api/v1/compliance/framework-detail/{framework}` | Framework detail view for UI |
| `GET` | `/api/v1/compliance/control-detail/{framework}/{control_id}` | Control detail for UI |

### Export

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/compliance/report/{report_id}/export` | Export report (`?format=pdf\|csv\|excel\|json`) |
| `GET` | `/api/v1/compliance/framework/{framework}/download/pdf` | Download framework report as PDF |
| `GET` | `/api/v1/compliance/framework/{framework}/download/excel` | Download framework report as Excel |
| `GET` | `/api/v1/compliance/report/{report_id}/download/pdf` | Download full report as PDF |
| `GET` | `/api/v1/compliance/report/{report_id}/download/excel` | Download full report as Excel |

All query endpoints that require scan context use query params: `csp`, `scan_id`, `tenant_id`.

---

## Database Tables (`threat_engine_compliance`)

| Table | Description |
|-------|-------------|
| `compliance_reports` | One row per scan — overall score, framework counts, full report JSONB |
| `compliance_findings` | Individual findings mapped to framework controls |
| `compliance_frameworks` | Framework definitions and metadata |
| `rule_control_mapping` | Maps `rule_id` to `(framework, control_id)` |

---

## Supported Frameworks

| Framework | ID | Controls |
|-----------|-----|---------|
| CIS AWS Foundations Benchmark v2.0 | `CIS` | 58 controls |
| CIS Azure Foundations Benchmark | `CIS-Azure` | 49 controls |
| CIS GCP Foundations Benchmark | `CIS-GCP` | 48 controls |
| ISO/IEC 27001:2022 | `ISO27001` | 93 controls |
| NIST Cybersecurity Framework v1.1 | `NIST` | 108 subcategories |
| NIST SP 800-53 Rev 5 | `NIST-800-53` | 20 control families |
| PCI-DSS v4.0 | `PCI-DSS` | 12 requirements |
| HIPAA Security Rule | `HIPAA` | 18 standards |
| GDPR | `GDPR` | 24 articles |
| SOC 2 | `SOC2` | 5 trust service criteria |
| FedRAMP | `FedRAMP` | 325 controls |
| MITRE ATT&CK | `MITRE` | 14 tactics |
| AWS Well-Architected | `AWS-WA` | 5 pillars |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `COMPLIANCE_DB_HOST` | `localhost` | Compliance DB host |
| `COMPLIANCE_DB_PORT` | `5432` | Compliance DB port |
| `COMPLIANCE_DB_NAME` | `threat_engine_compliance` | Compliance database name |
| `COMPLIANCE_DB_USER` | `postgres` | DB user |
| `COMPLIANCE_DB_PASSWORD` | — | DB password (from K8s secret) |
| `CHECK_DB_HOST` | `localhost` | Check DB host (read-only) |
| `CHECK_DB_PORT` | `5432` | Check DB port |
| `CHECK_DB_NAME` | `threat_engine_check` | Check database name |
| `CHECK_DB_PASSWORD` | — | Check DB password |
| `OUTPUT_DIR` | `/output` | Directory for JSON report (synced to S3) |
| `LOG_LEVEL` | `INFO` | Log verbosity |

---

## Running Locally

```bash
cd engine_compliance
pip install -r engine_compliance_aws/requirements.txt

export COMPLIANCE_DB_HOST=localhost
export COMPLIANCE_DB_PASSWORD=your_password
export CHECK_DB_HOST=localhost
export CHECK_DB_PASSWORD=your_password
export PYTHONPATH=$(pwd)/..

python -m uvicorn compliance_engine.api_server:app --host 0.0.0.0 --port 8010 --reload
```

---

## Docker

```bash
# Build (from repo root)
docker build -t yadavanup84/threat-engine-compliance-engine:latest -f engine_compliance/Dockerfile .

# Run
docker run -p 8010:8010 \
  -e COMPLIANCE_DB_HOST=host.docker.internal \
  -e COMPLIANCE_DB_PASSWORD=your_password \
  -e CHECK_DB_HOST=host.docker.internal \
  -e CHECK_DB_PASSWORD=your_password \
  yadavanup84/threat-engine-compliance-engine:latest
```

---

## Kubernetes Deployment

Manifest: `deployment/aws/eks/engines/engine-compliance.yaml`

```bash
kubectl apply -f deployment/aws/eks/engines/engine-compliance.yaml
kubectl rollout status deployment/engine-compliance -n threat-engine-engines
kubectl logs -f -l app=engine-compliance -n threat-engine-engines
```

The pod runs two containers:
- `engine-compliance` — FastAPI app on port 8010
- `s3-sync` — syncs `/output/` to S3 every 30s

---

## Triggering a Scan (Pipeline Mode)

```bash
# Via orchestration_id (preferred in pipeline)
curl -X POST http://engine-compliance/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
    "csp": "aws",
    "frameworks": ["CIS", "ISO27001", "NIST", "PCI-DSS"]
  }'
```

The engine will:
1. Look up `check_scan_id` + `tenant_id` from `scan_orchestration`
2. Load check findings from `threat_engine_check` DB
3. Map each `rule_id` to its framework controls
4. Aggregate pass/fail counts per control per framework
5. Calculate compliance scores (0-100%) per framework
6. Write report to `compliance_reports` + `compliance_findings` tables
7. Write `compliance_scan_id` back to `scan_orchestration`
