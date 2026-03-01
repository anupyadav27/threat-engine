# Compliance Report Sample Output

This directory contains a **sample compliance report** produced by the Compliance Engine when using **Check DB** (`/from-check-db`) or **Threat DB** (`/from-threat-db`).

## File

- **`compliance_report_sample.json`** – Example report structure (same shape as API response and `from-threat-engine`).

## Report Structure

### Top-level

| Field | Description |
|-------|-------------|
| `report_id` | UUID of the report |
| `scan_id` | Check scan ID (from Check DB) |
| `csp` | Cloud provider (`aws`, `azure`, `gcp`, etc.) |
| `tenant_id` | Tenant identifier |
| `generated_at` | ISO8601 timestamp when the report was generated |
| `source` | `check_db`, `threat_db`, or `threat_engine` |
| `executive_dashboard` | High-level summary and framework scores |
| `framework_reports` | Per-framework detailed reports |

### `executive_dashboard`

- **`summary`**: `overall_compliance_score` (0–100), `total_frameworks`, `frameworks_passing` / `_partial` / `_failing` / `_error`, and severity counts (`total_critical`, `total_high`, etc.).
- **`frameworks`**: List of `{ framework, compliance_score, status, controls_total, controls_passed, controls_failed, controls_partial, ... }`.
- **`top_critical_findings`**: Up to 5 critical/high findings with `rule_id`, `framework`, `control_id`, `service`, `region`, `resource`, etc.

### `framework_reports`

Map **framework name →** detailed report:

- **`framework`**, **`status`**, **`framework_score`**: Overall framework result and score.
- **`category_scores`**: Scores by category (e.g. IAM, Storage).
- **`controls`**: Per-control details:
  - **`control_id`**, **`control_title`**, **`control_category`**, **`status`**
  - **`check_results`**: Individual checks with `rule_id`, `check_result` (PASS/FAIL), `severity`, `service`, `region`, `resource`, `evidence`.

## How to Generate a Report

### From Check DB (PostgreSQL)

```bash
curl -X POST "http://localhost:8000/api/v1/compliance/generate/from-check-db" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-456",
    "scan_id": "check_check_20260125_143022_20260125_143145",
    "csp": "aws",
    "frameworks": ["CIS AWS Foundations Benchmark", "NIST 800-53"]
  }'
```

Use `"scan_id": "latest"` to use the most recent completed check scan for the tenant.

### From Threat DB (PostgreSQL)

```bash
curl -X POST "http://localhost:8000/api/v1/compliance/generate/from-threat-db" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-456",
    "scan_run_id": "check_check_20260125_143022_20260125_143145",
    "csp": "aws"
  }'
```

Use `"scan_run_id": "latest"` for the most recent threat report.

### Environment

- **Check DB:** `CHECK_DB_HOST`, `CHECK_DB_PORT`, `CHECK_DB_NAME`, `CHECK_DB_USER`, `CHECK_DB_PASSWORD`
- **Threat DB:** `THREAT_DB_HOST`, `THREAT_DB_PORT`, `THREAT_DB_NAME`, `THREAT_DB_USER`, `THREAT_DB_PASSWORD`

### Creating the DBs

- **Single DB:** `scripts/init-databases.sql` (engine_* schemas)
- **Single consolidated DB:** `scripts/init-databases.sql` (includes `engine_threat.threat_reports`)

## Pipeline Context

- **Discovery → Check → Threat → Compliance** (all data in PostgreSQL).
- Compliance reads from **Check DB** (`check_results`, `scans`) via `CheckDBLoader`, or from **Threat DB** (`threat_reports.report_data` → `misconfig_findings`) via `ThreatDBLoader` when Threat uses `THREAT_USE_DB=true`.
- The same report shape is used for `from-check-db`, `from-threat-db`, and `from-threat-engine` flows.
