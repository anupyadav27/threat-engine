# IAM Security Engine (Engine_IAM)

Identity & Access Management posture engine for CSPM — same pattern as the Data Security Engine. Filters configScan findings by IAM-relevant rules (metadata `domain: identity_and_access_management`) and enriches with IAM modules (least_privilege, mfa, policy_analysis, role_management, password_policy, access_control).

## Overview

- **Rule identification**: IAM-relevant = `domain == 'identity_and_access_management'` in rule metadata (e.g. `engine_check/engine_check_aws/services/*/metadata/*.yaml`).
- **Flow**: Load IAM rule IDs from rule_db → filter configScan findings by those rule IDs → enrich with `iam_security_context` / `iam_security_modules` → generate report.

## Structure

- `iam_engine/` — main package
  - `api_server.py` — FastAPI app
  - `input/rule_db_reader.py` — discover IAM rule IDs from metadata (by domain)
  - `input/configscan_reader.py` — read configScan output, `filter_iam_related_findings(..., iam_rule_ids=...)`
  - `enricher/finding_enricher.py` — add IAM context to findings
  - `mapper/rule_to_module_mapper.py` — map findings to IAM modules
  - `reporter/iam_reporter.py` — generate IAM security report

## API

- `POST /api/v1/iam-security/scan` — generate IAM report (body: `csp`, `scan_id`, `tenant_id`, optional `max_findings`)
- `GET /api/v1/iam-security/rule-ids` — list all IAM-relevant rule IDs
- `GET /api/v1/iam-security/modules` — list IAM modules
- `GET /api/v1/iam-security/modules/{module}/rules` — rules per module
- `GET /api/v1/iam-security/rules/{rule_id}` — rule IAM info
- `GET /api/v1/iam-security/findings` — IAM findings (query: `csp`, `scan_id`, optional filters)

## Run locally

```bash
# From repo root
cd engine_iam
pip install -r requirements.txt
export PYTHONPATH="${PYTHONPATH}:$(pwd)/.."
python -m uvicorn iam_engine.api_server:app --host 0.0.0.0 --port 8001
```

Default rule_db path: `engine_check/engine_check_aws/services` or `engine_input/.../rule_db/default/services`. ConfigScan output: `engines-output/{csp}-configScan-engine/output/{scan_id}/`.
