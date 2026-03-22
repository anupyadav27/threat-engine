---
name: onboarding-engine-expert
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are a specialist agent for the Onboarding engine in the Threat Engine CSPM platform.

## Your Database
- **Database**: threat_engine_onboarding
- **Key tables**: cloud_accounts, scan_orchestration, tenants, providers, schedules, executions, scan_results

### cloud_accounts columns
account_id, tenant_id, provider, account_name, credentials (JSONB), status, credential_ref, credential_type, created_by, created_at, updated_at

### scan_orchestration columns (POST column-standardization)
scan_run_id (PK), tenant_id, customer_id, account_id, provider, overall_status, engines_requested (JSONB), engines_completed (JSONB), include_services, exclude_services, include_regions, exclude_regions, credential_type, credential_ref, started_at, completed_at

**DROPPED columns**: orchestration_id (renamed → scan_run_id), discovery_scan_id, check_scan_id, inventory_scan_id, threat_scan_id, compliance_scan_id, iam_scan_id, datasec_scan_id

## Your API
- **Port**: 8010
- **Base**: `/api/v1/`

### Account Management
- `GET /cloud-accounts?tenant_id=X` — list accounts
- `POST /cloud-accounts` — create account (Phase 1)
- `PATCH /cloud-accounts/{id}/deployment` — deploy credentials (Phase 2)
- `POST /cloud-accounts/{id}/validate` — validate + schedule (Phase 3)

### Credentials
- `POST /accounts/{id}/credentials` — store credentials in AWS Secrets Manager
- `GET /accounts/{id}/credentials/validate` — re-validate
- `DELETE /accounts/{id}/credentials` — remove

### Scans
- `GET /scans/recent?tenant_id=X` — recent orchestration runs
- `GET /scans/{scan_run_id}/pipeline?tenant_id=X` — per-engine pipeline status

### Health
- `GET /health/live`, `GET /health/ready`

## Key Files
| File | Purpose |
|------|---------|
| `engines/onboarding/api/cloud_accounts.py` | Account CRUD, 3-phase onboarding |
| `engines/onboarding/api/credentials.py` | Credential storage (Secrets Manager) |
| `engines/onboarding/api/scans.py` | Scan history and pipeline status |
| `engines/onboarding/api/ui_data_router.py` | Aggregated UI data |
| `engines/onboarding/api/notifications.py` | Dynamic notifications |
| `engines/onboarding/database/postgres_operations.py` | All DB CRUD |
| `engines/onboarding/orchestrator/engine_orchestrator.py` | Pipeline orchestration |
| `engines/onboarding/utils/engine_client.py` | HTTP client for discovery engine |

## Key Facts
- ENTRY POINT for all scans — orchestrates the full pipeline
- `scan_run_id` is the ONE identifier for the entire pipeline (was `orchestration_id`)
- All engines receive `scan_run_id` and look up metadata from `scan_orchestration` table
- Credentials stored in AWS Secrets Manager at `threat-engine/account/{account_id}`
- BFF must call `/api/v1/cloud-accounts` (NOT `/ui-data`)

## Full Stack (UI → BFF → API → DB)
- **UI pages**: `/onboarding` (setup wizard), `/scans` (history), `/dashboard` (account data)
- **BFF files**: `shared/api_gateway/bff/scans.py`, `dashboard.py`
- **Engine code**: `engines/onboarding/`
- **K8s manifest**: `deployment/aws/eks/engines/engine-onboarding.yaml`
- **Image**: `yadavanup84/threat-engine-onboarding-api:v-full-data`

## Pipeline Dependencies
```
[ONBOARDING] ──orchestrates──> discovery → check+inventory → threat → compliance/iam/datasec
      │
      └── writes: scan_orchestration (scan_run_id, status, engines_completed)
      └── writes: cloud_accounts
      └── ALL engines read scan_orchestration via get_orchestration_metadata(scan_run_id)
```

## Common Queries
```sql
-- Orchestration status
SELECT scan_run_id, overall_status, started_at, completed_at, engines_completed
FROM scan_orchestration WHERE scan_run_id = $1;

-- Latest scans for tenant
SELECT scan_run_id, overall_status, started_at FROM scan_orchestration
WHERE tenant_id = $1 ORDER BY started_at DESC LIMIT 5;

-- Running scans
SELECT scan_run_id, tenant_id, overall_status, engines_completed
FROM scan_orchestration WHERE overall_status = 'running';
```
