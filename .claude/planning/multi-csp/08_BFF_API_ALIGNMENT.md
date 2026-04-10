# BFF and Engine API Multi-CSP Alignment

## Scope

This is Track D — runs AFTER each CSP completes Track A (discovery) and Track B (inventory).
The UI is already multi-CSP at the component level. The work is ensuring each engine's
API endpoints return consistent schema regardless of provider.

## Current State

All engine `ui_data_router.py` files return data with AWS-specific assumptions:
- Hardcoded `provider='aws'` in some queries
- `region` displayed as AWS region names (`ap-south-1`) without CSP context
- Resource types displayed as AWS service names (EC2, S3) not normalised

## Alignment Tasks Per Engine

### Discoveries BFF
File: `engines/discoveries/common/api_server.py`
- GET /api/v1/discovery/{scan_run_id} — already returns `provider` field
- No changes needed (provider-agnostic)

### Inventory BFF
File: `engines/inventory/inventory_engine/api/ui_data_router.py`
- All endpoints need `provider` filter support
- Asset list: add `provider` to response for CSP badge in UI
- Relationship graph: add provider-specific icon hints
- No schema changes — `provider` column already in inventory_findings

### Check BFF
File: `engines/check/compliance_engine/api/ui_data_router.py`
- Findings list: already has `provider` column
- Rule display: rule names/descriptions may have AWS-specific wording
- Add: `GET /api/v1/check/findings?provider=azure` filter support

### Threat BFF
File: `engines/threat/threat_engine/api/ui_data_router.py` (if exists)
- Threat findings: already have `provider` via scan_run_id JOIN
- MITRE mapping is CSP-agnostic — no changes needed

### Compliance BFF
File: `engines/compliance/compliance_engine/api/ui_data_router.py`
- Framework mapping: CIS Benchmarks are CSP-specific (CIS AWS vs CIS Azure vs CIS GCP)
- Need: framework filter by provider
- No DB schema change needed (frameworks already tagged by provider in rule_metadata)

### IAM BFF
File: `engines/iam/iam_engine/api/ui_data_router.py`
- IAM findings are the most CSP-specific
- Azure: EntraID, Service Principals, RBAC
- GCP: IAM bindings, service accounts
- K8s: ClusterRoles, ServiceAccounts
- Need: CSP-specific IAM terminology in UI labels (handled by BFF response labels field)

## API Gateway Changes

File: `shared/api_gateway/`
- Route `/api/v1/discoveries/{provider}/...` — add provider prefix if needed
- Or: keep current routes, filter by `provider` query param
- Recommendation: query param (`?provider=azure`) — simpler, no route duplication

## Multi-CSP Dashboard Requirements

The UI needs:
1. CSP selector (AWS / Azure / GCP / K8s / OCI / IBM)
2. Per-CSP summary cards (findings by severity, compliance score)
3. Per-CSP resource counts

BFF endpoint needed:
- `GET /api/v1/summary?provider=azure` — returns compliance score, findings count,
  resource count, last scan time for that provider

## Implementation Priority

Per CSP, this is the LAST task after discovery+inventory+check all working.
Azure first, then GCP, then K8s.

Estimated effort per CSP: 2-3 days (1 full-stack/backend engineer)