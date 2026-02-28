# API Uniformity Analysis — CSPM Threat Engine Platform

**Date:** 2026-02-28
**Platform:** Multi-Cloud Security Posture Management (CSPM)
**ELB under test:** `http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com`
**Scope:** All nine active engines (onboarding, discoveries, check, inventory, threat, compliance, iam, datasec, secops)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State — Inconsistency Catalogue](#2-current-state--inconsistency-catalogue)
   - 2.1 Health Check Paths
   - 2.2 Route Prefix Patterns
   - 2.3 Query Parameter Naming
   - 2.4 Scan Trigger Endpoints
   - 2.5 Findings / Results Endpoints
   - 2.6 Pagination Response Shape
3. [Proposed Uniform API Standard](#3-proposed-uniform-api-standard)
   - 3.1 Health Check Standard
   - 3.2 Route Prefix Standard
   - 3.3 Standard Endpoint Catalogue
   - 3.4 Query Parameter Standard
   - 3.5 Scan Trigger Request/Response Standard
   - 3.6 Pagination Response Standard
4. [Per-Engine Migration Path](#4-per-engine-migration-path)
5. [Implementation Reference — Code Snippets](#5-implementation-reference--code-snippets)
6. [Summary Migration Effort Table](#6-summary-migration-effort-table)

---

## 1. Executive Summary

The platform runs nine independent FastAPI services. Because each engine was built independently, the external API surface has diverged across six distinct dimensions:

| Dimension | Number of distinct patterns found |
|---|---|
| Health check URL paths | 3 |
| Route prefixes | 5 (some non-standard) |
| Scan trigger endpoints | 6 |
| Findings endpoint names | 5 |
| Query parameter naming (`scan_id` vs `scan_run_id`, `csp` vs `provider`) | 2 per dimension |
| Pagination response shapes | 3 |

These divergences impose friction on every API consumer: the UI frontend, the scan orchestrator, and any external integration. The goal of this document is to define a single standard and provide a concrete, file-level migration path for each engine.

---

## 2. Current State — Inconsistency Catalogue

### 2.1 Health Check Paths

Live testing against the ELB reveals three distinct health-check patterns across nine engines:

| Engine | `GET /health` | `GET /api/v1/health` | `GET /api/v1/health/live` | `GET /api/v1/health/ready` | Source file |
|---|---|---|---|---|---|
| **onboarding** | no | yes (via `/api/v1/health` router prefix + empty path) | yes (`/api/v1/health/live`) | yes (`/api/v1/health/ready`) | `engine_onboarding/api/health.py` |
| **discoveries** | yes | no | yes | yes | `engine_discoveries/common/api_server.py` |
| **check** | no | yes (`/api/v1/health`) | no | no | `engine_check/engine_check_aws/api_server.py` |
| **inventory** | yes | no | no | no | `engine_inventory/inventory_engine/api/api_server.py` |
| **threat** | yes | no | no | no | `engine_threat/threat_engine/api_server.py` |
| **compliance** | no | yes (`/api/v1/health`) | no | no | `engine_compliance/compliance_engine/api_server.py` |
| **iam** | yes | no | yes | yes | `engine_iam/iam_engine/api_server.py` |
| **datasec** | yes | no | yes | yes | `engine_datasec/data_security_engine/api_server.py` |
| **secops** | yes | no | no | no | `engine_secops/scanner_engine/api_server.py` |

**Problems:**

- Kubernetes liveness and readiness probes require predictable paths. Today, only three engines (`discoveries`, `iam`, `datasec`) expose both `/api/v1/health/live` and `/api/v1/health/ready`. The remaining six use ad-hoc patterns, forcing each K8s manifest to use a different probe path.
- `GET /health` (no version prefix) conflicts with the convention that all versioned APIs live under `/api/v1/`.
- `onboarding` correctly uses `APIRouter(prefix="/api/v1/health")` with sub-routes `/live` and `/ready`, but omits `GET /health` for load-balancer target-group health checks.

### 2.2 Route Prefix Patterns

The convention across most engines is `/api/v1/{engine-name}/...`. Two engines violate this:

| Engine | Actual prefix | Expected prefix | Non-conforming? |
|---|---|---|---|
| onboarding | `/api/v1/cloud-accounts` | `/api/v1/onboarding` | Partially — cloud-accounts is a resource name, acceptable as a sub-resource |
| discoveries | `/api/v1/discovery` (scan trigger only) | `/api/v1/discoveries` | Minor (singular vs plural) |
| check | `/api/v1/scan`, `/api/v1/checks`, `/api/v1/check/{id}` | `/api/v1/check/scan`, `/api/v1/check/findings` | Yes — scan trigger lacks engine prefix |
| inventory | `/api/v1/inventory/...` | `/api/v1/inventory/...` | Correct |
| threat | `/api/v1/threat/...` + `/api/v1/scan` | `/api/v1/threat/...` | `/api/v1/scan` lacks prefix |
| compliance | `/api/v1/compliance/...` + `/api/v1/scan` | `/api/v1/compliance/...` | `/api/v1/scan` lacks prefix |
| **iam** | `/api/v1/iam-security/...` | `/api/v1/iam/...` | **Yes — wrong name** |
| **datasec** | `/api/v1/data-security/...` | `/api/v1/datasec/...` | **Yes — wrong name** |
| secops | `/api/v1/secops/...` | `/api/v1/secops/...` | Correct |

`iam-security` and `data-security` are the two highest-impact violations. Every UI component, every gateway route rule, and every test fixture hard-codes these non-standard names. The correct names follow the engine directory names (`engine_iam` → `/api/v1/iam`, `engine_datasec` → `/api/v1/datasec`).

### 2.3 Query Parameter Naming

Two parameters are named inconsistently across engines:

#### `scan_id` versus `scan_run_id`

| Engine | Parameter name used | Notes |
|---|---|---|
| threat | `scan_run_id` | Correct — this is the orchestration-level ID |
| iam | `scan_id` (required) | Maps to Threat engine's `scan_run_id` |
| datasec | `scan_id` (required) | Same as IAM |
| check | `discovery_scan_id` (in list endpoint) | Engine-internal ID, not orchestration ID |
| compliance | `scan_id` (body field) | Maps to check engine's `check_scan_id` |
| secops | `secops_scan_id` (path param) | Engine-internal ID |
| inventory | `scan_run_id` (in response) | Correct |
| discoveries | `discovery_scan_id` (internal) | Engine-internal ID |

**Recommended standard:** `scan_run_id` is the orchestration-level identifier. Engine-internal IDs (`discovery_scan_id`, `check_scan_id`, etc.) are implementation details and must not be exposed as primary query parameters on external-facing GET endpoints.

#### `csp` versus `provider`

| Engine | Parameter name | Value examples |
|---|---|---|
| iam | `csp` (required query param) | aws, azure, gcp |
| datasec | `csp` (required query param) | aws, azure, gcp |
| compliance | `csp` (body field, required) | aws, azure, gcp |
| discoveries | `provider` (body field) | aws, azure, gcp |
| check | `provider` (body field) | aws, azure, gcp |
| inventory | `providers` (body field, list) | ["aws", "azure"] |
| threat | neither — derived from orchestration | — |

**Recommended standard:** `provider` (singular lowercase string: `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`). The field `csp` is legacy terminology and conflicts with `provider` used throughout the orchestration layer and discovery engine.

### 2.4 Scan Trigger Endpoint Inconsistencies

Observed scan trigger endpoints from live engine code:

| Engine | HTTP Method | Path | Source |
|---|---|---|---|
| discoveries | POST | `/api/v1/discovery` | `engine_discoveries/common/api_server.py:271` |
| check | POST | `/api/v1/scan` | `engine_check/engine_check_aws/api_server.py:96` |
| inventory | POST | `/api/v1/scan` | `engine_inventory/inventory_engine/api/api_server.py:167` |
| threat | POST | `/api/v1/scan` | `engine_threat/threat_engine/api_server.py:175` |
| compliance | POST | `/api/v1/compliance/generate` (primary) | `engine_compliance/compliance_engine/api_server.py:430` |
| compliance | POST | `/api/v1/compliance/generate/direct` | `engine_compliance/compliance_engine/api_server.py:583` |
| compliance | POST | `/api/v1/compliance/generate/from-threat-engine` | `engine_compliance/compliance_engine/api_server.py:649` |
| compliance | POST | `/api/v1/compliance/generate/from-check-db` | `engine_compliance/compliance_engine/api_server.py:784` |
| compliance | POST | `/api/v1/compliance/generate/from-threat-db` | `engine_compliance/compliance_engine/api_server.py:914` |
| compliance | POST | `/api/v1/scan` | `engine_compliance/compliance_engine/api_server.py:1092` |
| iam | POST | `/api/v1/iam-security/scan` | `engine_iam/iam_engine/api_server.py:94` |
| datasec | POST | `/api/v1/data-security/scan` | `engine_datasec/data_security_engine/api_server.py:129` |
| secops | POST | `/api/v1/secops/scan` | `engine_secops/scanner_engine/api_server.py:259` |
| secops | POST | `/scan` (legacy) | `engine_secops/scanner_engine/api_server.py:455` |

**Problems:**

- `check`, `inventory`, and `threat` all use `POST /api/v1/scan` without an engine prefix. Since each engine runs on its own port, this works at the service level, but it is ambiguous when routing through the API gateway or load balancer and confuses developers.
- `compliance` has five different scan trigger paths, all doing variations of the same operation. This was accumulated organically and should be consolidated.
- `discoveries` uses the singular noun `discovery` instead of the engine name.

### 2.5 Findings / Results Endpoint Inconsistencies

| Engine | GET findings endpoint | Array key in response |
|---|---|---|
| threat | `GET /api/v1/threat/threats` | `threats` |
| iam | `GET /api/v1/iam-security/findings` | `findings` |
| datasec | `GET /api/v1/data-security/findings` | `findings` |
| compliance | `GET /api/v1/compliance/reports` | (varies) |
| check | `GET /api/v1/checks` | `scans` |
| secops | `GET /api/v1/secops/scan/{id}/findings` | (per-scan) |
| inventory | `GET /api/v1/inventory/assets` | `assets` |

**Problems:**

- `threat` uses `/threats` as the endpoint name and `threats` as the array key, diverging from every other engine which uses `/findings`.
- `check` uses `/checks` but returns a `scans` array (naming mismatch between URL and response body).
- `inventory` correctly uses a domain-specific noun (`assets`) for its primary collection, which is acceptable as a semantic alias.

### 2.6 Pagination Response Format

Three distinct pagination shapes exist across the platform:

**Shape A — Full pagination (inventory, threat/threats endpoint):**
```json
{
  "assets": [...],
  "total": 100,
  "limit": 20,
  "offset": 0,
  "has_more": true
}
```
Sources: `engine_inventory/inventory_engine/api/api_server.py:733`, `engine_threat/threat_engine/api_server.py:1646`

**Shape B — Partial pagination (check `/api/v1/checks`, secops list):**
```json
{
  "scans": [...],
  "total": 42
}
```
Missing: `limit`, `offset`, `has_more`. Source: `engine_check/engine_check_aws/api_server.py:306`

**Shape C — No pagination (iam, datasec `/findings`):**
```json
{
  "filters": {...},
  "summary": {...},
  "findings": [...]
}
```
No `total`, `limit`, `offset`, or `has_more` at the top level. Sources: `engine_iam/iam_engine/api_server.py:270`, `engine_datasec/data_security_engine/api_server.py:824`

Shape C is particularly problematic: IAM has 57 rules and DataSec has 62 rules applied across potentially thousands of resources. Returning all findings in a single response with no pagination is a reliability risk under load.

---

## 3. Proposed Uniform API Standard

### 3.1 Health Check Standard

All nine engines must expose all four health endpoints:

| Path | Purpose | DB check? | K8s probe type |
|---|---|---|---|
| `GET /health` | Load-balancer / ALB target-group check | No | None (infrastructure) |
| `GET /api/v1/health` | Full human-readable health including DB status and version | Yes | None (debugging) |
| `GET /api/v1/health/live` | Kubernetes liveness probe | No | `livenessProbe` |
| `GET /api/v1/health/ready` | Kubernetes readiness probe | Yes (quick ping) | `readinessProbe` |

**Response contract:**

`GET /health` — minimal, must return HTTP 200 always (even if DB is down, so the pod stays in rotation for ALB deregistration to be graceful):
```json
{ "status": "ok" }
```

`GET /api/v1/health` — full status:
```json
{
  "status": "healthy",
  "engine": "iam",
  "version": "1.0.0",
  "database": {
    "status": "connected",
    "host": "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "latency_ms": 3
  },
  "uptime_seconds": 3600
}
```

`GET /api/v1/health/live` — HTTP 200 if process is running, 503 otherwise:
```json
{ "status": "alive" }
```

`GET /api/v1/health/ready` — HTTP 200 if DB is reachable, 503 otherwise:
```json
{ "status": "ready" }
```
or on failure:
```json
{ "status": "not_ready", "reason": "database unreachable" }
```

### 3.2 Route Prefix Standard

Every engine uses its canonical kebab-case name as the URL prefix. The canonical names are derived from the engine directory name, stripping the `engine_` prefix:

| Engine directory | Canonical name | URL prefix |
|---|---|---|
| `engine_onboarding` | `onboarding` | `/api/v1/onboarding/...` |
| `engine_discoveries` | `discoveries` | `/api/v1/discoveries/...` |
| `engine_check` | `check` | `/api/v1/check/...` |
| `engine_inventory` | `inventory` | `/api/v1/inventory/...` (already correct) |
| `engine_threat` | `threat` | `/api/v1/threat/...` (already correct) |
| `engine_compliance` | `compliance` | `/api/v1/compliance/...` (already correct) |
| `engine_iam` | `iam` | `/api/v1/iam/...` (currently `/api/v1/iam-security/...`) |
| `engine_datasec` | `datasec` | `/api/v1/datasec/...` (currently `/api/v1/data-security/...`) |
| `engine_secops` | `secops` | `/api/v1/secops/...` (already correct) |

### 3.3 Standard Endpoint Catalogue

Every engine exposes the following routes under its prefix. Not every engine uses every route — engines that have no concept of "accounts" (e.g., secops) omit that route. All health routes are universal.

```
Health (ALL engines):
  GET  /health                                    → simple alive check
  GET  /api/v1/health                             → full health with DB status
  GET  /api/v1/health/live                        → liveness probe
  GET  /api/v1/health/ready                       → readiness probe

Scan lifecycle:
  POST /api/v1/{engine}/scan                      → trigger a new scan
  GET  /api/v1/{engine}/scan/{scan_run_id}/status → poll scan progress

Findings (primary read surface):
  GET  /api/v1/{engine}/findings                  → paginated findings list
  GET  /api/v1/{engine}/findings/{id}             → single finding detail

Reports (scan-level aggregations):
  GET  /api/v1/{engine}/reports                   → list scan reports
  GET  /api/v1/{engine}/reports/{scan_run_id}     → report summary for one scan

Cross-dimension summaries (optional per engine):
  GET  /api/v1/{engine}/accounts/{account_id}     → per-account summary
  GET  /api/v1/{engine}/services/{service}        → per-service summary

Module/rule introspection (IAM and DataSec):
  GET  /api/v1/{engine}/modules                   → list of analysis modules
  GET  /api/v1/{engine}/modules/{module}/rules    → rules in a module
  GET  /api/v1/{engine}/rules/{rule_id}           → single rule detail
```

Engines may add additional domain-specific endpoints (e.g., `/api/v1/compliance/frameworks/{id}`, `/api/v1/threat/analysis/prioritized`) as long as they follow the prefix rule and the pagination standard.

### 3.4 Query Parameter Standard

The following parameters are standardized across all engines. All engines must accept (and ignore gracefully if not applicable) `tenant_id`, `scan_run_id`, `provider`, `limit`, and `offset`.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tenant_id` | string | Required on all GET endpoints | Tenant isolation — never omit |
| `scan_run_id` | string | Optional | Filter by orchestration-level scan run. Replaces `scan_id` everywhere. |
| `provider` | string | Optional | Cloud provider: `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`. Replaces `csp` everywhere. |
| `account_id` | string | Optional | Filter by a single account ID |
| `account_ids` | string | Optional | Comma-separated list of account IDs for multi-account filter |
| `severity` | string | Optional | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `status` | string | Optional | Filter by outcome: `PASS`, `FAIL`, `WARN`, or threat status `open`, `resolved`, `suppressed` |
| `service` | string | Optional | Filter by cloud service name (e.g., `s3`, `iam`, `ec2`) |
| `limit` | integer | Optional (default: 50, max: 1000) | Page size |
| `offset` | integer | Optional (default: 0) | Page offset |

**Breaking changes required:**

- `csp` → rename to `provider` in `engine_iam` and `engine_datasec` (currently required query parameters on `/findings`, `/accounts/{id}`, `/services/{service}`)
- `scan_id` → rename to `scan_run_id` in `engine_iam` and `engine_datasec` (currently required query parameters on the same endpoints)
- Compliance engine body field `csp` → rename to `provider`

For the transition period, accept both names and log a deprecation warning when the old name is used:
```python
# Transition helper in each engine
def resolve_provider(provider: Optional[str] = None, csp: Optional[str] = None) -> str:
    if csp and not provider:
        logger.warning("Query param 'csp' is deprecated; use 'provider' instead")
        return csp
    return provider or "aws"
```

### 3.5 Scan Trigger Request/Response Standard

**Standard POST body for all `POST /api/v1/{engine}/scan` endpoints:**

```json
{
  "orchestration_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tenant_id": "tenant-abc",
  "account_id": "123456789012",
  "provider": "aws"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `orchestration_id` | UUID string | Required (pipeline mode) | The `scan_run_id` from `scan_orchestration` table. Mutually exclusive with ad-hoc fields. |
| `tenant_id` | string | Optional (derived from orchestration if omitted) | Overrides orchestration value when provided. |
| `account_id` | string | Optional (derived from orchestration if omitted) | Cloud account to scan. |
| `provider` | string | Optional (derived from orchestration if omitted) | `aws`, `azure`, `gcp`, etc. |

All engines already support both pipeline mode (derive context from `orchestration_id`) and ad-hoc mode (caller provides all fields). The body above unifies the naming.

**Standard scan trigger response (HTTP 202 Accepted):**

```json
{
  "scan_run_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "accepted",
  "message": "Scan started successfully",
  "poll_url": "/api/v1/{engine}/scan/{scan_run_id}/status",
  "started_at": "2026-02-28T10:30:00Z"
}
```

| Field | Notes |
|---|---|
| `scan_run_id` | The engine-internal scan ID assigned to this run. For pipeline mode this is the engine-specific sub-ID (e.g., `iam_scan_id`), not the orchestration ID. |
| `status` | Always `"accepted"` on 202; transitions to `"running"`, `"completed"`, `"failed"` at the poll URL. |
| `message` | Human-readable status line. |
| `poll_url` | Absolute path (not including host) to the status endpoint. Clients must poll this. |
| `started_at` | ISO 8601 UTC timestamp. |

**Before (current check engine — `engine_check/engine_check_aws/api_server.py:188`):**
```json
{
  "check_scan_id": "some-uuid",
  "status": "started",
  "message": "Check scan started in background"
}
```

**After (standard):**
```json
{
  "scan_run_id": "some-uuid",
  "status": "accepted",
  "message": "Check scan started in background",
  "poll_url": "/api/v1/check/scan/some-uuid/status",
  "started_at": "2026-02-28T10:30:00Z"
}
```

### 3.6 Pagination Response Standard

All list endpoints must return:

```json
{
  "<semantic_key>": [...],
  "total": 100,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

The `<semantic_key>` is the engine-appropriate noun for the collection. Use a domain-specific noun for clarity — do not force every engine to use the generic key `items`. Acceptable semantic keys:

| Engine | Endpoint | Semantic key |
|---|---|---|
| check | `/findings` | `findings` |
| inventory | `/assets` | `assets` |
| threat | `/findings` | `findings` (change from `threats`) |
| iam | `/findings` | `findings` |
| datasec | `/findings` | `findings` |
| compliance | `/reports` | `reports` |
| secops | `/{id}/findings` | `findings` |
| any engine | `/reports` | `reports` |
| any engine | `/scans` | `scans` |

**Rules:**
1. `total` must reflect the count of all records matching the filters before pagination is applied.
2. `limit` echoes the `limit` query parameter actually used (including default values).
3. `offset` echoes the `offset` query parameter actually used.
4. `has_more` is `(offset + len(<semantic_key>)) < total`.
5. On empty results, return `total: 0`, `has_more: false`, and an empty array — never a 404.

**Before (iam findings — `engine_iam/iam_engine/api_server.py:270`):**
```json
{
  "filters": { "account_id": null, "service": null, "module": null },
  "summary": { "total_findings": 347, "by_module": {}, "by_status": {} },
  "findings": [...]
}
```

**After (standard):**
```json
{
  "findings": [...],
  "total": 347,
  "limit": 50,
  "offset": 0,
  "has_more": true,
  "summary": { "by_module": {}, "by_status": {} },
  "filters": { "account_id": null, "service": null, "module": null }
}
```

Note: `summary` and `filters` remain as supplementary fields — they are not removed, only repositioned so that `findings`, `total`, `limit`, `offset`, and `has_more` are at the top level.

---

## 4. Per-Engine Migration Path

### 4.1 Engine: onboarding

**Source files:**
- `engine_onboarding/main.py`
- `engine_onboarding/api/health.py`
- `engine_onboarding/api/cloud_accounts.py`

**Current health status:** Has `/api/v1/health`, `/api/v1/health/live`, `/api/v1/health/ready` via `APIRouter(prefix="/api/v1/health")`. Missing `GET /health` (bare path).

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /health` bare-path route | `engine_onboarding/main.py` | Low |
| No route prefix changes needed (`/api/v1/cloud-accounts` is a resource name, not an engine prefix violation) | — | — |
| Scan trigger: onboarding does not run scans — N/A | — | — |

**Code change for `GET /health`** in `engine_onboarding/main.py`:
```python
@app.get("/health")
async def health_bare():
    return {"status": "ok"}
```

**Effort: Low**

---

### 4.2 Engine: discoveries

**Source files:**
- `engine_discoveries/common/api_server.py`

**Current state:** Has `GET /health`, `GET /api/v1/health/live`, `GET /api/v1/health/ready`. Missing `GET /api/v1/health` (full status). Scan trigger is `POST /api/v1/discovery` (should be `POST /api/v1/discoveries/scan`).

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /api/v1/health` full health endpoint | `engine_discoveries/common/api_server.py` | Low |
| Rename scan trigger from `POST /api/v1/discovery` to `POST /api/v1/discoveries/scan` | `engine_discoveries/common/api_server.py` | Low |
| Keep `POST /api/v1/discovery` as a deprecated alias returning HTTP 301 or 200 with deprecation warning header | `engine_discoveries/common/api_server.py` | Low |
| Update scan response to include `poll_url` | `engine_discoveries/common/api_server.py` | Low |
| Add `GET /api/v1/discoveries/scan/{scan_run_id}/status` | `engine_discoveries/common/api_server.py` | Low |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-discoveries.yaml` | Low |

**Effort: Low**

---

### 4.3 Engine: check

**Source files:**
- `engine_check/engine_check_aws/api_server.py`

**Current state:** Has `GET /api/v1/health` only. Scan trigger is `POST /api/v1/scan` (no engine prefix). Results endpoint is `GET /api/v1/checks` returning `{"scans": [...], "total": N}` — missing `limit`, `offset`, `has_more`.

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /health` bare-path route | `engine_check/engine_check_aws/api_server.py` | Low |
| Add `GET /api/v1/health/live` and `GET /api/v1/health/ready` | `engine_check/engine_check_aws/api_server.py` | Low |
| Rename `POST /api/v1/scan` to `POST /api/v1/check/scan` | `engine_check/engine_check_aws/api_server.py` | Low |
| Keep `POST /api/v1/scan` as deprecated alias | `engine_check/engine_check_aws/api_server.py` | Low |
| Rename `GET /api/v1/checks` to `GET /api/v1/check/findings` | `engine_check/engine_check_aws/api_server.py` | Low |
| Add `limit`, `offset`, `has_more` to `/check/findings` response | `engine_check/engine_check_aws/api_server.py` | Low |
| Change response key from `scans` to `findings` in `/check/findings` | `engine_check/engine_check_aws/api_server.py` | Low |
| Rename `GET /api/v1/check/{check_scan_id}/status` to `GET /api/v1/check/scan/{scan_run_id}/status` | `engine_check/engine_check_aws/api_server.py` | Low |
| Update scan trigger response to standard format (add `poll_url`, rename `check_scan_id` to `scan_run_id`) | `engine_check/engine_check_aws/api_server.py` | Low |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-check.yaml` | Low |

**Effort: Low-Medium** (many small changes, no logic changes)

---

### 4.4 Engine: inventory

**Source files:**
- `engine_inventory/inventory_engine/api/api_server.py`

**Current state:** Has `GET /health` only. Scan trigger is `POST /api/v1/scan` (no engine prefix) plus `POST /api/v1/inventory/scan/async`, `POST /api/v1/inventory/scan/discovery`. Pagination is correct on `/assets` (has `assets`, `total`, `limit`, `offset`, `has_more`).

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /api/v1/health` full health endpoint | `engine_inventory/inventory_engine/api/api_server.py` | Low |
| Add `GET /api/v1/health/live` and `GET /api/v1/health/ready` | `engine_inventory/inventory_engine/api/api_server.py` | Low |
| Rename `POST /api/v1/scan` to `POST /api/v1/inventory/scan` | `engine_inventory/inventory_engine/api/api_server.py` | Low |
| Keep `POST /api/v1/scan` as deprecated alias | `engine_inventory/inventory_engine/api/api_server.py` | Low |
| Consolidate `POST /api/v1/inventory/scan/discovery` and `POST /api/v1/inventory/scan/async` under `POST /api/v1/inventory/scan` with optional `async` query param | `engine_inventory/inventory_engine/api/api_server.py` | Medium |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-inventory.yaml` | Low |

**Effort: Low-Medium**

---

### 4.5 Engine: threat

**Source files:**
- `engine_threat/threat_engine/api_server.py`

**Current state:** Has `GET /health` only. Scan trigger is `POST /api/v1/scan` (no engine prefix) plus `POST /api/v1/threat/generate/async`. Primary findings list is `GET /api/v1/threat/threats` returning `{"threats": [...], "total": N, "limit": N, "offset": N, "has_more": bool}` — pagination is correct but endpoint name and key name should change to `findings`.

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /api/v1/health` full health endpoint | `engine_threat/threat_engine/api_server.py` | Low |
| Add `GET /api/v1/health/live` and `GET /api/v1/health/ready` | `engine_threat/threat_engine/api_server.py` | Low |
| Rename `POST /api/v1/scan` to `POST /api/v1/threat/scan` | `engine_threat/threat_engine/api_server.py` | Low |
| Keep `POST /api/v1/scan` and `POST /api/v1/threat/generate/async` as deprecated aliases | `engine_threat/threat_engine/api_server.py` | Low |
| Add `GET /api/v1/threat/findings` as alias for `GET /api/v1/threat/threats` (keep `/threats` for backward compat) | `engine_threat/threat_engine/api_server.py` | Low |
| Return `findings` as the array key alongside `threats` (or switch key to `findings` at next major version) | `engine_threat/threat_engine/api_server.py` | Low |
| `scan_run_id` query parameter naming is already correct on `/threats` — no change needed | — | — |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-threat.yaml` (does not exist yet — create from template) | Low |

**Effort: Low**

---

### 4.6 Engine: compliance

**Source files:**
- `engine_compliance/compliance_engine/api_server.py`

**Current state:** Has `GET /api/v1/health` only. Has five distinct scan trigger variants plus `POST /api/v1/scan`. Uses `csp` as body field name throughout. Pagination on `/compliance/reports` needs verification.

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /health` bare-path route | `engine_compliance/compliance_engine/api_server.py` | Low |
| Add `GET /api/v1/health/live` and `GET /api/v1/health/ready` | `engine_compliance/compliance_engine/api_server.py` | Low |
| Designate `POST /api/v1/compliance/scan` as the single canonical scan trigger | `engine_compliance/compliance_engine/api_server.py` | Medium |
| Keep `POST /api/v1/compliance/generate`, `POST /api/v1/scan` as deprecated aliases | `engine_compliance/compliance_engine/api_server.py` | Low |
| Deprecate `generate/direct`, `generate/from-threat-engine`, `generate/from-check-db`, `generate/from-threat-db` — consolidate logic into the single `POST /api/v1/compliance/scan` using `mode` parameter | `engine_compliance/compliance_engine/api_server.py` | Medium |
| Rename body field `csp` to `provider` (accept both during transition) | `engine_compliance/compliance_engine/api_server.py` | Medium |
| Add `limit`, `offset`, `has_more` to `GET /api/v1/compliance/reports` | `engine_compliance/compliance_engine/api_server.py` | Low |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-compliance.yaml` | Low (does not appear in git status — verify file exists) |

**Effort: Medium** (consolidating 5 scan trigger variants is the highest-risk change)

---

### 4.7 Engine: iam

**Source files:**
- `engine_iam/iam_engine/api_server.py`

**Current state:** Has `GET /health`, `GET /api/v1/health/live`, `GET /api/v1/health/ready`. All routes use `/api/v1/iam-security/` prefix. `GET /api/v1/iam-security/findings` requires `csp` and `scan_id` as mandatory query parameters. Returns findings without pagination envelope.

This is the **highest-impact** breaking change: `iam-security` → `iam`. The UI and orchestrator call this prefix directly.

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /api/v1/health` full health endpoint | `engine_iam/iam_engine/api_server.py` | Low |
| Add new routes under `/api/v1/iam/` mirroring all `/api/v1/iam-security/` routes | `engine_iam/iam_engine/api_server.py` | Medium |
| Keep `/api/v1/iam-security/` routes as deprecated aliases with `Deprecation` response header | `engine_iam/iam_engine/api_server.py` | Low |
| Rename `POST /api/v1/iam-security/scan` to `POST /api/v1/iam/scan` | `engine_iam/iam_engine/api_server.py` | Low (part of above) |
| Rename `GET /api/v1/iam-security/findings` to `GET /api/v1/iam/findings` | `engine_iam/iam_engine/api_server.py` | Low (part of above) |
| Make `scan_id` optional and rename to `scan_run_id` (accept both during transition) | `engine_iam/iam_engine/api_server.py` | Medium |
| Make `csp` optional and rename to `provider` (accept both during transition) | `engine_iam/iam_engine/api_server.py` | Medium |
| Add `limit`, `offset`, `has_more`, `total` to findings response | `engine_iam/iam_engine/api_server.py` | Medium |
| Rename `GET /api/v1/iam-security/modules` to `GET /api/v1/iam/modules` | `engine_iam/iam_engine/api_server.py` | Low (part of above) |
| Update API gateway / ingress route rules | `deployment/aws/eks/` ingress or gateway config | Medium |
| Update all UI components calling `/iam-security/` | UI codebase (out of scope of this document) | High |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-onboarding.yaml` or equivalent | Low |

**Effort: High** (URL rename requires coordinated change across engine, gateway, and UI)

---

### 4.8 Engine: datasec

**Source files:**
- `engine_datasec/data_security_engine/api_server.py`

**Current state:** Has `GET /health`, `GET /api/v1/health/live`, `GET /api/v1/health/ready`. All routes use `/api/v1/data-security/` prefix. Same pattern as IAM for `csp` / `scan_id` mandatory parameters and missing pagination.

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /api/v1/health` full health endpoint | `engine_datasec/data_security_engine/api_server.py` | Low |
| Add new routes under `/api/v1/datasec/` mirroring all `/api/v1/data-security/` routes | `engine_datasec/data_security_engine/api_server.py` | Medium |
| Keep `/api/v1/data-security/` routes as deprecated aliases with `Deprecation` response header | `engine_datasec/data_security_engine/api_server.py` | Low |
| Rename `POST /api/v1/data-security/scan` to `POST /api/v1/datasec/scan` | `engine_datasec/data_security_engine/api_server.py` | Low (part of above) |
| Make `scan_id` optional and rename to `scan_run_id` | `engine_datasec/data_security_engine/api_server.py` | Medium |
| Make `csp` optional and rename to `provider` | `engine_datasec/data_security_engine/api_server.py` | Medium |
| Add `limit`, `offset`, `has_more`, `total` to `GET /api/v1/datasec/findings` | `engine_datasec/data_security_engine/api_server.py` | Medium |
| Rename `GET /api/v1/data-security/catalog` to `GET /api/v1/datasec/catalog` | `engine_datasec/data_security_engine/api_server.py` | Low (part of above) |
| Update API gateway / ingress route rules | `deployment/aws/eks/` ingress or gateway config | Medium |
| Update all UI components calling `/data-security/` | UI codebase | High |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-datasec.yaml` or equivalent | Low |

**Effort: High** (same reasoning as IAM — URL rename is a breaking change requiring UI coordination)

---

### 4.9 Engine: secops

**Source files:**
- `engine_secops/scanner_engine/api_server.py`

**Current state:** Has `GET /health`. Routes use `/api/v1/secops/` prefix (correct). Has a legacy `POST /scan` endpoint. Missing `GET /api/v1/health`, `GET /api/v1/health/live`, `GET /api/v1/health/ready`. The per-scan findings endpoint `GET /api/v1/secops/scan/{id}/findings` is acceptable as a sub-resource of the scan, but should also be exposed at `GET /api/v1/secops/findings?scan_run_id={id}` for consistency with other engines.

**Changes required:**

| Change | File | Effort |
|---|---|---|
| Add `GET /api/v1/health` full health endpoint | `engine_secops/scanner_engine/api_server.py` | Low |
| Add `GET /api/v1/health/live` and `GET /api/v1/health/ready` | `engine_secops/scanner_engine/api_server.py` | Low |
| Deprecate `POST /scan` (legacy bare path) with redirect or warning | `engine_secops/scanner_engine/api_server.py` | Low |
| Add `GET /api/v1/secops/findings` with standard pagination and `scan_run_id` filter | `engine_secops/scanner_engine/api_server.py` | Medium |
| Rename internal field `secops_scan_id` to `scan_run_id` in responses | `engine_secops/scanner_engine/api_server.py` | Medium |
| Update K8s manifest probe paths | `deployment/aws/eks/engines/engine-secops.yaml` (verify file exists) | Low |

**Effort: Low-Medium**

---

## 5. Implementation Reference — Code Snippets

### 5.1 Reusable Health Router (copy into each engine)

This snippet can be dropped into any engine's `api_server.py` to add all four health endpoints at once:

```python
import time
from fastapi import APIRouter

_start_time = time.time()

health_router = APIRouter(tags=["health"])

@health_router.get("/health")
async def health_bare():
    """Load-balancer / ALB target-group health check. Always 200."""
    return {"status": "ok"}

@health_router.get("/api/v1/health")
async def health_full():
    """Full health check including DB connectivity and uptime."""
    db_status = "unknown"
    db_latency_ms = None
    try:
        t0 = time.time()
        _get_health_db_manager().ping()  # engine-specific DB ping
        db_latency_ms = round((time.time() - t0) * 1000, 1)
        db_status = "connected"
    except Exception as exc:
        db_status = f"error: {exc}"
    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "engine": ENGINE_NAME,          # set per-engine constant
        "version": ENGINE_VERSION,      # set per-engine constant
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms,
        },
        "uptime_seconds": round(time.time() - _start_time),
    }

@health_router.get("/api/v1/health/live")
async def health_live():
    """Kubernetes liveness probe. Returns 200 if process is alive."""
    return {"status": "alive"}

@health_router.get("/api/v1/health/ready")
async def health_ready():
    """Kubernetes readiness probe. Returns 200 only if DB is reachable."""
    try:
        _get_health_db_manager().ping()
        return {"status": "ready"}
    except Exception as exc:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": str(exc)},
        )

# In api_server.py:
# app.include_router(health_router)
```

### 5.2 Standard Scan Trigger Response Helper

```python
from datetime import datetime, timezone

def scan_accepted_response(
    engine: str,
    scan_run_id: str,
    message: str = "Scan started successfully",
) -> dict:
    """Return a standard HTTP 202 scan-accepted response body."""
    return {
        "scan_run_id": scan_run_id,
        "status": "accepted",
        "message": message,
        "poll_url": f"/api/v1/{engine}/scan/{scan_run_id}/status",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
```

### 5.3 Standard Paginated Response Helper

```python
from typing import Any, List

def paginated_response(
    items: List[Any],
    total: int,
    limit: int,
    offset: int,
    key: str = "findings",
) -> dict:
    """Return a standard paginated response envelope."""
    return {
        key: items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": (offset + len(items)) < total,
    }
```

Usage example for IAM findings:
```python
@app.get("/api/v1/iam/findings")
async def get_iam_findings(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    # deprecated — accepted for backward compat
    scan_id: Optional[str] = Query(None),
    csp: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    effective_scan_id = scan_run_id or scan_id
    effective_provider = provider or csp

    all_findings = get_all_iam_findings(tenant_id, effective_scan_id, effective_provider)
    page = all_findings[offset : offset + limit]
    return paginated_response(page, total=len(all_findings), limit=limit, offset=offset)
```

### 5.4 Deprecation Header Middleware

Add this to engines that keep old routes as aliases, so API consumers are warned automatically:

```python
from fastapi import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware

DEPRECATED_PATHS = {
    "/api/v1/iam-security/": "/api/v1/iam/",
    "/api/v1/data-security/": "/api/v1/datasec/",
    "/api/v1/scan": "/api/v1/{engine}/scan",
}

class DeprecationHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        for old_prefix, new_prefix in DEPRECATED_PATHS.items():
            if request.url.path.startswith(old_prefix):
                response.headers["Deprecation"] = "true"
                response.headers["Sunset"] = "2026-06-01"
                response.headers["Link"] = (
                    f'<{request.url.path.replace(old_prefix, new_prefix)}>; rel="successor-version"'
                )
                break
        return response

# app.add_middleware(DeprecationHeaderMiddleware)
```

---

## 6. Summary Migration Effort Table

| Engine | Health Fix | Route Prefix Fix | Scan Trigger Fix | Findings Endpoint Fix | Pagination Fix | Param Naming Fix | Total Effort |
|---|---|---|---|---|---|---|---|
| **onboarding** | Low (add 1 route) | N/A | N/A | N/A | N/A | N/A | **Low** |
| **discoveries** | Low (add `/api/v1/health`) | Low (add prefix, alias old) | Low | Low (add `/findings`) | N/A | N/A | **Low** |
| **check** | Low (add 3 routes) | Low (add prefix, alias old) | Low | Low (rename + alias) | Low (add limit/offset/has_more) | N/A | **Low-Medium** |
| **inventory** | Low (add 3 routes) | Low (add prefix, alias old) | Medium (consolidate 3 variants) | N/A (assets correct) | Already correct | N/A | **Low-Medium** |
| **threat** | Low (add 3 routes) | Low (prefix existing `/api/v1/scan`) | Low | Low (alias `/findings`) | Already correct | N/A | **Low** |
| **compliance** | Low (add 2 routes) | Low (prefix `/api/v1/scan`) | Medium (consolidate 5 variants) | N/A | Low (add limit/offset) | Medium (`csp` → `provider`) | **Medium** |
| **iam** | Low (add `/api/v1/health`) | **High** (rename prefix + gateway + UI) | Low (part of prefix rename) | Low (part of prefix rename) | Medium (add pagination) | Medium (`csp`/`scan_id` → `provider`/`scan_run_id`, make optional) | **High** |
| **datasec** | Low (add `/api/v1/health`) | **High** (rename prefix + gateway + UI) | Low (part of prefix rename) | Low (part of prefix rename) | Medium (add pagination) | Medium (`csp`/`scan_id` → `provider`/`scan_run_id`, make optional) | **High** |
| **secops** | Low (add 3 routes) | N/A (already correct) | Low (deprecate `/scan`) | Medium (add `/findings`) | Medium (add to list endpoints) | N/A | **Low-Medium** |

### Recommended Implementation Order

The changes are mostly independent, but the following order minimises risk:

1. **Health endpoints** (all engines, 1 day) — No logic changes, immediate K8s probe benefit.
2. **Onboarding** (0.5 days) — Simplest engine, good test of the change template.
3. **SecOps** (1 day) — Self-contained, no UI dependency.
4. **Check + Discoveries + Threat** (2 days) — Medium scope, add prefixes and aliases.
5. **Inventory + Compliance** (2 days) — Medium scope, consolidation of multiple scan trigger variants.
6. **IAM + DataSec** (3 days + UI coordination) — Must be coordinated with the UI team. Deploy with old routes kept as aliases first, then remove aliases after UI migration is confirmed. Gateway route rules must be updated atomically with the engine deploy.

**Total estimate:** 10–14 engineering days including testing and rollout, assuming IAM and DataSec UI migrations are parallel-tracked by the UI team.

---

*This document reflects the state of the live ELB and engine source code as of 2026-02-28. Engine source files referenced are under `/Users/apple/Desktop/threat-engine/engine_*/`. Re-audit after each migration phase to verify the as-built state matches this specification.*
