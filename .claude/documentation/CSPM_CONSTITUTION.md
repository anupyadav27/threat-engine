# CSPM Platform Constitution

**Authority:** This document is the supreme rule set for the Threat Engine CSPM platform.
**Scope:** Every agent, every skill, every code change, every design decision.
**Enforcement:** Every agent reads this before acting. Any code or design that violates these rules MUST be corrected before merging.

---

## 0. Purpose & Product Vision

This platform is a **enterprise-grade, multi-tenant SaaS CSPM/CNAPP product** that competes directly with Wiz, Orca Security, Prisma Cloud, and Lacework. Every decision — UI, API, DB schema, infrastructure — must be made with that competitive bar in mind.

The platform scans multi-cloud infrastructure (AWS, Azure, GCP, OCI, AliCloud, IBM Cloud), evaluates it against 13+ compliance frameworks, detects threats using MITRE ATT&CK, and surfaces actionable findings to security teams. Speed, accuracy, and UX are the competitive differentiators.

---

## 1. SaaS Platform Constitution

### 1.1 Multi-Tenancy is Non-Negotiable

- **ALWAYS** scope every DB query by `tenant_id`. Never return cross-tenant data.
- **ALWAYS** upsert the tenant row before writing to any engine table — FK constraint is the safety net.
- **NEVER** hardcode a `tenant_id` in application code. Always derive from `AuthContext`.
- Every API endpoint **MUST** validate `tenant_id` from the authenticated `X-Auth-Context` header, never from query params or request body.
- Tenant isolation is enforced at: Gateway (AuthMiddleware) → Engine (require_permission) → DB (every query WHERE clause).

### 1.2 RBAC is Mandatory at Every Layer

- Auth flow is: `access_token` cookie → Gateway `AuthMiddleware` → `AuthContext` → `X-Auth-Context` header → engine `Depends(require_permission(...))`.
- **NEVER** add `DEV_BYPASS_AUTH` to any file for any reason. It was removed and must never return.
- Every new engine endpoint **MUST** declare `Depends(require_permission("feature:action"))`.
- The 5 roles (`platform_admin`, `org_admin`, `tenant_admin`, `analyst`, `viewer`) and 27 permissions are defined in `.claude/documentation/RBAC.md` — do not invent new roles without a migration and RBAC.md update.
- `strip_sensitive_fields()` **MUST** be called before returning findings — removes `credential_ref` and role-gated fields.
- `viewer` role receives 403 from: datasec, secops, vuln, ai_security, encryption, dbsec, container engines.

### 1.3 Audit Logs for All Mutations

- Every CREATE / UPDATE / DELETE operation in the Django platform layer **MUST** emit an audit log entry.
- Scan triggers, onboarding events, user invites, role changes are high-value audit events.
- Audit log format: `actor_id`, `tenant_id`, `action`, `resource_type`, `resource_id`, `before`, `after`, `timestamp`.

### 1.4 SaaS Operational Standards

- Every engine **MUST** expose `/api/v1/health/live` and `/api/v1/health/ready`.
- Health checks **MUST NOT** depend on external services (DB/cache) — liveness is process-only; readiness checks DB connectivity.
- No engine may write state to local disk that is not recoverable — all state lives in PostgreSQL or Neo4j.
- Every K8s deployment **MUST** have `readinessProbe` and `livenessProbe` configured.
- Resource limits (`requests` and `limits`) are mandatory on every K8s container spec.

---

## 2. Database-First Constitution

### 2.1 Schema Leads Code

- **DB schema is the single source of truth.** Define schema first, then build the API, then the UI.
- No column is added to code before it exists in the migration SQL.
- Schema SQL lives in `shared/database/schemas/<engine>_schema.sql` — keep it in sync with every migration.
- Migrations live in `shared/database/migrations/` — numbered, incremental, never destructive without explicit user approval.

### 2.2 Standard Columns — Non-Negotiable

Every engine findings table **MUST** include exactly these columns in this order:

```sql
finding_id       VARCHAR(32)   -- sha256(rule_id|resource_uid|scan_run_id)[:16] or domain equiv
scan_run_id      UUID          -- cross-engine link — the ONE identifier for a pipeline run
tenant_id        UUID
account_id       VARCHAR(512)  -- VARCHAR(512) for OCI OCID compatibility
credential_ref   TEXT
credential_type  VARCHAR(50)
provider         VARCHAR(20)   -- aws | azure | gcp | oci | alicloud | ibm
region           VARCHAR(100)
resource_uid     TEXT
resource_type    VARCHAR(200)
severity         VARCHAR(20)   -- critical | high | medium | low | informational
status           VARCHAR(20)   -- open | resolved | suppressed
first_seen_at    TIMESTAMP
last_seen_at     TIMESTAMP
```

Adding engine-specific columns is allowed. Removing or renaming standard columns is forbidden without a cross-engine migration plan.

### 2.3 JSONB Rules

- psycopg2 auto-deserializes JSONB columns to Python dicts. **NEVER** call `json.loads()` on a JSONB value from DB — it is already a dict.
- `json.dumps()` is only needed when inserting/updating JSONB from Python. Use `psycopg2.extras.Json()` or pass a serialized string.
- JSONB fields (`rule_metadata`, `emitted_fields`, `raw_response`, `engines_requested`, `engines_completed`) are dicts in Python. Access them with `result["key"]`, not `json.loads(result["key"])`.

### 2.4 Cross-Engine Linking

- `scan_run_id` (UUID) is the **one** identifier passed to all engines in a pipeline run. No engine invents its own scan identifier as the primary link.
- `scan_orchestration` table is the coordination hub — engines MUST update it on start/complete.
- `scan_orchestration.engines_requested` and `engines_completed` are **JSONB** (not TEXT[]).
- `rule_discoveries` table lives in **check DB** (`threat_engine_check`), not discoveries DB. Column is `service`, not `service_name`.

### 2.5 DB Separation by Engine

Each engine owns its own PostgreSQL database. Cross-engine data access happens via HTTP API, not direct DB queries. Never query another engine's DB from a different engine's code.

| Engine Group | Database |
|---|---|
| discoveries | threat_engine_discoveries |
| check | threat_engine_check |
| inventory | threat_engine_inventory |
| threat | threat_engine_threat |
| compliance | threat_engine_compliance |
| iam | threat_engine_iam |
| network-security | threat_engine_network |
| datasec | threat_engine_datasec |
| vulnerability | threat_engine_vulnerability |
| platform (Django) | threat_engine_platform |

---

## 3. UI / UX Competitive Standards

### 3.1 Competitive Bar

The UI **MUST** be at parity with or better than Wiz and Orca Security on:
- **Information density**: Security posture visible at a glance without scrolling.
- **Risk prioritization**: Highest-risk findings surface first, always. Risk score 0–100 prominently shown.
- **Visual clarity**: Clean card-based layout, consistent severity color coding, no cluttered tables.
- **Speed**: Dashboard loads in < 2 seconds. Charts render before full page load (progressive disclosure).
- **Actionability**: Every finding links to remediation. No dead-end screens.

### 3.2 Severity Color Coding — Always Consistent

| Severity | Color | Hex |
|---|---|---|
| Critical | Red | `#ef4444` |
| High | Orange | `#f97316` |
| Medium | Yellow | `#eab308` |
| Low | Blue | `#3b82f6` |
| Informational | Gray | `#6b7280` |
| Pass / Compliant | Green | `#22c55e` |

These colors **MUST** be used consistently across all charts, badges, and table rows. Never invent alternate severity colors.

### 3.3 Page Structure Standards

Every engine page **MUST** follow this layout:

```
┌─────────────────────────────────────────────────────┐
│  [Filter Bar]  CSP | Account | Region | Time Range  │
├──────────────────────────────────────────────────────┤
│  [KPI Cards Row]  4–6 metric cards with trend delta  │
├───────────────────────┬──────────────────────────────┤
│  [Primary Chart]      │  [Breakdown Chart]           │
│  (severity donut or   │  (framework/service bar      │
│   trend line)         │   or top-N list)             │
├───────────────────────┴──────────────────────────────┤
│  [Findings Table]  sortable, filterable, paginated   │
│  Click row → Side Panel (not full page nav)          │
└─────────────────────────────────────────────────────┘
```

### 3.4 Loading & Error States

- **MUST** use skeleton screens (not spinners) for charts and KPI cards while data loads.
- **MUST** use a spinner only for action-triggered operations (button clicks, form submits).
- **MUST** show a meaningful empty state (icon + message + call-to-action) when there is no data. Never show a blank box.
- **MUST** show an error state with retry option if an API call fails. Never silently fail.
- **NEVER** show raw JSON errors to the user. Map API errors to human-readable messages.

### 3.5 Chart Type Standards

| Use Case | Chart Type |
|---|---|
| Severity breakdown | Donut chart |
| Compliance framework score | Horizontal bar or gauge |
| Trend over time (findings, score) | Line chart |
| Top N (services, regions, accounts) | Horizontal bar chart |
| Attack paths / relationships | Graph/node visualization |
| Risk heat map | Matrix/heat map grid |
| KPI delta | Number + trend arrow (↑↓%) |

### 3.6 Data Table Standards

- **MUST** be sortable by at least severity, status, and last_seen_at.
- **MUST** be filterable by severity and status.
- **MUST** support pagination (page size: 25, 50, 100).
- **MUST** show total count and current range ("Showing 1–25 of 1,203").
- Row click opens a side panel with full finding detail — never navigates away unless the user explicitly clicks a link.
- Severity badge **MUST** appear in every findings table, always with the standard color.

### 3.7 Responsive & Theme

- **MUST** support both light and dark mode. Dark mode is the default for CSPM dashboards (Wiz standard).
- Minimum supported viewport: 1280px wide (enterprise security tools are desktop-first).
- Mobile is nice-to-have; never break desktop layout to accommodate mobile.

---

## 4. Data Architecture — BFF vs Gateway Split

This is the canonical rule for where every piece of UI data comes from. Violation of this split is a constitutional breach.

### 4.1 BFF Handles — Aggregated / Chart / Dashboard Data

```
UI → fetchView(pageName) → GET /gateway/api/v1/views/{pageName}
```

- **ALL** KPI cards, summary metrics, charts, and dashboard widgets use `fetchView()`.
- The BFF fans out to 1–N engine HTTP calls via `asyncio.gather` and returns a single UI-ready JSON.
- BFF views live in `shared/api_gateway/bff/`.
- **NEVER** add fallback data, mock data, or default values in BFF to mask engine gaps. If an engine is not returning data, fix the engine or the pipeline — do not paper over it.
- BFF **MUST** propagate `tenant_id`, `provider`, `account_id`, `region`, `scan_run_id` to every downstream engine call.
- BFF response shape is the contract — do not change field names without updating the frontend consumer.

### 4.2 Engine Gateway Handles — Tabular / Paginated / Raw Data

```
UI → direct engine call → GET /gateway/api/v1/{engine}/findings?...
```

- **ALL** paginated findings tables, drill-down lists, and export-ready raw data go through the engine gateway directly (not BFF).
- Engine endpoints for table data **MUST** support: `?page`, `?page_size`, `?severity`, `?status`, `?scan_run_id`, `?region`.
- The gateway proxies these calls with the `X-Auth-Context` header injected — engines enforce RBAC.

### 4.3 Never Cross the Streams

- UI **NEVER** calls engine APIs directly (bypassing gateway).
- UI **NEVER** calls BFF for paginated table data.
- BFF **NEVER** returns paginated raw findings (it returns aggregates only).
- BFF **NEVER** calls the gateway as a proxy — it calls engine service URLs directly within the cluster.

### 4.4 BFF View Registry

Every page that exists in the frontend **MUST** have a corresponding BFF view handler. If the BFF handler does not exist, the page must show an explicit "data unavailable" state — never fake it with mock data.

---

## 5. API Architecture Constitution

### 5.1 All Engines Follow FastAPI Standard

- Every engine is a **FastAPI** application with Uvicorn.
- URL prefix: `/api/v1/` for all business endpoints.
- Health endpoints: `GET /api/v1/health/live` and `GET /api/v1/health/ready`.
- OpenAPI docs available at `/docs` (FastAPI default).
- Every endpoint returns structured JSON — never plain text, never raw exceptions.

### 5.2 Standard Error Response

```json
{
  "error": "human_readable_error_code",
  "message": "Description of what went wrong",
  "detail": {}
}
```

HTTP status codes: 400 (bad input), 401 (not authenticated), 403 (not authorized), 404 (not found), 422 (validation error), 500 (internal error). Never return 200 with an error body.

### 5.3 Engine-to-Engine Communication

- Engines communicate via HTTP only — never direct DB queries across engine boundaries.
- All inter-engine calls within the cluster use the K8s service name (e.g., `http://engine-threat:8020`).
- Inter-engine calls **MUST** pass `scan_run_id` and `tenant_id` as query params or in the request body.
- Timeouts: set explicit `httpx` or `aiohttp` timeouts — never leave them unlimited.

### 5.4 Versioning

- All new endpoints use `/api/v1/` prefix.
- Breaking API changes require a new version prefix (`/api/v2/`) — never silently break `/v1/`.

---

## 6. Pipeline & Scan Architecture Constitution

### 6.1 Pipeline Order is Sacred

```
Onboarding → Discovery → Inventory → Check → Threat → [Compliance | IAM | DataSec | Network] → Risk → threat-narrative
  (8008)       (8001)      (8022)     (8002)  (8020)         (parallel)                          (8009)
```

- No engine may read from a later-stage engine's table.
- Check engine reads discovery_findings. Threat engine reads check_findings. Compliance reads check_findings. This order **MUST NOT** be reversed.
- Post-check engines (Compliance, IAM, DataSec, Network) run in parallel — they are independent of each other.

### 6.2 scan_run_id is the One Ring

- `scan_run_id` is a UUID generated once at scan trigger and passed to every engine.
- Every engine finding row **MUST** store `scan_run_id`.
- **NEVER** use a discovery_scan_id, job_id, or engine-local ID as the cross-engine link — only `scan_run_id`.
- `scan_orchestration` table tracks all engine completions for a given `scan_run_id`.

### 6.3 Argo Workflow Rules

- All scan triggers go through Argo Workflows — never trigger engines directly in production.
- Template names in `trigger-scan.sh`: use `network-security` (not `network`), `iam`, `check`, `threat`, etc.
- New engines **MUST** be added to `cspm-pipeline.yaml` before going to production.
- Cron pipelines (CIEM, tech scans) are separate workflow templates — do not embed them in the main scan pipeline.

---

## 7. Security Architecture Constitution

### 7.1 Mandatory Frameworks

All stories touching a new engine, endpoint, DB schema, or check rule **MUST** pass through these frameworks:

| Framework | Gate |
|---|---|
| OWASP SAMM | Design review (cspm-security-architect) + code review (cspm-security-reviewer) |
| STRIDE | Every new engine or endpoint |
| PASTA | Engines touching credentials, IAM, or network data |
| MITRE ATT&CK for Cloud | Every new check rule or finding type |
| MITRE D3FEND | Validate detection rules have defensive coverage |
| NIST CSF 2.0 | All engine stories — tag GV/ID/PR/DE/RS/RC |
| CSA CCM v4 | Every new rule maps to a CCM domain |
| SLSA Level 1-2 | All Docker image builds — pinned base images, no `latest` tag |

### 7.2 Credential & Secret Rules

- **NEVER** hardcode credentials, API keys, DB passwords, or secrets in code.
- All secrets come from AWS Secrets Manager — referenced by path in K8s env vars.
- `.env*` files, `~/.aws/`, and K8s secret manifests are **NEVER** committed to git.
- `credential_ref` field in findings is always stripped from viewer-role responses by `strip_sensitive_fields()`.

### 7.3 Injection & Tenant Isolation

- All DB queries use parameterized statements — never string-interpolated SQL.
- All API responses scope to `tenant_id` derived from `AuthContext` — never trust client-supplied `tenant_id`.
- SSRF: all outbound HTTP calls to cloud provider APIs use the official SDK (boto3, azure-sdk, google-cloud) — never raw user-supplied URLs.
- Container security: no `privileged: true`, no `hostNetwork: true`, no `runAsRoot` unless absolutely required and documented.

---

## 8. Multi-Cloud Constitution

### 8.1 Cloud-Parity Rules

- Every new check rule **SHOULD** have coverage for AWS first, then Azure, GCP, OCI, AliCloud in priority order.
- Cloud-specific implementation lives in `providers/<csp>.py` — never in the main engine file.
- `provider` field always uses lowercase abbreviations: `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`.
- Kubernetes is treated as `provider=k8s` where applicable.

### 8.2 Network Engine — 7-Layer Model is the Standard

All CSP topology providers **MUST** implement all 7 sub-layers:
`L1=isolation` → `L2=reachability` → `L3=acl` → `L4=security_group` → `L5=load_balancer` → `L6=waf` → `L7=monitoring`

Non-AWS providers (OCI, AliCloud, GCP, Azure) are pending refactor to the 7-layer model — mark incomplete providers clearly in code and in the BFF response.

---

## 9. Infrastructure Constitution

### 9.1 Docker Image Standards

- **NEVER** use `latest` tag for any image in K8s manifests.
- Image tag format: `yadavanup84/<engine>:v-<descriptor>` — descriptive, not generic version numbers.
- Base images **MUST** be pinned to a specific digest or minor version (e.g., `python:3.11-slim-bookworm`, not `python:3`).
- Every Dockerfile build context is the **repo root** — `docker build -f engines/<engine>/Dockerfile .`.
- Multi-stage builds preferred for production images to minimize attack surface.

### 9.2 Kubernetes Standards

- All engines deploy to namespace: `threat-engine-engines`.
- Every deployment **MUST** have: `readinessProbe`, `livenessProbe`, `resources.requests`, `resources.limits`.
- Services use port 80 externally, mapped to engine's `targetPort` (e.g., inventory: 80→8022).
- Spot scanners (vulnerability, discovery jobs) tolerate `spot-scanner=true:NoSchedule` taint.
- ConfigMaps and Secrets are never embedded in Deployment manifests — reference them by name.

### 9.3 Deployment Workflow — Always Follow This Order

```
1. docker build -t yadavanup84/<engine>:v-<tag> -f engines/<engine>/Dockerfile .
2. docker push yadavanup84/<engine>:v-<tag>
3. Update image tag in deployment/aws/eks/engines/<engine>.yaml
4. kubectl apply -f deployment/aws/eks/engines/<engine>.yaml
5. kubectl rollout status deployment/<engine> -n threat-engine-engines
6. kubectl logs -f -l app=<engine> -n threat-engine-engines --tail=100
```

Skipping steps 5 and 6 is not allowed. Always verify rollout and check for errors in logs.

---

## 10. Code Quality Constitution

### 10.1 No Comments Unless WHY is Non-Obvious

Default: write no comments. Only add a comment when documenting a hidden constraint, a workaround for a specific bug, or behavior that would surprise a reader. Never comment what the code does — name it clearly instead.

### 10.2 No Over-Engineering

- No abstractions for one use case.
- No error handling for impossible scenarios.
- No backwards-compatibility shims for removed code.
- No feature flags for things that can just be changed.
- Three similar lines is better than a premature abstraction.

### 10.3 Engine Code Structure Standards

Every engine **MUST** have:
```
engines/<name>/
├── main.py              # FastAPI app, router registration, startup
├── run_scan.py          # Scan entry point — receives scan_run_id
├── providers/           # Per-CSP implementations
│   ├── aws.py
│   ├── azure.py
│   └── gcp.py
├── models.py            # Pydantic request/response models
├── Dockerfile
└── requirements.txt
```

### 10.4 Shared Utilities

- `engine_common` (`shared/common/`) provides: DB connection, auth helpers, logging, standard response models.
- `consolidated_services` provides: multi-CSP credential resolution.
- **NEVER** re-implement DB connection logic, auth validation, or credential fetching in an engine — import from `engine_common`.

### 10.5 Logging Standards

- All log output goes to stdout/stderr (K8s + FluentBit captures it).
- Log format: structured JSON (level, timestamp, engine, scan_run_id, tenant_id, message).
- **NEVER** log: credentials, secrets, raw API keys, full `raw_response` JSONB at INFO level.
- Always log: scan_run_id, tenant_id, engine name at the start of every scan task.

---

## 11. Rule Authoring Constitution

### 11.1 Every Check Rule Must Have

```yaml
rule_id: <CSP>-<SERVICE>-<NUMBER>     # e.g., AWS-EC2-001
title: Human-readable title
description: What this checks and why it matters
severity: critical | high | medium | low
provider: aws | azure | gcp | oci | alicloud
service: ec2 | s3 | iam | ...
resource_type: AWS::EC2::Instance | ...
mitre_attack:
  tactic: <Tactic Name>
  technique: <Technique ID>            # e.g., T1190
compliance_frameworks:
  cis: <control-id>
  nist: <control-id>
  pci_dss: <requirement>
  iso27001: <control>
  hipaa: <safeguard>
  soc2: <criteria>
remediation: Step-by-step fix instructions
```

Partial rules (missing MITRE mapping or compliance framework coverage) **MUST NOT** be uploaded to production.

### 11.2 Rule Routing

- Config/posture rules → `check` engine (`catalog/rule/{csp}_rule_check/`)
- CIEM/log-dependent rules → `rule_ciem` (event-based, not discovery-based)
- Network rules → tag `rule_metadata.network_security.applicable=true` → surfaced by network engine Layer 1
- Do not put network rules in both check engine and network engine — they are different result types.

---

## 12. Competitive Intelligence — What We Match and Beat

### What Wiz Does That We Must Match

- **Security Graph**: visual graph of all cloud resources and their attack paths — we have Neo4j + threat engine.
- **Toxic Combinations**: compound risk from multiple misconfigurations combined — we have `threat_toxic_combos.py` BFF.
- **Agentless scanning**: no agents deployed in customer environment — all our scanning is API-based.
- **Attack path visualization**: clickable path from internet exposure to sensitive data — we have threat attack paths.
- **Risk score 0–100**: single number representing overall cloud risk — we have risk engine.

### What Orca Does That We Must Match

- **Context-aware alerts**: show blast radius and lateral movement paths for every finding.
- **Deep asset inventory**: every cloud asset with full metadata, relationships, and history.
- **Compliance posture per framework**: per-framework score with drill-down to failing controls.
- **Side-by-side remediation**: finding detail shows exactly what to fix, not just what's wrong.

### What We Must Never Regress On

1. Risk score must always be visible on the dashboard without scrolling.
2. Attack paths must be a visual graph, not a text list.
3. Compliance scores must show per-framework percentages, not just a global pass/fail.
4. Findings table must always show severity, resource, account, region, and last_seen_at.
5. Scan status must be real-time — users must never wonder if a scan is running.

---

## 13. Constitution Enforcement

### Every Agent Must

1. Read this constitution at the start of every task.
2. Flag any instruction that would violate a rule here before implementing it.
3. Refuse to write code that violates Section 1.2 (RBAC bypass), Section 4.1 (BFF fallback data), Section 7.2 (hardcoded secrets), or Section 9.1 (latest image tag).
4. When in doubt about a design decision, default to the most conservative interpretation of these rules.

### Change Process for Constitution Rules

A rule in this document can only be changed by:
1. Explicit user instruction with a stated reason.
2. A documented ADR in `.claude/documentation/ARCHITECTURE-DECISIONS.md`.
3. An update to this file with a dated changelog entry at the bottom.

---

## Changelog

| Date | Change | Reason |
|---|---|---|
| 2026-05-03 | Initial constitution created | Framework planning session — establish non-negotiable platform rules |
