# CSPM Platform — UI Developer Handoff

> Last updated: 2026-02-28 (all API samples verified against live cluster)
> Cluster: `vulnerability-eks-cluster` | Region: `ap-south-1`
> Live tenant with data: `test-tenant` | AWS account: `588989875114`

## Overview
This is the complete specification for building the frontend UI for the CSPM (Cloud Security Posture Management) platform. The platform consists of **10 backend engines + 1 API gateway**, all deployed on AWS EKS and exposed via a single NLB endpoint.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 01 | [Navigation & Pages](01-NAVIGATION-AND-PAGES.md) | Sidebar navigation structure, page hierarchy, route definitions |
| 02 | [Page Components & APIs](02-PAGE-COMPONENTS-AND-APIS.md) | Every page wireframe with component-to-API mapping |
| 03 | [Sample Requests & Responses](03-SAMPLE-REQUESTS-AND-RESPONSES.md) | **Real** API examples with request/response JSON — tested 2026-02-28 |
| 04 | [Tech Stack & Design System](04-TECH-STACK-AND-DESIGN-SYSTEM.md) | Recommended libraries, color tokens, component patterns, data flow |

### Backend Reference Docs

| Document | Location | Description |
|----------|----------|-------------|
| Full API Reference | [`docs/API_REFERENCE_ALL_ENGINES.md`](../API_REFERENCE_ALL_ENGINES.md) | All 10 engines: every endpoint, ClusterIPs, ELB URLs, real samples |
| API Uniformity Plan | [`docs/API_UNIFORMITY.md`](../API_UNIFORMITY.md) | Current inconsistencies + proposed standard + migration path per engine |
| Scan Pipeline Flow | [`docs/SCAN_PIPELINE.md`](../SCAN_PIPELINE.md) | End-to-end scan pipeline with timing and data flow |

---

## Quick Reference

### API Base URL (External ELB)

```
http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
```

No auth required currently (open HTTP). Pass `tenant_id` as query param to all requests.

---

### Engine Direct Routing via Nginx Ingress

**IMPORTANT**: Each engine is now directly accessible via its own path prefix.
The nginx ingress strips the prefix before forwarding to the engine.

| Path Prefix | Engine | Container Port | ClusterIP | Status |
|-------------|--------|----------------|-----------|--------|
| `/onboarding/*` | engine-onboarding | 8010 | 10.100.138.231 | ✓ Running |
| `/discoveries/*` | engine-discoveries | 8001 | 10.100.188.200 | ✓ Running |
| `/check/*` | engine-check | 8002 | 10.100.43.124 | ✓ Running |
| `/inventory/*` | engine-inventory | 8022 | 10.100.246.103 | ✓ Running |
| `/compliance/*` | engine-compliance | 8000 | 10.100.48.135 | ✓ Running |
| `/threat/*` | engine-threat | 8020 | 10.100.60.108 | ✓ Running |
| `/iam/*` | engine-iam | 8001 | 10.100.170.233 | ✓ Running |
| `/datasec/*` | engine-datasec | 8003 | 10.100.155.216 | ✓ Running |
| `/secops/*` | engine-secops | 8005 | 10.100.192.50 | ✓ Running |
| `/gateway/*` | api-gateway | 8080 | 10.100.209.181 | ✓ Running |

**How prefix stripping works:**
```
UI calls:  GET /inventory/api/v1/inventory/assets?tenant_id=T
Engine receives: GET /api/v1/inventory/assets?tenant_id=T
```

---

### Engine API Summary

| Engine | Direct Path | Key Endpoints | Health Path |
|--------|------------|---------------|-------------|
| **Onboarding** | `/onboarding/api/v1/` | `GET /cloud-accounts`, `POST /cloud-accounts`, `POST /{id}/validate-credentials` | `/onboarding/api/v1/health` |
| **Discoveries** | `/discoveries/api/v1/` | `POST /discovery`, `GET /discovery/{scan_id}` | `/discoveries/health` |
| **Check** | `/check/api/v1/` | `POST /scan`, `GET /checks`, `GET /check/{id}/status` | `/check/api/v1/health` |
| **Inventory** | `/inventory/api/v1/inventory/` | `GET /assets`, `GET /relationships`, `GET /graph`, `GET /runs/latest/summary` | `/inventory/health` |
| **Compliance** | `/compliance/api/v1/compliance/` | `POST /generate/from-threat-engine`, `GET /reports`, `GET /frameworks` | `/compliance/api/v1/health` |
| **Threat** | `/threat/api/v1/` | `POST /scan`, `GET /threat/threats`, `GET /graph/summary`, `GET /checks/dashboard` | `/threat/health` |
| **IAM** | `/iam/api/v1/iam-security/` | `POST /scan`, `GET /findings`, `GET /modules` | `/iam/health` |
| **DataSec** | `/datasec/api/v1/data-security/` | `POST /scan`, `GET /findings`, `GET /modules` | `/datasec/health` |
| **SecOps** | `/secops/api/v1/secops/` | `POST /scan`, `GET /scans`, `GET /rules/stats` | `/secops/health` |
| **API Gateway** | `/gateway/` | `/health`, `/services`, `/orchestrate` | `/gateway/health` |

> **API INCONSISTENCY NOTE**: IAM uses `/iam-security/` and DataSec uses `/data-security/` as route prefixes.
> Also, IAM and DataSec require `csp=aws&scan_id=latest` on GET endpoints.
> Threat engine requires `scan_run_id` instead of `tenant_id` for per-scan analytics.
> **Full analysis and migration plan**: see [`docs/API_UNIFORMITY.md`](../API_UNIFORMITY.md)

---

### Common Query Parameters

All engines accept these parameters:
- `tenant_id` (required on most endpoints)
- `limit` / `offset` — pagination (default limit=100)
- `account_id` — filter by single cloud account
- `account_ids` — comma-separated list for multi-account

---

### Scan Pipeline Order

```
1. Onboarding  →  2. Discoveries  →  3. Check  →  4. Inventory
                                       ↓
                   5. Compliance / Threat / IAM / DataSec (parallel)
```

All engines coordinate via `scan_orchestration` table. Pass `orchestration_id` to chain them.

---

### Pages Summary (10 sections, ~25 pages)

1. **Dashboard** — Executive overview (1 page)
2. **Onboarding** — Accounts, schedules (3 pages + wizard)
3. **Scans** — Run scan, history, detail (3 pages)
4. **Inventory** — Assets, relationships, graph, drift (4 pages)
5. **Threats** — Overview, list, detail, attack paths, analytics (5+ pages)
6. **Compliance** — Dashboard, framework detail, control detail, reports (4 pages)
7. **IAM Security** — Findings by module (1 page)
8. **Data Security** — Classification, exposure, encryption (1 page + tabs)
9. **Code Security** — IaC scan results, rule library (3 pages)
10. **Settings** — Platform health, engine status (1 page)

---

### Key Design Patterns

- **Global context**: Account selector in top bar (persisted, passed as `account_id`/`account_ids`)
- **Polling**: Use `GET /api/v1/inventory/jobs/{job_id}` (async scans polled every 3s)
- **Pagination**: All list endpoints support `limit` + `offset`; response includes `total` count
- **Multi-account**: Pass `account_ids=id1,id2,id3` as comma-separated query param
- **Filtering**: Most list endpoints accept `severity`, `status`, `provider`, `region`, `resource_type`
- **Scan IDs**: Store `orchestration_id` and use it to query all engines for a specific scan run

---

## For Figma Designer

Start with the **Dashboard** and **Inventory** pages first — they use the most production-ready APIs.
All inventory endpoints are fully tested and return real data (1,529 assets, 199 relationships).
Compliance, Threat, IAM, DataSec engines are also live.

See `docs/api/03_engine_inventory.md` for complete inventory API reference with real sample data.
