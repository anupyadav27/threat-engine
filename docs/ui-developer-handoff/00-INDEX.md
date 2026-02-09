# CSPM Platform — UI Developer Handoff

## Overview
This is the complete specification for building the frontend UI for the CSPM (Cloud Security Posture Management) platform. The platform consists of **9 backend engines + 1 API gateway**, all deployed on AWS EKS and exposed via a single NLB endpoint.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 01 | [Navigation & Pages](01-NAVIGATION-AND-PAGES.md) | Sidebar navigation structure, page hierarchy, route definitions |
| 02 | [Page Components & APIs](02-PAGE-COMPONENTS-AND-APIS.md) | Every page wireframe with component-to-API mapping |
| 03 | [Sample Requests & Responses](03-SAMPLE-REQUESTS-AND-RESPONSES.md) | Real API examples with request/response JSON for every endpoint |
| 04 | [Tech Stack & Design System](04-TECH-STACK-AND-DESIGN-SYSTEM.md) | Recommended libraries, color tokens, component patterns, data flow |

## Quick Reference

### API Base URLs
```
NLB:  http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
```

### Engine Routing (via Nginx Ingress)
| Path Prefix | Engine | Internal Port | Description |
|-------------|--------|---------------|-------------|
| `/gateway/*` | API Gateway | 8000 | Orchestration, service registry, proxy |
| `/secops/*` | SecOps Scanner | 8009 | Code security scanning |

> **Note**: Other engines are accessed via the API Gateway proxy:
> `/gateway/api/v1/discovery/*`, `/gateway/api/v1/check/*`, etc.

### Engines Summary
| Engine | API Prefix | Endpoints | Primary Use |
|--------|-----------|-----------|-------------|
| **API Gateway** | `/gateway/` | ~10 | Orchestration, routing |
| **Onboarding** | `/gateway/api/v1/onboarding/` | ~20 | Tenants, accounts, schedules |
| **Discovery** | `/gateway/api/v1/discovery/` | ~8 | Cloud resource discovery |
| **Check** | `/gateway/api/v1/check/` | ~7 | Misconfig rule checks |
| **Threat** | `/gateway/api/v1/threat/` | ~45 | Threats, analysis, hunting, intel |
| **Inventory** | `/gateway/api/v1/inventory/` | ~18 | Assets, relationships, drift |
| **Compliance** | `/gateway/api/v1/compliance/` | ~32 | Framework compliance |
| **IAM Security** | `/gateway/api/v1/iam-security/` | ~7 | Identity & access findings |
| **Data Security** | `/gateway/api/v1/data-security/` | ~16 | Data catalog, classification |
| **SecOps** | `/secops/api/v1/secops/` | ~7 | Code scanning (14 languages) |

### Total: ~170 API endpoints

### Pages Summary (10 sections, ~25 pages)
1. **Dashboard** — Executive overview (1 page)
2. **Onboarding** — Tenants, accounts, schedules (3 pages + onboarding wizard)
3. **Scans** — Run scan, history, detail (3 pages)
4. **Inventory** — Assets, relationships, graph, drift (4 pages)
5. **Threats** — Overview, list, detail, attack paths, analytics, hunting, intel (7 pages)
6. **Compliance** — Dashboard, framework detail, control detail, reports (4 pages)
7. **IAM Security** — Findings, modules (1 page)
8. **Data Security** — Catalog, classification, lineage, residency, activity (1 page + tabs)
9. **Code Security** — Run scan, results, rule library (3 pages)
10. **Settings** — Platform health, engine status (1 page)

### Key Design Patterns
- **Global context**: Tenant + Account selector in top bar (persisted across pages)
- **Polling**: Scan status endpoints polled every 3s until completion
- **Pagination**: All list endpoints support `limit` + `offset`
- **Filtering**: Severity, status, category, region, account, service
- **Export**: PDF/Excel download for compliance reports
- **Graph visualization**: Force-directed graph for inventory relationships and attack paths

## For Figma Designer
Start with the **Dashboard** and **Threat List** pages first — they represent the core user experience. Use the wireframes in document 02 as the layout foundation, and the component patterns in document 04 for the design system.
