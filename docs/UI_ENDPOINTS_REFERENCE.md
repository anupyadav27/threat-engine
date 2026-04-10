# UI Endpoints Reference — SecOps & Vulnerability Modules

> **Base URL**: `http://localhost:3002/ui`
> All routes below are relative to this base. For example `/vulnerability` → `http://localhost:3002/ui/vulnerability`

---

## Table of Contents

- [SecOps Module](#secops-module)
- [Vulnerability Module](#vulnerability-module)
- [Backend API Proxy](#backend-api-proxy)
- [Backend Engine APIs](#backend-engine-apis)
- [Authentication](#authentication)

---

## SecOps Module

Base path: `/secops`
Backend engine: SecOps Scanner (EKS service — secops-scanner)

---

### `GET /secops`
**SecOps Dashboard**

Main overview page showing unified security posture across SAST, DAST, and SCA scans.

| Element | Description |
|---------|-------------|
| KPI cards | Total findings, critical count, scan status, active projects |
| Findings table | Unified view across all scan types with severity badges and source labels |
| Severity filter | Filter by CRITICAL / HIGH / MEDIUM / LOW |
| Scan tabs | Switch between SAST, DAST, SCA views |
| Launch scan | Trigger new SAST or DAST scan from this page |

**APIs called:**
```
GET  /secops/api/v1/secops/sast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/dast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/sca/api/v1/sbom              (X-API-Key: sbom-api-key-2024)
GET  /secops/api/v1/secops/sast/scan/{id}/findings?limit=200
GET  /secops/api/v1/secops/dast/scan/{id}/findings?limit=200
POST /secops/api/v1/secops/sast/scan                     (launch new SAST scan)
POST /secops/api/v1/secops/dast/scan                     (launch new DAST scan)
```

---

### `GET /secops/projects`
**Projects List**

All scanned repositories grouped by project, showing aggregated risk posture per repo.

| Element | Description |
|---------|-------------|
| KPI cards | Total projects, total vulnerabilities, critical issues, last scan time |
| Projects table | Name, repo URL, risk score, critical/high counts, languages, last scan |
| New Scan modal | Launch SAST scan — enter repo URL and branch |
| Filters | Risk level (critical / high / medium / low), language |
| Pagination | 20 rows per page |

**APIs called:**
```
GET  /secops/api/v1/secops/sast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/dast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/sca/api/v1/sbom
POST /secops/api/v1/secops/sast/scan    body: { repo_url, branch, tenant_id }
```

---

### `GET /secops/projects/[projectId]`
**Project Detail**

Full security breakdown for a single repository across SAST, DAST, and SCA.

| Element | Description |
|---------|-------------|
| Tabs | SAST · DAST · SCA — each shows its own findings |
| Severity bar | Distribution of findings by severity |
| Findings table | Expandable rows with description, remediation, CVSS vector |
| Severity filter | Per-tab filtering |

`projectId` = URL-encoded repository URL (e.g. `https%3A%2F%2Fgithub.com%2Forg%2Frepo`)

**APIs called:**
```
GET  /secops/api/v1/secops/sast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/dast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/sca/api/v1/sbom
GET  /secops/api/v1/secops/sast/scan/{id}/findings?limit=500
GET  /secops/api/v1/secops/dast/scan/{id}/findings?limit=500
GET  /secops/api/v1/secops/sca/api/v1/sbom/{id}
```

---

### `GET /secops/[scanId]`
**SAST Scan Detail**

Detailed findings for a single SAST scan — file paths, line numbers, rule IDs.

| Element | Description |
|---------|-------------|
| KPI cards | Total findings, critical+high, languages scanned, scan timestamp |
| Findings table | Severity, rule ID, file path, line number, description, remediation |
| Severity bar chart | Distribution of all findings |
| Expandable rows | Code snippet context, remediation guidance, copy file path |
| Severity filter | CRITICAL / HIGH / MEDIUM / LOW buttons |

**APIs called:**
```
GET  /secops/api/v1/secops/sast/scan/{scanId}/status?tenant_id=test-tenant
GET  /secops/api/v1/secops/sast/scan/{scanId}/findings?limit=500
```

---

### `GET /secops/dast/[scanId]`
**DAST Scan Detail**

Web vulnerability findings from a dynamic application security test.

| Element | Description |
|---------|-------------|
| KPI cards | Total findings, critical+high, endpoints discovered, attacks sent |
| Findings table | Severity, vulnerability type, HTTP method badge, endpoint URL, CVSS |
| HTTP method badges | GET · POST · PUT · DELETE · PATCH |
| Expandable rows | Remediation, CVSS vector, external link to target URL |
| Severity filter | CRITICAL / HIGH / MEDIUM / LOW |

**APIs called:**
```
GET  /secops/api/v1/secops/dast/scan/{scanId}/status?tenant_id=test-tenant
GET  /secops/api/v1/secops/dast/scan/{scanId}/findings?limit=500
```

---

### `GET /secops/sca/[sbomId]`
**SCA / SBOM Detail**

Software Composition Analysis — vulnerable third-party dependencies and license inventory.

| Element | Description |
|---------|-------------|
| KPI cards | Total components, vulnerable packages, total CVEs, license types |
| Tab: Vulnerable Packages | Package name, version, PURL, CVE count, risk level, CVE IDs |
| Tab: License Analysis | License type, component count, percentage bar chart |
| Expandable rows | All CVEs with direct NVD links |
| Sort | By risk level or package name |

**APIs called:**
```
GET  /secops/api/v1/secops/sca/api/v1/sbom/{sbomId}    (X-API-Key: sbom-api-key-2024)
```

---

### `GET /secops/reports`
**Security Reports**

Aggregated trends and historical analysis across all scans and projects.

| Element | Description |
|---------|-------------|
| Trend chart | Findings over time (weekly/monthly) |
| Scan status dashboard | Execution history — pass/fail rates |
| Project summary table | Risk score trend indicators (↑ / ↓ / stable) |
| Time range selector | 7d · 30d · 90d · 180d · 365d |
| Export | Download report data |

**APIs called:**
```
GET  /secops/api/v1/secops/sast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/dast/scans?tenant_id=test-tenant
GET  /secops/api/v1/secops/sca/api/v1/sbom
```

---

## Vulnerability Module

Base path: `/vulnerability`
Backend engine: Vulnerability Engine (EKS LoadBalancer — `vulnerability-engine-service`)

> **Note:** All vulnerability API calls go through the Next.js proxy at `/api/vuln/[...path]`
> which forwards to the backend LoadBalancer with API key injection.

---

### `GET /vulnerability`
**Vulnerability Dashboard**

Main dashboard — select an agent and see its vulnerability posture and latest scan summary.

| Element | Description |
|---------|-------------|
| Agent picker | Search/select from registered agents or enter agent ID manually |
| KPI cards | Total vulnerabilities, critical count, high count, packages scanned |
| Recent findings table | Latest 50 vulnerabilities with CVSS scores and source |
| Severity trend | 365-day rolling chart of findings by severity |
| Latest scan card | Status, packages, vuln count, scan duration |

**APIs called:**
```
GET  /api/v1/agents/                                              (no auth — public)
GET  /api/v1/scans?agent_id={agentId}&limit=100
GET  /api/v1/vulnerabilities/stats/severity?agent_id={agentId}&days=365
GET  /api/v1/scans/{scanId}
GET  /api/v1/vulnerabilities?agent_id={agentId}&limit=50
```

---

### `GET /vulnerability/scans`
**Scan History**

All scans for the selected agent with status, counts, and navigation to detail.

| Element | Description |
|---------|-------------|
| KPI strip | Total scans, completed, packages scanned, total vulns |
| Status filter | All · Completed · Running · Failed |
| Scans table | Scan ID (+LATEST badge), status, packages, vulnerabilities, duration, mode, started at |
| Auto-refresh | Polls every 8 seconds while any scan is in "running" state |

**APIs called:**
```
GET  /api/v1/scans?agent_id={agentId}&limit=200
```

---

### `GET /vulnerability/scans/[scanId]`
**Scan Detail**

Complete vulnerability report for one scan — filterable, searchable, paginated.

| Element | Description |
|---------|-------------|
| KPI cards | Packages scanned, vulnerabilities found, affected packages, scan duration |
| Severity filter | CRITICAL · HIGH · MEDIUM · LOW with counts |
| Search | Searches CVE ID, package name, description |
| Findings table | CVE ID, severity pill, CVSS score (color-coded), source badge, package/version, description (2-line clip), remediation (2-line clip) |
| Expandable rows | Full description, CVSS vector, full remediation, NVD link |
| Pagination | 25 rows per page (default) |
| Auto-refresh | Polls every 8 seconds while scan is running |

**CVSS color coding:**
| Score | Color |
|-------|-------|
| 9.0 – 10.0 | Red (Critical) |
| 7.0 – 8.9  | Orange (High) |
| 4.0 – 6.9  | Yellow (Medium) |
| 0.1 – 3.9  | Green (Low) |
| null / —   | Muted (not available) |

**APIs called:**
```
GET  /api/v1/scans/{scanId}
```

---

### `GET /vulnerability/agents`
**Registered Agents**

Inventory of all vulnerability scanning agents deployed across infrastructure.

| Element | Description |
|---------|-------------|
| KPI cards | Total agents, active agents, last check-in timestamp |
| Agents table | Hostname / agent ID, platform, architecture, status badge, first seen, last seen |
| MY AGENT badge | Highlights the agent currently set as active in the dashboard |

**APIs called:**
```
GET  /api/v1/agents/    (no auth — public endpoint)
```

---

### `GET /vulnerability/agents/[agentId]`
**Agent Detail**

Configuration, status, and full scan history for a specific host/agent.

| Element | Description |
|---------|-------------|
| Agent header | Hostname, status badge (Active / Inactive), platform, first seen, last seen |
| View Dashboard button | Sets this agent as active in localStorage and navigates to `/vulnerability` |
| KPI cards | Total scans, cumulative packages scanned, cumulative vulnerabilities, latest scan vuln count |
| Scan history table | Scan ID (+LATEST badge), status, packages, vulns, scanned at |
| Auto-refresh | Polls while any scan is running |

**APIs called:**
```
GET  /api/v1/agents/{agentId}    (no auth — public)
GET  /api/v1/scans?agent_id={agentId}&limit=200
```

---

### `GET /vulnerability/cves`
**CVE Explorer**

Global cross-agent CVE search — find any vulnerability across all agents or scoped to one.

| Element | Description |
|---------|-------------|
| Scope toggle | My Agent (agent-scoped) · All Agents (global) |
| Severity summary cards | CRITICAL / HIGH / MEDIUM / LOW counts — click to filter |
| Search | CVE ID, package name, description, remediation |
| Active filter highlight | Ring highlight on active severity button |
| Findings table | CVE ID, severity pill, CVSS score, source badge, package/version, agent ID, description, remediation |
| Expandable rows | Full details + NVD link |

**APIs called:**
```
GET  /api/v1/agents/                                          (no auth)
# When scoped to agent (avoids global 1000-record limit):
GET  /api/v1/scans?agent_id={agentId}&limit=100
GET  /api/v1/scans/{scanId}                                   (per scan)
# When viewing all agents:
GET  /api/v1/vulnerabilities/?limit=1000
GET  /api/v1/vulnerabilities/?severity={severity}&limit=1000  (when filtered)
```

---

## Backend API Proxy

**File:** `ui_samples/src/app/api/vuln/[...path]/route.js`

The Next.js app proxies all vulnerability backend calls server-side to avoid CORS issues and inject auth.

| Property | Value |
|----------|-------|
| Client calls | `/api/vuln/v1/{path}` |
| Forwards to | `http://{VULN_ENGINE_LB}/vulnerability/api/v1/{path}` |
| API key | Appended as `?api_key={NEXT_PUBLIC_VULN_API_KEY}` |
| Auth header | `Authorization: Bearer {api_key}` |
| Trailing slash | Auto-added for collection endpoints (single path segment) |

**Example mapping:**
```
Client:   GET /ui/api/vuln/v1/scans?agent_id=abc123
Backend:  GET http://LB/vulnerability/api/v1/scans/?agent_id=abc123&api_key=your-secret-api-key
```

---

## Backend Engine APIs

### Vulnerability Engine

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/agents/scan` | `X-API-Key` header | Submit a new scan |
| GET | `/api/v1/agents/` | None | List all registered agents |
| GET | `/api/v1/agents/{agentId}` | None | Get agent details |
| GET | `/api/v1/scans/` | Bearer + api_key | List all scans |
| GET | `/api/v1/scans/?agent_id={id}` | Bearer + api_key | Scans for a specific agent |
| GET | `/api/v1/scans/{scanId}` | Bearer + api_key | Scan detail with vulnerabilities |
| GET | `/api/v1/scans/{scanId}/vulnerabilities` | Bearer + api_key | Vulnerabilities for a scan |
| GET | `/api/v1/scans/stats/summary?days={n}` | Bearer + api_key | Scan statistics (date-bounded) |
| GET | `/api/v1/vulnerabilities/` | Bearer + api_key | Search all vulnerabilities |
| GET | `/api/v1/vulnerabilities/?agent_id={id}` | Bearer + api_key | Agent-scoped vulnerabilities |
| GET | `/api/v1/vulnerabilities/?severity={s}` | Bearer + api_key | Filter by severity |
| GET | `/api/v1/vulnerabilities/stats/severity?days={n}` | Bearer + api_key | Severity breakdown stats |
| GET | `/api/v1/vulnerabilities/stats/trending` | Bearer + api_key | Most frequent CVEs |

### SecOps Engine

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/v1/secops/sast/scan` | API key | Launch SAST scan |
| GET | `/api/v1/secops/sast/scans` | API key | List all SAST scans |
| GET | `/api/v1/secops/sast/scan/{id}/status` | API key | SAST scan status |
| GET | `/api/v1/secops/sast/scan/{id}/findings` | API key | SAST findings |
| POST | `/api/v1/secops/dast/scan` | API key | Launch DAST scan |
| GET | `/api/v1/secops/dast/scans` | API key | List all DAST scans |
| GET | `/api/v1/secops/dast/scan/{id}/status` | API key | DAST scan status |
| GET | `/api/v1/secops/dast/scan/{id}/findings` | API key | DAST findings |
| GET | `/api/v1/secops/sca/api/v1/sbom` | `X-API-Key: sbom-api-key-2024` | List all SBOMs |
| GET | `/api/v1/secops/sca/api/v1/sbom/{id}` | `X-API-Key: sbom-api-key-2024` | SBOM detail |

---

## Authentication

| Module | Mechanism | Default Key |
|--------|-----------|-------------|
| Vulnerability Engine — scan submission | `X-API-Key` request header | `your-secret-api-key` |
| Vulnerability Engine — data queries | `Authorization: Bearer {key}` + `?api_key={key}` query param (both required) | `your-secret-api-key` |
| Vulnerability Engine — agent endpoints | No auth (public) | — |
| SecOps Engine — SAST/DAST | API key via engine client | Configured in env |
| SecOps Engine — SCA/SBOM | `X-API-Key` request header | `sbom-api-key-2024` |

---

## Route Summary

| Route | Module | Purpose |
|-------|--------|---------|
| `/vulnerability` | Vulnerability | Dashboard — agent picker + overview |
| `/vulnerability/scans` | Vulnerability | All scans for selected agent |
| `/vulnerability/scans/{scanId}` | Vulnerability | Single scan full report |
| `/vulnerability/agents` | Vulnerability | All registered agents |
| `/vulnerability/agents/{agentId}` | Vulnerability | Agent detail + scan history |
| `/vulnerability/cves` | Vulnerability | Global CVE explorer |
| `/secops` | SecOps | Dashboard — unified SAST/DAST/SCA |
| `/secops/projects` | SecOps | All scanned repositories |
| `/secops/projects/{projectId}` | SecOps | Project detail — all scan types |
| `/secops/{scanId}` | SecOps | SAST scan detail |
| `/secops/dast/{scanId}` | SecOps | DAST scan detail |
| `/secops/sca/{sbomId}` | SecOps | SCA/SBOM detail |
| `/secops/reports` | SecOps | Aggregated reports + trends |

---

*Last updated: 2026-04-02*
