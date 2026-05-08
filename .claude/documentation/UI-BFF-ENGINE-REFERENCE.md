# UI ↔ BFF ↔ Engine ↔ DB — Reference Map

> Single source of truth for "what does the UI need vs. what does the BFF provide".
> Generated 2026-05-04 from a code scan; last updated 2026-05-07 (attack-coverage → attack-map route rename).
> Authoritative file paths are absolute (`/Users/apple/Desktop/threat-engine/...`).

---

## How requests flow

```
┌──────────────┐   Next.js rewrites    ┌───────────────────┐    AuthMiddleware    ┌──────────┐
│ Browser      │ ───────────────────▶  │ /gateway/...      │ ──────────────────▶  │  BFF     │
│ Next.js 15   │   /gateway/* &        │ NLB ingress       │   (cookie → ctx,     │  views   │
│ React 19     │   /onboarding /threat │ shared/api_gateway│    X-Auth-Context)   │ (fan-out)│
└──────────────┘   /inventory /check…  └───────────────────┘                      └────┬─────┘
       │                                        │                                       │
       │ fetchView(name)            engine prefix proxy (SERVICE_ROUTES)                │
       │  → /gateway/api/v1/views/{name}        │                                       │
       │ getFromEngine(engine,path)             ▼                                       ▼
       │  → /{engine}/{path}      ┌────────────────────┐                ┌──────────────────────┐
       └─────────────────────────▶│  Engine HTTP API   │ ◀──────────────│  Engine HTTP API     │
                                  │  api_server.py     │                │  (other engines)     │
                                  └─────────┬──────────┘                └──────┬───────────────┘
                                            │                                  │
                                            ▼                                  ▼
                                  ┌────────────────────┐                ┌──────────────────────┐
                                  │  Postgres / Neo4j  │                │  Postgres            │
                                  └────────────────────┘                └──────────────────────┘
```

Key helpers (see `/Users/apple/Desktop/threat-engine/frontend/src/lib/api.js` and
`use-view-fetch.js`):

- **`fetchView(page, params)`** → `GET /gateway/api/v1/views/{page}` (BFF view).
- **`useViewFetch(name, extra)`** → React hook wrapping `fetchView`, auto-injects
  global filter scope (`provider/account/region`).
- **`getFromEngine(engine, path, params)`** → `GET /{enginePrefix}{path}` using
  `ENGINE_ENDPOINTS` map (engines exposed through ingress prefix rewrites).

---

## Quick lookup

- "What endpoint does page X call?" → §1 (UI Page Inventory)
- "What does BFF view Y return?" → §2 (BFF View Registry)
- "What gateway routes exist outside BFF?" → §3
- "Where does engine Z live and what does it expose?" → §4 (Engine API Surface)
- "Which DB table holds finding type W?" → §5 (Engine-to-DB)

---

## §1 UI Page Inventory

Source root: `/Users/apple/Desktop/threat-engine/frontend/src/app/`

### Auth & onboarding

| Route | File | Tabs / Sections | BFF views | Other endpoints |
|---|---|---|---|---|
| `/auth/login` | `auth/login/page.jsx` | Login form | — | Django (`/cspm/api/...`) |
| `/auth/signup` | `auth/signup/page.jsx` | Signup | — | Django |
| `/auth/forgot-password` | `auth/forgot-password/page.jsx` | Reset request | — | Django |
| `/auth/reset-password` | `auth/reset-password/page.jsx` | Reset confirm | — | Django |
| `/auth/invite/[token]` | `auth/invite/[token]/page.jsx` | Accept invite | — | Django |
| `/auth/platform-admin` | `auth/platform-admin/page.jsx` | Platform-admin login | — | Django |
| `/onboarding` | `onboarding/page.jsx` | Account list, schedules | — | `onboarding /api/v1/cloud-accounts`, `/api/v1/schedules` |
| `/onboarding/wizard` | `onboarding/wizard/page.jsx` | Multi-step setup wizard | — | onboarding |
| `/onboarding/setup` | `onboarding/setup/page.jsx` | Initial setup | — | onboarding |
| `/onboarding/getting-started` | `onboarding/getting-started/page.jsx` | Starter | — | onboarding |
| `/onboarding/tenants` | `onboarding/tenants/page.jsx` | Tenants table | — | `onboarding /api/v1/tenants` |
| `/onboarding/users` | `onboarding/users/page.jsx` | Users table | — | onboarding |
| `/onboarding/accounts/[accountId]` | `onboarding/accounts/[accountId]/page.jsx` | Account detail, schedules, scan history | — | `onboarding /api/v1/cloud-accounts/{id}`, `/api/v1/schedules`, `/api/v1/scan-runs` |
| `/accounts` | `accounts/page.jsx` | All accounts + run-all | — | `/gateway/api/v1/cloud-accounts/`, `/gateway/api/v1/schedules/run-all` |

### Dashboard & global

| Route | File | Tabs | BFF | Notes |
|---|---|---|---|---|
| `/` | `page.jsx` | Landing | — | redirect/marketing |
| `/dashboard` | `dashboard/page.jsx` | Posture, Threats, Compliance, IAM, Assets, Data, Network, Risk, CIEM | `dashboard` (+ tab-config calls `bffView` for each pillar: `misconfig`, `threats`, `compliance`, `iam`, `inventory`, `datasec`, `network-security`, `risk`, `ciem`) | useViewFetch + per-tab fetchView |
| `/admin/dashboard` | `admin/dashboard/page.jsx` | Platform-admin orgs, trial mgmt | `platform-admin` | `/gateway/api/v1/billing/admin/orgs/{id}/extend-trial`, `.../grant-trial` |
| `/profile` | `profile/page.jsx` | User profile | — | Django |
| `/settings` | `settings/page.jsx` | Engines health | — | `getFromEngine(prefix,'/api/v1/health')` per engine |
| `/settings/users` | `settings/users/page.jsx` | Users table | — | `onboarding /api/v1/users` |
| `/settings/users/add` | `settings/users/add/page.jsx` | Add user | — | onboarding |
| `/settings/users/[userId]/accounts` | `settings/users/[userId]/accounts/page.jsx` | User account assignment | — | onboarding |
| `/settings/groups` | `settings/groups/page.jsx` | Groups list | — | `/gateway/api/v1/groups/` |
| `/settings/access` | `settings/access/page.jsx` | Tenant↔group access | — | `/gateway/api/v1/tenants/`, `/group-access/` |
| `/settings/tenants` | `settings/tenants/page.jsx` | Tenant accounts | — | `onboarding /api/v1/cloud-accounts` |
| `/notifications` | `notifications/page.jsx` | Notifications | — | `onboarding /api/v1/notifications` |
| `/billing` | `billing/page.jsx` | Plan, usage, invoices | `billing` | `/gateway/api/v1/billing/checkout` |
| `/reports` | `reports/page.jsx` | Compliance reports | `reports` | — |
| `/policies` | `policies/page.jsx` | Policies list | `policies` | — |
| `/policies/add` | `policies/add/page.jsx` | Add policy | — | rule engine |
| `/rules` | `rules/page.jsx` | Rules library | `rules` | — |
| `/scans` | `scans/page.jsx` | Scan-runs table | — | `onboarding /api/v1/scan-runs`, `cloud-accounts`, `schedules` |
| `/scans/[scanId]` | `scans/[scanId]/page.jsx` | Live SSE pipeline view | — | `/gateway/api/v1/pipeline-monitor/scans/{id}/stream`, `/scan-runs/{id}/status` |

### Threats / risk / posture

| Route | File | Tabs | BFF | Other |
|---|---|---|---|---|
| `/threats` | `threats/page.jsx` | Command Room (Pulse, Scenarios, Preview) | `threat-command-room` | via `<CommandRoom/>` |
| `/threats/[threatId]` | `threats/[threatId]/page.jsx` | Overview, MITRE, Misconfig, Attack Path, Blast Radius, Risk, Evidence, Remediation, Timeline | `threats/{threatId}` | postToEngine for actions |
| `/threats/attack-paths` | `threats/attack-paths/page.jsx` | Attack-path list | `threats/attack-paths` | — |
| `/threats/attack-map` | `threats/attack-map/page.jsx` | MITRE technique heatmap | `threat-mitre-heatmap` | — |
| `/threats/toxic-combinations` | `threats/toxic-combinations/page.jsx` | Toxic combo cards | `threats/toxic-combinations` | — |
| `/threats/graph` | `threats/graph/page.jsx` | Cytoscape graph explorer | `threats/graph` | `getFromEngine('threat','/api/v1/graph/explore')` |
| `/threats/timeline` | `threats/timeline/page.jsx` | Redirect → per-threat timeline | — | redirect only |
| `/threats/blast-radius` | `threats/blast-radius/page.jsx` | Redirect → inventory asset blast-radius | — | redirect only |
| `/threats/trends` | `threats/trends/page.jsx` | Posture-delta + trend lines | `threat-posture-delta`, `threat-trend` | — |
| `/risk` | `risk/page.jsx` | Risk dashboard | `risk` | — |
| `/risk_old` | `risk_old/page.jsx` | Legacy risk | `risk` | deprecated |
| `/misconfig` | `misconfig/page.jsx` | Misconfig findings | `misconfig` | — |

### Inventory / asset

| Route | File | Tabs | BFF | Other |
|---|---|---|---|---|
| `/inventory` | `inventory/page.jsx` | Overview, Assets list | `inventory` | `risk /api/v1/risk/blast-radius`, `risk /api/v1/risk/toxic-combos` |
| `/inventory/[assetId]` | `inventory/[assetId]/page.jsx` | Overview, Misconfig, Threats, Compliance, CIEM, Drift, Blast Radius, Architecture, Relationships | (per-tab) `inventory/asset/{uid}`, `inventory/asset/{uid}/blast-radius`, `inventory/{assetId}/ciem` | `inventory /api/v1/inventory/assets/{uid}`, `.../drift` |
| `/inventory/architecture` | `inventory/architecture/page.jsx` | Architecture taxonomy | `inventory/architecture` | also direct `inventory /api/v1/inventory/architecture` |
| `/inventory/graph` | `inventory/graph/page.jsx` | Inventory graph | `threats/graph` | (reuses threat graph) |

### Compliance / IAM / data / encryption / network

| Route | File | Tabs | BFF | Other |
|---|---|---|---|---|
| `/compliance` | `compliance/page.jsx` | Frameworks, drilldown | `compliance` | `compliance /api/v1/compliance/findings/by-control`, `/api/v1/compliance/control/{id}`; CSV/JSON exports via `compliance/framework/{id}/report` |
| `/compliance/matrix` | `compliance/matrix/page.jsx` | Control matrix | `compliance/matrix` | — |
| `/compliance/remediation` | `compliance/remediation/page.jsx` | Remediation guide | `compliance/remediation` | — |
| `/compliance/[framework]` | `compliance/[framework]/page.jsx` | Framework detail | `compliance/framework/{id}` | — |
| `/check/[provider]/[checkId]` | `check/[provider]/[checkId]/page.jsx` | Check detail, mappings, failing assets | — | `compliance /api/v1/check/{p}/{id}`, `.../mappings`, `.../failing-assets` |
| `/iam` | `iam/page.jsx` | Identities, roles, keys, priv-esc, svc-accounts | `iam` | — |
| `/datasec` | `datasec/page.jsx` | Catalog, classification, residency | `datasec` | — |
| `/datasec/lineage` | `datasec/lineage/page.jsx` | Data lineage | `datasec` | — |
| `/encryption` | `encryption/page.jsx` | Keys, KMS posture | `encryption` | — |
| `/encryption/key-detail` | `encryption/key-detail/page.jsx` | Key dependencies, blast radius | — | `gateway /api/v1/encryption/keys/{id}/dependencies`, `.../blast-radius` |
| `/network-security` | `network-security/page.jsx` | Findings, topology | `network-security` | — |
| `/network-security/graph` | `network-security/graph/page.jsx` | Network graph | (component) | — |

### CIEM / CNAPP / CWPP / specialized

| Route | File | Tabs | BFF | Other |
|---|---|---|---|---|
| `/ciem` | `ciem/page.jsx` | Identities, log sources, heatmap | `ciem`, `ciem/heatmap` | — |
| `/ciem/identity/[principal]` | `ciem/identity/[principal]/page.jsx` | Profile, findings, activity | `ciem_identity` | — |
| `/ciem/identity/[principal]/blast-radius` | `ciem/identity/[principal]/blast-radius/page.jsx` | Identity blast radius | (component) | — |
| `/cnapp` | `cnapp/page.jsx` | Pillars (CSPM, CIEM, CWPP, KSPM, DSPM, AI, ConfigSec) | `cnapp` | — |
| `/cwpp` | `cwpp/page.jsx` | Workloads, CVE crosswalk | `cwpp` | — |
| `/ai-security` | `ai-security/page.jsx` | AI workload findings | `ai-security` | — |
| `/container-security` | `container-security/page.jsx` | Container findings | `container-security` | — |
| `/database-security` | `database-security/page.jsx` | DB findings | `database-security` | — |

### Vulnerability / SecOps

| Route | File | Tabs | BFF | Other |
|---|---|---|---|---|
| `/vulnerability` | `vulnerability/page.jsx` | Agents, scans, severity | `vulnerability` | direct `vulnerability /api/v1/agents/`, `/api/v1/scans`, `/api/v1/vulnerabilities` |
| `/vulnerability/agents` | `vulnerability/agents/page.jsx` | Agent list | — | `vulnerability /api/v1/agents` |
| `/vulnerability/agents/[agentId]` | `vulnerability/agents/[agentId]/page.jsx` | Agent detail | — | vulnerability |
| `/vulnerability/cves` | `vulnerability/cves/page.jsx` | CVE catalog | — | vulnerability |
| `/vulnerability/scans` | `vulnerability/scans/page.jsx` | Scan list | — | vulnerability |
| `/vulnerability/scans/[scanId]` | `vulnerability/scans/[scanId]/page.jsx` | Scan detail | — | vulnerability |
| `/vulnerabilities` | `vulnerabilities/page.jsx` | Aggregate vuln view | — | secops + vulnerability |
| `/secops` | `secops/page.jsx` | SAST + DAST overview | `secops` | `secops /api/v1/secops/sast/scan/{id}/findings`, `/dast/...` |
| `/secops/projects` | `secops/projects/page.jsx` | Projects | — | `secops /api/v1/secops/sast/scans`, `dast/scans`, `sast/scan` (POST) |
| `/secops/projects/[projectId]` | `secops/projects/[projectId]/page.jsx` | Project detail | — | secops |
| `/secops/[scanId]` | `secops/[scanId]/page.jsx` | SAST scan detail | — | `secops /api/v1/secops/sast/scan/{id}/status`, `.../findings` |
| `/secops/dast/[scanId]` | `secops/dast/[scanId]/page.jsx` | DAST scan detail | — | secops |
| `/secops/sca/[sbomId]` | `secops/sca/[sbomId]/page.jsx` | SCA SBOM detail | — | secops |
| `/secops/vuln/[id]` | `secops/vuln/[id]/page.jsx` | Vuln detail (SAST/DAST) | — | `secops /api/v1/secops/sast/scan/{id}/findings`, `dast/...` |
| `/secops/reports` | `secops/reports/page.jsx` | Reports | — | secops |

---

## §2 BFF View Registry

Source root: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/`
URL prefix: `/api/v1/views` (also mounted at `/gateway/api/v1/views`).
Method is GET unless noted.

| Module | URL | Engines called (engine, path) | Purpose |
|---|---|---|---|
| `ai_security.py` | `/api/v1/views/ai-security` | `ai_security /api/v1/ai-security/ui-data` | AI-security page |
| `billing.py` | `/api/v1/views/billing` | `billing /api/v1/billing/subscription`, `/usage`, `/plans`, `/invoices` | Billing page |
| `ciem.py` | `/api/v1/views/ciem` | `ciem /api/v1/ciem/dashboard`, `/identities`, `/top-rules`, `/log-sources` | CIEM landing |
| `ciem.py` | `/api/v1/views/ciem/heatmap` | `ciem /api/v1/ciem/identities/heatmap` (via internal helper) | Identity activity heatmap |
| `ciem_identity.py` | `/api/v1/views/ciem_identity` | `ciem /api/v1/ciem/identity/profile`, `/findings`, `/activity` | Identity detail |
| `cnapp.py` | `/api/v1/views/cnapp` | `cnapp /api/v1/cnapp/dashboard` | CNAPP pillars roll-up |
| `compliance.py` | `/api/v1/views/compliance` | `compliance /api/v1/compliance/ui-data`, `/frameworks/summary`; `onboarding /api/v1/cloud-accounts`; `threat /api/v1/threat/ui-data` | Compliance landing |
| `compliance.py` | `/api/v1/views/compliance/remediation` | `compliance /api/v1/compliance/ui-data`; `onboarding /api/v1/cloud-accounts` | Remediation page |
| `compliance.py` | `/api/v1/views/compliance/framework/{id}` | `compliance /api/v1/compliance/framework/{id}/detailed` | Framework detail |
| `compliance.py` | `/api/v1/views/compliance/framework/{id}/report` | compliance | Framework export (CSV/JSON) |
| `compliance.py` | `/api/v1/views/compliance/matrix` | compliance frameworks/controls | Control matrix |
| `container_security.py` | `/api/v1/views/container-security` | `container_sec /api/v1/container-security/ui-data` | Container findings |
| `cwpp.py` | `/api/v1/views/cwpp` | `cwpp /api/v1/cwpp/ui-data` | CWPP workloads |
| `cwpp.py` | `/api/v1/views/cwpp/cve-crosswalk` | `cwpp /api/v1/cwpp/ui-data` | CVE crosswalk |
| `dashboard.py` | `/api/v1/views/dashboard` | `threat /api/v1/threat/ui-data`; `compliance /api/v1/compliance/ui-data`; `inventory /api/v1/inventory/ui-data`; `iam /api/v1/iam-security/ui-data`; `datasec /api/v1/data-security/ui-data`; `risk /api/v1/risk/ui-data`; `onboarding /api/v1/cloud-accounts` | Top-level dashboard |
| `database_security.py` | `/api/v1/views/database-security` | `dbsec /api/v1/database-security/ui-data` | DB security |
| `datasec.py` | `/api/v1/views/datasec` | `datasec /api/v1/data-security/ui-data` | Data security |
| `encryption.py` | `/api/v1/views/encryption` | `encryption /api/v1/encryption/ui-data` | Encryption / KMS |
| `iam.py` | `/api/v1/views/iam` | `iam /api/v1/iam-security/ui-data` (+ fallback to check findings filtered by IAM domain) | IAM landing |
| `inventory.py` | `/api/v1/views/inventory` | `inventory /api/v1/inventory/ui-data`; `threat /api/v1/threat/ui-data`; `onboarding /api/v1/cloud-accounts` | Asset list |
| `inventory.py` | `/api/v1/views/inventory/taxonomy` | `inventory /api/v1/inventory/taxonomy` | Taxonomy |
| `inventory.py` | `/api/v1/views/inventory/architecture` | `inventory /api/v1/inventory/architecture` | Architecture diagram data |
| `inventory.py` | `/api/v1/views/inventory/graph` | `inventory /api/v1/inventory/runs/latest/graph` | Asset graph |
| `inventory.py` | `/api/v1/views/inventory/asset/{resource_uid:path}` | `inventory /api/v1/inventory/assets/{uid}`; `check /api/v1/check/findings/resource/{uid}`; `threat /api/v1/threat/findings/resource/{uid}`; `compliance /api/v1/compliance/resource/drilldown` | Asset detail (cross-engine) |
| `inventory.py` | `/api/v1/views/inventory/asset/{uid}/blast-radius` | `threat /api/v1/graph/blast-radius/{uid}` (Neo4j) | Asset blast-radius |
| `inventory.py` | `/api/v1/views/inventory/{asset_id}/ciem` | `inventory` (ownership check) → `ciem /api/v1/ciem/findings` | Asset CIEM tab (gated) |
| `misconfig.py` | `/api/v1/views/misconfig` | `threat /api/v1/threat/ui-data` (+ check findings) | Misconfig list |
| `network_security.py` | `/api/v1/views/network-security` | `network /api/v1/network-security/ui-data` | Network security |
| `platform_admin.py` | `/api/v1/views/platform-admin` | `platform_admin /api/v1/padmin/engines/health`, `/api/v1/padmin/metrics` | Platform-admin dashboard |
| `policies.py` | `/api/v1/views/policies` | `rule /api/v1/rules` | Policies list |
| `reports.py` | `/api/v1/views/reports` | `compliance /api/v1/compliance/ui-data`; `onboarding /api/v1/cloud-accounts` | Reports landing |
| `risk.py` | `/api/v1/views/risk` | `risk /api/v1/risk/ui-data`; `threat /api/v1/threat/ui-data` | Risk dashboard |
| `rules.py` | `/api/v1/views/rules` | `rule /api/v1/rules/ui-data` | Rules library |
| `scan_status.py` | `/api/v1/views/scan-status` | `onboarding /api/v1/scan-runs` | Recent scans status |
| `scan_status.py` | `/api/v1/views/scan-status/{scan_run_id}` | `onboarding /api/v1/scan-runs/{id}` | Per-scan status |
| `scan_timing.py` | `/api/v1/views/scan-timing` | `onboarding /api/v1/scan-runs` | Aggregate timing |
| `scan_timing.py` | `/api/v1/views/scan-timing/{scan_run_id}` | onboarding + per-engine status | Per-scan timing |
| `scans.py` | `/api/v1/views/scans` | `onboarding /api/v1/cloud-accounts`, `/api/v1/scan-runs` | Scans page |
| `scope.py` | `/api/v1/views/scope` | `onboarding /api/v1/cloud-accounts` | Global filter scope (provider/account/region picker) |
| `secops.py` | `/api/v1/views/secops` | `secops /api/v1/secops/sast/scans`, `/dast/scans` | SecOps overview |
| `technique_detail.py` | `/api/v1/views/threats/technique/{technique_id}` | (direct DB) `mitre_technique_reference`, `threat_detections` | Technique modal |
| `threat_attack_paths.py` | `/api/v1/views/threats/attack-paths` | `threat /api/v1/threat/analysis/attack-paths`, `/api/v1/graph/orca-paths` | Attack paths |
| `threat_blast_radius.py` | `/api/v1/views/threats/blast-radius` | `threat /api/v1/threat/analysis/blast-radius` | Blast radius (legacy entrypoint) |
| `threat_command_room.py` | `/api/v1/views/threat-command-room` | `threat /api/v1/threat/ui-data` | Command Room (3-zone) |
| `threat_detail.py` | `/api/v1/views/threats/{threat_id}` | `threat /api/v1/threat/threats/{id}`, `/api/v1/threat/analysis/{id}`, `/api/v1/threat/detections/{id}/check-findings` | Threat detail page |
| `threat_graph.py` | `/api/v1/views/threats/graph` | `threat /api/v1/graph/summary`, `/api/v1/graph/subgraph` | Threat graph view |
| `threat_graph.py` | `/api/v1/views/threats/graph/filtered` | `threat /api/v1/graph/explore` | Filtered graph |
| `threat_mitre_heatmap.py` | `/api/v1/views/threat-mitre-heatmap` | `threat` (heatmap endpoint) | MITRE coverage |
| `threat_posture_delta.py` | `/api/v1/views/threat-posture-delta` | `onboarding /api/v1/scan-runs`; `threat /api/v1/threat/ui-data` (×2 scans) | Scan-A vs scan-B delta |
| `threat_posture_delta.py` | `/api/v1/views/threat-trend` | `threat` trend; `onboarding /api/v1/scan-runs` | Trend timeseries |
| `threat_scenario_detail.py` | `/api/v1/views/threat-scenario/{scenario_id}` | `threat /api/v1/threat/threats/{id}`, `/analysis/{id}`, `/detections/{id}/check-findings`, `/{id}/remediation`; `risk /api/v1/risk/scenarios/{id}` | Scenario card detail |
| `threat_timeline.py` | `/api/v1/views/threats/timeline` | `threat /api/v1/threat/ui-data`; `onboarding /api/v1/scan-runs` | Timeline (legacy) |
| `threat_toxic_combos.py` | `/api/v1/views/threats/toxic-combinations` | `threat /api/v1/threat/analysis/toxic-combinations` | Toxic combos |
| `threats.py` | `/api/v1/views/threats` | `threat /api/v1/threat/ui-data`; `onboarding /api/v1/cloud-accounts` | Legacy threats list |
| `vulnerability.py` | `/api/v1/views/vulnerability` | `vulnerability /api/v1/agents/`, `/api/v1/scans/stats/summary`, `/api/v1/vulnerabilities/stats/severity` | Vulnerability dashboard |

---

## §3 Gateway-Native Routes (non-BFF)

Source: `/Users/apple/Desktop/threat-engine/shared/api_gateway/main.py` and
`asset_context.py`.

| URL | Source | Purpose |
|---|---|---|
| `GET /` | `main.py` | Root info / health-style root |
| `GET /gateway/health` | `main.py:644` | Gateway liveness (incl. registry status) |
| `GET /gateway/services` | `main.py:655` | List services and health |
| `POST /gateway/services/{service_name}/health-check` | `main.py:673` | Trigger one-shot health check |
| `GET /gateway/configscan/csps` | `main.py:686` | Supported CSPs for ConfigScan |
| `GET /gateway/configscan/route-test` | `main.py:710` | ConfigScan routing test |
| `POST /gateway/orchestrate` | `main.py:735` | Trigger full pipeline orchestration (when enabled) |
| `ANY /argo/{path:path}` | `main.py:415` | Streaming proxy to Argo Workflows UI/API |
| `GET /api/v1/asset-context/{resource_uid}` | `asset_context.py:168` | Cross-engine fan-out summary for asset investigation panel — fans out to check/network/iam/datasec/encryption/threat/vulnerability/container/dbsec/ai_security/ciem with 2s timeout per engine, returns partial results |
| `ANY /{prefix}/...` (proxy) | `main.py` SERVICE_ROUTES | Engine reverse-proxy: routes incoming `/api/v1/...` paths to the correct engine pod based on path prefix table |

### SERVICE_ROUTES path-prefix → engine map (proxy)

| Path prefix(es) | Engine service |
|---|---|
| `/api/v1/configscan/{aws,azure,gcp,alicloud,ibm,oci}` | configscan-{csp} |
| `/api/v1/discovery` | discoveries |
| `/api/v1/check` | check |
| `/api/v1/threat`, `/api/v1/graph`, `/api/v1/intel`, `/api/v1/hunt` | threat |
| `/api/v1/inventory` | inventory |
| `/api/v1/cloud-accounts`, `/api/v1/scan-runs`, `/api/v1/accounts`, `/api/v1/tenants`, `/api/v1/schedules` | onboarding |
| `/api/v1/compliance` | compliance |
| `/api/v1/rules`, `/api/v1/providers` | rule |
| `/api/v1/iam-security` | iam |
| `/api/v1/data-security` | datasec |
| `/api/v1/secops` | secops |
| `/api/v1/ciem`, `/api/v1/log-collection` | ciem |
| `/api/v1/pipeline`, `/api/v1/admin/logs` | pipeline-monitor |
| `/api/v1/cnapp` | cnapp |
| `/api/v1/cwpp` | cwpp |
| `/api/v1/network-security` | network-security |
| `/api/v1/risk` | risk |
| `/api/v1/encryption` | encryption |
| `/api/v1/container-security` | container-security |
| `/api/v1/ai-security` | ai-security |
| `/api/v1/database-security` | database-security |
| `/api/v1/vulnerabilities`, `/api/v1/agents`, `/api/v1/reports`, `/api/v1/scans`, `/vulnerability` | vulnerability |
| `/api/v1/billing` | billing |
| `/api/v1/padmin` | platform-admin |

---

## §4 Engine HTTP API Surface

> Notes:
> - Engines are reached from the browser via Next.js rewrites that strip the
>   short prefix (e.g. `/threat/...`) and from the gateway via the
>   SERVICE_ROUTES table above.
> - Listed routes are the user-data-relevant endpoints actually called from
>   pages or BFF views. Health/metrics endpoints are omitted unless they are
>   the only relevant routes.

### onboarding (port 8008)

`engines/onboarding/main.py` + `engines/onboarding/api/*.py`

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/cloud-accounts` | List cloud accounts |
| POST | `/api/v1/cloud-accounts` | Create account |
| GET | `/api/v1/cloud-accounts/{account_id}` | Account detail |
| PATCH | `/api/v1/cloud-accounts/{id}` | Update account |
| DELETE | `/api/v1/cloud-accounts/{id}` | Delete account |
| POST | `/api/v1/cloud-accounts/{id}/scan` | Trigger scan |
| POST | `/api/v1/cloud-accounts/{id}/credentials` | Set credentials |
| POST | `/api/v1/cloud-accounts/{id}/validate-credentials` | Validate creds |
| GET | `/api/v1/cloud-accounts/aws/cloudformation-template` | CFN template |
| GET | `/api/v1/cloud-accounts/{id}/log-sources` | Log sources for account |
| POST | `/api/v1/cloud-accounts/{id}/agent-token` | Issue agent token |
| GET | `/api/v1/tenants` | List tenants |
| POST | `/api/v1/tenants` | Create tenant |
| GET | `/api/v1/tenants/{tenant_id}` | Tenant detail |
| GET | `/api/v1/scan-runs` | Scan runs (filterable) |
| GET | `/api/v1/scan-runs/{scan_run_id}` | Scan run detail |
| GET | `/api/v1/scan-runs/{id}/status` | Scan run status |
| POST | `/api/v1/scan-runs/{id}/re-run` | Re-run |
| GET | `/api/v1/schedules` | List schedules |
| POST | `/api/v1/schedules` | Create schedule |
| POST | `/api/v1/schedules/{id}/run-now` | Trigger schedule |
| POST | `/api/v1/schedules/run-all` | Run all |
| GET | `/api/v1/scans/recent` | Recent scans |
| GET | `/api/v1/scans/{scan_run_id}/pipeline` | Pipeline view |
| GET | `/api/v1/users` | List users |
| GET | `/api/v1/notifications` | Notifications |
| POST | `/api/v1/agents/bootstrap` | Agent bootstrap |
| POST | `/api/v1/agents/{registration_id}/heartbeat` | Heartbeat |

### discoveries (port 8001)

`engines/discoveries/common/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/discovery` | Trigger discovery scan |
| GET | `/api/v1/discovery/{scan_id}` | Discovery scan detail |
| GET | `/api/v1/discovery/{scan_id}/timing` | Per-service timing |
| GET | `/api/v1/discovery/{scan_id}/service-results` | Per-service results |
| GET | `/api/v1/accounts` | Accounts seen |
| GET | `/api/v1/resources` | Resources discovered |

### check (port 8002)

`engines/check/common/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/scan` | Run check scan |
| GET | `/api/v1/check/{scan_run_id}/status` | Status |
| GET | `/api/v1/checks` | List checks |
| GET | `/api/v1/providers` | Providers |
| GET | `/api/v1/check/findings` | Findings (paginated) |
| GET | `/api/v1/check/findings/summary` | Severity counts |
| GET | `/api/v1/check/findings/resource/{resource_uid}` | Findings for one asset |
| POST | `/api/v1/check/findings/batch-severity` | Bulk severity counts |

### inventory (port 8022, svc port 80)

`engines/inventory/inventory_engine/api/`

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/inventory/ui-data` | Engine UI bundle |
| GET | `/api/v1/inventory/assets` | Asset list |
| GET | `/api/v1/inventory/assets/{resource_uid:path}` | Asset detail |
| GET | `/api/v1/inventory/assets/{uid}/drift` | Asset drift history |
| GET | `/api/v1/inventory/assets/{uid}/relationships` | Per-asset relationships |
| GET | `/api/v1/inventory/accounts/{account_id}` | Per-account assets |
| GET | `/api/v1/inventory/services/{service}` | Per-service assets |
| GET | `/api/v1/inventory/taxonomy` | Resource taxonomy |
| GET | `/api/v1/inventory/architecture` | Architecture graph data |
| GET | `/api/v1/inventory/graph` | Graph |
| GET | `/api/v1/inventory/runs/latest/graph` | Latest run graph |
| GET | `/api/v1/inventory/relationships` | All relationships |
| GET | `/api/v1/inventory/drift` | Drift list |
| GET | `/api/v1/inventory/runs/{scan_run_id}/drift` | Per-run drift |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | Run summary |
| GET | `/api/v1/inventory/runs/latest/summary` | Latest run summary |

### threat (port 8020)

`engines/threat/threat_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/scan` | Run threat scan |
| GET | `/api/v1/threat/{scan_run_id}/status` | Status |
| GET | `/api/v1/threat/ui-data` | UI bundle |
| GET | `/api/v1/threat/list` | Detections list |
| GET | `/api/v1/threat/{threat_id}` | Threat detail |
| PATCH | `/api/v1/threat/{threat_id}` | Update (assign/suppress/resolve) |
| GET | `/api/v1/threat/{threat_id}/misconfig-findings` | Linked check findings (legacy) |
| GET | `/api/v1/threat/detections/{detection_id}/check-findings` | Linked check findings |
| GET | `/api/v1/threat/{threat_id}/assets` | Affected resources |
| GET | `/api/v1/threat/analysis/prioritized` | Prioritized list |
| GET | `/api/v1/threat/analysis/blast-radius` | Blast radius (analysis) |
| GET | `/api/v1/threat/analysis/attack-paths` | Attack paths |
| GET | `/api/v1/threat/analysis/toxic-combinations` | Toxic combos |
| GET | `/api/v1/threat/analysis/{detection_id}` | Per-detection analysis |
| GET | `/api/v1/threat/findings/resource/{resource_uid}` | Findings for asset |
| GET | `/api/v1/threat/summary` | Summary KPIs |
| GET | `/api/v1/threat/drift` | Threat drift |
| GET | `/api/v1/threat/map/geographic` | Geo map |
| GET | `/api/v1/graph/summary` | Graph summary |
| GET | `/api/v1/graph/subgraph` | Subgraph |
| GET | `/api/v1/graph/explore` | Explorable graph |
| GET | `/api/v1/graph/blast-radius/{resource_uid}` | Neo4j blast radius |
| GET | `/api/v1/graph/orca-paths` | Orca-style attack chains |

### compliance (port 8010)

`engines/compliance/compliance_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/compliance/generate` | Generate compliance report |
| POST | `/api/v1/compliance/generate/from-check-db` | From check findings |
| POST | `/api/v1/compliance/generate/from-threat-db` | From threats |
| GET | `/api/v1/compliance/ui-data` | UI bundle |
| GET | `/api/v1/compliance/frameworks` | Frameworks |
| GET | `/api/v1/compliance/frameworks/all` | All frameworks |
| GET | `/api/v1/compliance/framework/{fw}/detailed` | Detailed |
| GET | `/api/v1/compliance/framework/{fw}/structure` | Structure |
| GET | `/api/v1/compliance/framework/{fw}/control/{ctrl}` | Control detail |
| GET | `/api/v1/compliance/framework/{fw}/controls/grouped` | Grouped controls |
| GET | `/api/v1/compliance/framework/{fw}/resources/grouped` | Grouped by resource |
| GET | `/api/v1/compliance/findings/by-control` | Findings per control |
| GET | `/api/v1/compliance/control/{ctrl}` | Control by id |
| GET | `/api/v1/compliance/resource/drilldown` | Per-resource drilldown |
| GET | `/api/v1/compliance/accounts/{account_id}` | Per-account |
| GET | `/api/v1/compliance/trends` | Trends |
| GET | `/api/v1/compliance/reports` | Saved reports |
| GET | `/api/v1/compliance/report/{report_id}` | Report |
| GET | `/api/v1/compliance/report/{report_id}/export` | Export |
| GET | `/api/v1/check/{provider}/{check_id}` | Check metadata |
| GET | `/api/v1/check/{provider}/{check_id}/mappings` | Framework mappings |
| GET | `/api/v1/check/{provider}/{check_id}/failing-assets` | Failing assets |

### iam (port 8003)

`engines/iam/iam_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/iam-security/scan` | Run scan |
| GET | `/api/v1/iam-security/{iam_scan_id}/status` | Status |
| GET | `/api/v1/iam-security/ui-data` | UI bundle |
| GET | `/api/v1/iam-security/findings` | Findings |
| GET | `/api/v1/iam-security/findings/by-resource` | Per-resource |
| GET | `/api/v1/iam-security/modules` | Modules |
| GET | `/api/v1/iam-security/rules/{rule_id}` | Rule meta |
| GET | `/api/v1/iam-security/rule-ids` | Rule ids |
| GET | `/api/v1/iam-security/accounts/{account_id}` | Per-account |
| GET | `/api/v1/iam-security/services/{service}` | Per-service |
| GET | `/api/v1/iam-security/resources/{resource_uid}` | Per-resource |

### datasec (port 8004)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/data-security/scan` | Run scan |
| GET | `/api/v1/data-security/ui-data` | UI bundle (via wrapper) |
| GET | `/api/v1/data-security/catalog` | Catalog |
| GET | `/api/v1/data-security/classification` | Classification |
| GET | `/api/v1/data-security/lineage` | Lineage |
| GET | `/api/v1/data-security/residency` | Residency |
| GET | `/api/v1/data-security/activity` | Activity |
| GET | `/api/v1/data-security/compliance` | Compliance map |
| GET | `/api/v1/data-security/findings` | Findings |
| GET | `/api/v1/data-security/governance/{resource_id}` | Governance |
| GET | `/api/v1/data-security/protection/{resource_id}` | Protection |
| GET | `/api/v1/data-security/rules/{rule_id}` | Rule |
| GET | `/api/v1/data-security/modules` | Modules |
| GET | `/api/v1/data-security/accounts/{account_id}` | Per-account |
| GET | `/api/v1/data-security/services/{service}` | Per-service |

### encryption (svc port 80 → 8006)

`engines/encryption-security/encryption_security_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/encryption/scan` | Scan |
| GET | `/api/v1/encryption/{scan_run_id}/status` | Status |
| GET | `/api/v1/encryption/ui-data` | UI bundle |
| GET | `/api/v1/encryption/findings` | Findings (used by asset-context) |
| GET | `/api/v1/encryption/keys/{key_id}/dependencies` | Key dependencies |
| GET | `/api/v1/encryption/keys/{key_id}/blast-radius` | Key blast radius |

### secops (port 8009)

`engines/secops/sast_engine/api_server.py` (unified SAST+DAST+SCA)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/secops/scan` | Generic scan |
| GET | `/api/v1/secops/scan/{scan_id}/status` | Status |
| GET | `/api/v1/secops/scan/{scan_id}/findings` | Findings |
| GET | `/api/v1/secops/scans` | List scans |
| GET | `/api/v1/secops/rules/stats` | Rule stats |
| POST | `/api/v1/secops/rules/sync` | Sync rules |
| (also) | `/api/v1/secops/sast/...`, `/dast/...`, `/sca/...` | Sub-engine namespaces |

### risk (port 8009)

`engines/risk/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/scan` | Run risk scoring |
| GET | `/api/v1/risk/ui-data` | UI bundle |
| GET | `/api/v1/risk/dashboard` | Dashboard |
| GET | `/api/v1/risk/scenarios` | Scenarios list |
| GET | `/api/v1/risk/scenarios/{scenario_id}` | Scenario detail |
| GET | `/api/v1/risk/score` | Score |
| GET | `/api/v1/risk/breakdown` | Breakdown |
| GET | `/api/v1/risk/trend` | Trend |
| GET | `/api/v1/risk/trends` | Multi-tenant trend |
| GET | `/api/v1/risk/blast-radius` | Top blast-radius |
| GET | `/api/v1/risk/toxic-combos` | Top toxic combos |
| GET | `/api/v1/risk/assets/top` | Top risky assets |

### rule (port 8000)

`engines/rule/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/rules` | Rules list |
| GET | `/api/v1/rules/ui-data` | UI bundle |
| GET | `/api/v1/rules/{rule_id}` | Rule |
| PUT | `/api/v1/rules/{rule_id}` | Update |
| DELETE | `/api/v1/rules/{rule_id}` | Delete |
| POST | `/api/v1/rules/validate` | Validate |
| POST | `/api/v1/rules/generate` | Generate |
| GET | `/api/v1/rules/search` | Search |
| GET | `/api/v1/rules/statistics` | Stats |
| GET | `/api/v1/rules/export` | Export |
| POST | `/api/v1/rules/import` | Import |
| POST | `/api/v1/user-rules` | Create user rule |
| GET | `/api/v1/user-rules` | List user rules |
| GET | `/api/v1/providers` | Providers |
| GET | `/api/v1/providers/{p}/services` | Services |
| GET | `/api/v1/providers/{p}/services/{s}/fields` | Fields |
| GET | `/api/v1/providers/{p}/services/{s}/rules` | Rules per service |
| GET | `/api/v1/providers/{p}/services/{s}/capabilities` | Capabilities |

### network-security (port 80)

`engines/network-security/network_security_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/network-security/scan` | Scan |
| GET | `/api/v1/network-security/{scan_id}/status` | Status |
| GET | `/api/v1/network-security/ui-data` | UI bundle |
| GET | `/api/v1/network-security/findings` | Findings |
| GET | `/api/v1/network-security/findings/by-resource` | Per-resource |
| GET | `/api/v1/network-security/topology` | Topology |
| GET | `/api/v1/network-security/modules` | Modules |

### ciem

`engines/ciem/ciem_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/scan` | Run CIEM scan |
| POST | `/api/v1/scan/all` | All-CSP scan |
| GET | `/api/v1/ciem/dashboard` | Dashboard |
| GET | `/api/v1/ciem/findings` | Findings |
| GET | `/api/v1/ciem/findings/{finding_id}` | Finding detail |
| GET | `/api/v1/ciem/findings/{id}/timeline` | Timeline |
| GET | `/api/v1/ciem/findings/by-resource` | Per-resource |
| GET | `/api/v1/ciem/identities` | Identities |
| GET | `/api/v1/ciem/identities/heatmap` | Heatmap |
| GET | `/api/v1/ciem/identities/{principal}/hourly-activity` | Hourly activity |
| GET | `/api/v1/ciem/top-rules` | Top firing rules |
| GET | `/api/v1/ciem/log-sources` | Log sources |
| GET | `/api/v1/ciem/identity/profile`, `/findings`, `/activity` | Identity tabs |
| GET | `/api/v1/ciem/report/{scan_run_id}` | Run report |

### ai-security

`engines/ai-security/ai_security_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/ai-security/scan` | Scan |
| GET | `/api/v1/ai-security/{scan_run_id}/status` | Status |
| GET | `/api/v1/ai-security/ui-data` | UI bundle |
| GET | `/api/v1/ai-security/findings` | Findings |
| GET | `/api/v1/ai-security/findings/by-resource` | Per-resource |

### container-security

`engines/container-security/container_security_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/container-security/scan` | Scan |
| GET | `/api/v1/container-security/{id}/status` | Status |
| GET | `/api/v1/container-security/ui-data` | UI bundle |
| GET | `/api/v1/container-security/findings` | Findings |
| GET | `/api/v1/container-security/findings/by-resource` | Per-resource |

### cnapp

`engines/cnapp/cnapp_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/cnapp/dashboard` | 7-pillar roll-up |
| GET | `/api/v1/cnapp/posture` | Posture |
| GET | `/api/v1/cnapp/score` | Score |
| GET | `/api/v1/cnapp/pillars` | Pillar list |
| GET | `/api/v1/cnapp/pillars/{pillar}` | Single pillar |

### cwpp

`engines/cwpp/cwpp_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/cwpp/dashboard` | Dashboard |
| GET | `/api/v1/cwpp/posture` | Posture |
| GET | `/api/v1/cwpp/score` | Score |
| GET | `/api/v1/cwpp/workloads` | All workloads |
| GET | `/api/v1/cwpp/workloads/{workload_type}` | Per-type |
| GET | `/api/v1/cwpp/ui-data` | UI bundle |

### vulnerability (port 8000 inside engine; ingress at `/vulnerability`)

`engines/vulnerability/vul_engine/main.py` (mounts routers at `/api/v1/...`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/agents/register` | Register agent |
| POST | `/api/v1/agents/scan` | Trigger agent scan |
| GET | `/api/v1/agents/` | Agents list |
| GET | `/api/v1/agents/{agent_id}` | Agent |
| GET | `/api/v1/agents/{agent_id}/scans` | Agent scans |
| GET | `/api/v1/agents/scans/{scan_id}` | Scan detail |
| GET | `/api/v1/scans/` | Scans list |
| GET | `/api/v1/scans/{scan_id}` | Scan detail |
| GET | `/api/v1/scans/{scan_id}/vulnerabilities` | Vulns in scan |
| GET | `/api/v1/scans/stats/summary` | Stats summary |
| GET | `/api/v1/vulnerabilities/` | CVE catalog |
| GET | `/api/v1/vulnerabilities/{cve_id}` | CVE |
| GET | `/api/v1/vulnerabilities/stats/severity` | Severity stats |
| GET | `/api/v1/vulnerabilities/stats/trending` | Trending |
| GET | `/api/v1/reports/dashboard` | Dashboard |
| GET | `/api/v1/reports/executive` | Executive |
| GET | `/api/v1/reports/compliance` | Compliance |
| GET | `/api/v1/reports/technical` | Technical |

### dbsec (database-security engine, separate from `database-security`)

`engines/dbsec/dbsec_engine/api_server.py` and
`engines/database-security/database_security_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/scan` | Run dbsec scan |
| GET | `/api/v1/findings/{scan_run_id}` | Findings |
| POST | `/api/v1/database-security/scan` | (database-security engine) scan |
| GET | `/api/v1/database-security/{id}/status` | Status |
| GET | `/api/v1/database-security/ui-data` | UI bundle |
| GET | `/api/v1/database-security/findings` | Findings |
| GET | `/api/v1/database-security/findings/by-resource` | Per-resource |

### billing (port 8040) / platform-admin (port 8041)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/billing/subscription` | Subscription |
| GET | `/api/v1/billing/usage` | Usage |
| GET | `/api/v1/billing/plans` | Plans |
| GET | `/api/v1/billing/invoices` | Invoices |
| POST | `/api/v1/billing/checkout` | Checkout |
| POST | `/api/v1/billing/admin/orgs/{org_id}/extend-trial` | Extend trial |
| POST | `/api/v1/billing/admin/orgs/{org_id}/grant-trial` | Grant trial |
| GET | `/api/v1/padmin/engines/health` | Engine health roll-up |
| GET | `/api/v1/padmin/metrics` | Metrics |

### pipeline-monitor

`engines/pipeline-monitor/pipeline_monitor_engine/api_server.py`

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/pipeline-monitor/scans/{scan_run_id}/stream` | SSE stream of pipeline events (used by `/scans/[scanId]`) |
| GET | `/api/v1/health/live`, `/ready` | Health |

---

## §5 Engine-to-DB Map

> All finding tables share standard columns: `finding_id`, `scan_run_id`,
> `tenant_id`, `account_id`, `credential_ref`, `credential_type`, `provider`,
> `region`, `resource_uid`, `resource_type`, `severity`, `status`,
> `first_seen_at`, `last_seen_at`. (See `CLAUDE.md` "Standardized Column Names".)

| Engine | DB | Primary tables | Notes |
|---|---|---|---|
| onboarding | `threat_engine_onboarding` | `tenants`, `cloud_accounts`, `credentials`, `schedules`, `scan_runs`, `scan_orchestration` | `scan_run_id` UUID is the central pipeline id; `engines_requested/completed` JSONB |
| discoveries | `threat_engine_discoveries` | `discovery_findings`, `rule_discoveries` (rule_discoveries actually lives in check DB) | enumerates raw cloud resources |
| inventory | `threat_engine_inventory` | `inventory_assets`, `inventory_findings`, `inventory_relationships`, `resource_inventory_identifier`, `resource_relationship_rules` | drift in `inventory_drift_*` |
| check | `threat_engine_check` | `check_findings`, `rule_metadata`, `rule_discoveries`, `rule_control_mapping` | `check_findings.finding_id` is GENERATED STORED |
| threat | `threat_engine_threat` (+ Neo4j) | `threat_detections`, `threat_findings`, `mitre_technique_reference`, `attack_paths` | `finding_id` = sha256(rule_id|uid|account|region)[:16] |
| compliance | `threat_engine_compliance` | `compliance_reports`, `compliance_findings`, `compliance_frameworks`, `framework_controls` | reads from check DB to assemble |
| iam | `threat_engine_iam` | `iam_findings`, `iam_modules`, `iam_policy_statements` | `account_id` VARCHAR(512) for OCI |
| datasec | `threat_engine_datasec` | `datasec_findings`, `datasec_classification`, `datasec_lineage`, `datasec_residency`, `datasec_activity` | enhanced schema for catalog/governance |
| encryption | `threat_engine_encryption` | `encryption_findings`, `encryption_keys` | KMS posture |
| network-security | `threat_engine_network` | `network_findings`, `network_topology` | 7 sub-layers (L1-L7) |
| ciem | `threat_engine_ciem` | `ciem_findings`, `ciem_identities`, `ciem_log_sources` | log-driven |
| risk | `threat_engine_risk` | `risk_scenarios`, `risk_summary` | scoring; multi-tenant trend |
| container-security | `threat_engine_container` | `container_sec_findings`, `container_images` | runtime + image |
| ai-security | `threat_engine_ai_security` | `ai_security_findings` | LLM/agent risk |
| dbsec / database-security | `threat_engine_dbsec` | `dbsec_findings` | DB posture |
| secops | `threat_engine_secops` | `secops_scans`, `secops_findings` (SAST/DAST/SCA) | unified |
| vulnerability | `threat_engine_vulnerability` | `vuln_agents`, `vuln_scans`, `vulnerabilities`, `cve_*` | host-side CVE scanning |
| cnapp / cwpp | (no own DB — aggregator) | reads from check / threat / iam / datasec / container / ai_security | composes pillars |
| rule | `threat_engine_rules` | `rule_metadata`, `user_rules`, `rule_control_mapping` | YAML-backed |
| billing | `threat_engine_billing` | `billing_subscriptions`, `billing_usage`, `billing_invoices`, `billing_plans` | Stripe-backed |
| platform-admin | (cross-DB read) | reads from onboarding + billing + per-engine `_health` views | platform-wide ops |
| pipeline-monitor | `threat_engine_onboarding` (reads `scan_orchestration`) + Postgres `pg_listen` | — | streams SSE |

Schema source files: `/Users/apple/Desktop/threat-engine/shared/database/schemas/*.sql`.

---

## §6 Common patterns

- **`fetchView(name, params)`** — `frontend/src/lib/api.js:147`. Hits
  `${API_BASE}/gateway/api/v1/views/{name}`. Always GET, returns parsed JSON
  or `{ error }`.
- **`useViewFetch(name, extra)`** — `frontend/src/lib/use-view-fetch.js`.
  React hook that auto-injects `provider/account/region` from
  `GlobalFilterContext` and `selectedTenant` from `AuthContext`. Tenant is
  resolved server-side from `X-Auth-Context` header.
- **`getFromEngine(engine, path, params)`** — `frontend/src/lib/api.js:60`.
  Maps `engine` → ingress prefix via `ENGINE_ENDPOINTS` (`/onboarding`,
  `/threat`, `/inventory`, `/check`, `/compliance`, `/iam`, `/datasec`,
  `/secops`, `/risk`, `/rule`, `/cnapp`, `/cwpp`, `/vulnerability`,
  `/gateway` for billing/platformAdmin/encryption keys). Strips prefix at
  the ingress and forwards to the engine.
- **`X-Auth-Context`** — opaque header injected by `AuthMiddleware`
  (`shared/api_gateway/main.py`, registered last so it runs first). Built
  from the validated `access_token` cookie. Forwarded verbatim by BFF
  views (`fetch_many(..., auth_headers={"X-Auth-Context": ...})`) so
  engines enforce RBAC consistently. `tenant_id` is derived server-side
  from this header — never trusted from query string.
- **`scan_run_id`** — single UUID threaded from `scan_orchestration` through
  every engine. BFF views accept `scan_run_id="latest"` which engines resolve
  to the most recent completed run for that tenant.
- **Empty/health-stub detection** — `is_empty_or_health()` in `_shared.py`
  treats `{}`-only or `{"status": "healthy"}` engine responses as empty so
  fallbacks (e.g. IAM → check findings filtered by `domain=identity_and_access_management`)
  can kick in.
- **Cache** — `cached_view(key)` in `_cache.py` provides per-view in-memory
  TTL caching keyed by tenant + scan_run_id + filters + role level (so a
  viewer never sees an admin-cached blob).

---

## §7 Known gaps (cross-reference)

- **Asset detail "blast radius" tab** sometimes returns 500 when the
  threat engine cannot reach Neo4j (G-2). The BFF route
  `/api/v1/views/inventory/asset/{uid}/blast-radius` returns the `_EMPTY`
  shape on Neo4j failure, but UI tab readiness depends on graph schema
  parity — see `inventory.py:837`.
- **`mitre_technique_reference` table** is required by `technique_detail.py`
  (G-1). If empty in a fresh DB the modal returns 404; `/api/v1/views/threats/technique/{tid}`.
- **Investigation journey gaps** (G-12 through G-20) — missing per-detail
  pages and tab wiring documented in `ADR-INVESTIGATION-JOURNEY-UNIFICATION.md`
  and `ui_journey_data_model.md`. Touch points: `inventory/[assetId]` tabs
  (CIEM, blast-radius, drift), `threats/[threatId]` tabs (attack-path,
  evidence, remediation).
- **`/threats/timeline` and `/threats/blast-radius`** are both redirect-only
  pages now — actual data is per-threat (in `threats/{threatId}` BFF) and
  per-asset (in `inventory/asset/{uid}/blast-radius` BFF) respectively.
- **`secops` page mixes** `fetchView('secops')` with direct
  `getFromEngine('secops', ...)` calls — every project/scan tab calls the
  engine directly because the BFF view only returns a dashboard summary.
- **No BFF fallbacks rule** (constitution): if an engine returns empty,
  fix the pipeline or trigger the engine — do not paper over with
  cross-engine merges in BFF. The IAM-domain fallback in `iam.py` predates
  this rule and should be removed once the IAM engine guarantees
  `ui-data` shape on every successful run.
