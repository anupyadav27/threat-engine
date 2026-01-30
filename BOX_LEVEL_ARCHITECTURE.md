# Threat Engine – Box-Level Architecture

**Repo root (local):** `threat-engine/`  
**Git path from root:** All paths below are relative to repo root. After push, reference as: `https://github.com/<org>/<repo>/blob/<branch>/<path>`.

---

## Overview

This document defines:
- **High-level boxes** (components) and their databases/tables
- **Box diagram** (data flow)
- **Per-engine UI pages** and mapping to API endpoints or DB queries/views
- **File references** with local path and Git path for UI mocks

Use it for architecture clarity and for implementing the frontend against the right APIs and DB views.

---

## 1. Box Diagram (High-Level Flow)

```
+--------------------------------------------------------------------------------------------------+
|                           USER PORTAL (UI + Django Backend)                                       |
|  Login | Tenants | Assets | Threats | Compliance | Onboarding (accounts, schedules, trigger)   |
+--------------------------------------------------------+---------------------------------------+
                                                         |
                                                         v
+--------------------------------------------------------------------------------------------------+
|                           ONBOARDING ENGINE                                                       |
|  Accounts, Schedules, Credentials | Scheduler polls due schedules -> triggers orchestration      |
+--------------------------------------------------------+---------------------------------------+
                                                         |
                                                         v
+--------------------------------------------------------------------------------------------------+
|                           API GATEWAY                                                             |
|  POST /gateway/orchestrate  =>  Discovery -> Check -> Threat -> (Compliance|IAM|DataSec) -> Inv  |
+--------+--------+--------+--------+--------+--------+------------------------------------------+
         |        |        |        |        |        |
         v        v        v        v        v        v
    +--------+ +------+ +--------+ +----------+ +--------+ +-----------+
    |Discover| |Check | |Threat  | |Compliance| |IAM/    | |Inventory |
    |Engine  | |Engine| |Engine  | |Engine    | |DataSec | |Engine    |
    +---+----+ +--+---+ +---+----+ +-----+----+ +---+----+ +-----+----+
        |         |         |           |          |           |
        v         v         v           v          v           v
    +--------+ +--------+ +--------+ +--------+ +--------+ +--------+
    |threat_ | |threat_ | |threat_ | |threat_ | |threat_ | |threat_  |
    |engine_ | |engine_ | |engine_ | |engine_ | |engine_ | |engine_  |
    |discov. | |check   | |threat  | |compl.  | |check   | |invent.  |
    +--------+ +--------+ +--------+ +--------+ +(views) + +--------+
```

**Flow in words:**  
User Portal uses Onboarding for accounts/schedules and “Run scan”. Onboarding (or its scheduler) calls API Gateway `POST /gateway/orchestrate`. Gateway runs Discovery → Check → Threat → (Compliance, IAM, DataSec in parallel) → Inventory. Each engine reads/writes its database (or views on Check DB for IAM/DataSec).

---

## 2. High-Level Boxes Table

**Boxes ↔ Databases ↔ Tables/Views ↔ Uses**

| Box | Database(s) | Tables / Views | Uses |
|-----|-------------|----------------|------|
| **User Portal (UI + Django)** | engine_onboarding; engines via API | tenants, accounts, schedules, executions; proxy to engine APIs | Login, dashboards, CRUD, “Run scan” / “Trigger schedule” via Onboarding |
| **Onboarding Engine** | engine_onboarding (PostgreSQL) | tenants, accounts, schedules, executions, credentials (or refs) | Account/schedule/credential management; scheduler triggers orchestration |
| **API Gateway** | — | — | Route requests; `POST /gateway/orchestrate` runs full pipeline |
| **Discovery Engine** | threat_engine_discoveries (or configscan DB) | discoveries | Scan cloud resources; write discovery rows |
| **Check Engine** | threat_engine_check | check_results, rule_metadata | Run checks; write check_results; rule_metadata is pre-built |
| **Threat Engine** | threat_engine_threat, threat_engine_check (read) | threat_scans, threats, threat_resources, drift_records; check_results for posture | Threat analysis, drift; resource posture from Check DB |
| **Compliance Engine** | threat_engine_compliance, threat_engine_check (read) | compliance_control_detail (view), resource_compliance_status, compliance_control_mappings | Framework/control/resource compliance; control_mappings pre-built |
| **IAM Engine (view-based)** | threat_engine_check | iam_security_posture, iam_resource_summary, security_posture_summary (views) | IAM check posture; no separate DB |
| **DataSec Engine (view-based)** | threat_engine_check | data_security_posture, datasec_by_module, datasec_resource_summary, security_posture_summary (views) | Data security posture; no separate DB |
| **Inventory Engine** | threat_engine_inventory | asset_index_latest, relationship_index_latest, inventory_run_index | Asset list, relationships, run summary |
| **Rule Engine** | — | — | Rule/metadata support; optional UI |

---

## 3. Pre-Built / Supportive Data Table

| Database | Table / View | Purpose |
|----------|--------------|---------|
| threat_engine_check | rule_metadata | Rule metadata (severity, threat_category, compliance_frameworks); required for Threat/Compliance/views |
| threat_engine_compliance | compliance_control_mappings | Framework control definitions and rule mappings; loaded from CSV |
| threat_engine_check | iam_security_posture, data_security_posture, security_posture_summary | Views for IAM/DataSec UI |
| engine_onboarding | tenants, accounts, providers | Tenant/account/provider setup for User Portal and scheduler |

---

## 4. File Reference: UI Mocks and API Mapping (Paths)

**Local path** = from repo root (e.g. `threat-engine/`).  
**Git path** = same path under repo; URL = `https://github.com/<org>/<repo>/blob/<branch>/<path>`.

| Engine | UI Screens Mockup (local + Git path) | UI API Mapping (local + Git path) |
|--------|--------------------------------------|-----------------------------------|
| **Compliance** | `engine_compliance/UI_SCREENS_MOCKUP.md` | `engine_compliance/UI_API_MAPPING.md` |
| **Threat** | `engine_threat/UI_SCREENS_MOCKUP.md`, `engine_threat/UI_CHECKS_MOCKUP.md`, `engine_threat/UI_DISCOVERY_MOCKUP.md` | `engine_threat/UI_API_MAPPING.md` |
| **Inventory** | `engine_inventory/UI_SCREENS_MOCKUP.md` | `engine_inventory/UI_API_MAPPING.md` |
| **IAM** | — | `engine_iam/UI_API_MAPPING.md` |
| **DataSec** | `engine_datasec/UI_SCREENS_MOCKUP.md` | `engine_datasec/UI_API_MAPPING.md`, `engine_datasec/UI_API_SPECIFICATION.md` |
| **Onboarding** | `engine_onboarding/UI_SCREENS_MOCKUP.md` | Onboarding API docs, schedules API |
| **User Portal** | (Frontend app) | `engine_userportal/API_ENDPOINTS.md`, `engine_userportal/ACCESS_URLS.md` |

**Quick open from repo root:**
- Compliance UI mock: `./engine_compliance/UI_SCREENS_MOCKUP.md`
- Threat UI mock: `./engine_threat/UI_SCREENS_MOCKUP.md`
- Inventory UI mock: `./engine_inventory/UI_SCREENS_MOCKUP.md`
- Onboarding UI mock: `./engine_onboarding/UI_SCREENS_MOCKUP.md`
- DataSec UI mock: `./engine_datasec/UI_SCREENS_MOCKUP.md`

---

## 5. Per-Engine: UI Pages and API/DB Mapping

Each subsection lists: **UI mock files** (with path), **database**, **pages/screens**, and a **table** mapping each page to **API endpoint** or **DB query/view**.

---

### 5.1 Compliance Engine

| Reference | Path |
|-----------|------|
| UI Screens Mockup | `engine_compliance/UI_SCREENS_MOCKUP.md` |
| UI API Mapping | `engine_compliance/UI_API_MAPPING.md` |

**Database:** `threat_engine_compliance`  
- View: `compliance_control_detail`  
- Tables: `resource_compliance_status`, `compliance_control_mappings`

| UI Page | URL | API Endpoint | DB Query / View |
|---------|-----|--------------|------------------|
| Executive Compliance Dashboard | `/compliance/dashboard` | `GET /api/v1/compliance/dashboard?tenant_id=&scan_id=latest` | `compliance_control_detail` (GROUP BY compliance_framework) |
| Framework Detail | `/compliance/framework/{framework}` | `GET /api/v1/compliance/framework-detail/{framework}?tenant_id=&scan_id=latest` | `compliance_control_detail` WHERE compliance_framework |
| Control Detail | `/compliance/framework/{framework}/control/{control_id}` | `GET /api/v1/compliance/control-detail/{framework}/{control_id}?tenant_id=&scan_id=latest` | `compliance_control_detail` + `resource_compliance_status` |
| Account Compliance | `/compliance/accounts/{account_id}` | `GET /api/v1/compliance/accounts/{account_id}` | `resource_compliance_status` WHERE account_id |
| Resource Compliance | `/compliance/resource/{resource_uid}` | `GET /api/v1/compliance/resource/{resource_uid}/compliance?tenant_id=` | `resource_compliance_status` WHERE resource_uid |
| Service Compliance | `/compliance/service/{service}` | (Optional) | View `compliance_by_service` WHERE service |

**UI components (from mock):** Dashboard: overall score, framework cards, progress bars, top critical findings. Framework: control list, failed/passed tabs. Control: control description, affected resources, mapped rules. Resource: framework summaries, control list.

---

### 5.2 Threat Engine

| Reference | Path |
|-----------|------|
| UI Screens Mockup | `engine_threat/UI_SCREENS_MOCKUP.md` |
| UI Checks Mockup | `engine_threat/UI_CHECKS_MOCKUP.md` |
| UI Discovery Mockup | `engine_threat/UI_DISCOVERY_MOCKUP.md` |
| UI API Mapping | `engine_threat/UI_API_MAPPING.md` |

**Databases:** `threat_engine_threat` (threats, scans, resources, drift), `threat_engine_check` (posture)

| UI Page | URL | API Endpoint | DB Query / View |
|---------|-----|--------------|------------------|
| Threat Dashboard | `/threats/dashboard` | `GET /api/v1/threat/scans/{scan_run_id}/summary?tenant_id=` | `threat_scans` WHERE scan_run_id |
| Threat List | `/threats/list` | `GET /api/v1/threat/threats?tenant_id=&severity=&category=&limit=` | `threats` with filters |
| Threat Detail | `/threats/{threat_id}` | `GET /api/v1/threat/threats/{threat_id}?tenant_id=` | `threats` + `threat_resources` |
| Resource Threats | `/resources/{resource_uid}/threats` | `GET /api/v1/threat/resources/{resource_uid}/threats?tenant_id=` | `threats` JOIN `threat_resources` ON resource_uid |
| Resource Posture | `/resources/{resource_uid}/posture` | `GET /api/v1/threat/resources/{resource_uid}/posture?tenant_id=&scan_id=` | `check_results` (Check DB) WHERE resource_uid, scan_id |
| Drift Monitoring | `/threats/drift` | `GET /api/v1/threat/drift?tenant_id=&current_scan_id=` | `drift_records` |

**UI components (from mock):** Dashboard: total/critical/high/medium, by category, top critical threats, trend. List: filters (severity, category, status), group by category. Detail: title, description, affected resources, remediation.

---

### 5.3 Inventory Engine

| Reference | Path |
|-----------|------|
| UI Screens Mockup | `engine_inventory/UI_SCREENS_MOCKUP.md` |
| UI API Mapping | `engine_inventory/UI_API_MAPPING.md` |

**Database:** `threat_engine_inventory`  
- Tables: `asset_index_latest`, `relationship_index_latest`, `inventory_run_index`

| UI Page | URL | API Endpoint | DB Query / View |
|---------|-----|--------------|------------------|
| Inventory Dashboard | `/inventory/dashboard` | `GET /api/v1/inventory/runs/latest/summary?tenant_id=` | `inventory_run_index` ORDER BY completed_at DESC LIMIT 1 |
| Asset List | `/inventory/assets` | `GET /api/v1/inventory/assets?tenant_id=&resource_type=&limit=` | `asset_index_latest` with filters |
| Asset Detail | `/inventory/assets/{resource_uid}` | `GET /api/v1/inventory/assets/{resource_uid}?tenant_id=` | `asset_index_latest` WHERE resource_uid |
| Asset Relationships | `/inventory/assets/{resource_uid}/relationships` | `GET /api/v1/inventory/assets/{resource_uid}/relationships?tenant_id=` | `relationship_index_latest` WHERE source_uid or target_uid |
| Relationships Graph | `/inventory/relationships` | `GET /api/v1/inventory/relationships?tenant_id=` | `relationship_index_latest` |
| Drift | `/inventory/drift` | `GET /api/v1/inventory/drift?tenant_id=` or runs/{id}/drift | Drift tables / run comparison |

**UI components (from mock):** Dashboard: total assets, relationships, by provider, by resource type, recent drift. Asset list: filters (type, provider, region, account). Asset detail: metadata, tags, relationships.

---

### 5.4 IAM Security Engine (View-Based)

| Reference | Path |
|-----------|------|
| UI API Mapping | `engine_iam/UI_API_MAPPING.md` |

**Database:** `threat_engine_check` only  
- Views: `iam_security_posture`, `iam_resource_summary`, `security_posture_summary`

| UI Page | URL | API Endpoint | DB Query / View |
|---------|-----|--------------|------------------|
| IAM Dashboard / Posture | `/iam/dashboard` | `GET /api/v1/iam-security/scan` or Check API IAM posture | `iam_security_posture`, `iam_resource_summary` |
| IAM Resource Summary | `/iam/resources` | (Check API or gateway proxy) | `iam_resource_summary` |
| IAM Findings | `/iam/findings` | `GET /api/v1/iam-security/findings?tenant_id=` | Engine aggregates from Check DB views |
| Identity Threats | `/iam/threats` | `GET /api/v1/threat/threats?category=identity` | Threat API (threat_engine_threat.threats) |

---

### 5.5 Data Security Engine (View-Based)

| Reference | Path |
|-----------|------|
| UI Screens Mockup | `engine_datasec/UI_SCREENS_MOCKUP.md` |
| UI API Mapping | `engine_datasec/UI_API_MAPPING.md` |
| UI API Specification | `engine_datasec/UI_API_SPECIFICATION.md` |

**Database:** `threat_engine_check` only  
- Views: `data_security_posture`, `datasec_by_module`, `datasec_resource_summary`, `security_posture_summary`

| UI Page | URL | API Endpoint | DB Query / View |
|---------|-----|--------------|------------------|
| DataSec Dashboard | `/datasec/dashboard` | `GET /api/v1/data-security/scan` (report) or posture API | `datasec_by_module`, `security_posture_summary` |
| DataSec by Module | `/datasec/modules` | (Engine or direct view) | `datasec_by_module` |
| DataSec Findings | `/datasec/findings` | `GET /api/v1/data-security/findings?tenant_id=` | Engine from Check DB views |
| Data Exfiltration Threats | `/datasec/threats` | `GET /api/v1/threat/threats?category=data_exfiltration` | Threat API |

---

### 5.6 Onboarding Engine (User Portal Config & Trigger)

| Reference | Path |
|-----------|------|
| UI Screens Mockup | `engine_onboarding/UI_SCREENS_MOCKUP.md` |

**Database:** `engine_onboarding`  
- Tables: tenants, accounts, schedules, executions, providers; credentials in secrets/store

| UI Page | URL | API Endpoint | DB Query / View |
|---------|-----|--------------|------------------|
| Onboarding Dashboard | `/onboarding/dashboard` | `GET /api/v1/onboarding/tenants`, `/accounts`, `/providers` | tenants, accounts, providers |
| Account List | `/onboarding/accounts` | `GET /api/v1/onboarding/accounts?tenant_id=` | accounts (join tenant, provider) |
| Account Detail / Create | `/onboarding/accounts/new`, `/{id}` | `GET/POST/PUT /api/v1/onboarding/accounts` | accounts |
| Schedule List | `/onboarding/schedules` | `GET /api/v1/schedules?tenant_id=` or `/api/v1/onboarding/schedules` | schedules |
| Schedule Create/Edit | `/onboarding/schedules/new`, `/{id}` | `POST/PUT /api/v1/schedules` | schedules (cron, regions, services) |
| Trigger Scan / Orchestration | (Button) | `POST /api/v1/schedules/{schedule_id}/trigger` or “run orchestration” → Gateway | executions; Onboarding calls `POST /gateway/orchestrate` |
| Credentials | (Part of account flow) | `POST/GET /api/v1/credentials/store`, `/{id}` | Credentials store / secrets refs |

---

### 5.7 User Portal (Django Backend + Frontend)

**UI:** Frontend (React/Vue) – dashboards, threats, inventory, compliance, onboarding. Django Backend – auth, tenant/asset APIs; proxies to Onboarding and engine APIs.

| UI Page | API / Data Source | Notes |
|---------|-------------------|--------|
| Login | `POST /api/auth/login/` | Django backend |
| Tenants | `GET /api/tenants/` | Django or Onboarding API |
| Assets | `GET /api/assets/` | Django or Inventory API `GET /api/v1/inventory/assets` |
| Threats | `GET /api/threats/` | Threat API `GET /api/v1/threat/threats` |
| Compliance | Dashboard / frameworks | Compliance API `GET /api/v1/compliance/dashboard`, framework-detail, etc. |
| Onboarding (accounts, schedules) | Onboarding API | `GET/POST /api/v1/onboarding/accounts`, `GET/POST /api/v1/schedules` |
| “Run scan” / “Trigger schedule” | Onboarding API → Gateway | Onboarding calls `POST /gateway/orchestrate` |

**API Gateway:** All engine APIs via Gateway (`/api/v1/compliance/*`, `/api/v1/threat/*`, `/api/v1/inventory/*`, `/api/v1/iam-security/*`, `/api/v1/data-security/*`). Full pipeline: `POST /gateway/orchestrate`.

---

## 6. Summary: Pages per Engine and Data Source

| Engine | Pages / Sections | Primary API Prefix | Primary DB / View |
|--------|------------------|--------------------|--------------------|
| Compliance | Dashboard, Framework, Control, Account, Resource, Service | `/api/v1/compliance/` | threat_engine_compliance (compliance_control_detail, resource_compliance_status) |
| Threat | Dashboard, List, Detail, Resource Threats, Resource Posture, Drift | `/api/v1/threat/` | threat_engine_threat (threats, threat_resources, threat_scans, drift_records); posture from threat_engine_check |
| Inventory | Dashboard, Asset List, Asset Detail, Relationships, Drift | `/api/v1/inventory/` | threat_engine_inventory (asset_index_latest, relationship_index_latest, inventory_run_index) |
| IAM | Dashboard, Resources, Findings, Identity Threats | `/api/v1/iam-security/`, `/api/v1/threat/threats?category=identity` | threat_engine_check (iam_* views) |
| DataSec | Dashboard, Modules, Findings, Data Threats | `/api/v1/data-security/`, `/api/v1/threat/threats?category=data_exfiltration` | threat_engine_check (data_* views) |
| Onboarding | Dashboard, Accounts, Schedules, Credentials, Trigger | `/api/v1/onboarding/`, `/api/v1/schedules/`, `/gateway/orchestrate` | engine_onboarding (tenants, accounts, schedules, executions) |
| User Portal | Login, Tenants, Assets, Threats, Compliance, Onboarding | Django + proxy to above | Same as above via APIs |

---

## 7. Git and Local Path Reference

**Repo root (local):** `threat-engine/` (or your clone path).  
**Git URL template:** `https://github.com/<org>/<repo>/blob/<branch>/<path>`  

Replace `<org>`, `<repo>`, `<branch>` after push. Example: `https://github.com/myorg/threat-engine/blob/main/engine_compliance/UI_SCREENS_MOCKUP.md`.

| File | Local path (from repo root) | Git path (same) |
|------|-----------------------------|------------------|
| This doc | `BOX_LEVEL_ARCHITECTURE.md` | `BOX_LEVEL_ARCHITECTURE.md` |
| Compliance UI mock | `engine_compliance/UI_SCREENS_MOCKUP.md` | `engine_compliance/UI_SCREENS_MOCKUP.md` |
| Compliance API mapping | `engine_compliance/UI_API_MAPPING.md` | `engine_compliance/UI_API_MAPPING.md` |
| Threat UI mock | `engine_threat/UI_SCREENS_MOCKUP.md` | `engine_threat/UI_SCREENS_MOCKUP.md` |
| Threat checks mock | `engine_threat/UI_CHECKS_MOCKUP.md` | `engine_threat/UI_CHECKS_MOCKUP.md` |
| Threat discovery mock | `engine_threat/UI_DISCOVERY_MOCKUP.md` | `engine_threat/UI_DISCOVERY_MOCKUP.md` |
| Threat API mapping | `engine_threat/UI_API_MAPPING.md` | `engine_threat/UI_API_MAPPING.md` |
| Inventory UI mock | `engine_inventory/UI_SCREENS_MOCKUP.md` | `engine_inventory/UI_SCREENS_MOCKUP.md` |
| Inventory API mapping | `engine_inventory/UI_API_MAPPING.md` | `engine_inventory/UI_API_MAPPING.md` |
| IAM API mapping | `engine_iam/UI_API_MAPPING.md` | `engine_iam/UI_API_MAPPING.md` |
| DataSec UI mock | `engine_datasec/UI_SCREENS_MOCKUP.md` | `engine_datasec/UI_SCREENS_MOCKUP.md` |
| DataSec API mapping | `engine_datasec/UI_API_MAPPING.md` | `engine_datasec/UI_API_MAPPING.md` |
| DataSec API spec | `engine_datasec/UI_API_SPECIFICATION.md` | `engine_datasec/UI_API_SPECIFICATION.md` |
| Onboarding UI mock | `engine_onboarding/UI_SCREENS_MOCKUP.md` | `engine_onboarding/UI_SCREENS_MOCKUP.md` |
| User Portal API docs | `engine_userportal/API_ENDPOINTS.md` | `engine_userportal/API_ENDPOINTS.md` |
| User Portal access | `engine_userportal/ACCESS_URLS.md` | `engine_userportal/ACCESS_URLS.md` |

---

*Single box-level reference for architecture, databases, and UI-to-API/DB mapping. Use local paths for opening files; use Git path (or full URL after push) for links and references.*
