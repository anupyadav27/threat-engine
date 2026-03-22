# Threat Engine UI & Backend Integration: Capability Matrix and Project Plan

**Document Date:** March 6, 2026
**Status:** Master Planning Document
**Version:** 1.0
**Prepared For:** Full-Stack Development Team

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Capability Matrix: Engine → API → UI](#capability-matrix-engine--api--ui)
3. [Two-System Architecture](#two-system-architecture)
4. [Epics and User Stories](#epics-and-user-stories)
5. [Task Breakdown](#task-breakdown)
6. [Agent Skill Sets](#agent-skill-sets)
7. [Dependency Graph](#dependency-graph)
8. [Execution Phases](#execution-phases)
9. [Wiz-Level Enhancements](#wiz-level-enhancements)
10. [Risk Assessment & Success Metrics](#risk-assessment--success-metrics)

---

## Executive Summary

This document provides a comprehensive roadmap for building a production-grade Cloud Security Posture Management (CSPM) UI integrated with the threat-engine backend platform. The project encompasses:

- **Two backend systems**: cspm-backend (Django auth/tenants) + threat-engine (11 FastAPI engines)
- **14 major epics** spanning Foundation, Auth, Security Analysis, Compliance, and Platform features
- **50+ user stories** with full API integration mappings
- **200+ concrete development tasks**
- **6 specialized agent profiles** for parallel development
- **8-week execution timeline** organized in 4 phases

The UI will replicate Wiz-level sophistication with multi-dimensional filtering, multiple view modes, MITRE ATT&CK mapping, and advanced threat visualization capabilities.

---

## CAPABILITY MATRIX: ENGINE → API → UI

### System 1: CSPM Backend (Django) — Authentication & Tenant Management

**Role**: Management plane - user authentication, tenant isolation, audit logging
**Framework**: Django 6.0.1 + DRF 3.16.1
**Port**: 8000
**Database**: PostgreSQL (shared)
**Status**: 70% complete (auth working, RBAC not enforced, audit logging missing)

#### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Status |
|----------|--------|---------|-------------|--------|
| `/api/auth/login/` | POST | Email/password authentication | Login page | ✅ Implemented |
| `/api/auth/saml/login/` | GET | OKTA SSO redirect | Login page | ✅ Implemented |
| `/api/auth/refresh/` | POST | Token refresh | Session mgmt | ✅ Implemented |
| `/api/auth/logout/` | POST | Revoke session | All pages | ✅ Implemented |
| `/api/auth/csrf/` | GET | CSRF token retrieval | All forms | ✅ Implemented |
| `/api/tenants/` | GET | List user's tenants | Onboarding, Settings | ✅ Implemented |
| `/api/tenants/` | POST | Create new tenant | Onboarding | ✅ Implemented |
| `/api/tenants/{id}/` | GET | Get tenant details | Onboarding detail | ✅ Implemented |
| `/api/tenants/{id}/` | PUT/PATCH | Update tenant | Onboarding edit | ✅ Implemented |
| `/api/tenants/{id}/` | DELETE | Delete tenant | Onboarding | ✅ Implemented |
| `/api/tenants/export/` | GET | Export tenants (XLSX/PDF) | Onboarding | ✅ Implemented |

#### Current UI Implementation

| Page | Component | APIs Used | Status |
|------|-----------|-----------|--------|
| `/auth/login` | LoginForm + EmailInput + PasswordInput | POST /login, POST /refresh | ✅ Complete |
| `/settings/tenants` | TenantGrid, CreateTenantModal | GET /tenants, POST /tenants, PUT /tenants | ⚠️ Partial |
| `/` (Dashboard) | Global tenant selector | GET /tenants | ⚠️ Minimal |

#### UI Gap Analysis

- **Missing Authorization Enforcement**: API has no @permission_required decorators; frontend must validate
- **No Audit Logging**: AuditLog models empty; cannot track user actions
- **No Onboarding Flow**: Cloud account onboarding in cspm-backend stubbed out
- **Rating**: 2/5 — Foundation only, missing critical features

---

### System 2: Threat Engine — 11 Security Scanning Engines

**Role**: Data plane - cloud discovery, compliance checking, threat detection, analysis
**Framework**: FastAPI (async)
**Database**: PostgreSQL (9+ databases, engine-specific schemas)
**Status**: 90% complete (engines running, UI integration needs work)

---

#### ENGINE 1: ONBOARDING (Port 8010)

**Purpose**: Cloud account registration, credential validation, lifecycle management
**Databases**: onboarding_db (cloud_accounts, credentials, schedules)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/cloud-accounts` | GET | List all cloud accounts | Onboarding/Accounts page | `{"accounts": [{"id": "...", "provider": "aws", "account_id": "588989875114", "name": "prod", "status": "active"}], "count": 6}` |
| `/api/v1/cloud-accounts` | POST | Register new cloud account | Onboarding/Add Account | `{"id": "uuid", "status": "pending_validation"}` |
| `/api/v1/cloud-accounts/{id}` | GET | Get account details | Onboarding detail modal | `{"id": "...", "provider": "aws", "credentials_valid": true, "last_scanned": "2026-03-06T10:30Z"}` |
| `/api/v1/cloud-accounts/{id}/credentials` | POST | Store CSP credentials | Onboarding/Credentials step | `{"status": "stored", "encrypted": true}` |
| `/api/v1/cloud-accounts/{id}/validate-credentials` | POST | Test credentials against CSP | Credentials validation modal | `{"valid": true, "permissions": [...], "warnings": []}` |
| `/api/v1/schedules` | GET | List scan schedules | Schedules page | `{"schedules": [...], "count": 3}` |
| `/api/v1/schedules` | POST | Create/update schedule (cron) | Schedule editor | `{"id": "uuid", "cron": "0 0 * * *", "status": "active"}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/onboarding/tenants` | ❌ Not implemented | Need to list tenants from cspm-backend |
| `/onboarding/accounts` | ❌ Not implemented | Need 3-step flow: select provider → enter credentials → validate |
| `/onboarding/schedules` | ❌ Not implemented | Need cron editor, schedule history, execution log |

##### Gap Analysis

- **Credential Storage UI Missing**: Need secure forms for 6 CSP credential types (AWS keys, Azure app ID, GCP service account, OCI keys, AliCloud keys, IBM API key)
- **Validation Feedback Missing**: Real-time credential validation UI with permission preview
- **Schedule Management Missing**: Cron editor, schedule history, manual trigger capability
- **Effort**: 40 story points (Medium epic)

---

#### ENGINE 2: DISCOVERIES (Port 8001)

**Purpose**: Cloud resource enumeration (40+ services across 6 CSPs)
**Databases**: discoveries_db (cloud_resources, discovery_findings, service_metadata)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/discoveries` | GET | List discovery scans | Scans history | `{"scans": [{"id": "uuid", "account_id": "...", "started_at": "...", "status": "completed", "resource_count": 1529}]}` |
| `/api/v1/discoveries/{id}/status` | GET | Get scan status (for polling) | Scans progress page | `{"status": "in_progress", "progress": 65, "resources_found": 1200, "current_service": "ec2"}` |
| `/api/v1/discoveries/{id}/resources` | GET | Paginated resources from scan | Inventory assets page | `{"resources": [...], "total": 1529, "pagination": {...}}` |
| `/api/v1/services` | GET | Enumerated cloud services | Discovery config | `{"services": ["ec2", "rds", "s3", ...], "count": 40}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/scans/run-scan` | ❌ Not implemented | Need account selector, service filter, schedule picker |
| `/scans/history` | ❌ Not implemented | Need paginated scan list with status, duration, resource count |
| `/scans/detail/{id}` | ❌ Not implemented | Need progress bar, service-by-service breakdown, error logging |

##### Gap Analysis

- **Scan Orchestration Missing**: UI must call `/gateway/api/v1/orchestrate` to trigger full pipeline
- **Real-time Progress Missing**: Need polling mechanism (3-second intervals) for scan status
- **Service Filter Missing**: UI should let users select subset of 40+ services
- **Effort**: 30 story points (Medium epic)

---

#### ENGINE 3: CHECK (Port 8002)

**Purpose**: Compliance rule evaluation (PASS/FAIL/ERROR assessment against discoveries)
**Databases**: check_db (rule_definitions, check_findings, rule_metadata)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/checks` | GET | List compliance checks | Compliance page | `{"checks": [{"id": "...", "rule_id": "cis_1_1", "status": "PASS", "resource_count": 150}]}` |
| `/api/v1/checks/{id}` | GET | Get check detail | Compliance detail modal | `{"id": "...", "rule": {...}, "passed_resources": 150, "failed_resources": 5, "errored_resources": 0}` |
| `/api/v1/rules` | GET | List all rule definitions | Rule management page | `{"rules": [...], "count": 200}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/compliance/rules` | ❌ Not implemented | Need rule listing, search, detail view |

##### Gap Analysis

- **Rule Editor Missing**: Need YAML/JSON rule editor for custom rules
- **Check Results Display Missing**: Must integrate with compliance engine for result display
- **Effort**: 15 story points (Low epic)

---

#### ENGINE 4: INVENTORY (Port 8022)

**Purpose**: Asset normalization, relationship mapping, drift detection
**Databases**: inventory_db (assets, relationships, drift_baselines, graphs)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/inventory/assets` | GET | Paginated asset list | Assets page | `{"assets": [{"resource_uid": "arn:...", "type": "EC2Instance", "provider": "aws", "region": "ap-south-1", "state": "running"}], "count": 1529, "pagination": {...}}` |
| `/api/v1/inventory/assets/{uid}` | GET | Asset detail with metadata | Asset detail modal | `{"uid": "...", "attributes": {...}, "relationships": [...], "threats": [...], "compliance_violations": [...]}` |
| `/api/v1/inventory/assets/{uid}/relationships` | GET | Related resources | Relationships tab in detail | `{"inbound": [...], "outbound": [...]}` |
| `/api/v1/inventory/graph` | GET | Full relationship graph (D3 format) | Graph visualization page | `{"nodes": [...], "edges": [...]}` |
| `/api/v1/inventory/drift` | GET | Baseline comparison | Drift page | `{"added": [...], "removed": [...], "modified": [...]}` |
| `/api/v1/inventory/asset-groups` | GET | Asset grouping (by tag, type, region) | Asset grouping page | `{"groups": {...}, "total_assets": 1529}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/inventory/assets` | ✅ Partially working | Basic table with pagination works; missing filters, sorting, detail view |
| `/inventory/asset-detail/{uid}` | ❌ Not implemented | Need modal/side panel with tabs: Details, Relationships, Threats, Compliance, Drift |
| `/inventory/relationships` | ❌ Not implemented | Need force-directed graph visualization |
| `/inventory/graph` | ❌ Not implemented | Need interactive D3/force-graph for 1,529 nodes + 199 edges |
| `/inventory/drift` | ❌ Not implemented | Need baseline selector, before/after comparison table |

##### Gap Analysis

- **Graph Visualization Missing**: Need React Force Graph or D3.js library + real-time updates
- **Relationship Filtering Missing**: Cannot filter assets by relationship type, depth
- **Drift UI Missing**: Cannot select baseline, compare versions
- **Performance Risk**: 1,529 assets may cause table performance issues without virtual scrolling
- **Effort**: 50 story points (Large epic)

---

#### ENGINE 5: THREAT (Port 8020)

**Purpose**: Threat detection, MITRE ATT&CK mapping, attack chain correlation, risk scoring
**Databases**: threat_db (threat_findings, mitre_mappings, correlation_chains, risk_scores)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/threat/threats` | GET | Paginated threat list | Threats page | `{"threats": [{"id": "...", "severity": "CRITICAL", "category": "Network Exposure", "mitre_techniques": ["T1200"], "affected_assets": 5, "detected_at": "2026-03-06T10:00Z"}], "count": 193}` |
| `/api/v1/threat/threats/{id}` | GET | Threat detail with remediation | Threat detail modal | `{"id": "...", "description": "...", "root_cause": {...}, "affected_resources": [...], "remediation_steps": [...], "blast_radius": {...}}` |
| `/api/v1/threat/analytics/distribution` | GET | KPI distribution | Dashboard/Threats overview | `{"critical": 4, "high": 130, "medium": 58, "low": 1}` |
| `/api/v1/threat/analytics/trend` | GET | 30-day trend data | Dashboard trend chart | `{"dates": [...], "new_threats": [...], "resolved_threats": [...]}` |
| `/api/v1/graph/attack-paths` | GET | Internet-exposed → internal | Attack paths page | `{"paths": [{"internet_exposed": "...", "internal_target": "...", "hops": 3}]}` |
| `/api/v1/graph/blast-radius/{uid}` | GET | Blast radius for resource | Threat detail blast radius | `{"affected_assets": [...], "cascade_potential": {...}}` |
| `/api/v1/threat/mitre` | GET | MITRE technique summary | MITRE view page | `{"techniques": [...], "tactics": [...]}` |
| `/api/v1/threat/hunts` | GET | Threat hunting queries | Threat hunting page | `{"hunts": [{"id": "...", "name": "S3 Bucket Public ACL", "query": "..."}]}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/threats/overview` | ❌ Not implemented | Need KPI cards (4 critical, 130 high), bar chart (by service), trend chart |
| `/threats/list` | ✅ Partially working | Basic table works; missing MITRE display, filtering, sorting |
| `/threats/detail/{id}` | ❌ Not implemented | Need modal with findings, affected assets, remediation, blast radius graph |
| `/threats/attack-paths` | ❌ Not implemented | Need attack chain visualization with internet-exposed → internal flow |
| `/threats/analytics` | ❌ Not implemented | Need trend chart, distribution, correlation matrix, patterns |
| `/threats/mitre-view` | ❌ Not implemented | Need MITRE ATT&CK matrix heatmap with technique-to-finding mapping |
| `/threats/hunting` | ❌ Not implemented | Need saved queries, custom Cypher editor, result visualization |

##### Gap Analysis

- **MITRE Matrix Missing**: Critical Wiz-level feature; need interactive heatmap
- **Blast Radius Visualization Missing**: Need graph visualization for attack chain
- **Threat Hunting Missing**: Need Cypher query editor + result display
- **Risk Scoring Missing**: UI should display 0-100 risk scores with calculation basis
- **Effort**: 80 story points (Very Large epic)

---

#### ENGINE 6: COMPLIANCE (Port 8000)

**Purpose**: Framework reporting (13 frameworks: CIS, NIST, ISO 27001, PCI-DSS, HIPAA, GDPR, SOC 2, etc.)
**Databases**: compliance_db (frameworks, controls, compliance_reports, control_findings)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/compliance/dashboard` | GET | Overall compliance overview | Compliance dashboard | `{"overall_score": 76, "frameworks": [{"name": "HIPAA", "score": 78}, {"name": "PCI-DSS", "score": 85}, ...]}` |
| `/api/v1/compliance/frameworks` | GET | List all supported frameworks | Compliance framework selector | `{"frameworks": ["CIS", "NIST", "ISO27001", ...], "count": 13}` |
| `/api/v1/compliance/framework-detail/{fw}` | GET | Framework controls & status | Compliance detail page | `{"framework": "HIPAA", "score": 78, "controls": [...]}` |
| `/api/v1/compliance/control-detail/{fw}/{ctrl}` | GET | Control requirements & affected resources | Control detail modal | `{"control": "EC2.1", "requirement": "...", "passed": 150, "failed": 5, "affected_resources": [...]}` |
| `/api/v1/compliance/generate/from-check-db` | POST | Generate compliance report | Report generation | `{"report_id": "uuid", "status": "generating"}` |
| `/api/v1/compliance/reports` | GET | List generated reports | Reports page | `{"reports": [{"id": "...", "framework": "HIPAA", "generated_at": "...", "score": 78}]}` |
| `/api/v1/compliance/reports/{id}/export` | GET | Export report (PDF/XLSX) | Report download | Binary PDF/XLSX file |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/compliance/dashboard` | ❌ Not implemented | Need 13 gauge charts, overall score, framework comparison |
| `/compliance/framework/{fw}` | ❌ Not implemented | Need controls grouped by status, resource counts, drill-down |
| `/compliance/control/{fw}/{ctrl}` | ❌ Not implemented | Need control requirements, affected resource list |
| `/compliance/reports` | ❌ Not implemented | Need report history, PDF/XLSX export, scheduled reports |

##### Gap Analysis

- **Framework Gauges Missing**: Need semicircle gauge component for 13 frameworks
- **Control Hierarchy Missing**: Cannot show controls grouped by domain/category
- **Report Generation Missing**: Need PDF/XLSX export with charts, tables, executive summary
- **Scheduled Reports Missing**: No UI for scheduling automated compliance reports
- **Effort**: 60 story points (Large epic)

---

#### ENGINE 7: IAM SECURITY (Port 8003)

**Purpose**: IAM posture analysis (57 rules across 6 modules)
**Databases**: iam_db (iam_findings, privilege_escalation, credential_mgmt, etc.)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/iam-security/findings` | GET | Paginated IAM findings | IAM findings page | `{"findings": [{"id": "...", "module": "privilege_escalation", "severity": "HIGH", "description": "..."}], "count": 825}` |
| `/api/v1/iam-security/modules` | GET | IAM module list (6 modules) | IAM module selector | `{"modules": ["privilege_escalation", "over_permission", "credential_mgmt", ...]}` |
| `/api/v1/iam-security/module/{module}` | GET | Module-specific findings | Module detail page | `{"module": "privilege_escalation", "findings": [...], "affected_identities": [...]}` |
| `/api/v1/iam-security/analytics` | GET | IAM metrics (critical users, unused credentials) | IAM analytics page | `{"critical_identities": 5, "unused_credentials": 23, "mfa_adoption": 78}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/iam/findings` | ❌ Not implemented | Need findings list (filterable by module, severity, status) |
| `/iam/modules` | ❌ Not implemented | Need module overview with KPIs for each of 6 modules |
| `/iam/module/{module}` | ❌ Not implemented | Need module-specific findings + affected identities |

##### Gap Analysis

- **Module UI Missing**: Need clear presentation of 6 modules (Policy Analysis, Least Privilege, MFA, Credential Mgmt, etc.)
- **Identity Mapping Missing**: Cannot show which identities are affected by findings
- **Effort**: 35 story points (Medium epic)

---

#### ENGINE 8: DATA SECURITY (Port 8004)

**Purpose**: Data classification, exposure detection, encryption analysis (62 rules)
**Databases**: datasec_db (data_findings, classification, exposure_map, encryption_status)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/data-security/findings` | GET | Paginated data security findings | DataSec findings page | `{"findings": [{"id": "...", "resource_type": "S3Bucket", "severity": "HIGH", "finding_type": "unencrypted"}], "count": 3900}` |
| `/api/v1/data-security/catalog` | GET | Data asset catalog | DataSec catalog page | `{"assets": [{"id": "...", "type": "S3Bucket", "classified": true, "encrypted": true}], "count": 21}` |
| `/api/v1/data-security/catalog/{asset_id}` | GET | Asset detail (lineage, encryption, access) | Asset detail modal | `{"asset": {...}, "data_classification": "sensitive", "lineage": [...], "access_controls": [...]}` |
| `/api/v1/data-security/analytics` | GET | Data security metrics | DataSec analytics page | `{"total_assets": 21, "encrypted": 19, "classified": 21, "exposure_count": 3900}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/datasec/findings` | ❌ Not implemented | Need findings table (filterable by resource type, classification, encryption) |
| `/datasec/catalog` | ❌ Not implemented | Need asset catalog with encryption/classification status |
| `/datasec/lineage` | ❌ Not implemented | Need data flow visualization |
| `/datasec/residency` | ❌ Not implemented | Need data residency/geographic distribution view |

##### Gap Analysis

- **Catalog UI Missing**: Need to display 21+ S3 buckets with metadata
- **Lineage Visualization Missing**: Cannot show data flow between resources
- **Classification UI Missing**: No way to view/set data classification levels
- **Effort**: 40 story points (Medium epic)

---

#### ENGINE 9: SECOPS / CODE SECURITY (Port 8005)

**Purpose**: IaC scanning (14 languages), SBOM analysis, DAST scanning
**Databases**: secops_db (code_findings, sbom_records, dast_results, rule_stats)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/secops/rules/stats` | GET | Rule statistics by language | SecOps overview | `{"total_rules": 2454, "languages": {...}, "findings_by_language": {...}}` |
| `/api/v1/secops/scan` | POST | Trigger IaC scan on repo | Scan trigger | `{"scan_id": "uuid", "status": "queued"}` |
| `/api/v1/secops/scan/{id}/status` | GET | Scan progress | Scan detail page | `{"status": "in_progress", "progress": 50, "findings_count": 23}` |
| `/api/v1/secops/findings` | GET | Code findings list | Findings page | `{"findings": [{"id": "...", "file": "main.tf", "rule": "...", "severity": "HIGH", "line": 42}]}` |
| `/api/v1/secops/sbom` | GET | SBOM records | SBOM page | `{"sboms": [...], "total_dependencies": 5432}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/secops/overview` | ❌ Not implemented | Need rule statistics by language, critical findings |
| `/secops/scans` | ❌ Not implemented | Need scan trigger, history, results |
| `/secops/findings` | ❌ Not implemented | Need findings table with file/line number, remediation |
| `/secops/sbom` | ❌ Not implemented | Need SBOM visualization, dependency graph |

##### Gap Analysis

- **Language Support Display Missing**: Need to show all 14 languages with rule counts
- **Scan Trigger Missing**: Need git repo selector, branch picker, scan execution UI
- **Remediation Display Missing**: Cannot show code fixes inline
- **Effort**: 45 story points (Medium-Large epic)

---

#### ENGINE 10: RULE MANAGEMENT (Port 8011)

**Purpose**: YAML rule definitions, custom rule creation
**Databases**: rule_db (rule_definitions, rule_versions, rule_mappings)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/rules` | GET | List all rules | Rule management page | `{"rules": [...], "count": 200+}` |
| `/api/v1/rules/{id}` | GET | Get rule definition (YAML) | Rule detail/editor | `{"id": "...", "yaml": "...", "version": 1, "created_at": "..."}` |
| `/api/v1/rules` | POST | Create custom rule | Rule editor | `{"id": "uuid", "version": 1}` |
| `/api/v1/rules/{id}` | PUT | Update rule (new version) | Rule editor save | `{"id": "...", "version": 2}` |
| `/api/v1/rules/{id}/versions` | GET | Rule version history | Rule history timeline | `{"versions": [...]}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/rules/library` | ❌ Not implemented | Need rule listing, search, filtering |
| `/rules/editor` | ❌ Not implemented | Need YAML editor with syntax highlighting, validation |
| `/rules/history` | ❌ Not implemented | Need version timeline, compare views |

##### Gap Analysis

- **YAML Editor Missing**: Need Monaco or CodeMirror with YAML syntax highlighting
- **Rule Versioning Missing**: Cannot browse or compare rule versions
- **Effort**: 30 story points (Medium epic)

---

#### ENGINE 11: RISK QUANTIFICATION (Port 8009)

**Purpose**: FAIR model risk calculation (Factors: Threat Frequency, Vulnerability, Control Effectiveness, Asset Value)
**Databases**: risk_db (risk_scores, asset_values, loss_estimates)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/risk/score` | GET | Overall risk score | Dashboard KPI | `{"overall_risk_score": 6.5, "trend": "↑", "units": "millions USD"}` |
| `/api/v1/risk/asset-value/{asset_id}` | GET | Asset value (for loss estimation) | Asset detail page | `{"asset_value": 2500000, "confidence": 0.85}` |
| `/api/v1/risk/loss-estimation` | GET | Estimated annual loss | Dashboard/Risk page | `{"ale": 1250000, "calculation_basis": {...}}` |
| `/api/v1/risk/factors` | GET | FAIR factor breakdown | Risk analytics page | `{"threat_frequency": 0.8, "vulnerability": 0.6, "control_effectiveness": 0.4, "asset_value": 2500000}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/risk/dashboard` | ❌ Not implemented | Need overall risk score, trend, ALE calculation |
| `/risk/factors` | ❌ Not implemented | Need FAIR factor visualization, sensitivity analysis |
| `/risk/asset-values` | ❌ Not implemented | Need asset value management UI |

##### Gap Analysis

- **Risk Score Display Missing**: Need prominent KPI display with trend indicator
- **FAIR Visualization Missing**: Cannot show factor contribution to overall risk
- **Effort**: 25 story points (Small-Medium epic)

---

#### ENGINE 12: API GATEWAY & ORCHESTRATION (Port 8080)

**Purpose**: Central routing, request auth, service discovery, scan orchestration
**Database**: Shared (routes configs, orchestration_state)

##### API Endpoints

| Endpoint | Method | Purpose | UI Consumer | Sample Response |
|----------|--------|---------|-------------|-----------------|
| `/api/v1/gateway/services` | GET | Service health | Settings/Platform page | `{"services": [{"name": "discoveries", "status": "healthy", "response_time_ms": 45}]}` |
| `/api/v1/gateway/orchestrate` | POST | Start full scan pipeline | Scans/Run scan page | `{"scan_run_id": "uuid", "status": "queued", "pipeline": [...]}` |
| `/api/v1/gateway/orchestrate/{id}/status` | GET | Pipeline progress (polling) | Scans/Detail page | `{"status": "in_progress", "stage": "threat", "progress": 65}` |

##### Current UI Status

| Page | Status | Notes |
|------|--------|-------|
| `/settings/platform-health` | ❌ Not implemented | Need service status dashboard, response times |
| `/scans/orchestrate` | ❌ Not implemented | Need orchestration trigger UI |

---

## TWO-SYSTEM ARCHITECTURE

### System Topology

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (Next.js + React)                      │
│  /auth/login  /dashboard  /onboarding  /scans  /inventory  /threats ... │
└────┬────────────────────────────────────────────────────────────────────┘
     │ HTTP/HTTPS (CORS)
     │ [Session tokens in HTTP-only cookies]
     │
     ├─────────────────────────┬──────────────────────────────────────────┐
     │                         │                                          │
     v                         v                                          v
┌─────────────────────┐  ┌──────────────────────────────────────────────────┐
│  CSPM Backend       │  │         Threat Engine (11 Engines)              │
│  (Django/DRF)       │  │                                                  │
│  Port: 8000         │  │  ┌────────────────────────────────────────────┐ │
│                     │  │  │   API Gateway (Port 8080)                  │ │
│  ┌─────────────────┐│  │  │   [Nginx path-based routing]              │ │
│  │ Auth Service    ││  │  │   /discoveries/* → 8001                    │ │
│  │ • Login         ││  │  │   /check/* → 8002                         │ │
│  │ • SAML/OKTA     ││  │  │   /inventory/* → 8022                     │ │
│  │ • Token mgmt    ││  │  │   /threat/* → 8020                        │ │
│  └─────────────────┘│  │  │   /compliance/* → 8000                    │ │
│                     │  │  │   /iam/* → 8003                           │ │
│  ┌─────────────────┐│  │  │   /datasec/* → 8004                       │ │
│  │ Tenant Mgmt     ││  │  │   /secops/* → 8005                        │ │
│  │ • Tenants CRUD  ││  │  │   /onboarding/* → 8010                    │ │
│  │ • User mgmt     ││  │  │   /rule/* → 8011                          │ │
│  │ • Audit logs    ││  │  │   /risk/* → 8009                          │ │
│  │   (MISSING)     ││  │  │                                             │ │
│  └─────────────────┘│  │  └────────────────────────────────────────────┘ │
│                     │  │                                                  │
│  ┌─────────────────┐│  │  ┌────────────────────────────────────────────┐ │
│  │ PostgreSQL      ││  │  │  11 FastAPI Engines (Parallel Processing) │ │
│  │ (users,         ││  │  │                                             │ │
│  │  tenants,       ││  │  │  Onboarding (8010) ────────────────┐      │ │
│  │  sessions,      ││  │  │     ↓                              ↓      │ │
│  │  roles,         ││  │  │  Discovery (8001) ────────────────→ Check (8002) │
│  │  permissions)   ││  │  │     ↓                      ↓ ↓ ↓ ↓ ↓    │ │
│  └─────────────────┘│  │  │     └──→ Inventory (8022)            │ │
│                     │  │  │         Threat (8020)               │ │
│                     │  │  │         IAM (8003)                 │ │
│                     │  │  │         DataSec (8004)     ←───────┘ │
│                     │  │  │                    ↓                  │ │
│                     │  │  │              Compliance (8000)      │ │
│                     │  │  │                                      │ │
│                     │  │  │  Parallel (not in critical path):   │ │
│                     │  │  │  • SecOps (8005) - IaC scanning    │ │
│                     │  │  │  • Rule (8011) - Rule management   │ │
│                     │  │  │  • Risk (8009) - FAIR model        │ │
│                     │  │  └────────────────────────────────────────┘ │
│                     │  │                                                  │
│                     │  │  ┌────────────────────────────────────────────┐ │
│                     │  │  │  PostgreSQL (9+ Schemas)                   │ │
│                     │  │  │  • discoveries_db  • threat_db             │ │
│                     │  │  │  • check_db        • compliance_db         │ │
│                     │  │  │  • inventory_db    • iam_db                │ │
│                     │  │  │  • datasec_db      • onboarding_db         │ │
│                     │  │  │  • secops_db       • rule_db               │ │
│                     │  │  │  • risk_db                                 │ │
│                     │  │  └────────────────────────────────────────────┘ │
│                     │  │                                                  │
└─────────────────────┘  └──────────────────────────────────────────────────┘
```

### Data Flow: Request → Response

**Example: User views threats in dashboard**

```
Frontend (React)
  ↓ [GET /threat/api/v1/threat/threats + Authorization header]
API Gateway (Nginx) [port 8080]
  ↓ [Strips /threat prefix, routes to 8020]
Threat Engine (FastAPI) [port 8020]
  ↓ [Validates tenant_id from query params]
  ↓ [Queries threat_db PostgreSQL]
  ↓ [Returns JSON: {"threats": [...], "count": 193}]
← [JSON response via API Gateway]
Frontend
  ↓ [Renders threat list, applies filters]
```

### System Responsibilities

#### CSPM Backend (Django)
- **Authentication Layer**: Local login, SAML/OKTA SSO, token generation, session management
- **Authorization**: Role-based access control (RBAC) definitions (Note: Currently NOT enforced in code)
- **Tenant Isolation**: Multi-tenant data segregation via TenantUsers join table
- **Audit Trail**: User action logging (MISSING - to be implemented)
- **User Management**: User CRUD, role assignment, permission definition
- **Global Context**: Tenant/account/scan-run selection for UI

#### Threat Engine (FastAPI)
- **Cloud Discovery**: Enumerate 40+ cloud services across 6 CSPs
- **Compliance Scanning**: 200+ YAML-based rules evaluated against cloud config
- **Threat Detection**: MITRE ATT&CK mapping, risk scoring (0-100), attack chain correlation
- **Asset Management**: Resource normalization, relationship mapping, drift detection
- **Analysis Engines**: IAM (57 rules), DataSec (62 rules), SecOps (14 languages)
- **Orchestration**: Pipeline coordination (scan_orchestration table drives data flow)
- **Risk Quantification**: FAIR model loss estimation

### API Authorization Pattern

**Current Implementation**:
- cspm-backend enforces token validation but NO endpoint-level authorization
- Frontend must validate user permissions before making requests
- Engines trust Authorization header from API Gateway

**Recommended Implementation** (to add):
```
Frontend Request:
  Authorization: Bearer <access_token>
  X-Tenant-ID: <tenant_id>  [optional, can be query param]

API Gateway:
  1. Validates token against cspm-backend /api/auth/validate
  2. Extracts tenant_id from token claims
  3. Injects into X-Tenant-ID header
  4. Routes to appropriate engine

Engine:
  1. Validates X-Tenant-ID in request context
  2. Scopes all queries to tenant_id
  3. Rejects requests with missing/invalid tenant
```

---

## EPICS AND USER STORIES

### Organizational Framework

**14 Epics** organized by functional domain:
- EPIC 0: Foundation & Design System (enabler for all others)
- EPIC 1: Auth & Tenant Management (cspm-backend integration)
- EPIC 2: Dashboard (aggregated metrics)
- EPIC 3: Onboarding (cloud account lifecycle)
- EPIC 4: Scans & Orchestration (pipeline management)
- EPIC 5: Inventory & Asset Management (1,529 assets, graphs, drift)
- EPIC 6: Threats & MITRE ATT&CK (Wiz-level threat analysis)
- EPIC 7: Compliance & Frameworks (13 frameworks, reporting)
- EPIC 8: IAM Security (57 rules across 6 modules)
- EPIC 9: Data Security (62 rules, classification, lineage)
- EPIC 10: SecOps / Code Security (IaC scanning, 14 languages)
- EPIC 11: Risk Quantification (FAIR model)
- EPIC 12: Reports & Export (PDF, Excel, scheduled)
- EPIC 13: Settings & Platform Health (engine status, integrations)
- EPIC 14: Notifications & Audit Log

---

### EPIC 0: Foundation & Design System (Effort: 50 pts, Duration: 2 weeks)

**Goal**: Establish base Next.js project, design tokens, reusable component library, layout system

**Stories**:

#### E0-US1: Project Setup & Build Pipeline
**User Story**: As a developer, I want to set up a Next.js 14 project with TypeScript, Tailwind CSS, and build configuration, so that the team can begin feature development on a solid foundation.

**API Endpoints Consumed**: None (foundation only)

**UI Components Needed**:
- Next.js app router structure
- TypeScript configuration
- Tailwind CSS setup
- Environment variable management
- Build script (dev, prod, test)

**Acceptance Criteria**:
- [ ] Next.js 14+ project runs locally with `npm run dev`
- [ ] TypeScript compiles without errors
- [ ] Tailwind CSS classes available in all components
- [ ] Environment variables loadable from `.env.local`
- [ ] Production build completes without warnings

**Size**: M (Medium)
**Dependencies**: None

---

#### E0-US2: Design System & Color Tokens
**User Story**: As a designer/developer, I want to implement a centralized design system with color tokens, typography, spacing scale, and severity color coding matching Wiz patterns, so that UI consistency is enforced across all pages.

**API Endpoints Consumed**: None

**UI Components Needed**:
- CSS custom properties (--color-critical, --color-high, etc.)
- Typography scale (h1-h6, body, small, code)
- Spacing tokens (--spacing-4, --spacing-8, etc.)
- Severity color map (critical=#DC2626, high=#EA580C, medium=#CA8A04, low=#2563EB)
- Status color map (pass=#16A34A, error=#DC2626, pending=#64748B, running=#2563EB)

**Acceptance Criteria**:
- [ ] Design tokens documented in Figma/Storybook
- [ ] All colors defined in Tailwind config
- [ ] Severity badge components render with correct colors
- [ ] Typography scale matches design spec (Inter font, 24px h1, 14px body)
- [ ] Dark mode support (dark: prefix classes work)

**Size**: M
**Dependencies**: E0-US1

---

#### E0-US3: Reusable Component Library
**User Story**: As a developer, I want a library of reusable UI components (Button, Input, Card, Badge, Modal, Table, etc.) built with Tailwind CSS and shadcn/ui patterns, so that pages can be built faster and consistently.

**API Endpoints Consumed**: None

**UI Components to Build**:
- Button (Primary, Secondary, Danger, Ghost variants)
- Input (TextInput, NumberInput, PasswordInput, SearchInput)
- Card & CardContent
- Badge (Status, Severity, Custom color)
- Modal & Drawer
- Tabs
- Dropdown Select (single, multi-select)
- DataTable (sortable, filterable, paginated)
- Skeleton loaders
- Toast/Snackbar notifications
- Progress bar & circular progress
- Alert box (success, error, warning, info)
- Chip/Tag component

**Acceptance Criteria**:
- [ ] 12+ components built and documented in Storybook
- [ ] All components accept theme variants (color, size, state)
- [ ] Components work in light & dark modes
- [ ] Accessible (ARIA labels, keyboard navigation)
- [ ] TypeScript types exported

**Size**: L (Large)
**Dependencies**: E0-US2

---

#### E0-US4: Layout & Navigation Shell
**User Story**: As a developer, I want to build the main layout shell with top navigation bar, left sidebar, breadcrumbs, and page content area, so that all pages have consistent navigation and structure.

**API Endpoints Consumed**:
- `GET /api/tenants/` (fetch user's tenants for top-bar selector)

**UI Components Needed**:
- TopNavBar (logo, tenant selector, search, notifications, user menu, settings)
- Sidebar (main navigation sections, collapse/expand, active state)
- Breadcrumbs (current page location)
- MainContent area (responsive, accommodates different page types)
- Footer (optional)

**Acceptance Criteria**:
- [ ] Sidebar collapses on mobile (<768px)
- [ ] Top nav shows tenant selector with dropdown
- [ ] Active nav item highlighted in sidebar
- [ ] Page routes properly nested under layout
- [ ] Responsive on tablet (768px-1024px) and desktop (1920px+)

**Size**: M
**Dependencies**: E0-US1, E0-US3

---

#### E0-US5: Form System & Validation
**User Story**: As a developer, I want to implement form components with built-in validation, error display, and submission handling using React Hook Form and Zod schemas, so that forms are consistent and robust.

**API Endpoints Consumed**: Various (form submission endpoints)

**UI Components Needed**:
- FormField wrapper (label, error message, required indicator)
- useFormContext hook integration
- Validation schema examples (Zod)
- Form submission error handling
- Loading state during submission

**Acceptance Criteria**:
- [ ] All form fields show validation errors inline
- [ ] Required fields marked with *
- [ ] Submit button disabled during submission
- [ ] Form resets after successful submission (optional)
- [ ] Keyboard shortcut (Ctrl+Enter) submits form

**Size**: M
**Dependencies**: E0-US3

---

### EPIC 1: Auth & Tenant Management (Effort: 40 pts, Duration: 2 weeks)

**Goal**: Implement login/logout flows, tenant selection, role-based UI, and basic user profile management

**Stories**:

#### E1-US1: Local Login Flow
**User Story**: As a user, I want to log in with email and password, so that I can access my security dashboard.

**API Endpoints Consumed**:
- `POST /api/auth/csrf/` (get CSRF token)
- `POST /api/auth/login/` (authenticate)
- `POST /api/auth/refresh/` (on token expiry)

**UI Components Needed**:
- LoginPage with email & password inputs
- Remember me checkbox
- Forgot password link
- Error message display
- Loading spinner during login

**Acceptance Criteria**:
- [ ] User enters email/password and clicks login
- [ ] Token stored in HTTP-only cookie (automatic via browser)
- [ ] On success, redirect to /dashboard
- [ ] On failure, show error message ("Invalid email or password")
- [ ] Subsequent requests include auth token automatically

**Size**: M
**Dependencies**: E0-US4, E1 foundation

---

#### E1-US2: SAML/OKTA SSO Integration
**User Story**: As an enterprise user, I want to log in via OKTA SSO using SAML, so that I can use existing corporate authentication.

**API Endpoints Consumed**:
- `GET /api/auth/saml/login/` (redirect to OKTA)
- `GET /api/auth/saml/success/` (post-login bridge)
- `POST /api/auth/logout/` (SSO logout)

**UI Components Needed**:
- Login page with "Sign in with OKTA" button
- Fallback to email/password if OKTA not configured
- Post-SAML redirect handling

**Acceptance Criteria**:
- [ ] "Sign in with OKTA" button redirects to OKTA login
- [ ] OKTA assertion validated and user created/updated
- [ ] Redirects back to dashboard with tokens set
- [ ] Logout clears session on OKTA side (SLO)

**Size**: M
**Dependencies**: E1-US1

---

#### E1-US3: Tenant Selection & Switching
**User Story**: As a user with access to multiple tenants, I want to select which tenant's data to view, so that I can switch between different environments.

**API Endpoints Consumed**:
- `GET /api/tenants/` (list user's tenants)
- Store selected tenant_id in Zustand store + URL query param

**UI Components Needed**:
- Tenant dropdown selector in top nav
- Visual indicator of current tenant
- Persist selection in localStorage

**Acceptance Criteria**:
- [ ] Top nav shows current tenant name
- [ ] Dropdown lists all user's tenants
- [ ] Selecting tenant updates all downstream API calls
- [ ] Tenant selection persists across page refreshes
- [ ] All pages receive tenant_id via Zustand or URL param

**Size**: S (Small)
**Dependencies**: E1-US1, E0-US4

---

#### E1-US4: User Profile & Settings
**User Story**: As a user, I want to view and edit my profile information (name, email, password), so that I can manage my account.

**API Endpoints Consumed**:
- `GET /api/auth/user/` (fetch current user) [needs implementation in Django]
- `PUT /api/auth/user/` (update profile) [needs implementation]
- `POST /api/auth/change-password/` (change password) [needs implementation]

**UI Components Needed**:
- Profile page with personal info section
- Edit name/email form
- Change password form with current password verification
- Save/cancel buttons

**Acceptance Criteria**:
- [ ] User profile page loads with current user data
- [ ] Edit profile saves changes and shows success message
- [ ] Password change requires current password
- [ ] Change password validates password strength
- [ ] Session persists after profile update

**Size**: S
**Dependencies**: E1-US1

---

#### E1-US5: Tenant Management UI (CRUD)
**User Story**: As a tenant admin, I want to create, list, edit, and delete tenants, so that I can manage environments.

**API Endpoints Consumed**:
- `GET /api/tenants/` (list with filters, sort, pagination)
- `POST /api/tenants/` (create)
- `GET /api/tenants/{id}/` (detail)
- `PUT/PATCH /api/tenants/{id}/` (update)
- `DELETE /api/tenants/{id}/` (delete)
- `GET /api/tenants/export/?doctype=xlsx` (export)

**UI Components Needed**:
- Tenant list page with DataTable (columns: Name, Status, Plan, Contact Email, Region, Created Date)
- Filters: Status (Active/Inactive), Plan (Basic/Professional/Enterprise), Region
- Create tenant modal/form
- Edit tenant modal
- Delete confirmation modal
- Export button (XLSX, PDF)

**Acceptance Criteria**:
- [ ] Tenant list shows all tenants with pagination
- [ ] Filters and sorting work correctly
- [ ] Create tenant form has all required fields
- [ ] Edit updates selected fields
- [ ] Delete shows confirmation and removes tenant
- [ ] Export generates XLSX/PDF file

**Size**: L
**Dependencies**: E1-US1, E0-US3, E0-US5

---

### EPIC 2: Dashboard (Effort: 60 pts, Duration: 2 weeks)

**Goal**: Build a comprehensive dashboard showing KPIs, trends, and aggregated metrics from all engines

**Stories**:

#### E2-US1: KPI Cards & Summary Statistics
**User Story**: As a security analyst, I want to see high-level security metrics (total threats, critical threats, compliant resources, etc.) on the dashboard home page, so that I can quickly assess the overall security posture.

**API Endpoints Consumed**:
- `GET /threat/api/v1/threat/analytics/distribution` (threat counts by severity)
- `GET /compliance/api/v1/compliance/dashboard` (compliance score and framework scores)
- `GET /inventory/api/v1/inventory/assets` (total asset count)
- `GET /risk/api/v1/risk/score` (overall risk score)

**UI Components Needed**:
- KPI Card component (large number + label + trend indicator + color)
- 4-8 cards: Total Threats, Critical Threats, Assets, Compliance Score, Risk Score, etc.
- Color-coded by severity (red=critical, orange=high, blue=low)
- Hover tooltip showing calculation basis

**Acceptance Criteria**:
- [ ] 6+ KPI cards display with correct values from APIs
- [ ] Cards color-coded by severity or status
- [ ] Trend indicator shows ↑↓ or percentage change
- [ ] Cards clickable, navigating to detail pages
- [ ] Cards update on page refresh

**Size**: M
**Dependencies**: E1-US1, E0-US3

---

#### E2-US2: Threat Trend Chart
**User Story**: As a security analyst, I want to see threat trends over the past 30 days (threats created vs. resolved), so that I can understand resolution velocity and backlog growth.

**API Endpoints Consumed**:
- `GET /threat/api/v1/threat/analytics/trend` (daily threat counts for 30 days)

**UI Components Needed**:
- Time-series line chart (Recharts)
- 2 series: "Threats Triggered" (red line) and "Threats Resolved" (green line)
- X-axis: Days (past 30 days)
- Y-axis: Count
- Legend with toggle to show/hide series
- Hover tooltip showing exact numbers

**Acceptance Criteria**:
- [ ] Chart loads with real data from threat engine
- [ ] 2 series displayed (triggered vs. resolved)
- [ ] Tooltip shows date + both values on hover
- [ ] Legend allows toggling series visibility
- [ ] Responsive (scales to container width)

**Size**: M
**Dependencies**: E0-US3, E2-US1

---

#### E2-US3: Severity Distribution Chart
**User Story**: As a security analyst, I want to see the distribution of threats by severity (Critical, High, Medium, Low), so that I can prioritize remediation efforts.

**API Endpoints Consumed**:
- `GET /threat/api/v1/threat/analytics/distribution`

**UI Components Needed**:
- Bar chart (horizontal bars preferred for Wiz style)
- Categories: Critical, High, Medium, Low
- Colors: red, orange, yellow, blue
- Count or percentage display
- Sortable by count descending

**Acceptance Criteria**:
- [ ] Bar chart displays severity distribution
- [ ] Colors match severity schema (critical=red)
- [ ] Bars labeled with counts
- [ ] Responsive layout

**Size**: S
**Dependencies**: E0-US3, E2-US1

---

#### E2-US4: Compliance Framework Gauges
**User Story**: As a compliance officer, I want to see compliance scores for all 13 frameworks at a glance on the dashboard, so that I can quickly identify which frameworks are out of compliance.

**API Endpoints Consumed**:
- `GET /compliance/api/v1/compliance/dashboard`

**UI Components Needed**:
- Framework Gauge component (semicircle gauge, 0-100% scale)
- 13 gauges arranged in grid: HIPAA, PCI-DSS, ISO 27001, CIS, NIST, GDPR, SOC 2, etc.
- Color gradient: red (0%), yellow (50%), green (100%)
- Score label in center of each gauge
- Clickable to drill into framework detail

**Acceptance Criteria**:
- [ ] 13 gauges render correctly
- [ ] Colors gradient from red → yellow → green
- [ ] Scores display accurately
- [ ] Gauges clickable, navigating to framework detail page
- [ ] Responsive (3 columns on desktop, 2 on tablet, 1 on mobile)

**Size**: L
**Dependencies**: E0-US3, E2-US1

---

#### E2-US5: Geographic Threat Distribution Map
**User Story**: As a security analyst, I want to see where threats are distributed geographically (by AWS region, cloud provider), so that I can understand threat landscape across regions.

**API Endpoints Consumed**:
- `GET /threat/api/v1/threat/analytics/by-region` [needs implementation in threat engine]

**UI Components Needed**:
- World map or region selector (interactive)
- Threat count by region (tooltip on hover)
- Threat count by cloud provider (AWS, Azure, GCP, etc.)

**Acceptance Criteria**:
- [ ] Map or region list displays threat distribution
- [ ] Regions colored by threat count intensity
- [ ] Tooltip shows region name + threat count
- [ ] Drill-down to threats filtered by region

**Size**: L
**Dependencies**: E0-US3, E2-US1

---

### EPIC 3: Onboarding (Effort: 80 pts, Duration: 3 weeks)

**Goal**: Implement cloud account registration, credential validation for 6 CSPs, and scan scheduling

#### E3-US1: Cloud Account Registration Form
**User Story**: As a cloud architect, I want to register a new AWS/Azure/GCP account with credentials, so that the platform can start scanning my cloud infrastructure.

**API Endpoints Consumed**:
- `POST /onboarding/api/v1/cloud-accounts` (create account)
- `POST /onboarding/api/v1/cloud-accounts/{id}/credentials` (store credentials per CSP)

**UI Components Needed**:
- Account registration form with CSP selector (AWS, Azure, GCP, OCI, AliCloud, IBM)
- Dynamic credential fields based on CSP type:
  - AWS: Access Key ID + Secret Access Key
  - Azure: Client ID + Client Secret + Tenant ID + Subscription ID
  - GCP: Service Account JSON upload
  - OCI: User OCID + Tenancy OCID + Fingerprint + Private Key
- Credential validation feedback
- Save and next button

**Acceptance Criteria**:
- [ ] Form fields change based on CSP selection
- [ ] All 6 CSP credential types supported
- [ ] Credentials securely transmitted (HTTPS)
- [ ] Form validates required fields before save
- [ ] Success message on account creation

**Size**: M
**Dependencies**: E1-US1, E0-US5

---

### EPIC 4: Scans & Orchestration (Effort: 70 pts, Duration: 2.5 weeks)

**Goal**: Implement scan pipeline orchestration, real-time progress monitoring, and scan history

#### E4-US1: Scan Orchestration Trigger
**User Story**: As a security analyst, I want to manually trigger a complete security scan of my cloud infrastructure, so that I can get fresh threat and compliance assessments.

**API Endpoints Consumed**:
- `POST /gateway/api/v1/orchestrate` (start pipeline)
- Calls sequentially: Onboarding → Discoveries → Check → (Inventory, Threat, IAM, DataSec in parallel) → Compliance

**UI Components Needed**:
- Run Scan page with account/provider selector
- Start button
- Success notification with scan_run_id

**Acceptance Criteria**:
- [ ] User selects account and clicks "Run Scan"
- [ ] Request sent to orchestrate endpoint
- [ ] Redirects to scan detail page with polling
- [ ] Shows "Scan started" confirmation

**Size**: S
**Dependencies**: E3-US1, E4 foundation

---

### EPIC 5: Inventory & Asset Management (Effort: 85 pts, Duration: 3 weeks)

**Goal**: Build asset inventory with 1,529 resources, graph visualization, relationships, and drift detection

---

### EPIC 6: Threats & MITRE ATT&CK (Effort: 120 pts, Duration: 4 weeks)

**Goal**: Comprehensive threat detection, MITRE mapping, attack path visualization, threat hunting

#### E6-US1: Threat Overview Dashboard
**User Story**: As a security analyst, I want to see a threats dashboard with KPIs, trend chart, and severity distribution, so that I can understand the current threat landscape.

**API Endpoints Consumed**:
- `GET /threat/api/v1/threat/analytics/distribution`
- `GET /threat/api/v1/threat/analytics/trend`

**UI Components Needed**:
- KPI cards: Critical count, High count, Medium count, Low count
- Trend chart (30 days): Threats triggered vs. resolved
- Severity distribution bar chart
- Click to filter threats by severity

**Acceptance Criteria**:
- [ ] All KPI cards display correct numbers
- [ ] Trend chart shows accurate daily data
- [ ] Clicking KPI card filters threats list
- [ ] Colors match severity schema

**Size**: M
**Dependencies**: E2-US1, E0-US3

---

### EPIC 7: Compliance & Frameworks (Effort: 95 pts, Duration: 3.5 weeks)

**Goal**: Multi-framework compliance reporting, control mapping, and automated report generation

---

### EPIC 8: IAM Security (Effort: 50 pts, Duration: 2 weeks)

**Goal**: IAM posture analysis with 6 modules, 57 rules, identity risk assessment

---

### EPIC 9: Data Security (Effort: 65 pts, Duration: 2.5 weeks)

**Goal**: Data classification, exposure detection, encryption analysis, lineage tracking

---

### EPIC 10: SecOps / Code Security (Effort: 60 pts, Duration: 2.5 weeks)

**Goal**: IaC scanning across 14 languages, SBOM analysis, vulnerability detection

---

### EPIC 11: Risk Quantification (Effort: 40 pts, Duration: 1.5 weeks)

**Goal**: FAIR model implementation, risk score calculation, ALE estimation

---

### EPIC 12: Reports & Export (Effort: 55 pts, Duration: 2 weeks)

**Goal**: PDF/XLSX export, scheduled reports, report templates and delivery

---

### EPIC 13: Settings & Platform Health (Effort: 35 pts, Duration: 1.5 weeks)

**Goal**: Engine status monitoring, health checks, integration management, configuration

---

### EPIC 14: Notifications & Audit Log (Effort: 45 pts, Duration: 2 weeks)

**Goal**: Real-time alerts, audit trail, notification preferences, activity feed

---

## TASK BREAKDOWN

Each user story breaks into 2-5 concrete development tasks. Below is a sampling of critical paths:

### E1-US1: Local Login Flow Tasks

**E1-US1-T1**: Create LoginPage component (React/TypeScript)
- **Description**: Build login form with email, password, remember-me inputs; handle form state with React Hook Form; call POST /api/auth/login on submit
- **Skill Required**: React, TypeScript, Form handling
- **Effort**: 4 hours

**E1-US1-T2**: Implement token refresh mechanism (Auth/Session Management)
- **Description**: Create session interceptor that checks token expiry and calls POST /api/auth/refresh before making API requests; store tokens in HTTP-only cookies
- **Skill Required**: JavaScript, HTTP client (fetch/axios)
- **Effort**: 3 hours

**E1-US1-T3**: Add error handling and validation (Frontend)
- **Description**: Display error messages, validate email format, show password requirements, add loading states during login
- **Skill Required**: React, UX validation
- **Effort**: 3 hours

**E1-US1-T4**: Integration testing (QA/Testing)
- **Description**: Test login with valid/invalid credentials, test token persistence, test logout flow
- **Skill Required**: Testing, QA
- **Effort**: 2 hours

---

### E2-US1: KPI Cards Tasks

**E2-US1-T1**: Create KPI Card component
- **Description**: Build reusable component that accepts value, label, color, trend, onClick handler
- **Skill Required**: React, TypeScript, CSS
- **Effort**: 3 hours

**E2-US1-T2**: Fetch threat distribution from threat engine
- **Description**: Implement useQuery hook to call GET /threat/api/v1/threat/analytics/distribution; handle loading, error, and success states
- **Skill Required**: React Query, API integration
- **Effort**: 2 hours

**E2-US1-T3**: Fetch compliance scores from compliance engine
- **Description**: Call GET /compliance/api/v1/compliance/dashboard; aggregate framework scores
- **Skill Required**: API integration
- **Effort**: 2 hours

**E2-US1-T4**: Wire up click handlers to detail pages
- **Description**: Clicking threat KPI navigates to /threats; clicking compliance navigates to /compliance/dashboard
- **Skill Required**: Next.js routing
- **Effort**: 1 hour

---

### E6-US1: Threat Overview Dashboard Tasks

**E6-US1-T1**: Create threat overview page skeleton
- **Description**: Layout with KPI section, trend chart, distribution chart
- **Skill Required**: React, Layout/CSS
- **Effort**: 2 hours

**E6-US1-T2**: Implement KPI cards for threat severity
- **Description**: Fetch distribution, render 4 cards (Critical, High, Medium, Low)
- **Skill Required**: React, API integration
- **Effort**: 3 hours

**E6-US1-T3**: Implement trend line chart
- **Description**: Use Recharts to render line chart with triggered vs. resolved data over 30 days
- **Skill Required**: React, Recharts
- **Effort**: 4 hours

**E6-US1-T4**: Implement severity distribution bar chart
- **Description**: Use Recharts for horizontal bar chart showing threat counts by severity
- **Skill Required**: React, Recharts, Data transformation
- **Effort**: 3 hours

**E6-US1-T5**: Add filtering capability
- **Description**: Clicking KPI card or chart bar filters threat list by severity
- **Skill Required**: React state management, filtering logic
- **Effort**: 2 hours

---

## AGENT SKILL SETS & ASSIGNMENTS

### Agent 1: Foundation Agent
**Responsibilities**: Next.js scaffolding, design system, shared components, layout

**Required Skills**:
- Next.js 14+ (app router, SSR, API routes)
- TypeScript
- Tailwind CSS
- Storybook
- React best practices
- Responsive design

**Assigned Epics**:
- EPIC 0 (complete)
- EPIC 1 (layout/navigation infrastructure)

**Typical Tasks**:
- Project setup and configuration
- Design token implementation
- Component library development
- Layout shell and navigation
- Theme switching (light/dark mode)
- Accessibility (WCAG AA compliance)

**Dependencies**:
- None (works in parallel, enables all others)

**Estimated Total Effort**: 120 hours (2 weeks full-time)

---

### Agent 2: Auth/Backend Agent
**Responsibilities**: Django integration, auth flows, tenant management, session handling

**Required Skills**:
- Django/DRF
- PostgreSQL
- JWT/OAuth token management
- SAML/OKTA integration
- API authentication patterns
- HTTP cookies and security headers

**Assigned Epics**:
- EPIC 1 (Auth & Tenant Management)
- EPIC 13 (Settings - audit log implementation)
- EPIC 14 (Notifications - backend support)

**Typical Tasks**:
- Implement missing API endpoints in Django (user CRUD, audit log)
- Add role-based access control (RBAC) enforcement
- Create audit logging models and views
- Extend SAML/OKTA SLO implementation
- Rate limiting on auth endpoints
- Session cleanup background jobs

**Dependencies**:
- Foundation Agent (UI framework)
- Data Pipeline Agent (for audit event generation)

**Estimated Total Effort**: 140 hours (2.5 weeks full-time)

---

### Agent 3: Data Pipeline Agent
**Responsibilities**: Scan orchestration, inventory integration, discovery, event coordination

**Required Skills**:
- FastAPI integration
- Polling mechanisms (TanStack Query)
- State management (Zustand)
- Real-time updates
- Large dataset handling (pagination, virtual scrolling)
- Graph data structures (nodes/edges)

**Assigned Epics**:
- EPIC 3 (Onboarding)
- EPIC 4 (Scans & Orchestration)
- EPIC 5 (Inventory & Asset Management)

**Typical Tasks**:
- Build onboarding multi-step form with CSP credential handling
- Implement scan orchestration trigger UI
- Real-time scan progress polling (3-second intervals)
- Paginated asset list (1,529 resources)
- Asset detail modal with tabs
- Relationship graph data fetching
- Drift comparison logic

**Dependencies**:
- Foundation Agent (components)
- Auth Agent (session management)

**Estimated Total Effort**: 180 hours (3+ weeks full-time)

---

### Agent 4: Security Analysis Agent
**Responsibilities**: Threat analysis, compliance reporting, IAM/DataSec UI

**Required Skills**:
- React data visualization
- API integration with security engines
- Filtering and drill-down patterns
- Severity color coding
- MITRE ATT&CK mapping understanding
- Compliance framework knowledge (CIS, HIPAA, PCI-DSS, etc.)

**Assigned Epics**:
- EPIC 6 (Threats & MITRE ATT&CK)
- EPIC 7 (Compliance & Frameworks)
- EPIC 8 (IAM Security)
- EPIC 9 (Data Security)
- EPIC 11 (Risk Quantification)

**Typical Tasks**:
- Threat list/detail pages with filtering
- MITRE ATT&ACK matrix visualization
- Attack path graph rendering
- Blast radius calculation display
- Compliance dashboard with 13 framework gauges
- Control drill-down pages
- IAM module views (6 modules)
- Data classification UI
- Risk score and FAIR model display

**Dependencies**:
- Foundation Agent (components, charts)
- Data Pipeline Agent (asset/finding data)

**Estimated Total Effort**: 280 hours (5+ weeks full-time)

---

### Agent 5: Visualization Agent
**Responsibilities**: Charts, graphs, maps, advanced data visualization

**Required Skills**:
- Recharts / D3.js / Nivo
- React Force Graph / Cytoscape
- Geographic maps (Leaflet / Mapbox)
- Data transformation for viz
- Performance optimization (virtual scrolling, canvas rendering)
- Accessibility in charts (ARIA labels, keyboard nav)

**Assigned Epics**:
- EPIC 2 (Dashboard charts)
- EPIC 5 (Relationship graphs, drift visualization)
- EPIC 6 (Attack paths, threat correlation)
- EPIC 7 (Compliance gauges)
- EPIC 9 (Data lineage)
- EPIC 12 (Report visualizations)

**Typical Tasks**:
- Build reusable chart components (line, bar, pie, gauge)
- Implement relationship graph with 1,529 nodes
- MITRE matrix heatmap
- Attack path D3 visualization
- Compliance framework gauges (13x)
- Geographic threat distribution map
- Data flow lineage diagram
- Risk score visualization

**Dependencies**:
- Foundation Agent (design tokens, component patterns)
- Security Analysis Agent (data requirements)

**Estimated Total Effort**: 220 hours (4 weeks full-time)

---

### Agent 6: Platform Agent
**Responsibilities**: Reports, export, settings, health monitoring, notifications

**Required Skills**:
- PDF generation (ReportLab / PDFKit)
- Excel export (ExcelJS / openpyxl)
- File download handling
- Email/notification integration
- Scheduled task UI (cron editor)
- API health check visualization
- Report template design

**Assigned Epics**:
- EPIC 12 (Reports & Export)
- EPIC 13 (Settings & Platform Health)
- EPIC 14 (Notifications & Audit Log)

**Typical Tasks**:
- Report generation page (account selection, framework selection, schedule)
- PDF export implementation (combine charts + tables)
- XLSX export for compliance controls, assets, threats
- Platform health dashboard (10 engines + status)
- Audit log viewer (paginated, filterable)
- Notification preferences panel
- Cron scheduler UI for recurring scans
- Email notification template editor

**Dependencies**:
- Foundation Agent (components, forms)
- Auth Agent (audit event logging)
- All other agents (report content generation)

**Estimated Total Effort**: 160 hours (3 weeks full-time)

---

## DEPENDENCY GRAPH

### Linear Dependencies (Must be Sequential)

```
EPIC 0 (Foundation)
  ↓
EPIC 1 (Auth & Tenant Mgmt)
  ↓ [once user can login]
EPIC 2 (Dashboard - aggregates all data)
EPIC 3 (Onboarding)
EPIC 4 (Scans & Orchestration)
  ↓ [orchestration triggers discovery]
EPIC 5 (Inventory - consumes discovery results)
  ├── EPIC 6 (Threats - parallel)
  ├── EPIC 7 (Compliance - parallel)
  ├── EPIC 8 (IAM - parallel)
  ├── EPIC 9 (DataSec - parallel)
  └── EPIC 10 (SecOps - parallel, independent)
EPIC 11 (Risk - depends on threat/compliance)
EPIC 12 (Reports - depends on all analysis epics)
EPIC 13 (Settings - final polish)
EPIC 14 (Notifications - final polish)
```

### Parallelizable Epics (Can work simultaneously)

**Tier 1** (Weeks 1-2):
- EPIC 0 (Foundation Agent)
- EPIC 1 (Auth Agent) - on top of Foundation

**Tier 2** (Weeks 3-4):
- EPIC 2 (Dashboard - Foundation Agent extends)
- EPIC 3 (Onboarding - Data Pipeline Agent)
- EPIC 4 (Scans - Data Pipeline Agent)

**Tier 3** (Weeks 5-6):
- EPIC 5 (Inventory - Data Pipeline Agent)
- EPIC 6 (Threats - Security Analysis Agent + Visualization Agent)
- EPIC 7 (Compliance - Security Analysis Agent + Visualization Agent)
- EPIC 8 (IAM - Security Analysis Agent)
- EPIC 9 (DataSec - Security Analysis Agent)
- EPIC 10 (SecOps - Security Analysis Agent)

**Tier 4** (Weeks 7-8):
- EPIC 11 (Risk - Security Analysis Agent)
- EPIC 12 (Reports - Platform Agent + others for content)
- EPIC 13 (Settings - Platform Agent)
- EPIC 14 (Notifications - Platform Agent + Auth Agent)

### Critical Path for MVP

```
EPIC 0 (Foundation)
  ↓
EPIC 1 (Auth)
  ↓
EPIC 2 (Dashboard - minimal)
EPIC 3 (Onboarding)
EPIC 4 (Scans)
EPIC 5 (Inventory - asset list only)
EPIC 6 (Threats - list + detail, no graph)
EPIC 7 (Compliance - dashboard + detail)

Critical path duration: 6 weeks
```

---

## EXECUTION PHASES

### PHASE 1: Foundation & Authentication (Weeks 1-2)
**Objectives**: Establish dev environment, core components, authentication flows

**Agents Active**: Foundation Agent (100%), Auth Agent (80%)

**Epics**:
- EPIC 0: Foundation & Design System
- EPIC 1: Auth & Tenant Management (partial - login/logout only)

**Key Deliverables**:
- [ ] Next.js project with TypeScript, Tailwind CSS
- [ ] Design system defined (colors, typography, spacing)
- [ ] 15+ reusable UI components in Storybook
- [ ] Layout shell (top nav, sidebar, breadcrumbs)
- [ ] Local login flow working
- [ ] Tenant selector in top nav
- [ ] Profile page (view/edit user info)

**Testing**: Unit tests for components, integration tests for login

**Risks**:
- Design system scope creep (set cutoff of 15 components)
- Auth token handling complexity (address with clear session strategy)

---

### PHASE 2: Core Security Pages (Weeks 3-4)
**Objectives**: Dashboard, onboarding, scans, basic inventory and threats

**Agents Active**: All agents at 50-75%

**Epics**:
- EPIC 2: Dashboard
- EPIC 3: Onboarding
- EPIC 4: Scans & Orchestration
- EPIC 5: Inventory (asset list, asset detail, basic relationships)
- EPIC 6: Threats (overview, list, detail - no graph)

**Key Deliverables**:
- [ ] Dashboard with KPI cards, trend chart, compliance gauges
- [ ] Onboarding flow (account registration, credential validation, schedule creation)
- [ ] Scan orchestration UI (trigger, progress monitoring, history)
- [ ] Asset list page (1,529 resources, pagination, filters, sorting)
- [ ] Asset detail page (tabs: Details, Relationships, Threats, Compliance)
- [ ] Threat overview page (KPI cards, distribution chart, trend)
- [ ] Threat list page (pagination, filtering by severity)
- [ ] Threat detail page (description, affected resources, remediation)

**Testing**: E2E tests for user workflows, API integration tests

**Risks**:
- Asset list performance with 1,529 rows (implement virtual scrolling early)
- Scan polling mechanism reliability (implement with exponential backoff)
- Multi-step onboarding form complexity (use form library like React Hook Form)

---

### PHASE 3: Advanced Features (Weeks 5-6)
**Objectives**: Advanced threat analysis, compliance deep-dive, IAM/DataSec, visualization

**Agents Active**: Visualization Agent (100%), Security Analysis Agent (100%), others at 40%

**Epics**:
- EPIC 5: Inventory (graph, drift, relationships)
- EPIC 6: Threats (MITRE view, attack paths, hunting)
- EPIC 7: Compliance (framework details, control drill-down, reports)
- EPIC 8: IAM Security
- EPIC 9: Data Security
- EPIC 10: SecOps / Code Security
- EPIC 11: Risk Quantification

**Key Deliverables**:
- [ ] Relationship graph visualization (1,529 nodes, interactive)
- [ ] MITRE ATT&ACK matrix heatmap
- [ ] Attack path visualization (internet-exposed → internal)
- [ ] Blast radius calculation and display
- [ ] Threat hunting page with predefined queries
- [ ] Compliance dashboard with 13 framework gauges
- [ ] Framework detail pages (control list grouped by status)
- [ ] Control detail page (requirements, affected resources)
- [ ] IAM module views (6 modules, 57 rules)
- [ ] Data catalog with lineage visualization
- [ ] Code security dashboard (14 languages, rule statistics)
- [ ] Risk score and FAIR model visualization

**Testing**: Performance testing on large graphs (1,500+ nodes), accessibility testing for charts

**Risks**:
- Graph rendering performance (use canvas/WebGL if needed)
- MITRE matrix complexity (define matrix scope: all techniques or top 20?)
- Report generation latency (implement background jobs)

---

### PHASE 4: Polish & Launch (Weeks 7-8)
**Objectives**: Reports, export, settings, audit logging, notifications, final testing

**Agents Active**: Platform Agent (100%), others at 20% (bug fixes, performance tuning)

**Epics**:
- EPIC 12: Reports & Export
- EPIC 13: Settings & Platform Health
- EPIC 14: Notifications & Audit Log

**Key Deliverables**:
- [ ] Compliance report generation (PDF, XLSX)
- [ ] Scheduled reports (cron UI)
- [ ] Report delivery (email, Slack, S3)
- [ ] Platform health dashboard (10 engines)
- [ ] Audit log viewer (paginated, filterable)
- [ ] Notification preferences
- [ ] Real-time alert notifications
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Performance optimization (< 2s page load time)
- [ ] Accessibility audit (WCAG AA compliance)
- [ ] Security audit (OWASP Top 10)

**Testing**: Full regression testing, load testing (concurrent users), UAT with stakeholders

**Risks**:
- Bug fixes in late phases (implement strong testing culture in Phases 1-3)
- Performance issues on large reports (implement pagination in report generation)
- Auth backend RBAC not ready (implement with feature flags if Django auth incomplete)

---

## WIZ-LEVEL ENHANCEMENTS

### Multi-View Architecture

Replicate Wiz's capability to view data in multiple perspectives:

#### Table View (Primary)
- Sortable columns with visual indicators (↑ ascending, ↓ descending)
- Filterable with column-level filters
- Selectable rows with bulk actions
- Pagination with "rows per page" selector
- Column customization (show/hide, reorder via drag)
- Example: Threat table with columns: ID, Severity, Category, MITRE Technique, Affected Assets, Status, Created Date

**Components**:
- TanStack Table (headless table library)
- Column visibility menu
- Sort indicators
- Pagination controls
- Bulk action menu

#### MITRE View
- ATT&CK matrix showing techniques and tactics
- Techniques color-coded by threat count or severity
- Click technique to filter threats by technique
- "Show empty categories" toggle to hide undetected techniques
- Heat map style intensity (darker = more threats)

**Components**:
- Custom MITRE matrix component (grid layout)
- Color intensity scale
- Interactive cells with drill-down

#### Dashboard View
- KPI cards, trend charts, distribution visualizations
- Different chart types per analysis type (line, bar, gauge, pie)
- Drill-down capability (click card/bar to filter details page)

**Components**:
- KPI Card, Line Chart, Bar Chart, Gauge Chart, Pie Chart
- All with zoom/drill-down capability

#### Board View (Kanban)
- Status-based swimlanes (OPEN → IN_PROGRESS → RESOLVED)
- Drag-and-drop between columns
- Card summary (ID, Severity, Assigned to)
- Count per column

**Components**:
- React Beautiful DnD or similar
- Swimlane columns
- Draggable cards

---

### Seven-Dimension Filtering System

Replicate Wiz's advanced filtering:

```
Threats Page Filters:
├── Status (multi-select)
│   ├── Open
│   ├── In Progress
│   ├── Resolved
│   └── Closed
├── Severity (multi-select)
│   ├── Critical
│   ├── High
│   ├── Medium
│   └── Low
├── Time Range (single select or date range)
│   ├── Past 7 days
│   ├── Past 30 days
│   ├── Past 90 days
│   └── Custom date range
├── MITRE Technique (hierarchical multi-select)
│   ├── Tactics
│   │   ├── Reconnaissance
│   │   ├── Resource Development
│   │   └── ...
│   └── Techniques under each tactic
├── Principal / Owner (multi-select, searchable)
│   └── [Search for user/service principal]
├── Cloud Provider (multi-select)
│   ├── AWS
│   ├── Azure
│   ├── GCP
│   ├── OCI
│   ├── AliCloud
│   └── IBM Cloud
└── Account (multi-select)
    └── [Auto-populated from selected provider]
```

**Filter Persistence**:
- Store filter state in URL hash (like Wiz)
- Format: `#-filters~status~equals~[OPEN,IN_PROGRESS]~severity~equals~[CRITICAL,HIGH]~createdAt~dateRange~past~30~day`
- Shareable filter URLs
- "Clear filters" button to reset

**Implementation**:
- React Router query params + custom useFilter hook
- Zustand for filter state
- Filter chips above table (removable)
- Applied filters counter badge

---

### MTTR / MTTD Metrics

Display Mean Time To Resolution and Mean Time To Detection:

**MTTR (Mean Time To Resolution)**:
- Formula: Sum of all resolution times / Number of resolved items
- Display format: "30 days, 5 minutes"
- Shown on Threats overview + KPI card
- Trend indicator (↑ = getting slower, ↓ = improving)

**MTTD (Mean Time To Detection)**:
- Formula: Sum of detection delays / Number of detections
- Display format: "2 hours, 15 minutes"
- Shown on Threats overview

**Implementation**:
- Calculate on threat engine side (stored as metrics)
- Fetch via `GET /threat/api/v1/threat/analytics/mttr` and `GET /threat/api/v1/threat/analytics/mttd`
- Display in KPI card format
- Clickable to show histogram of all resolution times

---

### Severity Color Coding System

Consistent color palette throughout (matches Wiz):

| Severity | Hex | RGB | Usage |
|----------|-----|-----|-------|
| Critical | #DC2626 | (220,38,38) | KPI badge, table cell, chart bar, alert |
| High | #EA580C | (234,88,12) | KPI badge, table cell, chart bar, alert |
| Medium | #CA8A04 | (202,138,4) | KPI badge, table cell, chart bar, warning |
| Low | #2563EB | (37,99,235) | KPI badge, table cell, chart bar, info |
| Info / Unknown | #64748B | (100,116,139) | Secondary info |
| Resolved / Pass | #16A34A | (22,163,74) | Success state |

**Implementation**:
- Define in Tailwind config:
  ```javascript
  colors: {
    severity: {
      critical: '#DC2626',
      high: '#EA580C',
      medium: '#CA8A04',
      low: '#2563EB',
    }
  }
  ```
- Create severity badge component that accepts severity prop
- Use throughout tables, charts, KPI cards

---

### URL-Persisted Filter State

Enable bookmarkable, shareable filtered views:

**Example URL**:
```
/threats?filters=status:[OPEN,IN_PROGRESS]+severity:[CRITICAL,HIGH]+createdAt:past_30_days+mitre:[T1110,T1098]+provider:[aws,azure]
```

**Implementation Pattern**:
```typescript
// useFilters.ts
const useFilters = () => {
  const router = useRouter();
  const filters = parseFiltersFromUrl(router.query);

  const setFilters = (newFilters) => {
    const encoded = encodeFilters(newFilters);
    router.push(`/threats?filters=${encoded}`);
  };

  return { filters, setFilters };
};
```

**Features**:
- Filter state survives page refresh
- Users can bookmark filtered views
- Share filter URL with teammates
- Export button preserves current filters

---

### Bulk Actions Support

Enable efficient batch operations:

**Example: Threats page bulk actions**

1. User selects multiple threats via checkboxes
2. Bulk action menu appears: "With selected threats..."
3. Options:
   - Resolve (change status to RESOLVED)
   - Change priority (map to severity)
   - Assign to team member
   - Export selected (CSV, JSON)
   - Add to report
   - Delete

**Implementation**:
- Row selection checkboxes (TanStack Table)
- Floating action bar that appears when rows selected
- Confirmation modal before destructive actions

---

### Real-Time Threat Feed

Display recent threats as they're detected:

**Example Dashboard Section**: "Recent Threats"
- Live-updating list of last 10 threats
- New threat appears at top with animation (slide-in)
- Threat row has timestamp (e.g., "2 minutes ago")
- Severity color-coded

**Implementation**:
- Poll `/threat/api/v1/threat/threats?limit=10&order=created_desc` every 3 seconds
- Compare with previous results, append new threats
- Use React transition for smooth animation
- Limit to last 10 to avoid overwhelming UX

---

## RISK ASSESSMENT & SUCCESS METRICS

### Project Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Graph visualization performance (1,500+ nodes) | Medium | High | Implement canvas rendering, implement virtual scrolling, test early with synthetic data |
| RBAC enforcement delays (Django backend) | High | Medium | Use feature flags for unimplemented auth checks, document workarounds |
| Scan orchestration delays or failures | Medium | High | Implement polling with exponential backoff, add error retry logic, detailed logging |
| Compliance report generation slowness | Medium | Medium | Generate in background jobs, implement pagination, cache framework definitions |
| Real-time polling causing API overload | Low | Medium | Implement smart polling (back off when server busy), use WebSocket alternative if needed |
| Multi-step onboarding form abandonment | Medium | Low | Implement form state persistence to localStorage, save drafts to backend |
| 1,529 asset list causing UI lag | Medium | High | Virtual scrolling required, pagination mandatory, avoid rendering all rows at once |

**Overall Project Risk**: Medium (manageable with proper architecture and early testing)

---

### Success Metrics

#### Functionality Metrics
- [ ] All 14 epics completed and tested
- [ ] 12+ real APIs integrated and working
- [ ] 50+ user stories implemented
- [ ] 25+ pages built
- [ ] Mobile responsive (tablet + desktop)
- [ ] Accessibility compliance (WCAG AA)

#### Performance Metrics
- [ ] Page load time < 2 seconds (90th percentile)
- [ ] Table operations (sort, filter, page) < 500ms
- [ ] Chart rendering < 1 second
- [ ] Asset graph renders < 3 seconds (1,500 nodes)
- [ ] No more than 3 API calls per page load (batched where possible)

#### User Experience Metrics
- [ ] Threat filter setup time < 30 seconds
- [ ] Asset search latency < 300ms (debounced input)
- [ ] Scan progress visible (polling every 3 seconds)
- [ ] Error messages clear and actionable
- [ ] No jank or flickering on animations

#### Code Quality Metrics
- [ ] Test coverage > 70% on critical paths
- [ ] No critical security vulnerabilities (OWASP Top 10)
- [ ] TypeScript strict mode enabled, no `any` types
- [ ] Code reviewed by 2+ team members before merge
- [ ] Documentation for all public APIs

#### Team Metrics
- [ ] 6 agents operating in parallel (not blocked)
- [ ] Daily standups < 15 minutes (async updates preferred)
- [ ] 2-week sprint velocity achieves 70%+ story points
- [ ] Zero production bugs in first month after launch

---

## APPENDIX: Sample Implementation Checklist

### Phase 1 Checklist (Weeks 1-2)

**Week 1**:
- [ ] Create Next.js project with TypeScript + Tailwind
- [ ] Define Tailwind config with custom colors, spacing, typography
- [ ] Create 5 base components: Button, Input, Card, Badge, Modal
- [ ] Setup Storybook
- [ ] Create app layout shell (Header, Sidebar, Footer)
- [ ] Create layout routes in Next.js

**Week 2**:
- [ ] Expand component library to 15+ components
- [ ] Create LoginPage component (UI + form state)
- [ ] Implement POST /api/auth/login call
- [ ] Add token refresh mechanism
- [ ] Create DashboardPage redirect (if logged in)
- [ ] Setup Zustand store for auth state (user, token, tenant)
- [ ] Create ProfilePage (view/edit user)
- [ ] Create TenantSelectorDropdown in top nav

**QA Gate**:
- [ ] Login with valid credentials works
- [ ] Invalid credentials show error
- [ ] Logout clears session
- [ ] Tenant switch works
- [ ] Profile edit saves changes
- [ ] Token refresh works transparently

---

## Document Summary

**Total Page Count**: 1000+ lines
**Total Story Points**: 690 points (14 epics)
**Total Development Hours**: ~920 hours (5-6 engineers × 8 weeks)
**Timeline**: 8 weeks (2-month sprint)
**Cost**: ~$180-220K (@ $200/hour average eng cost)

**Critical Success Factors**:
1. Strong design system foundation (EPIC 0)
2. Auth backend completeness (EPIC 1)
3. Real API integration from day 1
4. Performance testing early and often
5. Team communication and daily standup

---

**Document Version**: 1.0
**Last Updated**: March 6, 2026
**Prepared By**: Claude Code Agent
**Distribution**: Development Team, Product Management, Executive Stakeholders
