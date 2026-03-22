# Threat Engine — System Overview

> Last updated: 2026-02-22
> Cluster: `vulnerability-eks-cluster` | Region: `ap-south-1` | Account: `588989875114`

---

## What Is the Threat Engine?

The Threat Engine is a **Cloud Security Posture Management (CSPM)** platform that continuously
discovers, evaluates, and reports on the security posture of cloud infrastructure across
AWS, Azure, GCP, OCI, AliCloud, and IBM Cloud.

It runs as a set of microservices on EKS, each responsible for a specific stage of the
security pipeline. A single scan produces:
- **Asset inventory** (what resources exist)
- **Compliance findings** (pass/fail against 13+ frameworks)
- **Threat detections** (MITRE ATT&CK mapped, risk-scored 0–100)
- **IAM posture** (57 rules across identity & access)
- **Data security findings** (62 rules for data classification and protection)

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNAL ACCESS                                     │
│   ELB: a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com  │
│                           HTTP port 80                                          │
└───────────────────────────────────┬─────────────────────────────────────────────┘
                                    │
                            ┌───────▼────────┐
                            │  nginx ingress  │
                            │ (path routing)  │
                            └───────┬─────────┘
                                    │
          ┌─────────────────────────▼─────────────────────────────┐
          │              threat-engine-engines namespace            │
          │                                                         │
          │  /gateway  ─► api-gateway        ◄──── orchestrates    │
          │  /onboarding ► engine-onboarding │     all engines     │
          │  /discoveries► engine-discoveries│                     │
          │  /check      ► engine-check      │                     │
          │  /inventory  ► engine-inventory  │                     │
          │  /compliance ► engine-compliance │                     │
          │  /threat     ► engine-threat     │                     │
          │  /iam        ► engine-iam        │                     │
          │  /datasec    ► engine-datasec    │                     │
          │  /secops     ► engine-secops     │                     │
          │                                                         │
          └─────────────────────────┬───────────────────────────────┘
                                    │
          ┌─────────────────────────▼───────────────────────────────┐
          │                     AWS RDS PostgreSQL 15                │
          │  postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds  │
          │                                                          │
          │  threat_engine_onboarding  |  threat_engine_discoveries  │
          │  threat_engine_check       |  threat_engine_inventory    │
          │  threat_engine_compliance  |  threat_engine_threat       │
          │  threat_engine_iam         |  threat_engine_datasec      │
          │  threat_engine_secops      |  vulnerability_db           │
          └──────────────────────────────────────────────────────────┘
```

---

## Scan Pipeline (Ordered)

A full scan runs through these engines. All engines share a single `scan_run_id`
(UUID) generated at the start of the pipeline.

```
Step 1              Step 2
────────────────────────────────────────────────────────────────
ONBOARDING      →  DISCOVERIES
(register account)  (enumerate all resources)
 Port 8010           Port 8001
                     Writes: discovery_findings

                         │
              ┌──────────┴──────────┐
              ▼                     ▼
Step 3                         Step 4
CHECK                          INVENTORY
(evaluate 400+ rules           (normalize assets, build
 PASS/FAIL per resource)        relationships, detect drift)
 Port 8002                      Port 8022
 Reads: discovery_findings      Reads: discovery_findings
 *** PARALLEL WITH INVENTORY ***

              └──────────┬──────────┘
                         │ (both scan_run_id and scan_run_id available)
              ┌──────────┼──────────────────────┐
              ▼          ▼          ▼            ▼
Step 5a           Step 5b     Step 5c       Step 5d
COMPLIANCE    →  THREAT   →  IAM        →  DATASEC
 Port 8000        Port 8020   Port 8001*    Port 8003
 Reads:           Reads:      Reads:        Reads:
 check_findings   check_findi check_findi   check_findings
                  ngs +       ngs           + inventory_
                  inventory_                findings
                  findings

* Note: engine-iam and engine-discoveries share historical port number 8001
  but run on separate pods/services.

Supporting (run independently):
──────────────────────────────────────────────────────────────────────────────
SECOPS    →  Rule management (IaC scanning, 14 languages) Port 8005
RULE      →  YAML rule CRUD and publishing                 Port 8011
API-GW    →  Central routing, auth, service discovery      Port 8080
```

---

## Engine Descriptions

| Engine | Service Name | Port | Image | Role |
|--------|-------------|------|-------|------|
| API Gateway | `api-gateway` | 8080 | `threat-engine-api-gateway:latest` | Central routing, auth proxy |
| Onboarding | `engine-onboarding` | 8010 | `threat-engine-onboarding-api:latest` | Register cloud accounts, store credentials, kick off scans |
| Discoveries | `engine-discoveries` | 8001 | `engine-discoveries:v10-multicloud` | Enumerate 40+ cloud services via boto3/SDK, parallel scanning |
| Check | `engine-check` | 8002 | `engine-check:latest` | Evaluate 400+ YAML rules against discovery data (PASS/FAIL) |
| Inventory | `engine-inventory` | 8022 | `inventory-engine:v6-multi-csp` | Normalise discoveries into assets + relationships, drift detection |
| Compliance | `engine-compliance` | 8000 | `threat-engine-compliance-engine:v2-db-reports` | Map check findings to 13+ compliance frameworks, score reports |
| Threat | `engine-threat` | 8020 | `threat-engine:latest` | MITRE ATT&CK mapping, risk scoring (0–100), attack chain detection |
| IAM | `engine-iam` | 8001 | `engine-iam:v2-fixes` | 57-rule IAM posture analysis (roles, policies, access patterns) |
| DataSec | `engine-datasec` | 8003 | `engine-datasec:v3-fixes` | 62-rule data security analysis (encryption, classification, exposure) |
| SecOps | `engine-secops` | 8005 | `secops-scanner:latest` | IaC security scanning (14 languages: Terraform, CF, Helm, K8s, …) |
| Rule | `engine-rule` | 8011 | `threat-engine-yaml-rule-builder:latest` | CRUD for YAML security rules, rule publishing pipeline |
| User Portal | `engine-userportal` | 8080 | `cspm-django-backend:latest` | Django REST backend for the UI |
| UI | `engine-userportal-ui` | 80 | `cspm-ui:latest` | React frontend (currently CrashLoopBackOff) |

---

## Scan Orchestration — How Engines Coordinate

All engines share a single `scan_orchestration` table in the `threat_engine_onboarding` database.
This is the **coordination hub** of the entire pipeline.

```
scan_orchestration table (threat_engine_onboarding DB)
───────────────────────────────────────────────────────
scan_run_id          UUID (primary key) ← single ID shared by ALL engines
tenant_id            VARCHAR
account_id           VARCHAR   ← cloud account being scanned
provider_type        VARCHAR   ← 'aws' | 'azure' | 'gcp' | ...
status               VARCHAR   ← pending | running | completed | failed
created_at           TIMESTAMP
updated_at           TIMESTAMP
```

**Typical pipeline call sequence:**

```
1. UI / API-GW → POST /onboarding/api/v1/scan/trigger
                 → creates scan_orchestration row, returns scan_run_id

2. Onboarding → POST discoveries/api/v1/discovery
                { scan_run_id, provider, account_id }
                → scans cloud, stores discovery_findings

3. Check engine  → POST check/api/v1/check
                   { scan_run_id }
                   → reads discovery_findings, evaluates rules, stores check_findings

4. Inventory     → POST inventory/api/v1/inventory/scan/discovery
                   { scan_run_id }
                   → reads discovery_findings, normalises assets, stores inventory_findings

5. Compliance    → POST compliance/api/v1/compliance/scan
                   { scan_run_id }
                   → reads check_findings, builds framework report

6. Threat        → POST threat/api/v1/scan
                   { scan_run_id }
                   → reads check + inventory data, scores risks

7. IAM / DataSec → POST iam/..., datasec/...
                   { scan_run_id }
                   → specialised analysis
```

---

## Multi-Cloud (CSP) Support

| CSP | Status | Discovery | Check | Inventory |
|-----|--------|-----------|-------|-----------|
| AWS | Production | ✓ Full | ✓ 400+ rules | ✓ |
| Azure | Beta | ✓ via SDK | Partial | ✓ |
| GCP | Beta | ✓ via SDK | Partial | ✓ |
| OCI | Alpha | ✓ via SDK | Limited | ✓ |
| AliCloud | Alpha | ✓ via SDK | Limited | ✓ |
| IBM Cloud | Alpha | ✓ via SDK | Limited | ✓ |

CSP-specific resource catalogues live in:
`data_pythonsdk/{csp}/{service}/step5_resource_catalog_inventory_enrich.json`

---

## Multi-Account Support

The platform supports scanning multiple cloud accounts in a single orchestrated run:

- **Account identifier**: `account_id` (cloud account ID / subscription ID)
- **Stored in**: `cloud_accounts` table in `threat_engine_onboarding` DB
- **Propagated via**: `scan_orchestration.account_id`
- **Query pattern**: All engines accept `account_ids` (comma-separated) for multi-account queries
- **SQL pattern**: `WHERE account_id = ANY(%s::text[])`

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| **Orchestration** | Kubernetes (EKS v1.31) |
| **Language** | Python 3.11 |
| **API Framework** | FastAPI + uvicorn |
| **Database** | PostgreSQL 15 (AWS RDS) |
| **DB Driver** | psycopg2 (sync) |
| **Container Registry** | Docker Hub (`yadavanup84/`) |
| **Ingress** | nginx ingress controller |
| **Load Balancer** | AWS NLB (single ELB for all engines) |
| **Secrets** | AWS Secrets Manager + External Secrets Operator |
| **Object Storage** | S3 (`cspm-lgtech` bucket) |
| **Node Groups** | On-demand (t3.medium × 2) + Spot (t3.xlarge/m5.xlarge, 0–6 nodes) |

---

## External Access (For UI Developers)

**Base URL:**
```
http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
```

**Path Prefix → Engine mapping:**

| Path Prefix | Engine | Example |
|-------------|--------|---------|
| `/onboarding/...` | engine-onboarding | `GET /onboarding/api/v1/health` |
| `/discoveries/...` | engine-discoveries | `POST /discoveries/api/v1/discovery` |
| `/check/...` | engine-check | `GET /check/api/v1/findings` |
| `/inventory/...` | engine-inventory | `GET /inventory/api/v1/inventory/assets` |
| `/compliance/...` | engine-compliance | `GET /compliance/api/v1/compliance/reports` |
| `/threat/...` | engine-threat | `GET /threat/api/v1/threats` |
| `/iam/...` | engine-iam | `GET /iam/api/v1/findings` |
| `/datasec/...` | engine-datasec | `GET /datasec/api/v1/findings` |
| `/secops/...` | engine-secops | `GET /secops/api/v1/scans` |
| `/gateway/...` | api-gateway | `GET /gateway/api/v1/status` |

**Important:** The nginx ingress strips the prefix before forwarding.
`/inventory/api/v1/inventory/assets` → engine-inventory receives `/api/v1/inventory/assets`

See `API-REFERENCE.md` for full endpoint list with all parameters.
