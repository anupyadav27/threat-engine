# CSPM Threat Engine Platform

Cloud Security Posture Management (CSPM) platform built as a microservices architecture. Discovers cloud resources, evaluates 1000+ security rules, detects threats with MITRE ATT&CK mapping, and generates compliance reports across AWS, Azure, GCP, OCI, AliCloud, IBM Cloud, and Kubernetes.

---

## Architecture

```
                    EKS Cluster (ap-south-1)
                           │
                    nginx Ingress (NLB)
                           │
          ┌────────────────┼────────────────┐
          │                │                │
     /gateway/*       /ui/*  /cspm/*    /secops/*
          │                │                │
     api-gateway      cspm-ui          secops-scanner
          │
  ┌───────┴───────────────────────────────────┐
  │                                           │
  ▼                                           ▼
engine-discoveries (8001)          engine-onboarding (8008)
  ↓ discovery_scan_id
engine-check (8002)
  ↓ check_scan_id
  ├──→ engine-inventory (8022)
  ├──→ engine-threat (8020)
  │       ↓ threat_scan_id
  │       ├──→ engine-iam (8003)
  │       └──→ engine-datasec (8004)
  └──→ engine-compliance (8010)
```

### Engines

| Engine | K8s Service | Port | Image | Purpose |
|--------|------------|------|-------|---------|
| **engine_discoveries** | `engine-discoveries` | `8001` | `engine-discoveries:v10-multicloud` | Discover cloud resources via AWS/Azure/GCP/OCI APIs |
| **engine_check** | `engine-check` | `8002` | `engine-check:latest` | Evaluate 1000+ YAML security rules against discoveries |
| **engine_iam** | `engine-iam` | `8003` | `engine-iam:v2-fixes` | IAM posture analysis, privilege escalation, MFA, password policy |
| **engine_datasec** | `engine-datasec` | `8004` | `engine-datasec:v3-fixes` | Data classification, S3/RDS/DynamoDB governance, lineage, residency |
| **engine_secops** | `engine-secops` | `8000` | `secops-scanner:latest` | IaC scanning (Terraform, CloudFormation, Dockerfile, K8s YAML) |
| **engine_onboarding** | `engine-onboarding` | `8008` | `threat-engine-onboarding-api:latest` | Account onboarding, credential management, scan orchestration |
| **engine_compliance** | `engine-compliance` | `8010` | `threat-engine-compliance-engine:v2-db-reports` | Map findings to 13 compliance frameworks (CIS, NIST, SOC2, etc.) |
| **engine_threat** | `engine-threat` | `8020` | `threat-engine:latest` | Threat detection, MITRE ATT&CK mapping, risk scoring (0-100) |
| **engine_inventory** | `engine-inventory` | `8022` | `inventory-engine:v6-multi-csp` | Normalize assets, build relationships, detect drift |
| **engine_rule** | `engine-rule` | `8000` | `threat-engine-yaml-rule-builder:latest` | YAML rule builder and validator |

### Scan Pipeline (Sequential)

```
onboarding            # Stores account credentials and orchestration row
  ↓  orchestration_id
discoveries           # Phase 1 — enumerates all cloud resources
  ↓  discovery_scan_id
check                 # Phase 2 — evaluates YAML rules → PASS/FAIL per resource
  ↓  check_scan_id
inventory             # Phase 3 — normalizes assets, builds relationships
threat                # Phase 4 — groups findings into threats, MITRE mapping
  ↓  threat_scan_id
iam + datasec         # Phase 5a — IAM posture + data security analysis
compliance            # Phase 5b — maps check findings to 13 frameworks
```

All engines coordinate through the `scan_orchestration` table in the `threat_engine_onboarding` DB. Each engine reads its upstream scan_id from this table and writes its own scan_id back on completion.

---

## Infrastructure

- **Cloud:** AWS (Mumbai, ap-south-1)
- **Cluster:** `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`
- **Database:** Single RDS `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432` (13 databases)
- **Spot scanning:** `vulnerability-spot-scanners` node group (t3.xlarge/m5.xlarge/c5.xlarge, min=0, max=6)

### Databases

| Database | Used By | Key Tables |
|----------|---------|-----------|
| `threat_engine_onboarding` | onboarding | `cloud_accounts`, `scan_orchestration` |
| `threat_engine_discoveries` | discoveries | `discovery_report`, `discovery_findings`, `discovery_history` |
| `threat_engine_check` | check + discoveries | `rule_discoveries`, `check_findings`, `check_report` |
| `threat_engine_inventory` | inventory | `inventory_assets`, `inventory_relationships`, `resource_inventory_identifier` |
| `threat_engine_threat` | threat | `threat_report`, `threat_findings`, `tenants` |
| `threat_engine_iam` | iam | `iam_report`, `iam_findings` |
| `threat_engine_datasec` | datasec | `datasec_report`, `datasec_findings`, `datasec_data_store_services` |
| `threat_engine_compliance` | compliance | `compliance_reports`, `compliance_findings`, `rule_control_mapping` |
| `threat_engine_secops` | secops | `secops_scan`, `secops_findings` |
| `threat_engine_pythonsdk` | inventory | `resource_inventory_identifier`, `rule_discoveries_metadata` |
| `threat_engine_shared` | (deprecated) | — |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- PostgreSQL 15+ (or RDS)
- AWS credentials (for cloud scanning)

### Running an Engine Locally

```bash
# Discovery engine
cd engine_discoveries
pip install -r engine_discoveries_aws/requirements.txt
export DISCOVERY_DB_HOST=localhost
export DISCOVERY_DB_PASSWORD=your_password
export PYTHONPATH=$(pwd)/..
python -m uvicorn common.api_server:app --host 0.0.0.0 --port 8001 --reload

# Check engine
cd engine_check/engine_check_aws
pip install -r requirements.txt
export CHECK_DB_HOST=localhost
export CHECK_DB_PASSWORD=your_password
uvicorn api_server:app --host 0.0.0.0 --port 8002 --reload

# Threat engine
cd engine_threat
pip install -r threat_engine/requirements.txt
export THREAT_DB_HOST=localhost
export THREAT_DB_PASSWORD=your_password
export CHECK_DB_HOST=localhost
export CHECK_DB_PASSWORD=your_password
python -m uvicorn threat_engine.api_server:app --host 0.0.0.0 --port 8020 --reload
```

### Triggering a Full Pipeline Scan

```bash
# 1. Create an orchestration row via onboarding engine
curl -X POST http://engine-onboarding/api/v1/accounts/scan \
  -H "Content-Type: application/json" \
  -d '{"account_id": "588989875114", "provider": "aws"}'
# → returns orchestration_id

# 2. Trigger each engine with the orchestration_id
ORCH_ID="337a7425-5a53-4664-8569-04c1f0d6abf0"

# Phase 1: discoveries
curl -X POST http://engine-discoveries/api/v1/discovery \
  -d "{\"orchestration_id\": \"$ORCH_ID\"}"

# Phase 2: check (after discoveries complete)
curl -X POST http://engine-check/api/v1/scan \
  -d "{\"orchestration_id\": \"$ORCH_ID\"}"

# Phase 4: threat (after check complete)
curl -X POST http://engine-threat/api/v1/threat/scan \
  -d "{\"orchestration_id\": \"$ORCH_ID\"}"

# Phase 5: IAM + DataSec + Compliance (after threat complete)
curl -X POST http://engine-iam/api/v1/iam-security/scan \
  -d "{\"orchestration_id\": \"$ORCH_ID\", \"csp\": \"aws\"}"

curl -X POST http://engine-datasec/api/v1/data-security/scan \
  -d "{\"orchestration_id\": \"$ORCH_ID\", \"csp\": \"aws\"}"

curl -X POST http://engine-compliance/api/v1/scan \
  -d "{\"orchestration_id\": \"$ORCH_ID\", \"csp\": \"aws\"}"
```

### Kubernetes Operations

```bash
# Apply all engine manifests
kubectl apply -f deployment/aws/eks/engines/

# Check status
kubectl get pods -n threat-engine-engines

# View logs
kubectl logs -f -l app=engine-discoveries -n threat-engine-engines
kubectl logs -f -l app=engine-check -n threat-engine-engines

# Port-forward for local testing
kubectl port-forward svc/engine-check 8002:80 -n threat-engine-engines
kubectl port-forward svc/engine-threat 8020:80 -n threat-engine-engines
```

---

## Repository Structure

```
threat-engine/
├── README.md                       # This file
├── deployment/
│   └── aws/eks/
│       ├── engines/                # K8s Deployment + Service manifests (1 per engine)
│       ├── configmaps/             # DB config, S3 config
│       ├── secrets/                # ExternalSecret (ESO) manifests
│       └── cluster-autoscaler/     # Cluster Autoscaler for spot nodes
├── consolidated_services/
│   └── database/
│       ├── schemas/                # SQL schema files (1 per DB)
│       ├── migrations/             # Incremental migration scripts
│       └── config/database_config.py
├── engine_common/                  # Shared libraries (logger, middleware, orchestration)
├── engine_onboarding/              # Account onboarding (port 8008)
├── engine_discoveries/             # Multi-CSP resource discovery (port 8001)
├── engine_check/                   # YAML rule evaluation (port 8002)
├── engine_inventory/               # Asset normalization + relationships (port 8022)
├── engine_threat/                  # Threat detection + MITRE mapping (port 8020)
├── engine_iam/                     # IAM posture analysis (port 8003)
├── engine_datasec/                 # Data security analysis (port 8004)
├── engine_compliance/              # Compliance framework reporting (port 8010)
├── engine_secops/                  # IaC/code scanning (port 8000)
├── engine_rule/                    # YAML rule builder (port 8000)
├── engine_adminportal/             # Admin UI (Django)
├── engine_userportal/              # User UI (React/Next.js)
└── data_pythonsdk/                 # Multi-CSP service catalog (step1–step6 pipeline)
    ├── aws/                        # 479+ AWS services
    ├── azure/
    ├── gcp/
    ├── oci/
    ├── ibm/
    ├── alicloud/
    └── k8s/
```

---

## Per-Engine Documentation

Each engine has its own README with full API reference, DB schema, and deployment instructions:

| Engine | README | Port |
|--------|--------|------|
| Onboarding | `engine_onboarding/README.md` | 8008 |
| Discoveries | `engine_discoveries/README.md` | 8001 |
| Check | `engine_check/README.md` | 8002 |
| Inventory | `engine_inventory/README.md` | 8022 |
| Threat | `engine_threat/README.md` | 8020 |
| IAM Security | `engine_iam/README.md` | 8003 |
| Data Security | `engine_datasec/README.md` | 8004 |
| Compliance | `engine_compliance/README.md` | 8010 |
| SecOps | `engine_secops/README.md` | 8000 |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API Framework | FastAPI + Uvicorn |
| Language | Python 3.11 |
| Databases | PostgreSQL 15 (AWS RDS, single instance, 13 DBs) |
| Container | Docker |
| Orchestration | AWS EKS (Kubernetes 1.31) |
| Secrets | AWS Secrets Manager + External Secrets Operator |
| Storage | AWS S3 (scan output sync) |
| Cloud SDKs | boto3, azure-sdk, google-cloud, oci-sdk |
| Compliance | CIS, NIST CSF, NIST 800-53, SOC 2, ISO 27001, PCI-DSS, HIPAA, GDPR, FedRAMP, MITRE ATT&CK |

---

## DB-Driven Noise Control

Three layers of noise suppression with no code changes required:

| Layer | Mechanism | How to use |
|-------|-----------|-----------|
| 1 | `rule_discoveries.is_active = FALSE` | Suppress entire service from discovery + check |
| 2 | `rule_discoveries.filter_rules.response_filters` | Exclude specific API response items post-call |
| 3 | `resource_inventory_identifier.should_inventory = FALSE` | Skip asset creation in inventory engine |

These controls apply per `provider` column — same tables support AWS, Azure, GCP, OCI, IBM, AliCloud.

---

## Key Features

- **Multi-Cloud Discovery** — AWS (414 services), Azure, GCP, OCI with parallel scanning
- **1000+ Security Rules** — YAML-based rules, DB-driven, `is_active` toggle per service
- **Threat Detection** — MITRE ATT&CK technique mapping, risk scoring (0–100)
- **13-Framework Compliance** — CIS, NIST 800-53, SOC 2, ISO 27001, PCI-DSS, HIPAA, GDPR, FedRAMP, and more
- **IAM Security** — Privilege escalation detection, MFA audit, password policy (AWS, Azure, GCP)
- **Data Security** — Data store classification, PII/PCI/PHI detection, governance findings
- **Asset Inventory** — Normalized cross-CSP asset graph with relationship mapping
- **Drift Detection** — `config_hash` tracks configuration changes between scans
- **Orchestration** — `scan_orchestration` table coordinates the full pipeline via `orchestration_id`
- **Spot Node Scanning** — Auto-scaling spot node group for cost-efficient heavy scans
