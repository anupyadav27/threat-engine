# CSPM Threat Engine Platform

Cloud Security Posture Management (CSPM) platform built as a microservices architecture. Discovers cloud resources, evaluates security rules, detects threats, and generates compliance reports across AWS, Azure, GCP, OCI, AliCloud, IBM Cloud, and Kubernetes.

---

## Architecture

```
                     NLB (nginx ingress)
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   /gateway/*         /ui/*  /cspm/*     /secops/*
        │                  │                  │
   api-gateway        cspm-ui           secops-scanner
        │             django-backend
        │
   ┌────┴────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
   │         │      │      │      │      │      │      │      │
 /discovery /check /threat /compliance /iam /datasec /inventory /onboarding
   :8001    :8002   :8004   :8003      :8005  :8006   :8007     :8008
   │         │      │      │      │      │      │      │
   PostgreSQL (9 databases on single RDS) + Neo4j (graph)
```

### Engines

| Engine | K8s Name | Ingress Path | Port | Purpose |
|--------|----------|-------------|------|---------|
| **api_gateway** | `api-gateway` | `/gateway/*` | 80 | Unified entry point, service routing, scan orchestration |
| **engine_discoveries** | `engine-discoveries` | `/discoveries/*` | 8001 | Discover cloud resources via AWS/Azure/GCP APIs |
| **engine_check** | `engine-check` | `/check/*` | 8002 | Evaluate YAML security rules against discoveries |
| **engine_compliance** | `engine-compliance` | `/compliance/*` | 8003 | Map findings to 13 compliance frameworks (CIS, NIST, SOC2, etc.) |
| **engine_threat** | `engine-threat` | `/threat/*` | 8004 | Detect threats, risk scoring, attack paths (Neo4j), MITRE mapping |
| **engine_iam** | `engine-iam` | `/iam/*` | 8005 | IAM posture analysis, privilege escalation detection |
| **engine_datasec** | `engine-datasec` | `/datasec/*` | 8006 | Data classification, lineage, residency, governance |
| **engine_inventory** | `engine-inventory` | `/inventory/*` | 8007 | Normalize assets, build relationships, detect drift |
| **engine_onboarding** | `engine-onboarding` | `/onboarding/*` | 8008 | Account onboarding, credential management, scan scheduling |
| **engine_rule** | `engine-rule` | - | 8000 | YAML rule builder for 7 cloud providers |
| **engine_secops** | `engine-secops` | `/secops/*` | 8000 | IaC/code scanning (Terraform, CloudFormation, Docker, K8s) |

### Scan Pipeline

```
Discovery → Check ─┬─→ Threat ─┬─→ IAM Security
  (AWS)    (rules)  │  (MITRE)  └─→ DataSec
                    │
                    ├─→ Compliance (13 frameworks)
                    │
                    └─→ Inventory (assets, relationships, graph)
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- PostgreSQL 15+ (or use RDS)
- Neo4j 5+ (optional, for security graph)
- AWS credentials (for cloud scanning)

### Local Development

```bash
# 1. Clone and setup
git clone <repo-url>
cd threat-engine

# 2. Copy environment config
cp config.env.template .env

# 3. Start with Docker Compose
cd deployment
docker-compose up -d

# 4. Or run individual engine
cd engine_threat
pip install -r requirements.txt
python -m uvicorn threat_engine.api_server:app --host 0.0.0.0 --port 8020
```

### Verify

```bash
# Health check
curl http://localhost:8020/health

# Run a threat scan
curl -X POST http://localhost:8020/api/v1/threat/generate \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "YOUR_TENANT", "scan_run_id": "YOUR_SCAN_ID", "cloud": "aws"}'
```

---

## Documentation

### For UI Developers
- [API Overview](docs/api/00_OVERVIEW.md) — Architecture, ports, routing, deployment
- [Engine API Reference](docs/api/) — Per-engine endpoints with sample request/response

### For Backend Engineers
- [Setup Guide](docs/SETUP_GUIDE.md) — Local dev environment setup
- [Database Schema](docs/DATABASE_SCHEMA.md) — All tables, columns, relationships
- [Scan Pipeline](docs/SCAN_PIPELINE.md) — End-to-end data flow
- [Graph Schema](docs/GRAPH_SCHEMA.md) — Neo4j nodes, relationships, Cypher queries
- [Environment Variables](docs/ENV_REFERENCE.md) — All config variables

### For DevOps
- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md) — Docker, EKS, production setup
- [Troubleshooting](docs/TROUBLESHOOTING.md) — Common issues and fixes
- [Performance Tuning](docs/PERFORMANCE.md) — Optimization guide

### For Security Engineers
- [MITRE ATT&CK Mapping](docs/MITRE_MAPPING.md) — Technique coverage matrix
- [Security Practices](docs/SECURITY.md) — Auth, secrets, IRSA
- [Rule Authoring](docs/RULE_AUTHORING.md) — Write custom YAML rules

### Reference
- [Data Flow](docs/DATA_FLOW.md) — How data moves between services
- [Testing Guide](docs/TESTING_GUIDE.md) — Running tests
- [Multi-CSP Guide](docs/MULTI_CSP_GUIDE.md) — Onboarding each cloud provider
- [Changelog](CHANGELOG.md) — Version history

---

## Project Structure

```
threat-engine/
├── api_gateway/                # Unified API entry point
├── consolidated_services/      # Shared database layer
│   └── database/
│       ├── schemas/            # SQL schema definitions (8 DBs)
│       ├── migrations/         # Schema migrations
│       └── connections/        # Connection pool management
├── deployment/                 # Docker Compose & deployment configs
├── kubernetes/                 # K8s manifests (32+ files)
├── docs/                       # Documentation
│   └── api/                    # Per-engine API reference (13 files)
├── engine_threat/              # Threat detection + analysis + graph
├── engine_check/               # Compliance check scanning
├── engine_inventory/           # Asset inventory + relationships
├── engine_compliance/          # Compliance framework reporting
├── engine_rule/                # YAML rule builder (multi-CSP)
├── engine_discoveries/         # AWS resource discovery
├── engine_onboarding/          # Account onboarding + scheduling
├── engine_datasec/             # Data security engine
├── engine_iam/                 # IAM security engine
├── engine_secops/              # IaC/code scanner
├── engine_input/               # ConfigScan engines (7 CSPs)
├── engine_output/              # Result export
├── engine_common/              # Shared libraries
├── engine_adminportal/         # Admin UI (Django)
├── engine_userportal/          # User UI (Django + Next.js)
├── scripts/                    # Build & test scripts
└── tests/                      # Test suite
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API Framework | FastAPI + Uvicorn |
| Language | Python 3.11 |
| Databases | PostgreSQL 15 (RDS), Neo4j 5 (Aura) |
| Cache | Redis 7 |
| Storage | AWS S3 |
| Container | Docker |
| Orchestration | AWS EKS (Kubernetes) |
| Admin UI | Django + Celery |
| User UI | Django + Next.js |
| Cloud SDKs | boto3, azure-sdk, google-cloud, oci-sdk |
| Compliance | CIS, NIST 800-53, SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR |
| Threat Intel | MITRE ATT&CK framework |

---

## Key Features

- **Multi-Cloud Discovery** — Scan 40+ AWS services, Azure, GCP, OCI, AliCloud, IBM, K8s
- **1000+ Security Rules** — YAML-based rules with MITRE ATT&CK mapping
- **Threat Detection** — Group findings into threats with risk scoring (0-100)
- **Security Graph** — Neo4j-powered attack paths, blast radius, toxic combinations
- **Threat Hunting** — Ad-hoc and predefined Cypher queries against security graph
- **13-Framework Compliance** — CIS, NIST 800-53, SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, NIST CSF, FFIEC, ACSC, MAS-TRM, NYDFS, RBI
- **IAM Security Analysis** — Privilege escalation detection, MFA audit, password policy, root account, SSO posture
- **Data Security** — Classification, lineage tracking, residency mapping, activity monitoring
- **Drift Detection** — Track configuration changes between scans
- **Scheduled Scanning** — CRON-based scan scheduling with orchestration
- **200+ API Endpoints** — Full REST API for UI integration
- **Single NLB Entry Point** — All traffic routes through nginx ingress on one Network Load Balancer
