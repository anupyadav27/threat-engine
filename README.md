# CSPM Threat Engine Platform

Cloud Security Posture Management (CSPM) platform built as a microservices architecture. Discovers cloud resources, evaluates security rules, detects threats, and generates compliance reports across AWS, Azure, GCP, OCI, AliCloud, IBM Cloud, and Kubernetes.

---

## Architecture

```
                        api-gateway (:8000)
                              |
        +---------+-----------+-----------+---------+----------+
        |         |           |           |         |          |
   engine-    engine-    engine-     engine-     engine-     ...
   threat     check      inventory   compliance  rule
   (:8020)    (:8002)     (:8022)     (:8010)    (:8000)
        |         |           |           |         |
   PostgreSQL  PostgreSQL  PostgreSQL  PostgreSQL PostgreSQL
   + Neo4j     (check DB)  (inv DB)   (comp DB)  (check DB)
```

### Engines

| Engine | K8s Name | Port | Purpose |
|--------|----------|------|---------|
| **engine_discoveries** | `engine-discoveries` | 8001 | Discover cloud resources via AWS/Azure/GCP APIs |
| **engine_check** | `engine-check` | 8002 | Evaluate YAML security rules against discoveries |
| **engine_inventory** | `engine-inventory` | 8022 | Normalize assets, build relationships, detect drift |
| **engine_threat** | `engine-threat` | 8020 | Detect threats, risk scoring, attack paths (Neo4j), MITRE mapping |
| **engine_compliance** | `engine-compliance` | 8010 | Map findings to compliance frameworks (CIS, NIST, SOC2, etc.) |
| **engine_rule** | `engine-rule` | 8000 | YAML rule builder for 7 cloud providers |
| **engine_onboarding** | `engine-onboarding` | 8008 | Account onboarding, credential management, scan scheduling |
| **engine_datasec** | `engine-datasec` | 8004 | Data classification, lineage, residency, governance |
| **engine_iam** | `engine-iam` | 8003 | IAM posture analysis, privilege escalation detection |
| **engine_secops** | - | - | IaC/code scanning (Terraform, CloudFormation, Docker, K8s) |
| **api_gateway** | `api-gateway` | 8000 | Unified entry point, service routing, scan orchestration |

### Scan Pipeline

```
Discovery → Check → Inventory → Threat Detection → Compliance → Graph Build
   (AWS)    (rules)  (assets)   (MITRE, risk)     (frameworks)   (Neo4j)
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
- **Compliance Reporting** — Map to CIS, NIST, SOC2, ISO 27001, PCI DSS, HIPAA, GDPR
- **Drift Detection** — Track configuration changes between scans
- **Scheduled Scanning** — CRON-based scan scheduling with orchestration
- **200+ API Endpoints** — Full REST API for UI integration
