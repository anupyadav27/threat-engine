# CSPM Platform — API & Architecture Overview

> Complete architecture reference for UI developers, DevOps, and backend engineers.
> Covers all engines, cluster topology, deployment, and service routing.

---

## Platform Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │            AWS EKS Cluster                   │
                     │       (ap-south-1 / Mumbai)                  │
                     │    Namespace: threat-engine-engines           │
                     │                                              │
  Internet ────────► │   ┌────────────────────┐                     │
                     │   │   API Gateway       │                     │
                     │   │   Port 8000         │                     │
                     │   │   (LoadBalancer)     │                     │
                     │   └────────┬─────────────┘                     │
                     │            │                                  │
         ┌──────────┼────────────┼────────────────────────┐         │
         │          │            │                        │         │
    ┌────▼────┐ ┌───▼─────┐ ┌───▼──────┐ ┌──────────┐ ┌──▼────┐   │
    │ Threat  │ │  Check  │ │Inventory │ │Compliance│ │ Rule  │   │
    │  :8020  │ │  :8001  │ │  :8022   │ │  :8021   │ │ :8011 │   │
    └────┬────┘ └───┬─────┘ └───┬──────┘ └────┬─────┘ └──┬────┘   │
         │          │            │              │          │        │
    ┌────▼────┐ ┌───▼─────┐ ┌───▼──────┐ ┌────▼─────┐    │        │
    │DataSec  │ │  IAM    │ │Discover  │ │Onboarding│    │        │
    │  :8004  │ │  :8003  │ │  :8002   │ │  :8010   │    │        │
    └─────────┘ └─────────┘ └──────────┘ └──────────┘    │        │
         │                                                │        │
    ┌────▼────┐                                      ┌────▼────┐   │
    │ SecOps  │                                      │PythonSDK│   │
    │         │                                      │         │   │
    └─────────┘                                      └─────────┘   │
                     │                                              │
                     │   ┌─────────────┐  ┌──────────────┐         │
                     │   │ PostgreSQL  │  │    Neo4j     │         │
                     │   │ (RDS)       │  │  (Aura SaaS) │         │
                     │   │ Port 5432   │  │  neo4j+s://  │         │
                     │   └─────────────┘  └──────────────┘         │
                     │                                              │
                     │   ┌─────────────┐  ┌──────────────┐         │
                     │   │    Redis    │  │   S3 Bucket  │         │
                     │   │  Port 6379  │  │  cspm-lgtech │         │
                     │   └─────────────┘  └──────────────┘         │
                     └──────────────────────────────────────────────┘
```

---

## Engine Registry

| # | Engine | Port | Docker Image | Code Path | API Prefix | Endpoints |
|---|--------|------|-------------|-----------|------------|-----------|
| 1 | **engine_threat** | 8020 | `yadavanup84/threat-engine:latest` | `engine_threat/threat_engine/` | `/api/v1/threat/`, `/api/v1/graph/`, `/api/v1/intel/`, `/api/v1/hunt/` | 63+ |
| 2 | **engine_check** | 8001 | `yadavanup84/check-engine:latest` | `engine_check/engine_check_aws/` | `/api/v1/check/` | 7 |
| 3 | **engine_inventory** | 8022 | `yadavanup84/inventory-engine:latest` | `engine_inventory/inventory_engine/` | `/api/v1/inventory/` | 20+ |
| 4 | **engine_compliance** | 8021 | `yadavanup84/compliance-engine:latest` | `engine_compliance/compliance_engine/` | `/api/v1/compliance/` | 34 |
| 5 | **engine_rule** | 8011 | `yadavanup84/rule-engine:latest` | `engine_rule/` | `/api/v1/rules/`, `/api/v1/providers/` | 23 |
| 6 | **engine_datasec** | 8004 | `yadavanup84/datasec-engine:latest` | `engine_datasec/data_security_engine/` | `/api/v1/data-security/` | 17 |
| 7 | **engine_iam** | 8003 | `yadavanup84/iam-engine:latest` | `engine_iam/iam_engine/` | `/api/v1/iam-security/` | 8 |
| 8 | **engine_discoveries** | 8002 | `yadavanup84/discoveries-engine:latest` | `engine_discoveries/engine_discoveries_aws/` | `/api/v1/discovery/` | 8 |
| 9 | **engine_onboarding** | 8010 | `yadavanup84/onboarding-engine:latest` | `engine_onboarding/` | `/api/v1/onboarding/`, `/api/v1/schedules/`, `/api/v1/accounts/` | 28 |
| 10 | **engine_secops** | 8000 | `yadavanup84/secops-engine:latest` | `engine_secops/scanner_engine/` | `/api/v1/secops/`, `/scan` | 7 |
| 11 | **engine_pythonsdk** | 8000 | - | `engine_pythonsdk/pythonsdk_service/` | `/api/v1/` | 13 |
| 12 | **api_gateway** | 8000 | `threat-engine/api-gateway:latest` | `api_gateway/` | `/gateway/` | 6 |

**Non-API Engines:**

| Engine | Type | Description |
|--------|------|-------------|
| engine_input | Pipeline | AWS ConfigScan input processor |
| engine_output | Pipeline | Result export handler |
| engine_common | Library | Shared utilities (logger, middleware, retry, storage) |
| engine_adminportal | Django App | Admin management (users, tenants, config) — Port 8001 |
| engine_userportal | Django + Next.js | User dashboard — Backend :8000, UI :3000 |

---

## Database Architecture

### PostgreSQL Databases (AWS RDS)

| Database | Used By | Key Tables |
|----------|---------|-----------|
| `threat_engine_threat` | engine_threat | threat_report, threat_detections, threat_findings, threat_analysis, threat_intelligence, threat_hunt_queries, threat_hunt_results, mitre_technique_reference, tenants |
| `threat_engine_check` | engine_check, engine_threat | check_scans, check_findings, rule_metadata, tenants |
| `threat_engine_inventory` | engine_inventory, engine_threat | inventory_findings, inventory_relationships, inventory_scans, tenants |
| `threat_engine_compliance` | engine_compliance | compliance_reports, compliance_scores, compliance_findings, compliance_trends |
| `threat_engine_onboarding` | engine_onboarding | accounts, tenants, providers, credentials, schedules, schedule_executions |
| `threat_engine_discoveries` | engine_discoveries | discovery_scans, discovery_findings |
| `threat_engine_datasec` | engine_datasec | datasec_reports, datasec_findings |
| `threat_engine_iam` | engine_iam | iam_reports, iam_findings |

**RDS Connection:**
```
Host: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
Port: 5432
User: postgres
```

### Neo4j Graph Database (Aura SaaS)

| Property | Value |
|----------|-------|
| URI | `neo4j+s://17ec5cbb.databases.neo4j.io` |
| Instance ID | `17ec5cbb` |
| Node Types | Resource, ThreatDetection, Finding, Internet, Account, Region, S3Bucket, IAMRole, IAMPolicy, SecurityGroup |
| Relationship Types | HAS_FINDING, HAS_THREAT, CONTAINS, HOSTS, EXPOSES, ATTACK_PATH, RELATES_TO, REFERENCES |
| Used By | engine_threat (graph builder + queries) |

### Redis

| Property | Value |
|----------|-------|
| Port | 6379 |
| DB 0 | Celery result backend |
| DB 1 | Celery broker |
| Used By | engine_adminportal, engine_userportal (task queues) |

### S3 Storage

| Bucket | Paths |
|--------|-------|
| `cspm-lgtech` | `aws-configScan-engine/output/`, `azure-configScan-engine/output/`, `gcp-configScan-engine/output/`, `compliance-engine/output/`, `rule-engine/output/`, `secops/input/`, `secops/output/` |

---

## Cluster & Deployment

### EKS Cluster

| Property | Value |
|----------|-------|
| Cluster Name | `vulnerability-eks-cluster` |
| Region | `ap-south-1` (Mumbai) |
| Namespace | `threat-engine-engines` |
| Node Groups | Managed |
| Service Account | `aws-engine-sa` |
| IAM Role | `arn:aws:iam::588989875114:role/threat-engine-platform-role` |

### Kubernetes Services

**External (LoadBalancer):**

| Service | Port | Type |
|---------|------|------|
| api-gateway | 8000 | LoadBalancer |
| onboarding-service | 8010 | LoadBalancer |
| yaml-rule-builder | 8011 | LoadBalancer |

**Internal (ClusterIP):**

| Service | Port | Replicas |
|---------|------|----------|
| core-engine-service | 8001 | 3 (min 2, max 10) |
| configscan-service | 8002 | 1 |
| platform-service | 8003 | 1 |
| data-secops-service | 8004 | 1 |
| threat-engine | 8020 | 1 |
| compliance-engine | 8021 | 1 |
| inventory-engine | 8022 | 1 |

### Resource Limits

| Service | Memory Request/Limit | CPU Request/Limit |
|---------|---------------------|-------------------|
| API Gateway | 256Mi / 512Mi | 250m / 500m |
| Core Engine | 2Gi / 4Gi | 1000m / 2000m |
| Scanner Engine | 512Mi / 2Gi | 250m / 1000m |

### HPA (Horizontal Pod Autoscaler)

| Service | Min | Max | CPU Target | Memory Target |
|---------|-----|-----|------------|---------------|
| API Gateway | 2 | 10 | 70% | 80% |
| Core Engine | 3 | 10 | 70% | 80% |

### Health Probes

```yaml
# Standard across all engines
livenessProbe:
  httpGet:
    path: /health (or /api/v1/health/live)
    port: <engine-port>
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health (or /api/v1/health/ready)
    port: <engine-port>
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

---

## API Gateway Routing

The API Gateway at port 8000 routes requests to backend services:

| URL Pattern | Backend Service | Port |
|-------------|----------------|------|
| `/api/v1/threat/*` | threat-engine | 8020 |
| `/api/v1/graph/*` | threat-engine | 8020 |
| `/api/v1/intel/*` | threat-engine | 8020 |
| `/api/v1/hunt/*` | threat-engine | 8020 |
| `/api/v1/check/*` | check-engine | 8001 |
| `/api/v1/inventory/*` | inventory-engine | 8022 |
| `/api/v1/compliance/*` | compliance-engine | 8021 |
| `/api/v1/rules/*`, `/api/v1/providers/*` | rule-engine | 8011 |
| `/api/v1/data-security/*` | datasec-engine | 8004 |
| `/api/v1/iam-security/*` | iam-engine | 8003 |
| `/api/v1/discovery/*` | discoveries-engine | 8002 |
| `/api/v1/onboarding/*` | onboarding-engine | 8010 |
| `/api/v1/schedules/*` | onboarding-engine | 8010 |
| `/api/v1/secops/*` | secops-engine | 8000 |
| `/gateway/*` | api-gateway (self) | 8000 |

### Gateway-Specific Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Service list |
| GET | `/gateway/health` | Gateway health |
| GET | `/gateway/services` | List all registered services |
| POST | `/gateway/services/{name}/health-check` | Force health check on service |
| GET | `/gateway/configscan/csps` | List supported CSPs |
| GET | `/gateway/configscan/route-test` | Test CSP routing |
| POST | `/gateway/orchestrate` | Full scan pipeline orchestration |

---

## Docker Compose (Local Development)

### Primary: `deployment/docker-compose.yml`

```yaml
Services:
  postgres (5432)        # PostgreSQL 15
  redis (6379)           # Redis 7 Alpine
  api-gateway (8000)     # Unified API entry
  core-engine (8001)     # Check + Discoveries
  configscan (8002)      # AWS ConfigScan
  platform (8003)        # IAM + Onboarding
  data-secops (8004)     # DataSec + SecOps
```

### Hybrid Multi-Cloud: `deployment/docker/docker-compose-hybrid.yaml`

```yaml
Services:
  postgres (5432)
  api-gateway (8000)
  configscan-aws (8001)
  configscan-azure (8002)
  configscan-gcp (8003)
  onboarding (8010)
  rule-engine (8011)
  pgadmin (8080)
```

### Local Dev: `deployment/local/docker-compose/docker-compose.yml`

```yaml
Services:
  postgres (5432)
  compliance-engine (8001)
  rule-engine (8002)
  onboarding-engine (8003)
  threat-engine (8004)
  inventory-engine (8005)
  configscan-aws (8000)
  secops-engine (8006)
```

---

## Environment Variables

### Core Configuration

```bash
# AWS
AWS_REGION=ap-south-1
PLATFORM_AWS_ACCOUNT_ID=588989875114

# Database
DATABASE_URL=postgresql://user:pass@host:5432/dbname
DB_SCHEMA=engine_configscan,engine_shared

# Storage
USE_S3=true
S3_BUCKET=cspm-lgtech

# Service Discovery
CORE_ENGINE_URL=http://core-engine-service:8001
CONFIGSCAN_SERVICE_URL=http://configscan-service:8002
PLATFORM_SERVICE_URL=http://platform-service:8003
ONBOARDING_ENGINE_URL=http://onboarding-engine:8010
RULE_ENGINE_URL=http://rule-engine:8011

# Cache
REDIS_URL=redis://redis:6379
CELERY_BROKER_URL=redis://redis-service:6379/0

# Logging
LOG_LEVEL=INFO
ENVIRONMENT=production
```

---

## Security

### IAM Roles (IRSA)

| Role | ARN | Used By |
|------|-----|---------|
| Platform Role | `arn:aws:iam::588989875114:role/threat-engine-platform-role` | All engines |
| SecOps S3 Role | `arn:aws:iam::588989875114:role/secops-s3-access-role` | SecOps scanner |
| CSPM Role | `arn:aws:iam::588989875114:role/cspm-eks-role` | EKS service account |

### Security Context (All Pods)

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
```

---

## Documentation Index

| File | Description |
|------|-------------|
| [00_OVERVIEW.md](./00_OVERVIEW.md) | This file — architecture, cluster, deployment |
| [01_engine_threat.md](./01_engine_threat.md) | Threat engine — 63+ endpoints with sample responses |
| [02_engine_check.md](./02_engine_check.md) | Check engine — compliance scanning |
| [03_engine_inventory.md](./03_engine_inventory.md) | Inventory engine — asset management |
| [04_engine_compliance.md](./04_engine_compliance.md) | Compliance engine — framework reporting |
| [05_engine_rule.md](./05_engine_rule.md) | Rule engine — YAML rule builder |
| [06_engine_datasec.md](./06_engine_datasec.md) | Data security engine |
| [07_engine_iam.md](./07_engine_iam.md) | IAM security engine |
| [08_engine_discoveries.md](./08_engine_discoveries.md) | AWS resource discovery |
| [09_engine_onboarding.md](./09_engine_onboarding.md) | Account onboarding & scheduling |
| [10_engine_secops.md](./10_engine_secops.md) | SecOps scanner (IaC/code) |
| [11_engine_pythonsdk.md](./11_engine_pythonsdk.md) | Python SDK service |
| [12_api_gateway.md](./12_api_gateway.md) | API Gateway routing |
