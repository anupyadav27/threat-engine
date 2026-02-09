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
                     │    Service Account: engine-sa (IRSA)          │
                     │                                              │
  Internet ────────► │   ┌────────────────────┐                     │
                     │   │   api-gateway       │                     │
                     │   │   Port 8000         │                     │
                     │   │   (LoadBalancer)     │                     │
                     │   └────────┬─────────────┘                     │
                     │            │                                  │
         ┌──────────┼────────────┼────────────────────────┐         │
         │          │            │                        │         │
    ┌────▼────┐ ┌───▼─────┐ ┌───▼──────┐ ┌──────────┐ ┌──▼────┐   │
    │engine-  │ │engine-  │ │engine-   │ │engine-   │ │engine-│   │
    │threat   │ │check    │ │inventory │ │compliance│ │rule   │   │
    │  :8020  │ │  :8002  │ │  :8022   │ │  :8010   │ │ :8000 │   │
    └────┬────┘ └───┬─────┘ └───┬──────┘ └────┬─────┘ └──┬────┘   │
         │          │            │              │          │        │
    ┌────▼────┐ ┌───▼─────┐ ┌───▼──────┐ ┌────▼─────┐    │        │
    │engine-  │ │engine-  │ │engine-   │ │engine-   │    │        │
    │datasec  │ │iam      │ │discover. │ │onboarding│    │        │
    │  :8004  │ │  :8003  │ │  :8001   │ │  :8008   │    │        │
    └─────────┘ └─────────┘ └──────────┘ └──────────┘    │        │
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

| # | Engine | K8s Name | Port | Docker Image | Code Path | API Prefix | Endpoints |
|---|--------|----------|------|-------------|-----------|------------|-----------|
| 1 | **engine_threat** | `engine-threat` | 8020 | `yadavanup84/threat-engine:latest` | `engine_threat/threat_engine/` | `/api/v1/threat/`, `/api/v1/graph/`, `/api/v1/intel/`, `/api/v1/hunt/` | 63+ |
| 2 | **engine_check** | `engine-check` | 8002 | `yadavanup84/engine-check-aws:latest` | `engine_check/engine_check_aws/` | `/api/v1/check/` | 7 |
| 3 | **engine_inventory** | `engine-inventory` | 8022 | `yadavanup84/inventory-engine:latest` | `engine_inventory/inventory_engine/` | `/api/v1/inventory/` | 20+ |
| 4 | **engine_compliance** | `engine-compliance` | 8010 | `yadavanup84/threat-engine-compliance-engine:latest` | `engine_compliance/compliance_engine/` | `/api/v1/compliance/` | 34 |
| 5 | **engine_rule** | `engine-rule` | 8000 | `yadavanup84/threat-engine-yaml-rule-builder:latest` | `engine_rule/` | `/api/v1/rules/`, `/api/v1/providers/` | 23 |
| 6 | **engine_datasec** | `engine-datasec` | 8004 | `yadavanup84/threat-engine-datasec:latest` | `engine_datasec/data_security_engine/` | `/api/v1/data-security/` | 17 |
| 7 | **engine_iam** | `engine-iam` | 8003 | `yadavanup84/threat-engine-iam:latest` | `engine_iam/iam_engine/` | `/api/v1/iam-security/` | 8 |
| 8 | **engine_discoveries** | `engine-discoveries` | 8001 | `yadavanup84/engine-discoveries-aws:latest` | `engine_discoveries/engine_discoveries_aws/` | `/api/v1/discovery/` | 8 |
| 9 | **engine_onboarding** | `engine-onboarding` | 8008 | `yadavanup84/threat-engine-onboarding-api:latest` | `engine_onboarding/` | `/api/v1/onboarding/`, `/api/v1/schedules/`, `/api/v1/accounts/` | 28 |
| 10 | **engine_secops** | - | - | - | `engine_secops/scanner_engine/` | `/api/v1/secops/`, `/scan` | 7 |
| 11 | **engine_pythonsdk** | - | - | - | `engine_pythonsdk/pythonsdk_service/` | `/api/v1/` | 13 |
| 12 | **api_gateway** | `api-gateway` | 8000 | `yadavanup84/threat-engine-api-gateway:latest` | `api_gateway/` | `/gateway/` | 6 |

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
| Service Account | `engine-sa` (unified, single SA for all engines) |
| IAM Role | `arn:aws:iam::588989875114:role/threat-engine-platform-role` |

### Kubernetes Services (Uniform Naming)

**External (LoadBalancer):**

| Service | Port | Type |
|---------|------|------|
| `api-gateway-lb` | 8000 | LoadBalancer |

**Internal (ClusterIP) — All engines use `engine-{name}` naming:**

| Service | Port | Replicas | Image |
|---------|------|----------|-------|
| `api-gateway` | 8000 | 1 | `yadavanup84/threat-engine-api-gateway:latest` |
| `engine-threat` | 8020 | 1 | `yadavanup84/threat-engine:latest` |
| `engine-discoveries` | 8001 | 1 | `yadavanup84/engine-discoveries-aws:latest` |
| `engine-check` | 8002 | 1 | `yadavanup84/engine-check-aws:latest` |
| `engine-inventory` | 8022 | 1 | `yadavanup84/inventory-engine:latest` |
| `engine-onboarding` | 8008 | 1 | `yadavanup84/threat-engine-onboarding-api:latest` |
| `engine-compliance` | 8010 | 0 (scale when ready) | `yadavanup84/threat-engine-compliance-engine:latest` |
| `engine-iam` | 8003 | 0 (scale when ready) | `yadavanup84/threat-engine-iam:latest` |
| `engine-datasec` | 8004 | 0 (scale when ready) | `yadavanup84/threat-engine-datasec:latest` |
| `engine-rule` | 8000 | 0 (scale when ready) | `yadavanup84/threat-engine-yaml-rule-builder:latest` |

### Resource Limits

| Service | Memory Request/Limit | CPU Request/Limit |
|---------|---------------------|-------------------|
| `api-gateway` | 256Mi / 512Mi | 100m / 500m |
| `engine-threat` | 256Mi / 1Gi | 100m / 500m |
| `engine-onboarding` | 512Mi / 1Gi | 250m / 1000m |
| `engine-discoveries` | 128Mi / 512Mi | 50m / 250m |
| `engine-check` | 128Mi / 512Mi | 50m / 250m |
| `engine-inventory` | 128Mi / 512Mi | 50m / 250m |
| `engine-compliance` | 128Mi / 512Mi | 50m / 250m |
| `engine-iam` | 128Mi / 512Mi | 50m / 250m |
| `engine-datasec` | 128Mi / 512Mi | 50m / 250m |
| S3 Sync Sidecar | 64Mi / 128Mi | 25m / 100m |

### HPA (Horizontal Pod Autoscaler)

| Service | Min | Max | CPU Target |
|---------|-----|-----|------------|
| engine-threat | 2 | 10 | 70% |

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
| `/api/v1/threat/*` | `engine-threat` | 8020 |
| `/api/v1/graph/*` | `engine-threat` | 8020 |
| `/api/v1/intel/*` | `engine-threat` | 8020 |
| `/api/v1/hunt/*` | `engine-threat` | 8020 |
| `/api/v1/check/*` | `engine-check` | 8002 |
| `/api/v1/inventory/*` | `engine-inventory` | 8022 |
| `/api/v1/compliance/*` | `engine-compliance` | 8010 |
| `/api/v1/rules/*`, `/api/v1/providers/*` | `engine-rule` | 8000 |
| `/api/v1/data-security/*` | `engine-datasec` | 8004 |
| `/api/v1/iam-security/*` | `engine-iam` | 8003 |
| `/api/v1/discovery/*` | `engine-discoveries` | 8001 |
| `/api/v1/onboarding/*` | `engine-onboarding` | 8008 |
| `/api/v1/schedules/*` | `engine-onboarding` | 8008 |
| `/gateway/*` | `api-gateway` (self) | 8000 |

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

# Service Discovery (uniform naming)
THREAT_ENGINE_URL=http://engine-threat:8020
DISCOVERIES_ENGINE_URL=http://engine-discoveries:8001
CHECK_ENGINE_URL=http://engine-check:8002
INVENTORY_ENGINE_URL=http://engine-inventory:8022
COMPLIANCE_ENGINE_URL=http://engine-compliance:8010
IAM_ENGINE_URL=http://engine-iam:8003
DATASEC_ENGINE_URL=http://engine-datasec:8004
ONBOARDING_ENGINE_URL=http://engine-onboarding:8008
RULE_ENGINE_URL=http://engine-rule:8000

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

Single unified service account `engine-sa` with IRSA binding to one role:

| Role | ARN | Policies |
|------|-----|----------|
| Platform Role | `arn:aws:iam::588989875114:role/threat-engine-platform-role` | `ThreatEngineSecretsManager`, `threat-engine-s3-cspm-lgtech-access`, `ThreatEngineAssumeCustomerRoles`, `ThreatEngineDynamoDB` |

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
