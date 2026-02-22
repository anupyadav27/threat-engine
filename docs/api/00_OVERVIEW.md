# CSPM Platform — API & Architecture Overview

> Complete architecture reference for UI developers, DevOps, and backend engineers.
> Covers all engines, cluster topology, deployment, and service routing.
>
> **Last updated: 2026-02-22** | Image versions current as of this date.

---

## Platform Architecture

```
                        Internet
                            │
                            ▼
     ┌───────────────────────────────────────────────────────────────────────┐
     │  AWS NLB (Network Load Balancer)                                      │
     │  a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com  │
     │  HTTP port 80                                                         │
     └───────────────────────────────────┬───────────────────────────────────┘
                                         │
                               ┌─────────▼──────────┐
                               │  nginx ingress      │
                               │  (path-based routing)│
                               └─────────┬──────────┘
                                         │
              ┌──────────────────────────▼──────────────────────────────────┐
              │           EKS Namespace: threat-engine-engines               │
              │                                                              │
              │  /gateway  ──►  api-gateway        (ClusterIP 10.100.209.181) │
              │  /onboarding►  engine-onboarding   (ClusterIP 10.100.138.231) │
              │  /discoveries► engine-discoveries  (ClusterIP 10.100.188.200) │
              │  /check    ──►  engine-check        (ClusterIP 10.100.43.124)  │
              │  /compliance►  engine-compliance   (ClusterIP 10.100.48.135)  │
              │  /threat   ──►  engine-threat       (ClusterIP 10.100.60.108)  │
              │  /iam      ──►  engine-iam          (ClusterIP 10.100.170.233) │
              │  /datasec  ──►  engine-datasec      (ClusterIP 10.100.155.216) │
              │  /inventory──►  engine-inventory    (ClusterIP 10.100.246.103) │
              │  /secops   ──►  engine-secops       (ClusterIP 10.100.192.50)  │
              │                                                              │
              │  (internal only, no ingress)                                 │
              │           engine-rule      (ClusterIP 10.100.88.168)         │
              │           engine-userportal(ClusterIP 10.100.35.144)         │
              │           engine-userportal-ui(ClusterIP 10.100.213.168)     │
              └──────────────────────────────────────────────────────────────┘
                                         │
              ┌──────────────────────────▼──────────────────────────────────┐
              │              AWS RDS PostgreSQL 15                           │
              │  postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds      │
              │  Port 5432                                                   │
              │                                                              │
              │  11 databases — one per engine (see DATABASE SECTION)        │
              └──────────────────────────────────────────────────────────────┘
```

**IMPORTANT for UI developers:** The nginx ingress strips the leading path prefix
before forwarding. So `/inventory/api/v1/inventory/assets` arrives at
engine-inventory as `/api/v1/inventory/assets`.

---

## External Base URL (for UI calls)

```
http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
```

No authentication is currently required (open HTTP). Add `tenant_id` as a query
parameter to all requests (most endpoints require it).

---

## Engine Registry (Current Production)

| # | Engine | K8s Service | Container Port | ClusterIP | Current Image | Ingress Path | Status |
|---|--------|-------------|----------------|-----------|---------------|--------------|--------|
| 1 | engine-onboarding | `engine-onboarding` | 8010 | 10.100.138.231 | `threat-engine-onboarding-api:latest` | `/onboarding` | ✓ Running |
| 2 | engine-discoveries | `engine-discoveries` | 8001 | 10.100.188.200 | `engine-discoveries:v10-multicloud` | `/discoveries` | ✓ Running |
| 3 | engine-check | `engine-check` | 8002 | 10.100.43.124 | `engine-check:latest` | `/check` | ✓ Running |
| 4 | engine-inventory | `engine-inventory` | 8022 | 10.100.246.103 | `inventory-engine:v6-multi-csp` | `/inventory` | ✓ Running |
| 5 | engine-compliance | `engine-compliance` | 8000 | 10.100.48.135 | `threat-engine-compliance-engine:v2-db-reports` | `/compliance` | ✓ Running |
| 6 | engine-threat | `engine-threat` | 8020 | 10.100.60.108 | `threat-engine:latest` | `/threat` | ✓ Running |
| 7 | engine-iam | `engine-iam` | 8001 | 10.100.170.233 | `engine-iam:v2-fixes` | `/iam` | ✓ Running |
| 8 | engine-datasec | `engine-datasec` | 8003 | 10.100.155.216 | `engine-datasec:v3-fixes` | `/datasec` | ✓ Running |
| 9 | engine-secops | `engine-secops` | 8005 | 10.100.192.50 | `secops-scanner:latest` | `/secops` | ✓ Running |
| 10 | api-gateway | `api-gateway` | 8080 | 10.100.209.181 | `threat-engine-api-gateway:latest` | `/gateway` | ✓ Running |
| 11 | engine-rule | `engine-rule` | 8011 | 10.100.88.168 | `threat-engine-yaml-rule-builder:latest` | (no ingress) | ✓ Running |
| 12 | engine-userportal | `engine-userportal` | 8080 | 10.100.35.144 | `cspm-django-backend:latest` | (no ingress) | ✓ Running |
| 13 | engine-userportal-ui | `engine-userportal-ui` | 80 | 10.100.213.168 | `cspm-ui:latest` | (no ingress) | ⚠ CrashLoopBackOff |

All services in `threat-engine-engines` namespace expose port **80** on the ClusterIP
(which maps to the container port listed above).

---

## How to Call Each Engine

### Via External ELB (UI/external clients)

```
GET http://<ELB>/<engine-prefix>/api/v1/<path>?tenant_id=<tenant>
```

Examples:
```bash
# List inventory assets
GET http://<ELB>/inventory/api/v1/inventory/assets?tenant_id=T&limit=100

# Latest inventory scan summary
GET http://<ELB>/inventory/api/v1/inventory/runs/latest/summary?tenant_id=T

# Trigger discovery scan
POST http://<ELB>/discoveries/api/v1/discovery
Body: {"tenant_id":"T","orchestration_id":"...","provider":"aws","hierarchy_id":"588989875114"}

# Get compliance reports
GET http://<ELB>/compliance/api/v1/compliance/reports?tenant_id=T

# Get threat findings
GET http://<ELB>/threat/api/v1/threats?tenant_id=T

# Check engine health
GET http://<ELB>/inventory/health
```

### Via Internal ClusterIP (engine-to-engine calls)

```
http://<service-name>.<namespace>.svc.cluster.local:<port>/api/v1/...

# Short form (same namespace)
http://engine-inventory:80/api/v1/inventory/assets?tenant_id=T
```

---

## Scan Pipeline (Execution Order)

```
STEP 1          STEP 2           STEP 3         STEP 4
────────────────────────────────────────────────────────────────────────
ONBOARDING  →  DISCOVERIES  →   CHECK      →   INVENTORY
:8010           :8001            :8002           :8022
                                                 ↓
STEP 5a         STEP 5b          STEP 5c         STEP 5d
────────────────────────────────────────────────────────────────────────
COMPLIANCE  →  THREAT        →  IAM         →  DATASEC
:8000           :8020            :8001           :8003
```

All engines coordinate via the `scan_orchestration` table in `threat_engine_onboarding` DB.
Each engine reads `orchestration_id` from the request, looks up its prerequisite `scan_id`,
does its work, then writes its own `scan_id` back to the same row.

---

## Database Architecture

### Single RDS Instance, Multiple Databases

```
RDS: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432
User: postgres | All DBs share same password
```

| Database | Owner Engine | Key Tables |
|----------|-------------|-----------|
| `threat_engine_onboarding` | engine-onboarding | `cloud_accounts`, `scan_orchestration` (pipeline hub) |
| `threat_engine_discoveries` | engine-discoveries | `discovery_findings`, `discovery_report` |
| `threat_engine_check` | engine-check | `check_findings`, `check_report`, `rule_metadata`, `rule_discoveries` |
| `threat_engine_inventory` | engine-inventory | `inventory_findings`, `inventory_relationships`, `inventory_report`, `resource_inventory_identifier` |
| `threat_engine_compliance` | engine-compliance | `compliance_reports`, `compliance_findings`, `compliance_frameworks`, `rule_control_mapping` |
| `threat_engine_threat` | engine-threat | `threat_findings`, `threat_report`, `mitre_techniques`, `mitre_mappings` |
| `threat_engine_iam` | engine-iam | `iam_findings`, `iam_report` |
| `threat_engine_datasec` | engine-datasec | `datasec_findings`, `datasec_report`, `data_assets` |
| `threat_engine_secops` | engine-secops | `secops_scans` |
| `vulnerability_db` | Vulnerability-main | `cve_records`, `vulnerability_findings` |
| `threat_engine_shared` | — | (deprecated) |

### Cross-DB Read Pattern

```
onboarding DB (scan_orchestration) ←── ALL engines read this for coordination
discoveries DB (discovery_findings) ←── check, inventory read this
check DB (check_findings) ←── compliance, threat, iam, datasec read this
inventory DB (inventory_findings) ←── threat, datasec read this
```

---

## EKS Cluster Details

| Property | Value |
|----------|-------|
| Cluster Name | `vulnerability-eks-cluster` |
| ARN | `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster` |
| Region | `ap-south-1` (Mumbai) |
| Kubernetes Version | `1.31.13-eks` |
| Namespace | `threat-engine-engines` |
| Service Account | `engine-sa` (unified, IRSA bound) |

### Node Groups

| Group | Type | Instances | Count |
|-------|------|-----------|-------|
| Default | On-demand | t3.medium | 2 |
| `vulnerability-spot-scanners` | Spot | t3.xlarge/m5.xlarge/c5.xlarge | 0–6 (auto-scales) |

Spot nodes scale up when engine-discoveries runs large scans (via Cluster Autoscaler).
Taint: `spot-scanner=true:NoSchedule`. Scale-down: 5 min after scan.

---

## Resource Limits (All Engines)

| Engine | Memory Req/Limit | CPU Req/Limit |
|--------|-----------------|---------------|
| engine-discoveries | 512Mi / 1Gi | 250m / 500m |
| engine-inventory | 128Mi / 512Mi | 50m / 250m |
| engine-compliance | 128Mi / 512Mi | 50m / 250m |
| engine-threat | 256Mi / 1Gi | 100m / 500m |
| engine-check | 128Mi / 512Mi | 50m / 250m |
| engine-iam | 128Mi / 512Mi | 50m / 250m |
| engine-datasec | 128Mi / 512Mi | 50m / 250m |
| engine-onboarding | 512Mi / 1Gi | 250m / 1000m |
| s3-sync sidecar | 64Mi / 128Mi | 25m / 100m |

---

## S3 Storage

| Bucket | Purpose |
|--------|---------|
| `cspm-lgtech` | Scan results, engine outputs |

```
s3://cspm-lgtech/engine_output/
├── discoveries/
├── check/
├── inventory/
├── compliance/
├── threat/
├── iam/
├── datasec/
└── secops/
```

Most engines have an `s3-sync` sidecar that syncs `/output` to S3 every 30s.

---

## Ingress Configuration

```yaml
# nginx annotations
nginx.ingress.kubernetes.io/rewrite-target: /$2
nginx.ingress.kubernetes.io/proxy-read-timeout: "600"
nginx.ingress.kubernetes.io/proxy-send-timeout: "600"
nginx.ingress.kubernetes.io/proxy-body-size: "100m"
nginx.ingress.kubernetes.io/ssl-redirect: "false"

# Path pattern (strips prefix)
/inventory(/|$)(.*) → engine-inventory:80 → receives $2
```

---

## Documentation Index

| File | Description |
|------|-------------|
| [00_OVERVIEW.md](./00_OVERVIEW.md) | This file — cluster, deployment, routing |
| [01_engine_threat.md](./01_engine_threat.md) | Threat engine endpoints |
| [02_engine_check.md](./02_engine_check.md) | Check engine endpoints |
| [03_engine_inventory.md](./03_engine_inventory.md) | Inventory engine — **v6-multi-csp** |
| [04_engine_compliance.md](./04_engine_compliance.md) | Compliance engine endpoints |
| [05_engine_rule.md](./05_engine_rule.md) | Rule engine endpoints |
| [06_engine_datasec.md](./06_engine_datasec.md) | Data security engine |
| [07_engine_iam.md](./07_engine_iam.md) | IAM security engine |
| [08_engine_discoveries.md](./08_engine_discoveries.md) | Discovery engine — v10-multicloud |
| [09_engine_onboarding.md](./09_engine_onboarding.md) | Onboarding engine |
| [10_engine_secops.md](./10_engine_secops.md) | SecOps IaC scanner |
| [12_api_gateway.md](./12_api_gateway.md) | API Gateway |
| [../ui-developer-handoff/](../ui-developer-handoff/) | UI developer reference |
| [../SCAN_PIPELINE.md](../SCAN_PIPELINE.md) | Full pipeline flow |
| [../DATABASE_SCHEMA.md](../DATABASE_SCHEMA.md) | All table schemas |
