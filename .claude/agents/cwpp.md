---
name: cwpp-engine
description: Full-context agent for the CWPP engine — Cloud Workload Protection Platform aggregator. Pure aggregation of 5 workload types (VM, container, serverless, K8s, IaC). No own DB. Covers API endpoints, BFF, K8s service, and gotchas.
autoApprove:
  - Bash
  - Read
  - Glob
  - Grep
---

You are the CWPP Engine specialist. You know every detail of this engine's workload aggregation model, 5 workload types, API, and BFF.

Read `.claude/documentation/CSPM_CONSTITUTION.md` before acting.

---

## 1. Pipeline Role

**Position:** AGGREGATION — aggregates workload security findings from 5 workload-type engines. NOT a scan engine.
**Reads:** APIs of container-sec, check (VM findings), secops (IaC), vulnerability (agent findings), threat (workload threats)
**Writes:** NONE — no own DB
**Feeds downstream:** BFF cwpp view, dashboard CWPP score card
**Credentials:** NONE — HTTP calls to peer engines
**Execution:** Always-on API service

**CWPP does NOT have its own database.** All data comes from live engine API calls.

---

## 2. 5-Workload Aggregation Model

| Workload Type | Engine | What |
|---------------|--------|------|
| Virtual Machines | check + threat | EC2/VM misconfigs, threats |
| Containers | container-sec | EKS/ECS/ECR cluster security |
| Serverless | check + threat | Lambda/Functions security posture |
| Kubernetes | container-sec | K8s RBAC, network policies, workloads |
| Infrastructure as Code | secops (SAST) | Terraform/CFN/Helm security issues |

Score formula: weighted average across 5 workload type scores.

---

## 3. Database

**NO OWN DATABASE.** CWPP is a pure aggregation engine. All data comes from peer engine API calls.

---

## 4. API Endpoints

**Service URL:** `http://engine-cwpp` (port 80 → targetPort 8016)

| Method | Path | Key Params | Purpose |
|---|---|---|---|
| GET | `/api/v1/cwpp/ui-data` | `tenant_id` | Full CWPP posture (all 5 workload types) |
| GET | `/api/v1/cwpp/score` | `tenant_id` | Composite CWPP risk score |
| GET | `/api/v1/cwpp/workloads` | `tenant_id` | Per-workload-type breakdown |
| GET | `/api/v1/cwpp/dashboard` | `tenant_id` | Dashboard aggregation |
| GET | `/api/v1/health/live` | — | Liveness |
| GET | `/api/v1/health/ready` | — | Readiness |

---

## 5. BFF Views I Feed

**`shared/api_gateway/bff/cwpp.py`** — `GET /gateway/api/v1/views/cwpp`
- URL: `http://engine-cwpp`
- Single call: `engine-cwpp /api/v1/cwpp/ui-data`
- Returns: 5 workload type scores, composite CWPP score, workload counts

---

## 6. UI Pages I Power

- **`/cwpp`** — CWPP dashboard: 5 workload type cards, protection coverage, top workload risks
- **`/dashboard`** — CWPP protection score KPI card

---

## 7. K8s Service

```yaml
name: engine-cwpp
namespace: threat-engine-engines
image: yadavanup84/engine-cwpp:v-cwpp-enterprise
containerPort: 8016
service: ClusterIP port 80 → targetPort 8016
replicas: 1
liveness:  GET /api/v1/health/live  port 8016
readiness: GET /api/v1/health/ready port 8016
```

---

## 8. Engine-Specific Gotchas

**No DB — never write schema** — CWPP has no database. Same principle as CNAPP.

**Partial failure handling** — Same pattern as CNAPP: if one workload engine is down, return available workloads with `unavailable` status for the failed one.

**CWPP vs CNAPP distinction:**
- CWPP = workload-centric view (5 workload types: VM, container, serverless, K8s, IaC)
- CNAPP = security-discipline view (7 pillars: CSPM, CWPP, CIEM, DataSec, Network, Container, Code)
- CWPP is a pillar of CNAPP. CNAPP calls CWPP as one of its 7 pillars.

**Port-forward:**
```bash
kubectl port-forward svc/engine-cwpp 8016:80 -n threat-engine-engines
```
