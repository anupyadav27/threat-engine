# Multi-CSP CSPM Platform — Master Project Plan

## Executive Summary

Extend the production-grade AWS CSPM pipeline to support Azure, GCP, OCI, IBM Cloud,
AliCloud, and Kubernetes. The pipeline architecture (Argo, scan_runs, all downstream
engines) is already CSP-agnostic. The work is entirely in:

1. **Discovery** — CSP-specific scanner implementations (largest effort)
2. **Inventory** — Security relationship rules per CSP
3. **Check/Threat/Compliance/IAM/DataSec** — Already provider-aware, need real data
4. **BFF/API Gateway** — UI data alignment per CSP (parallel track, post-engine)

## CSP Readiness Matrix

| CSP       | Catalog YAMLs | Discovery Configs | Rules  | Scanner Code      | Credentials Available |
|-----------|--------------|-------------------|--------|-------------------|-----------------------|
| AWS       | 449          | 415               | 2,689  | ✅ Production     | ✅ Live               |
| Azure     | 266          | 174               | 1,573  | ⚠️ 4 services    | ✅ f6d24b5d sub       |
| GCP       | 279          | 126               | 1,576  | ⚠️ 4 services    | ✅ cloudsecurityapp   |
| K8s       | 17           | 17                | 649    | ⚠️ Stub          | ✅ EKS cluster        |
| OCI       | 317          | 156               | 1,914  | ⚠️ Stub          | ❌ Need creds         |
| IBM       | 126          | 63                | 1,504  | ⚠️ Partial       | ❌ Need creds         |
| AliCloud  | 272          | 136               | 1,306  | ❌ No provider    | ❌ Need creds         |

## Priority Order (Business Value × Readiness)

1. **Azure** — Enterprise priority, credentials available, 174 discovery configs ready
2. **GCP** — Cloud-native customers, credentials available, 126 configs ready
3. **Kubernetes** — CSP-agnostic, works on any cluster, highest security demand
4. **OCI** — Oracle enterprise market (need creds first)
5. **IBM Cloud** — Financial services market (need creds first)
6. **AliCloud** — APAC market (need creds + new provider dir)

## Architecture Principles (Non-Negotiable)

- **No shortcuts** — Every scanner reads from DB catalog (same as AWS)
- **No hardcoded service lists** — Rule-driven via `rule_discoveries` table
- **10s per-API-call timeout ceiling** — Same as AWS v-timeout-fix2
- **Security-only discoveries** — Remove noise: monitoring, billing, cost, audit logs,
  tagging-only APIs, and any API that doesn't return security-relevant resource attributes
- **Asset tab = inventory_findings only** — Not raw discovery data
- **Relationships are security-typed** — Via `resource_security_relationship_rules`
- **Enterprise-grade parallelism** — ThreadPoolExecutor per service-region pair,
  same scan-then-upload pattern as AWS

## Project Tracks

### Track A: Discovery Engine (per CSP)
Files: `engines/discoveries/providers/<csp>/scanner/service_scanner.py`
Blocking track — all other engines get richer data once this is done.

### Track B: Inventory Relationships (per CSP)
Files: `consolidated_services/database/schemas/inventory_schema.sql`
Table: `resource_security_relationship_rules` — add CSP-specific relationship rules.

### Track C: Check/Threat/Compliance/IAM/DataSec alignment
These engines are already CSP-agnostic. Work = verify SQL queries handle new CSP data
and add any CSP-specific threat rules/compliance framework mappings.

### Track D: BFF + Engine API alignment
Files: `engines/*/api/ui_data_router.py`, `shared/api_gateway/`
UI is multi-CSP already. Work = ensure BFF endpoints return consistent schema
regardless of CSP. Second priority after Track A.

### Track E: Pipeline (Argo)
`deployment/aws/eks/argo/cspm-pipeline.yaml` — Already handles `provider` param.
Work = test and verify each CSP flows through correctly.

## Shared Infrastructure (One-Time)

- [ ] K8s Secrets for non-AWS cloud credentials (Azure SP, GCP SA, OCI key)
- [ ] ConfigMap updates for per-CSP DB names and connection strings
- [ ] Engine Docker image split: `engine-discoveries-aws`, `engine-discoveries-azure`,
      `engine-discoveries-gcp` etc. (already started: YAML changed to `-aws:latest`)
- [ ] Onboarding engine: verify credential storage works for Azure/GCP/OCI
- [ ] `rule_discoveries` table: verify all CSP discovery configs have correct `provider` tag

## Project Files Index

- `01_AZURE_PLAN.md` — Azure full detailed plan
- `02_GCP_PLAN.md` — GCP full detailed plan
- `03_K8S_PLAN.md` — Kubernetes full detailed plan
- `04_OCI_PLAN.md` — OCI full detailed plan
- `05_IBM_PLAN.md` — IBM Cloud full detailed plan
- `06_ALICLOUD_PLAN.md` — AliCloud full detailed plan
- `07_INVENTORY_RELATIONSHIPS.md` — Security relationship rules for all CSPs
- `08_BFF_API_ALIGNMENT.md` — BFF/API Gateway multi-CSP alignment
- `09_NOISE_REMOVAL.md` — Audit and remove non-security discoveries per CSP
- `10_CREDENTIALS_CONTEXT.md` — All CSP credentials and test accounts
- `11_DOCKER_SPLIT.md` — Per-CSP Docker image strategy
- `12_PIPELINE_MULTI_CSP.md` — Argo pipeline multi-CSP trigger strategy