# Scan Pipeline — End-to-End Flow

> How a security scan flows through the CSPM platform, from cloud resource discovery
> to compliance reporting and threat detection.
>
> Last updated: 2026-02-22

---

## Pipeline Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         SCAN ORCHESTRATION HUB                              │
│              threat_engine_onboarding.scan_orchestration                    │
│   (all engines share a single scan_run_id per pipeline run)               │
└────────────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│  1. ONBOARDING  │  Port 8010
│  engine-        │  Register cloud account, create orchestration row
│  onboarding     │  Writes: scan_run_id, account_id, provider_type
└────────┬────────┘
         │ scan_run_id
         ▼
┌─────────────────┐
│  2. DISCOVERIES │  Port 8001
│  engine-        │  Enumerate all cloud resources (40+ services, 6 CSPs)
│  discoveries    │  Reads:  cloud_accounts (credentials), scan_orchestration
│                 │  Writes: discovery_findings, discovery_report
└────────┬────────┘
         │ scan_run_id
         ├────────────────────────────────────┐
         ▼                                    ▼
┌─────────────────┐                ┌──────────────────┐
│  3. CHECK       │  Port 8002     │  4. INVENTORY    │  Port 8022
│  engine-check   │                │  engine-inventory│
│  Evaluate 400+  │                │  Normalise assets│
│  rules PASS/FAIL│                │  Build edges     │
│  Reads:         │                │  Detect drift    │
│   discovery_    │                │  Reads:          │
│   findings      │                │   discovery_     │
│  Writes:        │                │   findings       │
│   check_        │                │  Writes:         │
│   findings,     │                │   inventory_     │
│   check_report  │                │   findings,      │
│                 │                │   inventory_     │
│                 │                │   relationships, │
└────────┬────────┘                │   inventory_     │
         │ scan_run_id           │   report         │
         │                        │                  │
         │                        │                  │
         │                        │                  │
         │                        └──────────────────┘
         │
         │ (scan_run_id available — downstream engines run in parallel)
         ├──────────────┬──────────────┬──────────────┐
         ▼              ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐
│  5. THREAT   │ │  6. COMPLI.  │ │  7. IAM  │ │  8. DATASEC  │
│  engine-     │ │  engine-     │ │  engine- │ │  engine-     │
│  threat      │ │  compliance  │ │  iam     │ │  datasec     │
│  Port: 8020  │ │  Port: 8000  │ │  Port:   │ │  Port: 8003  │
│              │ │              │ │  8001    │ │              │
│  MITRE ATT&CK│ │  13+frameworks│ │  57 IAM  │ │  62 data     │
│  Risk 0-100  │ │  scoring     │ │  rules   │ │  rules       │
│  Attack      │ │  CIS,NIST,   │ │          │ │              │
│  chains      │ │  SOC2,PCI,   │ │          │ │              │
│              │ │  HIPAA,GDPR, │ │          │ │              │
│              │ │  ISO27001… │ │          │ │              │
│              │ │              │ │          │ │              │
│  Writes:     │ │  Writes:     │ │  Writes: │ │  Writes:     │
│   threat_    │ │   compliance_│ │   iam_   │ │   datasec_   │
│   findings,  │ │   reports,   │ │   finding│ │   findings,  │
│   threat_    │ │   compliance_│ │   s,     │ │   data_      │
│   report     │ │   findings   │ │   iam_   │ │   assets     │
│              │ │              │ │   report │ │              │
└──────────────┘ └──────────────┘ └──────────┘ └──────────────┘

Additional (independent, on-demand):
┌──────────────────────────────────────────────┐
│  SECOPS  (engine-secops, Port 8005)          │
│  IaC scanning: Terraform, CloudFormation,    │
│  Helm, K8s, Ansible, Dockerfile, ARM, Bicep… │
│  Reads: source code / S3 input              │
│  Writes: secops_scans, secops_findings       │
└──────────────────────────────────────────────┘
```

---

## scan_orchestration — The Pipeline Hub

All engines coordinate through a single row in this table:

```sql
-- In threat_engine_onboarding DB
SELECT
    scan_run_id,     -- UUID — passed to every engine API call (single ID for full pipeline)
    tenant_id,
    account_id,           -- cloud account
    provider_type,        -- 'aws' | 'azure' | 'gcp' | 'oci' | 'alicloud' | 'ibm'
    status,               -- 'pending' | 'running' | 'completed' | 'failed'
    created_at,
    updated_at
FROM scan_orchestration
WHERE scan_run_id = '<uuid>';
```

---

## Stage-by-Stage Details

### Stage 1: Onboarding

**Endpoint:** `POST /onboarding/api/v1/scan/trigger` (or similar)
**Output:** `scan_run_id` — pass to every subsequent engine

Creates a row in `scan_orchestration` with account details and returns the
`scan_run_id` that chains the entire pipeline together.

---

### Stage 2: Discovery (engine-discoveries)

**Endpoint:** `POST /discoveries/api/v1/discovery`
```json
{
  "scan_run_id": "<uuid>",
  "provider": "aws",
  "account_id": "588989875114",
  "tenant_id": "..."
}
```

- Authenticates to cloud provider (AWS STS assume-role, or stored credentials)
- Iterates 40+ services (EC2, S3, IAM, RDS, Lambda, ECS, EKS, …)
- Calls SDK APIs to list and describe all resources
- Stores raw API responses in `discovery_findings` (one row per resource)
- Writes `scan_run_id` back to `scan_orchestration`

**Performance:** v10-multicloud — ~2.2 services/min using 100-thread pool, 10s boto3 timeout

---

### Stages 3 & 4: Check + Inventory (PARALLEL — both depend only on discoveries)

> **Key fact**: Both check and inventory read `discovery_findings` directly.
> Inventory does NOT depend on check. They run in parallel after discoveries complete.

### Stage 3: Check (engine-check)

**Endpoint:** `POST /check/api/v1/check`
```json
{ "scan_run_id": "<uuid>", "tenant_id": "..." }
```

- Reads `discovery_findings` for the `scan_run_id` from `scan_orchestration`
- Evaluates 400+ YAML rules (from `rule_metadata` table) per resource
- Produces PASS / FAIL / SKIP per rule per resource
- Enriches with MITRE ATT&CK technique mappings

---

### Stage 4: Inventory (engine-inventory)

**Endpoint:** `POST /inventory/api/v1/inventory/scan/discovery`
```json
{ "scan_run_id": "<uuid>", "tenant_id": "..." }
```

- Two-pass algorithm:
  - **Pass 1**: Root records → create normalised `inventory_findings` assets
  - **Pass 2**: Enrichment records → merge config into existing assets
- Extracts ARNs using step5 catalog (`resource_inventory_identifier` table)
- Builds `inventory_relationships` edges (e.g., EC2 → SecurityGroup, S3 → IAMPolicy)
- Writes `scan_run_id` to `scan_orchestration`
- Typical: 1,529 assets + 199 relationships in ~73s

---

### Stage 5: Threat Detection (engine-threat)

**Endpoint:** `POST /threat/api/v1/scan` (or `/api/v1/threat/generate`)
```json
{ "scan_run_id": "<uuid>", "tenant_id": "..." }
```

Risk score formula:
```
risk_score = severity_weight × 40
           + blast_radius_factor × 25
           + mitre_impact_score × 25
           + reachability_bonus × 10
```
Verdict: `critical_action_required` / `high_risk` / `medium_risk` / `low_risk` / `informational`

---

### Stage 6: Compliance (engine-compliance)

**Endpoint:** `POST /compliance/api/v1/compliance/scan`
```json
{ "scan_run_id": "<uuid>", "tenant_id": "..." }
```

Frameworks: CIS AWS, NIST 800-53, SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, CCPA, AWS Well-Architected, FedRAMP, CMMC, SWIFT CSP, Singapore MAS TRM

---

### Stages 7–8: IAM & DataSec

**IAM Endpoint:** `POST /iam/api/v1/scan`
**DataSec Endpoint:** `POST /datasec/api/v1/scan`

Both read `check_findings` and optionally `inventory_findings` for their specialised analysis.

---

## Trigger Methods

### Method A: Individual engine calls (manual)

Each engine can be triggered independently by calling its API directly with `scan_run_id`.

### Method B: Gateway orchestration

```
POST /gateway/api/v1/orchestrate
{
  "scan_run_id": "<uuid>",
  "stages": ["discovery", "check", "inventory", "threat", "compliance"]
}
```

### Method C: Scheduled (via onboarding engine)

Cron schedules can be configured to trigger the full pipeline automatically.

---

## Timing (Production Reference)

| Stage | Duration | Data Volume |
|-------|----------|-------------|
| Discovery | 3–4h (414 AWS services) | 400k+ findings |
| Discovery (partial, 38 services) | ~17 min | ~50k findings |
| Check | 30–60 sec | 400+ rules × resources |
| Inventory | ~73 sec | 1,529 assets, 199 relationships |
| Compliance | 10–30 sec | 13 framework reports |
| Threat | 5–15 sec | Threat detections with MITRE |
| IAM | 5–10 sec | 57-rule analysis |
| DataSec | 5–10 sec | 62-rule analysis |
