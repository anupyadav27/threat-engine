# Database Dependency Map

> Last updated: 2026-02-22
> RDS: `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com:5432`

All databases live on a **single RDS PostgreSQL 15 instance**.
All engines use the same password (from `threat-engine-db-passwords` K8s secret).

---

## Pipeline Data Flow

```
Cloud Accounts
(AWS / Azure / GCP / OCI / AliCloud / IBM)
        │
        ▼
┌───────────────────────────────────────────────────────────────────────┐
│  ONBOARDING  (threat_engine_onboarding)                               │
│  Tables:                                                              │
│    cloud_accounts      ← stores tenant/account credentials           │
│    scan_orchestration  ← CENTRAL HUB: pipeline scan IDs              │
│  Port: 8010                                                           │
└───────────────────────────┬───────────────────────────────────────────┘
                            │ creates orchestration row
                            ▼
┌───────────────────────────────────────────────────────────────────────┐
│  DISCOVERIES  (threat_engine_discoveries)                             │
│  Tables:                                                              │
│    discovery_findings   ← raw cloud resource records (WRITE)         │
│    discovery_report     ← scan metadata/summary (WRITE)              │
│  Reads:                                                               │
│    onboarding.scan_orchestration (get account details)               │
│    onboarding.cloud_accounts (get credentials)                        │
│  Writes back:                                                         │
│    onboarding.scan_orchestration.discovery_scan_id                    │
│  Port: 8001                                                           │
└───────────────────────────┬───────────────────────────────────────────┘
                            │ discovery_scan_id available
              ┌─────────────┴─────────────┐
              │  BOTH read discovery_findings directly (PARALLEL)       │
              ▼                           ▼
┌─────────────────────────┐   ┌────────────────────────────────────────┐
│  CHECK                  │   │  INVENTORY                             │
│  (threat_engine_check)  │   │  (threat_engine_inventory)             │
│  Tables:                │   │  Tables:                               │
│   rule_discoveries(R)   │   │   inventory_findings       (WRITE)     │
│   rule_metadata    (R)  │   │   inventory_relationships  (WRITE)     │
│   check_findings   (W)  │   │   inventory_report         (WRITE)     │
│   check_report     (W)  │   │   resource_inventory_identifier (R)    │
│  Reads:                 │   │  Reads:                                │
│   discoveries DB        │   │   discoveries.discovery_findings       │
│   (discovery_findings)  │   │   onboarding.scan_orchestration        │
│  Writes back:           │   │  Writes back:                          │
│   scan_orchestration    │   │   scan_orchestration.inventory_scan_id │
│   .check_scan_id        │   │  Port: 8022                            │
│  Port: 8002             │   └────────────────────────────────────────┘
└────────────┬────────────┘              │
             │                          │
             │ check_scan_id            │ inventory_scan_id
             └──────────────┬───────────┘
                            │
              ┌─────────────┴──────────────────────────────────┐
              ▼             ▼             ▼                     ▼
┌────────────────┐ ┌──────────────┐ ┌────────────┐  ┌──────────────────┐
│  COMPLIANCE    │ │  THREAT      │ │  IAM       │  │  DATASEC         │
│  (t_e_compli.) │ │  (t_e_threat)│ │  (t_e_iam) │  │  (t_e_datasec)   │
│  Tables:       │ │  Tables:     │ │  Tables:   │  │  Tables:         │
│  compliance_   │ │  threat_     │ │  iam_      │  │  datasec_        │
│  reports  (W)  │ │  findings(W) │ │  findings  │  │  findings  (W)   │
│  compliance_   │ │  threat_     │ │  (W)       │  │  datasec_        │
│  frameworks(R) │ │  report  (W) │ │  iam_      │  │  report    (W)   │
│  rule_control_ │ │  mitre_      │ │  report(W) │  │  data_assets(W)  │
│  mapping   (R) │ │  mappings(R) │ │            │  │                  │
│                │ │              │ │            │  │                  │
│  Reads:        │ │  Reads:      │ │  Reads:    │  │  Reads:          │
│  check DB      │ │  check DB    │ │  check DB  │  │  check DB        │
│  check_        │ │  check_      │ │  check_    │  │  check_findings  │
│  findings      │ │  findings    │ │  findings  │  │  inventory DB    │
│                │ │  inventory DB│ │            │  │  inventory_      │
│  Port: 8000    │ │  Port: 8020  │ │  Port:8001 │  │  findings        │
│                │ │              │ │            │  │  Port: 8003      │
└────────────────┘ └──────────────┘ └────────────┘  └──────────────────┘
```

---

## Database Inventory

### `threat_engine_onboarding`
**Owner:** engine-onboarding
**Access:** R/W by onboarding; READ by discoveries, check, inventory, compliance, threat, iam, datasec

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `cloud_accounts` | onboarding | discoveries | Registered cloud accounts + credentials |
| `scan_orchestration` | onboarding (create); all engines (update their scan_id) | all engines | Central pipeline coordination hub |

---

### `threat_engine_discoveries`
**Owner:** engine-discoveries
**Access:** WRITE by discoveries; READ by check, inventory, compliance, threat, iam, datasec

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `discovery_findings` | discoveries | check, inventory, threat, iam, datasec | Raw cloud resource records (provider, service, account, region, resource data) |
| `discovery_report` | discoveries | (summary only) | Scan metadata: counts, timing, errors |

---

### `threat_engine_check`
**Owner:** engine-check
**Access:** WRITE by check; READ by compliance, threat, iam, datasec, inventory

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `check_findings` | check | compliance, threat, iam, datasec | Rule evaluation results (PASS/FAIL per resource per rule) |
| `check_report` | check | — | Scan summary: total pass/fail counts |
| `rule_discoveries` | (seeded from YAML) | check | Maps rule_id → boto3 calls, ARN identifiers |
| `rule_metadata` | rule engine | check, compliance | Rule definitions: severity, description, remediation |

---

### `threat_engine_inventory`
**Owner:** engine-inventory
**Access:** WRITE by inventory; READ by threat, datasec

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `inventory_findings` | inventory | threat, datasec, UI | Normalised asset records (resource_uid, type, region, tags) |
| `inventory_relationships` | inventory | UI, graph API | Asset edges (e.g., ec2→security-group, s3→iam-policy) |
| `inventory_report` | inventory | UI | Scan summary: total assets, rels, by provider/type/region |
| `resource_inventory_identifier` | (seeded once) | inventory | Step5 catalog: ARN patterns, root/enrich ops per resource type |

---

### `threat_engine_compliance`
**Owner:** engine-compliance
**Access:** WRITE by compliance; READ by UI

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `compliance_reports` | compliance | UI | Framework score reports |
| `compliance_findings` | compliance | UI | Per-control findings |
| `compliance_frameworks` | (seeded) | compliance | Framework definitions (CIS, NIST, SOC2, PCI-DSS, HIPAA, GDPR, ISO27001 …) |
| `rule_control_mapping` | (seeded) | compliance | Maps rule_id → framework control |

---

### `threat_engine_threat`
**Owner:** engine-threat
**Access:** WRITE by threat; READ by UI

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `threat_findings` | threat | UI | Detected threats with MITRE technique, risk score |
| `threat_report` | threat | UI | Scan summary: high/medium/low counts |
| `mitre_techniques` | (seeded) | threat | MITRE ATT&CK technique catalog |
| `mitre_mappings` | (seeded) | threat | rule_id → MITRE technique mapping |

---

### `threat_engine_iam`
**Owner:** engine-iam
**Access:** WRITE by iam; READ by UI

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `iam_findings` | iam | UI | IAM posture findings (57 rules): privilege, MFA, key rotation… |
| `iam_report` | iam | UI | Scan summary |

---

### `threat_engine_datasec`
**Owner:** engine-datasec
**Access:** WRITE by datasec; READ by UI

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `datasec_findings` | datasec | UI | Data security findings (62 rules): encryption, exposure, classification |
| `datasec_report` | datasec | UI | Scan summary |
| `data_assets` | datasec | UI | Catalogued sensitive data assets |

---

### `threat_engine_secops` / `vulnerability_db`
**Owner:** engine-secops / Vulnerability-main

| Table | Writer | Readers | Purpose |
|-------|--------|---------|---------|
| `secops_scans` | secops | UI | IaC scan results (Terraform, CloudFormation, Helm, K8s…) |
| `cve_records` | vulnerability subsystem | secops | CVE database |
| `vulnerability_findings` | vulnerability subsystem | UI | CVE matches against discovered packages |

---

## Cross-Database Read Map

```
                      ┌────────────┐
                      │  CHECK DB  │
                      │check_      │◄──────────────────────────┐
                      │findings    │                           │
                      └──────┬─────┘                           │
                             │ read                            │ read
               ┌─────────────┼──────────────┐                 │
               ▼             ▼              ▼                  │
       ┌──────────────┐ ┌──────────┐ ┌──────────┐   ┌────────┴─────┐
       │  COMPLIANCE  │ │  THREAT  │ │   IAM    │   │   DATASEC    │
       │     DB       │ │    DB    │ │    DB    │   │      DB      │
       └──────────────┘ └──────────┘ └──────────┘   └──────────────┘

                      ┌──────────────┐
                      │ DISCOVERIES  │
                      │     DB       │
                      │ discovery_   │◄──────────────────────────┐
                      │ findings     │                           │
                      └──────┬───────┘                           │
                             │ read                              │ read
               ┌─────────────┴──────────┐                       │
               ▼                        ▼                        │
       ┌──────────────┐        ┌──────────────┐                 │
       │    CHECK     │        │  INVENTORY   │                 │
       │     DB       │        │     DB       │─────────────────►┘
       └──────────────┘        └──────────────┘  (inventory reads
                                                  discoveries;
                                                  datasec/threat
                                                  read inventory)
```

---

## scan_orchestration Column Reference

This single row ties all engines together for one scan run:

```sql
-- In threat_engine_onboarding DB
SELECT
    orchestration_id,      -- UUID, primary key
    tenant_id,             -- tenant identifier
    account_id,            -- cloud account (hierarchy_id)
    provider_type,         -- 'aws' | 'azure' | 'gcp' | 'oci' | 'alicloud' | 'ibm'
    status,                -- 'pending' | 'running' | 'completed' | 'failed'

    -- Written by each engine when its scan completes:
    discovery_scan_id,     -- engine-discoveries
    check_scan_id,         -- engine-check
    inventory_scan_id,     -- engine-inventory
    compliance_scan_id,    -- engine-compliance
    threat_scan_id,        -- engine-threat
    iam_scan_id,           -- engine-iam
    datasec_scan_id,       -- engine-datasec

    created_at,
    updated_at
FROM scan_orchestration
WHERE orchestration_id = '<uuid>';
```

---

## Connection String Pattern

All engines use environment variables injected from ConfigMap + Secret:

```bash
# ConfigMap: threat-engine-db-config
<ENGINE>_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
<ENGINE>_DB_PORT=5432
<ENGINE>_DB_NAME=threat_engine_<engine>
<ENGINE>_DB_USER=postgres

# Secret: threat-engine-db-passwords
<ENGINE>_DB_PASSWORD=<shared password from AWS Secrets Manager>
```

**Keys in Secrets Manager (`threat-engine/rds-credentials`):**
`CHECK_DB_PASSWORD`, `COMPLIANCE_DB_PASSWORD`, `DATASEC_DB_PASSWORD`,
`DISCOVERIES_DB_PASSWORD`, `DISCOVERY_DB_PASSWORD`, `IAM_DB_PASSWORD`,
`INVENTORY_DB_PASSWORD`, `ONBOARDING_DB_PASSWORD`, `PYTHONSDK_DB_PASSWORD`,
`SECOPS_DB_PASSWORD`, `SHARED_DB_PASSWORD`, `THREAT_DB_PASSWORD`

---

## Schema Files

Local reference schemas (match production RDS):

| File | Database |
|------|----------|
| `consolidated_services/database/schemas/onboarding_schema.sql` | threat_engine_onboarding |
| `consolidated_services/database/schemas/discoveries_schema.sql` | threat_engine_discoveries |
| `consolidated_services/database/schemas/check_schema.sql` | threat_engine_check |
| `consolidated_services/database/schemas/inventory_schema.sql` | threat_engine_inventory |
| `consolidated_services/database/schemas/compliance_schema.sql` | threat_engine_compliance |
| `consolidated_services/database/schemas/shared_schema.sql` | threat_engine_shared (deprecated) |
