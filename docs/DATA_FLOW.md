# Data Flow — How Data Moves Between Services

> How data flows between engines, databases, storage, and external systems.

---

## System Data Flow

```
                              ┌─────────────────┐
                              │   Cloud APIs     │
                              │ AWS/Azure/GCP/   │
                              │ OCI/AliCloud/IBM │
                              └────────┬─────────┘
                                       │ boto3/SDK calls
                                       ▼
┌──────────────┐           ┌───────────────────────┐
│ Onboarding   │──creds──►│   Discovery Engine     │
│ Engine       │           │   (:8002)              │
│ (:8010)      │           └───────────┬────────────┘
└──────┬───────┘                       │ write
       │                               ▼
       │ tenant/          ┌────────────────────────┐
       │ account          │   PostgreSQL (RDS)      │
       │ creds            │                        │
       ▼                  │  ┌─ threat_engine_discoveries ──┐
┌──────────────┐          │  │  discovery_scans             │
│ AWS Secrets  │          │  │  discovery_findings           │
│ Manager      │          │  └──────────────────────────────┘
└──────────────┘          │                        │
                          │  ┌─ threat_engine_check ────────┐
                          │  │  check_scans                 │
┌──────────────┐   read   │  │  check_findings    ◄── Check Engine (:8001)
│ Rule Engine  │◄────────│  │  rule_metadata      ◄── Rule Engine (:8011)
│ (:8011)      │─write──►│  └──────────────────────────────┘
└──────────────┘          │                        │
                          │  ┌─ threat_engine_inventory ────┐
                          │  │  inventory_findings  ◄── Inventory Engine (:8022)
                          │  │  inventory_relationships     │
                          │  │  inventory_drift             │
                          │  └──────────────────────────────┘
                          │                        │
                          │  ┌─ threat_engine_threat ───────┐
                          │  │  threat_report               │
                          │  │  threat_detections   ◄── Threat Engine (:8020)
                          │  │  threat_findings             │
                          │  │  threat_analysis             │
                          │  │  threat_intelligence         │
                          │  │  threat_hunt_queries         │
                          │  │  threat_hunt_results         │
                          │  │  mitre_technique_reference   │
                          │  └──────────────────────────────┘
                          │                        │
                          │  ┌─ threat_engine_onboarding ───┐
                          │  │  accounts, tenants, providers │
                          │  │  credentials, schedules       │
                          │  │  schedule_executions          │
                          │  └──────────────────────────────┘
                          └────────────────────────┘
                                       │
                          ┌────────────┤ read (3 DBs)
                          ▼            ▼
                   ┌─────────────┐  ┌──────────────┐
                   │   Neo4j     │  │  Compliance  │
                   │  (Aura)     │  │  Engine      │
                   │             │  │  (:8021)     │
                   │ Nodes:      │  └──────────────┘
                   │  Resource   │
                   │  Threat     │
                   │  Finding    │
                   │  Internet   │
                   │             │
                   │ Rels:       │
                   │  EXPOSES    │
                   │  HAS_THREAT │
                   │  HAS_FINDING│
                   └─────────────┘
```

---

## Cross-Database Reads

Most engines read from multiple PostgreSQL databases. Here's who reads what:

| Engine | Writes To | Reads From |
|--------|-----------|------------|
| engine_discoveries | threat_engine_discoveries | — |
| engine_check | threat_engine_check | threat_engine_discoveries |
| engine_inventory | threat_engine_inventory | threat_engine_discoveries, threat_engine_check |
| engine_threat | threat_engine_threat | threat_engine_check, threat_engine_inventory |
| engine_compliance | threat_engine_check (reports) | threat_engine_check, threat_engine_threat |
| engine_rule | threat_engine_check (rule_metadata) | — |
| engine_datasec | threat_engine_datasec | threat_engine_check |
| engine_iam | threat_engine_iam | threat_engine_check |
| engine_onboarding | threat_engine_onboarding | — |

---

## Data Format Transitions

```
Cloud API (JSON) ──► Discovery (NDJSON/DB) ──► Check (DB rows)
                                                     │
                                        ┌────────────┼───────────┐
                                        ▼            ▼           ▼
                                  Inventory      Threat      Compliance
                                 (normalized)   (grouped)   (framework-mapped)
                                      │             │
                                      ▼             ▼
                                    Neo4j        Risk Scores
                                   (graph)      (0-100 + verdict)
```

### Key Transformations

| From | To | Transformation |
|------|----|---------------|
| AWS API response | discovery_findings | Flatten boto3 response, add metadata |
| discovery_findings | check_findings | Evaluate YAML rules → PASS/FAIL per resource |
| check_findings | inventory_findings | Normalize resource schema, extract relationships |
| check_findings | threat_detections | Group by resource, aggregate MITRE techniques |
| threat_detections | threat_analysis | Compute risk score, blast radius, attack chain |
| check_findings | compliance_scores | Map rule_id → framework control → score |
| All PostgreSQL data | Neo4j nodes/edges | Transform rows into graph nodes and relationships |

---

## S3 Storage Paths

```
cspm-lgtech/
├── aws-configScan-engine/
│   └── output/{scan_run_id}/
│       └── {service}/{account}/{region}/    # Discovery NDJSON files
├── azure-configScan-engine/
│   └── output/...
├── gcp-configScan-engine/
│   └── output/...
├── compliance-engine/
│   └── output/{report_id}/                  # PDF/Excel reports
├── rule-engine/
│   └── output/{provider}/{service}/         # Generated YAML rules
├── secops/
│   ├── input/{project}/                     # Code to scan
│   └── output/{scan_id}/                    # Scan results
└── threat-engine/
    └── output/{scan_run_id}/                # Threat reports (JSON)
```

---

## Event-Driven Triggers

### Scan Schedule Flow
```
CRON timer
    │
    ▼
Scheduler Service (engine_onboarding)
    │
    ├── POST /api/v1/discovery         (engine_discoveries)
    │       ↓ wait for completion
    ├── POST /api/v1/check             (engine_check)
    │       ↓ wait for completion
    ├── POST /api/v1/inventory/scan    (engine_inventory)
    │       ↓ wait for completion
    ├── POST /api/v1/threat/generate   (engine_threat)
    │       ↓ auto-chains analysis
    ├── POST /api/v1/compliance/generate (engine_compliance)
    │       ↓ wait for completion
    └── POST /api/v1/graph/build       (engine_threat)
```

### Webhook Notifications
```
Scan completion ──► Webhook sender ──► External systems (Slack, PagerDuty, etc.)
```

---

## Data Retention

| Data Type | Default Retention | Storage |
|-----------|------------------|---------|
| Discovery findings | Keep last 5 scans | PostgreSQL |
| Check findings | Keep last 5 scans | PostgreSQL |
| Threat reports | Indefinite | PostgreSQL |
| Compliance reports | Indefinite | PostgreSQL + S3 |
| Neo4j graph | Latest only (rebuilt per scan) | Neo4j |
| Audit logs | 90 days | CloudWatch |
| NDJSON files | 30 days | S3 (lifecycle policy) |

---

## Authentication & Data Access

```
UI/Client
    │
    ▼
API Gateway (:8000) ──── tenant_id in request header/body
    │
    ▼
Engine ──── Validates tenant_id exists in tenants table
    │
    ▼
PostgreSQL ──── All queries filtered by tenant_id
    │
    ▼
Response ──── Only tenant's data returned
```

All data is tenant-isolated. Every database query includes `WHERE tenant_id = ?` to ensure data separation.
