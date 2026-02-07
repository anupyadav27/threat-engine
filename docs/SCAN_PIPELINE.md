# Scan Pipeline — End-to-End Flow

> How a security scan flows through the CSPM platform, from cloud resource discovery to compliance reporting.

---

## Pipeline Overview

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌─────────────┐
│  Discovery  │───►│    Check    │───►│  Inventory  │───►│    Threat    │───►│ Compliance  │───►│   Graph     │
│  Engine     │    │   Engine    │    │   Engine    │    │   Engine     │    │   Engine    │    │  (Neo4j)    │
│  (:8002)    │    │  (:8001)    │    │  (:8022)    │    │  (:8020)     │    │  (:8021)    │    │  (:8020)    │
└─────────────┘    └─────────────┘    └─────────────┘    └──────────────┘    └─────────────┘    └─────────────┘
      │                  │                  │                   │                  │                  │
      ▼                  ▼                  ▼                   ▼                  ▼                  ▼
 discovery_scans    check_findings     inventory_         threat_report      compliance_        Neo4j
 discovery_findings rule_metadata      findings           threat_detections  reports            Nodes &
                                       inventory_         threat_findings    compliance_        Relationships
                                       relationships      threat_analysis    scores
                                                          threat_intelligence
```

---

## Stage 1: Discovery (engine_discoveries)

**Purpose:** Connect to cloud provider APIs and discover all resources.

**Trigger:** `POST /api/v1/discovery`

**Input:**
```json
{
  "tenant_id": "588989875114",
  "scan_run_id": "ece8c3a6-...",
  "cloud": "aws",
  "accounts": ["588989875114"],
  "regions": ["ap-south-1"],
  "services": ["s3", "iam", "ec2", "rds", "lambda"]
}
```

**What it does:**
1. Authenticates to AWS using IAM role or access keys (from onboarding credentials)
2. Iterates through each requested service (40+ supported)
3. Calls AWS APIs (boto3) to list and describe all resources
4. Normalizes raw API responses into NDJSON format
5. Stores results in `discovery_findings` table and S3

**Output:**
- `discovery_scans` — Scan metadata (id, tenant, status, timing)
- `discovery_findings` — Raw resource configurations (one row per resource)
- S3: `cspm-lgtech/aws-configScan-engine/output/{scan_run_id}/`

**Data example:** Each discovery finding contains the full AWS API response for a resource (e.g., S3 bucket config, IAM role policies, EC2 security group rules).

---

## Stage 2: Check (engine_check)

**Purpose:** Evaluate security rules against discovered resources.

**Trigger:** `POST /api/v1/check`

**Input:** Same scan_run_id from discovery stage.

**What it does:**
1. Loads discovery findings from DB for the given scan_run_id
2. Loads YAML security rules from `rule_metadata` table (1000+ rules)
3. For each resource, evaluates applicable rules:
   - Matches rule's service/resource_type to discovery resource
   - Executes rule logic (field checks, policy evaluation)
   - Produces PASS/FAIL/ERROR status per rule per resource
4. Enriches results with MITRE ATT&CK technique mappings from rule metadata
5. Stores results in `check_findings` table

**Output:**
- `check_scans` — Scan metadata with total passed/failed counts
- `check_findings` — Individual check results (rule_id, resource_uid, status, evidence, severity)

**Data volume:** ~764 findings per scan (depending on resource count and rule count)

**Rule evaluation example:**
```
Rule: aws.s3.bucket.versioning_enabled
Resource: arn:aws:s3:::my-bucket
Check: resource.Versioning.Status == "Enabled"
Result: FAIL (versioning disabled)
Severity: high
MITRE: T1485 (Data Destruction)
```

---

## Stage 3: Inventory (engine_inventory)

**Purpose:** Normalize assets, build relationships between resources, detect drift.

**Trigger:** `POST /api/v1/inventory/scan`

**What it does:**
1. Reads discovery findings from DB
2. Normalizes each resource into a standard asset schema:
   - Extracts: resource_uid, resource_type, region, account, tags, configuration
   - Classifies by service (s3.resource, iam.role, ec2.security-group, etc.)
3. Builds relationships between resources:
   - IAM role → attached policies
   - EC2 instance → security groups
   - S3 bucket → IAM roles with access
   - VPC → subnets → instances
4. Compares with previous scan to detect drift (config changes)
5. Stores normalized assets and relationships

**Output:**
- `inventory_findings` — Normalized asset records
- `inventory_relationships` — Resource-to-resource edges (from_uid, to_uid, rel_type)
- `inventory_drift` — Configuration change records between scans

---

## Stage 4: Threat Detection (engine_threat)

**Purpose:** Group related findings into threats, assign MITRE techniques, score risk.

**Trigger:** `POST /api/v1/threat/generate`

**What it does (5 sub-stages):**

### 4a. Metadata Enrichment
- JOINs `check_findings` with `rule_metadata` to get severity, MITRE mappings
- Groups findings by resource_uid

### 4b. Threat Detection
- Groups related findings into threat detections
- Each threat = one resource with multiple failing checks
- Aggregates MITRE techniques from all findings for that resource
- Assigns threat category (misconfiguration, exposure, etc.)
- Calculates confidence based on finding consistency

### 4c. Threat Analysis (Risk Scoring)
- For each threat detection, computes:
  ```
  risk_score = severity_weight × 40
             + blast_radius_factor × 25
             + mitre_impact_score × 25
             + reachability_bonus × 10
  ```
- Builds attack chains (resource → related resources)
- Generates recommendations
- Assigns verdict: critical_action_required / high_risk / medium_risk / low_risk / informational

### 4d. Storage
- Saves to `threat_report`, `threat_detections`, `threat_findings`, `threat_analysis`

### 4e. Intel Correlation (optional)
- Cross-references threat detections with `threat_intelligence` entries
- Matches by MITRE technique overlap

**Output:**
- `threat_report` — Scan-level summary (total threats, by severity, by category)
- `threat_detections` — Individual threats (resource, severity, MITRE techniques)
- `threat_findings` — Links threats to underlying check findings
- `threat_analysis` — Risk scores, verdicts, recommendations, attack chains

**Data volume:** ~21 threats from 764 check findings (typical)

---

## Stage 5: Compliance Reporting (engine_compliance)

**Purpose:** Map check findings to compliance framework controls.

**Trigger:** `POST /api/v1/compliance/generate`

**What it does:**
1. Loads check findings from DB
2. Loads framework definitions (CIS AWS, NIST 800-53, SOC 2, etc.)
3. Maps each rule to framework controls via rule_metadata mappings
4. Calculates compliance scores per control, per domain, per framework
5. Generates executive summary, resource drilldowns, trend data
6. Exports as JSON, PDF, or Excel

**Output:**
- `compliance_reports` — Full compliance report
- `compliance_scores` — Scores per framework/control
- `compliance_findings` — Links findings to controls
- `compliance_trends` — Historical score tracking

**Frameworks supported:** CIS AWS Benchmark, NIST 800-53, SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, AWS Well-Architected

---

## Stage 6: Security Graph (engine_threat → Neo4j)

**Purpose:** Build a graph database for attack path analysis and threat hunting.

**Trigger:** `POST /api/v1/graph/build`

**What it does:**
1. Reads all data from PostgreSQL (3 databases):
   - Resources from inventory
   - Threats from threat_detections
   - Findings from check_findings
   - Relationships from inventory_relationships
2. Creates Neo4j nodes:
   - Virtual: Internet, Account, Region
   - Resources: S3Bucket, IAMRole, IAMPolicy, SecurityGroup, etc.
   - ThreatDetection nodes
   - Finding nodes
3. Creates relationships:
   - CONTAINS (Account → Resource), HOSTS (Region → Resource)
   - HAS_THREAT (Resource → Threat), HAS_FINDING (Resource → Finding)
   - EXPOSES (Internet → Resource — for internet-facing resources)
   - RELATES_TO, REFERENCES (resource-to-resource)
4. Infers internet exposure from security group rules (0.0.0.0/0)

**Output:**
- Neo4j graph: ~1,855 nodes, ~2,132 relationships (typical)
- Enables: attack path queries, blast radius, toxic combinations, threat hunting

---

## Trigger Methods

### Manual (API)
Each stage can be triggered individually via its API endpoint.

### Orchestrated (API Gateway)
```
POST /gateway/orchestrate
```
Triggers the full pipeline in sequence.

### Scheduled (Onboarding Engine)
CRON-based schedules trigger scans automatically:
```json
{
  "schedule": "0 2 * * *",
  "pipeline": ["discovery", "check", "inventory", "threat", "compliance", "graph"]
}
```

### Auto-chained (Threat Engine)
When `POST /api/v1/threat/generate` is called, it automatically:
1. Reads check findings from DB
2. Runs threat detection
3. Runs threat analysis (risk scoring)
4. Stores everything
5. Returns combined results

---

## Database Dependencies

```
                    ┌──────────────────┐
                    │  discovery_scans  │
                    │ discovery_findings│
                    └────────┬─────────┘
                             │ (scan_run_id)
                    ┌────────▼─────────┐
                    │  check_scans     │
                    │  check_findings  │◄──── rule_metadata
                    └────────┬─────────┘
                             │ (scan_run_id)
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼───────┐ ┌───▼──────┐ ┌─────▼──────┐
     │ inventory_     │ │ threat_  │ │ compliance_│
     │ findings       │ │ report   │ │ reports    │
     │ inventory_     │ │ threat_  │ │ compliance_│
     │ relationships  │ │ detections│ │ scores    │
     └────────────────┘ │ threat_  │ └────────────┘
                        │ findings │
                        │ threat_  │
                        │ analysis │
                        └───┬──────┘
                            │
                       ┌────▼────┐
                       │  Neo4j  │
                       │  Graph  │
                       └─────────┘
```

---

## Timing (Typical)

| Stage | Duration | Data Volume |
|-------|----------|-------------|
| Discovery | 2-5 min | 280+ resources |
| Check | 30-60 sec | 764 findings |
| Inventory | 15-30 sec | 280 assets, 300+ relationships |
| Threat Detection | 5-10 sec | 21 threats |
| Threat Analysis | 2-5 sec | 21 analyses with risk scores |
| Compliance | 10-30 sec | 7 framework reports |
| Graph Build | 3-5 min | 1,855 nodes, 2,132 relationships |
| **Total** | **~8-12 min** | End-to-end pipeline |
