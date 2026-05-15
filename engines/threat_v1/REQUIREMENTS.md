# Threat Detection Engine v1 — Requirements & Proposed Solution

**Status:** Draft — Pending Review  
**Author:** Engineering (via design session 2026-05-10)  
**Location:** `engines/threat_v1/`  
**Replaces:** `engines/threat/` (existing engine — kept live until v1 validated)

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [What We Are Building](#2-what-we-are-building)
3. [Data Sources](#3-data-sources)
4. [Graph Model](#4-graph-model)
5. [Pattern System](#5-pattern-system) — incl. 5.5 Authoring Workflow
6. [Target Definition — Crown Jewels](#6-target-definition--crown-jewels)
7. [MITRE Coverage Analysis](#7-mitre-coverage-analysis)
8. [Detection Tiers](#8-detection-tiers) — 3-state CDR grading (posture/suspicious/active)
9. [Incident Model](#9-incident-model) — incl. 9.4 Lifecycle SM, 9.5 Roll-up, 9.6 Evidence Schema
10. [Pipeline Triggers](#10-pipeline-triggers)
11. [Technical Decisions](#11-technical-decisions) — incl. 11.1 Concurrency, 11.2 Perf Budgets, 11.3 Failure Modes
12. [Existing Threat Table Migration Plan](#12-existing-threat-table-migration-plan)
13. [What Is Missing Today — Gaps](#13-what-is-missing-today--gaps) — incl. v1 explicit limitations
14. [Build Plan — Phases](#14-build-plan--phases)
15. [Decisions Log (Resolved)](#15-decisions-log-resolved)
16. [External Contracts — REST API](#16-external-contracts--rest-api)
17. [Security Architecture Review — Findings & Decisions](#17-security-architecture-review--findings--decisions)

---

## 1. Problem Statement

### What the Existing Threat Engine Does

The current `engines/threat/` engine:
- Reads `check_findings` (FAIL/WARN) from the Check engine
- Groups findings by `(threat_type, resource_uid, account, region)`
- Produces one `threat_detection` row per group
- Computes a risk score using: `severity×40 + blast_radius×25 + MITRE_impact×25 + reachability×10`
- Writes results to `threat_report`, `threat_findings`, `threat_detections`, `threat_analysis`
- Builds a Neo4j graph independently (separate Argo step post-scan)

### What It Cannot Do

| Capability | Current State |
|---|---|
| Attack path chains (multi-hop) | BFS/DFS exists in `threat_analyzer.py` but not connected to Neo4j |
| CDR correlation | `CDRReader` class exists but never called by threat engine |
| Active vs. passive incident distinction | No `incident_class` field — all detections are posture |
| Tactic chain pattern matching | No pattern registry, no tactic sequence validation |
| Real-time escalation when CDR actor observed | Not implemented |
| `on_attack_path` property on graph nodes | Does not exist anywhere |
| Crown jewel classification | No `is_crown_jewel` flag on resource nodes |
| 3-tier detection (toxic combo / partial / full path) | Tier 1 partially via `toxic_combinations()` query; Tier 2 and 3 absent |
| Pattern library with test cases | 47 ad-hoc Cypher queries in DB; no YAML, no positive/negative tests |
| Vuln findings in graph | `CVELoader` exists but guarded by optional env var, not reliably active |
| CDR events as graph nodes | Not implemented |

### Why This Matters

A CSPM platform that only detects posture misconfigurations is a configuration scanner.  
A threat detection platform detects **attack paths** — the sequence of conditions that allows an adversary to move from an entry point to a high-value target.

The gap: we have all three signal types (misconfig + vuln + CDR behavior) but they are never combined into a unified graph that answers: **"Is an attacker actively exploiting this path right now?"**

---

## 2. What We Are Building

A new threat detection engine (`threat_v1`) that:

1. **Resolves resources** across all three signal sources using `resource_uid + tenant_id + account_id`
2. **Builds a unified graph** in Neo4j — every cloud resource as a node, security relationships as edges, findings (misconfig, CVE, CDR) attached as finding nodes
3. **Applies declarative YAML patterns** to detect three tiers of threats:
   - Tier 1: Single-node toxic combinations (no path traversal needed)
   - Tier 2: Partial attack paths (chain forming, early warning)
   - Tier 3: Complete attack paths from entry point to crown jewel
4. **Overlays CDR signals** to escalate posture incidents to active incidents when a real actor is observed on a known attack path
5. **Produces prioritized incidents** with full kill-chain context, evidence, and recommended actions
6. **Maps everything to MITRE ATT&CK Cloud Matrix** — technique IDs are first-class, never optional

### Design Principles

1. Patterns are declarative YAML — no Python code inside pattern definitions
2. YAML is the source of truth; Postgres is the runtime copy (same as check rules)
3. Every pattern ships with a positive test case and a negative test case
4. Tactic chains drive pattern structure — the chain is the story, the pattern is the instantiation
5. Crown jewels are explicitly classified — a target must be declared, not inferred
6. Incidents deduplicate across tiers — one resource, one incident, escalating in place
7. The engine is built independently and validated before replacing `engines/threat/`

---

## 3. Data Sources

### 3.1 Signal Sources

The engine consumes three existing data streams. It does **not** create new scan jobs.

| Source | Database | Key Table | Join Key |
|---|---|---|---|
| CSPM Misconfigurations | `threat_engine_check` | `check_findings` | `resource_uid + tenant_id + account_id` |
| Vulnerability Findings | `threat_engine_vulnerability` (or vuln DB) | `scan_vulnerabilities` | `resource_uid + tenant_id + account_id` |
| CDR Behavioral Events | `threat_engine_cdr` | `cdr_findings` | `resource_uid + tenant_id` (actor via `actor_principal`) |
| Inventory / Relationships | `threat_engine_inventory` | `resource_inventory` + `resource_security_relationship_rules` | `resource_uid + tenant_id` |

### 3.2 Resource Resolution

The graph builder uses the **scan with the most findings per engine per tenant** — not the latest scan by timestamp. A scan that failed midway may be newer but have far fewer findings and produce a sparse, misleading graph.

```sql
-- Best check scan per tenant (most findings)
SELECT scan_run_id FROM check_findings
WHERE tenant_id = :tenant_id AND account_id = :account_id
GROUP BY scan_run_id
ORDER BY count(*) DESC
LIMIT 1;

-- Best vuln scan per tenant (most findings)
SELECT scan_run_id FROM scan_vulnerabilities
WHERE tenant_id = :tenant_id AND account_id = :account_id
GROUP BY scan_run_id
ORDER BY count(*) DESC
LIMIT 1;

-- Best CDR scan per tenant (most findings)
SELECT scan_run_id FROM cdr_findings
WHERE tenant_id = :tenant_id
GROUP BY scan_run_id
ORDER BY count(*) DESC
LIMIT 1;
```

Resources are joined by `resource_uid`. If a resource appears in inventory but has no findings, it still enters the graph — it may be part of a path even if clean.

**Cross-CSP note:** For multi-CSP tenants (AWS + Azure + GCP), run the resolution query per `(tenant_id, account_id)` pair, then union all results. Each CSP will have its own best scan_run_id.

### 3.3 MITRE Tagging State (Current Reality)

From actual catalog analysis (2026-05-10):

| CSP | MITRE-Tagged Rules | Total Metadata YAMLs | Coverage |
|---|---|---|---|
| AWS | 507 | 2,512 | 20% |
| Azure | 190 | 1,959 | 10% |
| GCP | 164 | 1,424 | 12% |
| K8s | 91 | 926 | 10% |
| OCI | 95 | 2,154 | 4% |
| IBM | 98 | 613 | 16% |
| AliCloud | 22 | 1,541 | 1% |

**Per-subcategory breakdown (AWS — most mature CSP):**

| Rule Group | Tagged | Total | Coverage | Critical Gap |
|---|---|---|---|---|
| CDR / CIEM rules | 100% | ~180 | ✅ Complete | None |
| aws_rule_metadata/paas (cloudtrail events) | 100% | 29 | ✅ Complete | None |
| aws_rule_metadata/iam | 26% | 182 | ⚠️ Partial | 133 rules untagged (root_mfa_enabled → T1078.004, allows_privilege_escalation → T1548) |
| aws_rule_metadata/s3 | 13% | 76 | ❌ Critical | 66 rules untagged (block_public_access → T1530, cross_account_replication → T1537) |
| aws_rule_metadata/ec2 | **0%** | 181 | ❌ Critical | ALL 181 rules untagged (imdsv2 → T1552.005, ssh_access → T1021.004, internet ingress → T1190) |
| Vulnerability findings | **0%** | — | ❌ Structural gap | `scan_vulnerabilities` has no `mitre_technique` column; `cve_attack_mappings` table exists but NVD parser doesn't populate it; DDL has broken extra-comma bug |

**~80% of rule_metadata YAMLs have no MITRE tag.** The EC2 group (181 rules) is 0% tagged — this is the single highest-value gap because EC2 is the most common attack entry point.  
Phase 0 of the build plan addresses this before pattern writing begins.

---

## 4. Graph Model

### 4.1 Node Types

#### Resource Node (one per cloud resource)

```
(:Resource {
    resource_uid:        string   -- primary key, stable across scans
    resource_type:       string   -- EC2Instance, S3Bucket, IAMRole, etc.
    tenant_id:           string
    account_id:          string
    region:              string
    provider:            string   -- aws, azure, gcp, k8s, oci

    -- Aggregated boolean flags (set by graph builder from finding data)
    -- Used for fast Tier 1 matching without graph traversal
    internet_exposed:    bool     -- from exposure_loader
    has_critical_cve:    bool     -- any CVE with CVSS >= 9.0
    has_high_misconfig:  bool     -- any check_finding FAIL with severity >= HIGH
    is_admin_role:       bool     -- IAM admin policy attached
    is_crown_jewel:      bool     -- see Section 6
    cdr_actor_seen:      bool     -- any CDR event observed on this resource
    on_attack_path:      bool     -- SET by PathTagger after Tier 3 match
})
```

Labels applied by resource_type (examples):
`EC2Instance`, `S3Bucket`, `IAMRole`, `RDSInstance`, `LambdaFunction`,
`KMSKey`, `SecretsManagerSecret`, `EKSCluster`, `ServiceAccount`, `VPC`

#### Finding Nodes (attached to Resource nodes)

```
(:MisconfigFinding {
    finding_id:       string   -- sha256 stable ID
    rule_id:          string   -- e.g. aws-ec2-imdsv1-enabled
    severity:         string   -- critical/high/medium/low
    title:            string
    mitre_techniques: list     -- from rule_metadata
    mitre_tactics:    list
    status:           string   -- FAIL/WARN
})
Edge: (:Resource)-[:HAS_MISCONFIG]->(:MisconfigFinding)

(:VulnFinding {
    cve_id:           string   -- CVE-2024-xxxx
    cvss_score:       float
    epss_score:       float    -- exploit probability
    has_known_exploit: bool
    mitre_technique:  string   -- inferred: CVSS>=9 + network AV = T1190
    package:          string
    fixed_version:    string
})
Edge: (:Resource)-[:HAS_CVE]->(:VulnFinding)

(:CDREvent {
    finding_id:       string
    actor_principal:  string   -- alice@corp.com / arn:aws:iam::xxx:role/xxx
    mitre_technique:  string   -- T1580, T1078.004, T1530, etc.
    mitre_tactic:     string
    event_time:       datetime
    source_ip:        string
    action:           string   -- ListBuckets, GetSecretValue, etc.
    anomaly_score:    float
})
Edge: (:Resource)-[:TRIGGERED_ON]->(:CDREvent)
Edge: (:CDRActor)-[:PERFORMED]->(:CDREvent)

(:CDRActor {
    actor_id:         string   -- actor_principal (normalized)
    tenant_id:        string
    last_seen:        datetime
    on_attack_path:   bool     -- SET when actor touches on_attack_path resource
})
```

### 4.2 Security Edge Types

From `resource_relationship_rules` (inventory engine table — 369 active rules total; 22 have `attack_path_category` set, 19 have NULL / non-attack-path category):

| Category | Edge Types |
|---|---|
| `exposure` (3) | `internet_connected`, `exposed_through`, `serves_traffic_for` |
| `lateral_movement` (6) | `allows_traffic_from`, `attached_to`, `connected_to`, `provides_image_to`, `routes_to`, `runs_on` |
| `privilege_escalation` (3) | `assumes`, `grants_access_to`, `has_policy` |
| `data_access` (4) | `backs_up_to`, `cached_by`, `replicates_to`, `stores_data_in` |
| `execution` (3) | `invokes`, `triggers`, `uses` |
| `data_flow` (3) | `publishes_to`, `resolves_to`, `subscribes_to` |
| Non-attack-path (19) | `authenticated_by`, `contained_by`, `depends_on`, `encrypted_by`, `manages`, etc. |

**Important:** `inventory_relationships` is the materialized edge table actually written to Neo4j — it stores `relation_type`, `from_uid`, `to_uid`, `attack_path_category`. The `resource_relationship_rules` table defines the extraction rules. The graph builder reads materialized edges from `inventory_relationships`, not from the rules table directly.

### 4.3 Node Design Rationale — Hybrid Model

**Why not just properties on Resource nodes?**

Option A (properties only):
```
Resource { has_critical_cve: true, internet_exposed: true }
```
- Fast Tier 1 matching
- Cannot answer: "which specific CVE?" or "which rule is failing?"

Option B (finding nodes only):
```
(Resource)-[:HAS_CVE]->(VulnFinding { cvss: 9.8, cve_id: "CVE-2024-xxx" })
```
- Full detail for evidence
- Slow Tier 1 (requires traversal)

**Decision: Hybrid (Option C)**
- Resource nodes carry aggregated boolean flags for fast Tier 1 filtering
- Finding nodes exist as separate nodes for Tier 2/3 evidence and detail queries
- Pattern matching uses flags for entry condition check; traverses to finding nodes for evidence collection

---

## 5. Pattern System

### 5.1 Tactic Chain = The Story Arc

A **tactic chain** is the abstract sequence of adversary goals:
```
Initial Access → Privilege Escalation → Collection
```

A **pattern** is the concrete instantiation of a tactic chain:
```
entry:  EC2Instance (internet_exposed=true, check rule aws-ec2-imdsv1-enabled failing)
edge:   assumes
pivot:  IAMRole (has_admin_policy=true)
edge:   stores_data_in
target: S3Bucket (is_crown_jewel=true)
```

The same tactic chain produces multiple patterns (different resource types, different CSPs).

### 5.2 Realistic Tactic Chain Enumeration

**Tactic partial order for cloud ATT&CK:**

- **START tactics** (chain entry point): `TA0001 Initial Access`, `TA0002 Execution` (insider)
- **TRANSIT tactics** (middle, 0 or more): `TA0002 Execution`, `TA0003 Persistence`, `TA0004 Privilege Escalation`, `TA0005 Defense Evasion`, `TA0006 Credential Access`, `TA0007 Discovery`, `TA0008 Lateral Movement`
- **END tactics** (chain terminus = where target lives): `TA0009 Collection`, `TA0010 Exfiltration`, `TA0040 Impact`

**Enumerated realistic chains (not all mathematical combinations):**

| Length | Chain | Example Pattern |
|---|---|---|
| 2-hop | IA → Collection | Public S3 direct read |
| 2-hop | IA → Exfiltration | Direct data transfer from entry |
| 2-hop | IA → Impact | Ransomware on public resource |
| 3-hop | IA → PrivEsc → Collection | EC2 → IAMRole → S3 (Capital One type) |
| 3-hop | IA → CredAccess → Collection | IMDSv1 → stolen creds → data |
| 3-hop | IA → LateralMov → Collection | Network hop → data store |
| 3-hop | IA → Execution → Impact | Exploit → run code → destroy/mine |
| 3-hop | IA → PrivEsc → Exfiltration | Role assumption → data dump |
| 4-hop | IA → Exec → PrivEsc → Collection | Exploit → run → elevate → steal |
| 4-hop | IA → CredAccess → LateralMov → Collection | Creds → hop → steal |
| 4-hop | IA → PrivEsc → LateralMov → Exfil | Elevate → move → exfil |
| 4-hop | IA → Persist → CredAccess → Collection | Backdoor → creds → steal |
| 5-hop | IA → Persist → PrivEsc → DefEvasion → Exfil | APT-style full chain |
| 5-hop | IA → Exec → LateralMov → PrivEsc → Collection | Container escape pattern |

**~20–25 unique tactic chains × instantiated per CSP × resource type = 60–100 patterns total.**

### 5.3 YAML Pattern Schema

Every pattern is one YAML file. The schema is the contract.

**⚠️ Security constraint (CP1-01):** All runtime values derived from pattern fields — `resource_types`, `check_rules_failing`, `edge_type`, `entry_type`, condition values — MUST be passed as Neo4j `$parameter` bindings in compiled Cypher. No string interpolation or f-string concatenation into Cypher strings is permitted. The PatternCompiler must be implemented as a parameterized template expander, not a string builder. CI gate enforces this with a Cypher parameterization linter. Violation example:

```python
# WRONG — injectable via malicious YAML
cypher = f"MATCH (r:Resource {{resource_type: '{entry_type}', tenant_id: $tid}})"

# CORRECT — all values as $params
cypher = "MATCH (r:Resource {resource_type: $entry_type, tenant_id: $tid})"
session.run(cypher, entry_type=entry_type, tid=tenant_id)
```

```yaml
# Full pattern schema (all fields)

id: PAT-AWS-001                          # Unique, stable pattern ID
version: 1                               # Increment on any meaningful change
deprecated_at: null                      # ISO datetime when this pattern is retired
description: >
  Replicates Capital One 2019 breach pattern. Public EC2 with IMDSv1
  enabled can leak IAM role credentials via SSRF, granting admin access
  to S3 buckets containing sensitive data.

tier: 3                                  # 1 / 2 / 3
severity_base: critical                  # critical / high / medium / low
confidence: confirmed                    # confirmed / theoretical / emerging

# MITRE coverage
mitre_tactics:      [TA0001, TA0006, TA0009]
mitre_techniques:   [T1190, T1552.005, T1530]
tactic_chain_order: [initial_access, credential_access, collection]

# CSP scope
csps: [aws]                              # [aws] / [azure] / [all] etc.

# Reference material
breach_reference: "Capital One 2019"
stratus_technique: "aws.credential-access.ec2-get-user-data"

# ── Structural definition ────────────────────────────────────────────
entry:
  node_type: Resource
  resource_types: [EC2Instance]
  conditions:
    internet_exposed: true
    check_rules_failing:                 # must match rule_id in check_findings
      - aws-ec2-imdsv1-enabled
      - aws-ec2-public-sg-ingress        # OR — any one qualifies

hops:
  - edge_type: assumes                   # from resource_security_relationship_rules
    target:
      node_type: Resource
      resource_types: [IAMRole]
      conditions:
        is_admin_role: true
        check_rules_failing:
          - aws-iam-role-admin-policy-attached

target:
  node_type: Resource
  resource_types: [S3Bucket, DynamoDBTable, RDSInstance]
  conditions:
    is_crown_jewel: true                 # see Section 6 for classification

# Tier 2 fires when this many hops are present (even if target not reached)
min_hops_for_tier2: 2

# ── CDR overlay (what escalates posture → active incident) ───────────
cdr_watch:
  techniques:     [T1552.005, T1580, T1530, T1567]
  window_minutes: 30
  min_coverage:   0.6                    # 60% of techniques must appear
  tactic_order_required: true            # tactics must appear in chain order

# ── Scoring overrides ────────────────────────────────────────────────
scoring:
  posture_severity:  high                # severity when no CDR match
  active_severity:   critical            # severity when CDR match fires
  path_length_bonus: true                # longer paths score higher

# ── Test cases (mandatory before pattern ships) ──────────────────────
tests:
  positive:
    description: "EC2 with IMDSv1 + admin IAMRole + S3 PII bucket in graph"
    stratus_ref:  "aws.credential-access.ec2-get-user-data"
    expected_tier: 3
    expected_severity: high              # posture (no CDR)
  positive_active:
    description: "Same graph + CDR events T1552.005 + T1530 within 30min"
    expected_tier: 3
    expected_severity: critical          # active (CDR match)
  negative:
    description: "EC2 with IMDSv2 enforced, no admin role"
    expected_tier: null                  # must NOT fire
```

### 5.4 Pattern Storage Flow

Note: `pattern_version` from the YAML is snapshotted into `threat_incidents.pattern_version` and `evidence.matched_patterns[].pattern_version` at incident creation time. This ensures every incident is reproducible — you know exactly which pattern version fired.



```
catalog/threat_patterns/{tier}/{csp}/pat-xxx.yaml   ← SOURCE OF TRUTH (git)
                │
                │ upload_scenario_patterns.py (at engine startup)
                ▼
threat_scenario_patterns (Postgres, threat_v1 DB)   ← RUNTIME COPY
                │
                │ PatternRegistry.load_active_patterns()
                ▼
PatternCompiler.compile(pattern) → parameterized Cypher
                │
                ▼
Neo4j execution
```

Same approach as check rules: YAML in git, loaded to DB, executed from DB.

### 5.5 Pattern Authoring Workflow

Patterns are authored as YAML, reviewed via PR, and validated by CI before merge. The workflow mirrors how check rules are authored today.

```
1. Engineer creates pattern:
     catalog/threat_patterns/{tier}/{csp}/PAT-{CSP}-{NNN}.yaml

2. Local validation (CLI at engines/threat_v1/cli/):
     threat-v1 pattern validate <path>   # Pydantic schema check
     threat-v1 pattern compile <path>    # Cypher generation (dry-run)
     threat-v1 pattern test <path>       # positive + negative test cases

3. PR submitted — CI runs automatically:
     - YAML schema validation (Pydantic models)
     - Cypher parameterization linter: rejects any compiled Cypher containing string-interpolated pattern values (CP1-01)
     - Cypher compilation against Neo4j test fixture
     - tenant_id filter presence check: all compiled Cypher must contain `$tid` or `$tenant_id` parameter (CP1-01)
     - MITRE technique ID validation (against ATT&CK catalog)
     - Positive test fires on fixture graph within tier latency budget
     - Negative test does NOT fire on fixture graph
     - Pattern deprecation check (if version bumped, old version stays readable)

4. Review gates (both mandatory):
     - Detection engineer sign-off
     - Security architect review for any new tactic chain (ATT&CK + D3FEND check)

5. Merge → upload_scenario_patterns.py runs at engine startup:
     YAML loaded to threat_scenario_patterns table
     pattern_version column updated from YAML
```

Patterns that fail CI cannot merge. Patterns that fail the security architect gate are blocked regardless of CI status.

---

## 6. Target Definition — Crown Jewels

A **crown jewel** is any resource that an attacker's final goal is to reach.  
Every Tier 3 pattern terminates at a crown jewel. The classification is set on the Resource node as `is_crown_jewel=true` by the graph builder.

### 6.1 Crown Jewel Source — `resource_inventory_identifier`

The inventory engine already classifies every cloud resource type via the `resource_inventory_identifier` table. This is the authoritative source for crown jewel classification. Do not hardcode resource type lists.

Relevant columns:
- `asset_category`: `secrets`, `data_store`, `identity`, `compute`, `network`, `messaging`, `monitoring`, `deployment`, `governance`
- `category` (15 values): `compute`, `container`, `database`, `storage`, `network`, `edge`, `security`, `identity`, `encryption`, `monitoring`, `management`, `messaging`, `analytics`, `ai_ml`, `iot`
- `access_pattern`: `public`, `private`, `internal`

Crown jewel SQL (join against `inventory_findings` for criticality/environment):
```sql
SELECT DISTINCT
    i.resource_uid,
    i.resource_type,
    i.account_id,
    i.tenant_id,
    rii.asset_category,
    rii.access_pattern,
    inv_f.criticality,
    inv_f.environment,
    inv_f.risk_score
FROM resource_inventory i
JOIN resource_inventory_identifier rii
    ON rii.provider = i.provider
    AND rii.service  = i.service
    AND rii.resource_type = i.resource_type
LEFT JOIN inventory_findings inv_f
    ON inv_f.resource_uid = i.resource_uid
    AND inv_f.tenant_id   = i.tenant_id
WHERE i.tenant_id = :tenant_id
  AND (
    rii.asset_category IN ('secrets', 'data_store', 'identity')   -- category-based
    OR rii.access_pattern = 'public'                               -- publicly accessible
    OR inv_f.criticality = 'critical'                              -- manually marked critical
    OR (inv_f.environment = 'production'
        AND inv_f.risk_score >= 80)                                -- high-risk prod resource
  );
```

### 6.2 Crown Jewel Categories

| Crown Jewel Category | `asset_category` Match | Additional Condition | Example Resource Types |
|---|---|---|---|
| **Secret Stores** | `secrets` | None — all secrets stores qualify by definition | SecretsManagerSecret, ParameterStoreSecureString, AzureKeyVault, GCPSecretManager |
| **Sensitive Data Stores** | `data_store` | DataSec tags PII/PCI/PHI/financial, OR `access_pattern=public`, OR `criticality=critical` | S3Bucket, RDSInstance, DynamoDB, BigQueryDataset, AzureBlob |
| **Identity Crown Jewels** | `identity` | IAM engine: admin policy (`*:*`) attached | IAMRole, AzureServicePrincipal, GCPServiceAccount, UserPool |
| **Customer-Tagged** | any | `inventory_findings.tags` contains `crown_jewel=true` | Any resource explicitly tagged by customer |
| **High-Risk Production** | any | `environment=production` AND `risk_score >= 80` | Any high-risk prod asset |

### 6.3 Crown Jewel Classification Logic (Graph Builder)

```python
def is_crown_jewel(
    resource_uid: str,
    rii_row: dict,        # row from resource_inventory_identifier
    inv_finding: dict,    # row from inventory_findings (may be None)
    iam_flags: dict,      # from IAM engine findings
) -> bool:
    asset_category  = rii_row.get("asset_category", "")
    access_pattern  = rii_row.get("access_pattern", "")
    criticality     = (inv_finding or {}).get("criticality", "")
    environment     = (inv_finding or {}).get("environment", "")
    risk_score      = (inv_finding or {}).get("risk_score", 0) or 0
    tags            = (inv_finding or {}).get("tags") or {}

    # Customer-explicit override
    if tags.get("crown_jewel") == "true":
        return True

    # Secret stores — always crown jewels
    if asset_category == "secrets":
        return True

    # Data stores — crown jewel when sensitive or public
    if asset_category == "data_store":
        if access_pattern == "public" or criticality == "critical":
            return True
        if environment == "production" and risk_score >= 80:
            return True

    # Identity — only admin roles
    if asset_category == "identity":
        if iam_flags.get("has_admin_policy") or iam_flags.get("has_star_star_policy"):
            return True

    # High-risk production resource (any category)
    if environment == "production" and risk_score >= 80:
        return True

    return False
```

### 6.4 Customer-Defined Crown Jewels

Customers can manually tag resources as crown jewels via API:
```
POST /api/v1/crown-jewels
{ "resource_uid": "arn:aws:s3:::prod-customer-data", "reason": "production PII store" }
```
This sets `is_crown_jewel=true` in the graph and persists to `threat_crown_jewels` table.

---

## 7. MITRE Coverage Analysis

### 7.1 Current Tactic Coverage (AWS — most mature CSP)

| Tactic | ATT&CK ID | AWS Rules | Top Technique | Pattern Relevance |
|---|---|---|---|---|
| Defense Evasion | TA0005 | 116 | T1562.001 (disable tools) | Transit tactic |
| Persistence | TA0003 | 62 | T1098.003 (add cloud role) | Transit + CDR watch |
| Discovery | TA0007 | 54 | T1087.004 (cloud account enum) | CDR-only signal |
| Initial Access | TA0001 | 49 | T1190 (exploit public app) | Entry point |
| Execution | TA0002 | 48 | T1651 (cloud admin command) | Transit tactic |
| Privilege Escalation | TA0004 | 45 | T1098.003 | Key pivot tactic |
| Impact | TA0040 | 38 | T1485 (data destruction) | End tactic |
| Exfiltration | TA0010 | 37 | T1537 (transfer to cloud) | End tactic |
| Lateral Movement | TA0008 | 34 | T1563.001 (cloud service session) | Transit tactic |
| Credential Access | TA0006 | 34 | T1552.005 (instance metadata) | Key pivot signal |
| Collection | TA0009 | 19 | T1530 (cloud storage) | End tactic |
| Command & Control | TA0011 | 12 | T1071 (app layer protocol) | CDR-only |

### 7.2 Cross-CSP Coverage Gaps

| Tactic | AWS | Azure | GCP | K8s | OCI |
|---|---|---|---|---|---|
| initial_access | 49 | 16 | 13 | **0** | 11 |
| discovery | 54 | **1** | **1** | **0** | **1** |
| lateral_movement | 34 | 7 | 8 | 8 | **2** |
| collection | 19 | 7 | 12 | **1** | **1** |
| command_and_control | 12 | **0** | **0** | **0** | **0** |

**Critical gaps:** Discovery is nearly blind for non-AWS CSPs. K8s has zero initial_access rules. C2 detection is AWS-only.

### 7.3 Phase 0 — MITRE Tagging Priority List

Before patterns can be precise, the following rule groups need MITRE tags applied:

| Priority | Rule Group | Technique Family | Approx Count |
|---|---|---|---|
| P1 | Network exposure rules (SG, NACLs, public endpoints) | T1190, T1595 | ~200 rules |
| P1 | IAM over-privilege rules | T1078, T1548 | ~150 rules |
| P1 | CDR cloudtrail event rules | T1530, T1552, T1098 | ~100 rules |
| P2 | Data store encryption / access rules | T1530, T1537 | ~100 rules |
| P2 | Logging disable rules | T1562.007, T1562.008 | ~80 rules |
| P3 | K8s initial access rules | T1190, T1610 | ~50 rules |
| P3 | Non-AWS discovery rules | T1580, T1087 | ~40 rules |

Auto-tag heuristic (to accelerate):
- Rule domain `network_security` → T1190 / T1595 family
- Rule domain `identity_and_access_management` → T1078 family
- Rule domain `data_protection` → T1530 / T1537 family
- Rule domain `logging_monitoring_and_alerting` → T1562 family

---

## 8. Detection Tiers

### Tier 1 — Toxic Combination

**Definition:** A single resource (or 2-resource pair) where conditions are dangerous without needing a path.  
**Action:** Fix the resource configuration. No attacker needed.  
**Latency target:** < 10ms (flag-based matching, no graph traversal)

Examples:
- EC2 with `internet_exposed=true` AND `has_critical_cve=true` AND `is_admin_role=true`
- IAMRole with `has_admin_policy=true` AND MFA disabled AND `cdr_actor_seen=true`
- S3Bucket with `internet_exposed=true` AND `is_crown_jewel=true`

Produces: **posture incident**, `incident_class=posture`, severity up to HIGH.

### Tier 2 — Partial Attack Path

**Definition:** N of M required hops in a Tier 3 pattern are observed. Crown jewel not yet reachable.  
**Action:** Monitor + prepare. Could be coincidental misconfigs or early-stage intrusion.  
**Latency target:** < 500ms (limited graph traversal)

`min_hops_for_tier2` set per pattern (typically 2 of 3 required hops).

Produces: **early warning incident**, `incident_class=posture`, severity MEDIUM.

### Tier 3 — Full Attack Path

**Definition:** Complete chain confirmed from entry point to crown jewel.  
**Action:** Immediate remediation. Investigate for active attacker.  
**Latency target:** < 2s (full graph traversal)

**CDR signal grading within Tier 3:**

| CDR signal state | `incident_class` | Severity |
|---|---|---|
| 0 CDR signals on path | `posture` | HIGH |
| 1 CDR technique observed (below `min_coverage`) | `suspicious` | HIGH |
| ≥2 CDR techniques OR `cdr_watch.min_coverage` met | `active` | CRITICAL |

Active variant recommended actions: revoke session, disable actor, rotate credentials.

Produces: **threat incident**, escalatable from posture → suspicious → active.

---

## 9. Incident Model

### 9.1 `threat_incidents` Table (new — does not exist today)

```sql
CREATE TABLE threat_incidents (
    incident_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_id          VARCHAR(32) NOT NULL,         -- PAT-AWS-001
    tenant_id           VARCHAR(128) NOT NULL,
    account_id          VARCHAR(512),

    -- Detection classification
    tier                SMALLINT NOT NULL,             -- 1 / 2 / 3
    incident_class      VARCHAR(16) NOT NULL,          -- posture / suspicious / active
    severity            VARCHAR(16) NOT NULL,          -- critical/high/medium/low

    -- Pattern versioning (for reproducibility)
    pattern_version     SMALLINT NOT NULL DEFAULT 1,
    input_scan_runs     JSONB NOT NULL,                -- {check, vuln, cdr, inventory: scan_run_ids used}

    -- Scoring
    risk_score          SMALLINT,                      -- 0–100
    score_breakdown     JSONB,                         -- component scores

    -- Attack path
    entry_resource_uid  VARCHAR(512),
    attack_path         JSONB,                         -- ordered list of resource_uids
    target_resource_uid VARCHAR(512),

    -- MITRE
    mitre_tactics       JSONB,                         -- [TA0001, TA0006, TA0009]
    mitre_techniques    JSONB,                         -- [T1190, T1552.005, T1530]
    tactic_chain        JSONB,                         -- ordered chain

    -- Actor (CDR overlay)
    actor_principal     VARCHAR(512),                  -- alice@corp.com
    cdr_event_ids       JSONB,                         -- CDR finding IDs that fired

    -- Narrative
    story_text          TEXT,                          -- human-readable story
    evidence            JSONB,                         -- all supporting findings
    recommendations     JSONB,                         -- ordered action list

    -- Lifecycle
    status              VARCHAR(16) DEFAULT 'open',    -- open / acknowledged / resolved
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at         TIMESTAMPTZ,

    -- Dedup
    dedup_key           VARCHAR(256) GENERATED ALWAYS AS (
                            encode(sha256((pattern_id || '|' || tenant_id || '|' ||
                            COALESCE(entry_resource_uid,'') || '|' ||
                            COALESCE(target_resource_uid,''))::bytea), 'hex')
                        ) STORED
);

CREATE UNIQUE INDEX ON threat_incidents (dedup_key) WHERE status != 'resolved';
```

### 9.2 Deduplication Rules

| Scenario | Behavior |
|---|---|
| Same pattern fires twice on same resource | Update `last_seen_at`, do NOT create new incident |
| Tier 1 fires, then Tier 3 fires on same resource | Roll up into Tier 3 incident (higher tier wins) |
| Posture incident exists, 1st CDR technique fires | Escalate in-place: `incident_class → suspicious`, severity unchanged |
| Suspicious incident exists, 2nd CDR technique OR min_coverage met | Escalate in-place: `incident_class → active`, `severity → critical` |
| Same actor triggers multiple patterns | One incident per pattern (not per actor) |

### 9.3 Incident Story Template

Each pattern defines a `story_template`. The incident writer populates it:

```
Template: "Internet-exposed {entry_type} with critical CVE is granting 
           {pivot_type} admin credentials access to {target_name}. 
           {actor_line}"

Posture:   "Internet-exposed EC2Instance with critical CVE is granting 
           IAMRole admin credentials access to prod-pii-bucket."

Active:    "Internet-exposed EC2Instance with critical CVE is granting 
           IAMRole admin credentials access to prod-pii-bucket. 
           Actor alice@corp.com was observed performing T1552.005 
           (GetInstanceMetadata) and T1530 (GetObject × 847 calls) 
           within a 23-minute window."
```

### 9.4 Incident Lifecycle State Machine

Incidents move through explicit states. Transitions are evaluated at the start of each pipeline trigger run (Argo) and at each CDR update — not on a separate scheduler (no new cron infrastructure in v1).

```
States:
  new         — just created, not yet visible in UI
  open        — visible to customer, action required (no CDR signal)
  suspicious  — 1 CDR technique observed; monitoring
  active      — 2+ CDR techniques OR min_coverage met; immediate action
  resolved    — underlying findings fixed, no active CDR signals
  reopened    — previously resolved; same dedup_key fires again within 7 days

Transitions:
  new → open           on first detection (immediate)
  open → suspicious    first CDR technique observed on path
  suspicious → active  second CDR technique OR cdr_watch.min_coverage met
  suspicious → open    CDR signal expires (outside window_minutes), step back
  active → resolved    actor session terminated AND no CDR events for 24h
                       AND underlying check findings fixed
  open → resolved      all underlying check findings fixed
  resolved → reopened  same dedup_key fires within 7 days of resolution
```

`active → resolved` requires both conditions simultaneously. The check-findings-fixed condition is verified by querying the current check DB for the rules listed in the pattern's `entry.conditions.check_rules_failing`.

### 9.5 Multi-Pattern Roll-up

A single resource or path may match multiple patterns simultaneously. Without roll-up, a customer sees N alerts for one underlying problem.

**Roll-up key:** `(tenant_id, entry_resource_uid, target_resource_uid)`

Rules:
- All patterns matching the same roll-up key are grouped into ONE incident
- The incident uses the highest tier among matched patterns
- Severity = max severity across matched patterns
- `pattern_id` (primary key column) = the highest-tier pattern's ID
- All matched patterns recorded in `evidence.matched_patterns[]`
- Story text comes from the highest-tier pattern's template

**Tension with dedup_key:** The current `dedup_key` is `sha256(pattern_id|tenant_id|entry_uid|target_uid)` — it includes `pattern_id`, so each pattern would produce a unique incident without roll-up. The `IncidentWriter` must perform the roll-up BEFORE the dedup check: group by `(tenant_id, entry_uid, target_uid)` first, select the primary pattern, then compute dedup_key from that primary pattern.

Example:
```
Resource X matches:
  PAT-AWS-T1-007  (Tier 1, severity=HIGH)
  PAT-AWS-T2-003  (Tier 2, severity=HIGH)
  PAT-AWS-T3-001  (Tier 3, severity=CRITICAL)

Result: 1 incident
  tier = 3
  pattern_id = PAT-AWS-T3-001
  severity = critical
  evidence.matched_patterns = [PAT-AWS-T1-007, PAT-AWS-T2-003, PAT-AWS-T3-001]
```

### 9.6 Evidence JSONB Schema

The `evidence` field in `threat_incidents` is the contract between the threat engine and the UI/BFF. Changes are versioned via `evidence._schema_version`. `graph_query` is included only in the single-incident GET response — omit from list endpoints to avoid large payloads.

```json
{
  "_schema_version": 1,
  "misconfig_findings": [
    {
      "finding_id": "<sha256>",
      "rule_id": "aws-ec2-imdsv1-enabled",
      "severity": "high",
      "resource_uid": "<arn>",
      "mitre_techniques": ["T1552.005"]
    }
  ],
  "vuln_findings": [
    {
      "cve_id": "CVE-2024-xxxx",
      "cvss_score": 9.8,
      "epss_score": 0.87,
      "has_known_exploit": true,
      "resource_uid": "<arn>"
    }
  ],
  "cdr_events": [
    {
      "finding_id": "<sha256>",
      "actor_principal": "alice@corp.com",   // PII — RESTRICTED (see CP1-02 below)
      "mitre_technique": "T1530",
      "event_time": "2026-05-10T08:42:01Z",
      "action": "GetObject",
      "source_ip": "203.0.113.x",            // PII — RESTRICTED (see CP1-02 below)
      "anomaly_score": 0.91
    }
  ],
  "path_resources": [
    {"resource_uid": "<arn>", "resource_type": "EC2Instance", "position": 0, "role": "entry"},
    {"resource_uid": "<arn>", "resource_type": "IAMRole",     "position": 1, "role": "pivot"},
    {"resource_uid": "<arn>", "resource_type": "S3Bucket",    "position": 2, "role": "target"}
  ],
  "matched_patterns": [
    {"pattern_id": "PAT-AWS-T3-001", "pattern_version": 3, "match_timestamp": "2026-05-10T09:02:35Z"}
  ],
  "graph_query": "<cypher_with_bound_params — omitted in list views>"
}
```

**CP1-02 — Evidence field exposure by endpoint:**

| Field | `GET /incidents` (list) | `GET /incidents/{id}` (detail) | Permission required |
|---|---|---|---|
| `misconfig_findings` | ✅ Included | ✅ Included | `threat:read` |
| `vuln_findings` | ✅ Included | ✅ Included | `threat:read` |
| `cdr_events[].mitre_technique` | ✅ Included | ✅ Included | `threat:read` |
| `cdr_events[].actor_principal` | ❌ **Stripped** | ✅ Included | `cdr:sensitive` (in addition to `threat:read`) |
| `cdr_events[].source_ip` | ❌ **Stripped** | ✅ Included | `cdr:sensitive` |
| `cdr_events[].action` | ❌ **Stripped** | ✅ Included | `cdr:sensitive` |
| `path_resources` | ✅ Included | ✅ Included | `threat:read` |
| `matched_patterns` | ✅ Included | ✅ Included | `threat:read` |
| `graph_query` | ❌ **Stripped** | ✅ Included | `threat:read` |

Enforcement: two distinct Pydantic response models — `IncidentListItem` and `IncidentDetail`. The `IncidentDetail` endpoint additionally checks `cdr:sensitive` when `cdr_event_ids` is populated. Use `strip_sensitive_fields()` from shared auth (extend for this engine).

---

## 10. Pipeline Triggers

### 10.1 Trigger A — Full CSPM Argo Pipeline

Runs when: Discovery → Inventory → Check → Vuln all complete for a tenant.

```
Argo DAG step (after existing engines):
  name: threat-v1-scan
  inputs:
    parameters:
      - name: tenant_id
      - name: account_id
      - name: scan_run_id          # passed from orchestration
  container:
    image: yadavanup84/engine-threat-v1:v-threat-v1-phase1  # NEVER use :latest (CP1-08 / platform constitution)
    command: ["python", "-m", "run_scan"]
    args:
      - "--tenant-id={{ inputs.parameters.tenant_id }}"
      - "--account-id={{ inputs.parameters.account_id }}"
      - "--scan-run-id={{ inputs.parameters.scan_run_id }}"
```

### 10.2 Trigger B — CDR Argo CronWorkflow

Runs when: CDR scan completes (currently every 3 hours).

After CDR writes to `cdr_findings`, the CDR pipeline triggers threat-v1 with:
```
--mode=cdr-update          # graph builder only refreshes CDR nodes
--tenant-id=X              # re-runs pattern execution after update
--skip-graph-rebuild=false # full rebuild or incremental (configurable)
```

### 10.3 Execution Flow (Both Triggers)

```
run_scan.py
  │
  ├── 0. OWNERSHIP VALIDATION (CP1-07 — mandatory before any DB reads):
  │        SELECT 1 FROM scan_orchestration
  │        WHERE scan_run_id = :scan_run_id
  │          AND tenant_id   = :tenant_id
  │          AND account_id  = :account_id;
  │        If no row found: abort with logged error, do NOT proceed.
  │        Prevents Argo parameter tampering from triggering cross-tenant graph builds.
  │
  ├── 1. ResourceResolver.resolve(tenant_id, account_id)
  │        Load: inventory + check findings + vuln findings + CDR findings
  │        Join on: resource_uid + tenant_id + account_id
  │
  ├── 2. GraphBuilder.build_or_update(resources, findings)
  │        Upsert: Resource nodes + finding nodes + edges
  │        Set:    aggregated flags on Resource nodes
  │        Set:    is_crown_jewel on target nodes
  │
  ├── 3. PatternExecutor.run_all(tenant_id)
  │        Load patterns from threat_scenario_patterns (Postgres)
  │        Run Tier 1 → Tier 2 → Tier 3 in sequence
  │        PathTagger: SET on_attack_path=true on matched nodes
  │
  ├── 4. IncidentWriter.write(detections, tenant_id)
  │        Dedup by dedup_key
  │        Roll up Tier 1 → Tier 3 on same resource
  │        Escalate posture → active on CDR match
  │
  └── 5. Update threat_scan_runs status → completed
```

---

## 11. Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Graph DB | Neo4j (same existing Aura instance) | Already deployed; use named database `threat_v1` within it to avoid polluting existing graph during development |
| Database tables | New `_v1`-suffixed tables in existing `threat_engine_threat` DB | Simpler — no new connection config; migration to new DB deferred until v1 validated |
| Kafka / streaming | Not in v1; CDR is batch (3h) | Avoid Kafka dependency until CDR moves to real-time; pipeline trigger is sufficient |
| Redis for hot labels | Not in v1 | Pattern execution is scheduled; hot Redis lookup only needed for sub-second real-time path |
| Pattern storage | YAML first (source of truth, git) → Postgres (runtime, loaded at startup) | Same pipeline as check rules; YAML files committed to `catalog/threat_patterns/`; upload script pushes to `threat_scenario_patterns` table |
| Finding nodes vs properties | Hybrid | Aggregated flags on Resource for Tier 1 speed; finding nodes for Tier 2/3 evidence |
| Engine isolation | Separate `engines/threat_v1/` | Build and validate before replacing `engines/threat/`; both run in parallel during transition |
| Resource scan resolution | Pipeline: use passed `scan_run_id`; CDR trigger: most-findings query for non-CDR engines | See Section 3.2 — pipeline trigger provides scan_run_id directly; CDR trigger needs cross-engine resolution |
| API port | 8021 (8020 = existing threat engine) | Avoids conflict during parallel operation |

### 11.1 Concurrency Model

- **Per-tenant advisory lock** during graph build: `SELECT pg_advisory_lock(tenant_hash)` before graph build starts; released on completion or exception. Prevents two Argo steps from building the same tenant graph simultaneously.
- Pattern execution runs parallel across tenants, serialized within a tenant.
- Incident upserts use `ON CONFLICT (dedup_key) DO UPDATE` — safe for concurrent writes.
- **Trigger B (CDR) waits if Trigger A (full pipeline) holds the advisory lock** for the same tenant. Max wait: 5 minutes. If exceeded, Trigger B logs a warning and exits cleanly — it will retry on the next CDR cycle (3h).
- No Redis, no distributed lock manager needed in v1.

### 11.2 Performance Budgets

Per-tenant targets (Neo4j Aura, spot node, batch mode):

| Resource Count | Graph Build | Pattern Execution | Total Scan |
|---|---|---|---|
| < 1,000 resources | < 30s | < 10s | < 1min |
| 1,000–10,000 | < 5min | < 1min | < 10min |
| 10,000–100,000 | < 30min | < 10min | < 45min |

Per-pattern budget: median < 100ms, p99 < 500ms.  
Patterns exceeding the p99 budget for 3 consecutive runs are auto-quarantined: `active = false` in `threat_scenario_patterns` and flagged for engineering review.

### 11.3 Failure Modes

| Failure | Behavior |
|---|---|
| Neo4j unavailable at scan start | Fail fast, mark `threat_scan_runs_v1.status = failed`; Argo retries on next trigger |
| Postgres unavailable | Fail fast |
| Individual pattern execution error | Log + skip pattern + continue with remaining patterns; errors counted in per-pattern metrics |
| Pattern Cypher timeout | Skip pattern, count as timeout in metrics; triggers auto-quarantine if repeated |
| Argo workflow killed (SIGTERM / spot preemption) | Next trigger does full graph rebuild (all operations are idempotent via upsert) |
| Stale resource nodes (no findings, >90 days) | Nightly Argo CronWorkflow (shared with CDR infra) runs a reaper: deletes Resource nodes where `last_seen` < NOW() - 90 days and has no finding nodes attached |

---

## 12. Existing Threat Table Migration Plan

Investigation of the current `threat_engine_threat` DB tables (2026-05-10). All decisions are based on what the current engine actually writes vs. what v1 needs.

### 12.1 Table-by-Table Disposition

| Table | Action | Reason |
|---|---|---|
| `threat_findings` | **MIGRATE** | Missing standard columns: `credential_ref`, `credential_type` (top-level), `provider` as explicit column. `account_id` is `VARCHAR(50)` — must expand to `VARCHAR(512)` for OCI OCIDs. Keep existing data; migration adds columns. |
| `threat_finding_techniques` | **KEEP** | Clean junction table. Trigger correctly maintains it. No changes needed. |
| `threat_detections` | **MIGRATE** | Drop legacy `scan_id` column. Make `scan_run_id` type `UUID NOT NULL PRIMARY`. Keep narrative columns (`chain_of_consequence`, `stakes_narrative`) — they provide value. |
| `threat_report` | **MIGRATE** | Change `scan_run_id` column type from TEXT → UUID. Add `account_id` column. |
| `threat_reports` (plural) | **SUPERSEDE** | Not written by current `ThreatStorage` or `ThreatDBWriter`. Legacy blob store from an older version. Do NOT migrate data. New v1 writes only to `threat_report` (singular). |
| `mitre_technique_reference` | **KEEP** | 102 curated rows. Has `aws_checks`, `azure_checks`, `gcp_checks` JSONB columns confirmed. Migration `threat_mitre_technique_ref_001.sql` adds 9 new columns (parent_id, kill_chain_phases, d3fend_mappings, etc.) — already applied. Do not modify curated data. |
| `tenants` | **KEEP** | FK anchor for all engine tables. No changes. |
| `threat_analysis` | **KEEP** | Clean schema. `UNIQUE(detection_id, analysis_type)` constraint applied by migration 010. |
| `threat_intelligence` | **KEEP + FIX** | Useful reference table. Fix trailing-comma DDL bug in UNIQUE constraint before next migration. |
| `threat_hunt_queries` | **MIGRATE** | Add `UNIQUE(tenant_id, query_name)` constraint. Currently 77 queries seeded: 46 toxic_combination + 24 predefined_hunt + 7 Azure-specific. |
| `threat_hunt_results` | **KEEP** | Clean audit log. No changes needed. |

### 12.2 New Tables Required by v1

| New Table | Purpose | Defined In |
|---|---|---|
| `threat_incidents` | v1 incident store with dedup_key, tier, incident_class, CDR escalation | Section 9.1 |
| `threat_scenario_patterns` | Runtime copy of YAML patterns (source of truth = YAML files in `catalog/threat_patterns/`) | Section 5.4 |
| `threat_scan_runs_v1` | v1-specific scan run tracking (separate from main `scan_orchestration` to avoid coupling) | Phase 4 |

### 12.3 Vulnerability Engine Structural Gap

`scan_vulnerabilities` has **no MITRE technique column**. The `cve_attack_mappings` table exists in the vulnerability DB schema but:
- NVD parser does not populate it
- DDL has a broken extra-comma in the UNIQUE constraint: `UNIQUE(cve_id,,` — syntax error; table may never have functioned in production

**Resolution (Phase 0):**
1. Fix `cve_attack_mappings` DDL (remove extra comma)
2. Add `mitre_techniques JSONB` column to `scan_vulnerabilities`
3. Wire NVD parser: CVSS ≥ 9.0 + `attackVector=NETWORK` → tag T1190; known exploit + `attackVector=NETWORK` → T1190 + T1595.002
4. This is a heuristic — not perfect, but unblocks pattern P1 (internet-facing service with critical CVE)

---

## 13. What Is Missing Today — Gaps

### 13.1 Hard Blockers (must fix before patterns can fire accurately)

| Gap | Impact | Resolution |
|---|---|---|
| ~80% of rule_metadata YAMLs have no MITRE tag | Patterns cannot match check rules to techniques by ID | Phase 0: auto-tag 500 priority rules |
| CDR rules (`paas/cloudtrail` YAMLs) partially MITRE-tagged | CDR watch techniques in patterns cannot match CDR events | Phase 0: map each cloudtrail action to technique |
| Vuln findings have no MITRE technique field | T1190 cannot be inferred from CVE presence | Phase 0: heuristic — CVSS≥9 + network attack vector = T1190 |
| `on_attack_path` property does not exist in Neo4j | PathTagger has nowhere to write | Built in Phase 2 |
| `is_crown_jewel` flag does not exist on Resource nodes | Tier 3 cannot identify target nodes | Built in Phase 2 |
| `CDREvent` and `CDRActor` nodes do not exist in graph | CDR overlay for active incidents impossible | Built in Phase 2 |
| `threat_incidents` table does not exist | No place to write incidents | Built in Phase 4 |

### 13.1b v1 Explicit Limitations (known scope boundaries)

| Limitation | Impact | Planned Fix |
|---|---|---|
| **Cross-account attack paths** | v1 joins on `tenant_id + account_id` — an attack crossing accounts (Account A assumes role in Account B) is invisible | Phase 2 post-launch: cross-account path via `sts:AssumeRole` edge type |
| **Cross-cloud / federated identity paths** | AWS → Azure via OIDC federation, GitHub Actions → AWS prod are not detectable | Phase 3: cross-provider path via federated identity edges |
| **Cross-tenant** | Impossible by design (tenant isolation is non-negotiable) | N/A |

Real-world attacks that v1 cannot see: Capital One-style cross-account pivot, Azure AD → AWS via workload identity federation, CI/CD supply chain (GitHub Actions → prod AWS).

### 13.2 Soft Gaps (affects quality, not functionality)

| Gap | Impact | Resolution |
|---|---|---|
| K8s has zero initial_access rules | K8s attack path entry points blind | Backlog: add K8s initial access rules |
| Discovery tactic: Azure/GCP have 1 rule each | Non-AWS enumeration not detectable | Backlog: add discovery rules per CSP |
| No `FEDERATES` edge type in relationship rules | SSO/Federation pattern (PAT-SSO-001) cannot be built | Add edge type to `resource_security_relationship_rules` |
| No CI/CD node type in graph | Supply chain pattern cannot traverse CI/CD → prod | Add CI/CD resource types to inventory |
| Stratus Red Team not integrated | No automated positive test execution | Phase 6: validation framework |

---

## 14. Build Plan — Phases

### Phase 0 — MITRE Tagging (parallel with Phase 1, 1 week)

- Auto-tag top 500 priority rules using domain heuristic
- Manual review top 100 auto-tagged rules
- Map CDR cloudtrail event types to MITRE techniques
- Add CVE → T1190 heuristic in vuln finding loader

**Output:** ≥500 additional MITRE-tagged rules across all CSPs

### Phase 1 — Foundations (1 week)

| Step | Deliverable |
|---|---|
| 1.1 | Project structure + dependency manifest (`requirements.txt`, `pyproject.toml`) |
| 1.2 | Graph schema definition (node types, edge types, property contracts) |
| 1.3 | Pattern DSL specification (YAML schema + Pydantic validators) |
| 1.4 | Pattern loader (`upload_scenario_patterns.py` YAML → Postgres) |

### Phase 2 — Graph Build Layer (1.5 weeks)

| Step | Deliverable |
|---|---|
| 2.1 | `ResourceResolver` — cross-engine join with latest scan per engine |
| 2.2 | `GraphBuilder` — Resource nodes + aggregated flag logic |
| 2.3 | `MisconfigLoader` — check_findings → MisconfigFinding nodes |
| 2.4 | `VulnLoader` — scan_vulnerabilities → VulnFinding nodes |
| 2.5 | `CDRLoader` — cdr_findings → CDREvent + CDRActor nodes |
| 2.6 | `EdgeBuilder` — security edges from `resource_security_relationship_rules` |
| 2.7 | `CrownJewelClassifier` — sets `is_crown_jewel` flag |
| 2.8 | `PathTagger` — sets `on_attack_path=true` after pattern execution |

### Phase 3 — Pattern Execution Engine (1.5 weeks)

| Step | Deliverable |
|---|---|
| 3.1 | `GraphAdapter` interface (Neo4j implementation + test stub) |
| 3.2 | `PatternRegistry` — loads patterns from Postgres |
| 3.3 | `PatternCompiler` — YAML pattern → parameterized Cypher |
| 3.4 | `Tier1Matcher` — flag-based toxic combo detection |
| 3.5 | `Tier2Matcher` — partial path hop-coverage scoring |
| 3.6 | `Tier3Matcher` — full path detection + CDR overlay |
| 3.7 | `PatternExecutor` — orchestrates all three tiers |

### Phase 4 — Incident Management (1 week)

| Step | Deliverable |
|---|---|
| 4.1 | DB schema: `threat_incidents` + `threat_scan_runs` tables |
| 4.2 | `SeverityScorer` — configurable formula, auditable |
| 4.3 | `IncidentDeduper` — dedup_key collision detection + roll-up |
| 4.4 | `IncidentWriter` — upsert with escalation logic |
| 4.5 | `StoryBuilder` — populates story_text from pattern template |
| 4.6 | `run_scan.py` — full pipeline entry point |

### Phase 5 — Pattern Library v1 (2 weeks)

| Step | Deliverable |
|---|---|
| 5.0 | Coverage matrix baseline (ATT&CK × CSP × Tier) |
| 5.1 | 10 Tier 1 toxic combo patterns (AWS-first, then extend) |
| 5.2 | 10 Tier 2 partial path patterns |
| 5.3 | 10 Tier 3 full path patterns (mostly AWS where all three signals exist) |
| 5.4 | Security architect review gate on all 30 patterns (ATT&CK + STRIDE + D3FEND) |
| 5.5 | Coverage matrix final — explicit gap acceptance log for missing tactic chains |

**30 total patterns at quality bar** (positive + negative tests + security review) is the v1 target. Additional patterns ship in Phase 8 (post-v1). Do not compromise test coverage to hit a higher count.

### Phase 6 — Validation & Observability (1.5 weeks)

| Step | Deliverable |
|---|---|
| 6.1 | Pattern test harness (positive + negative case runner) |
| 6.2 | Per-pattern metrics: `fire_count`, `match_latency_ms`, `error_count`, `tp_count`, `fp_count` |
| 6.3 | Per-tenant metrics: `graph_build_duration_s`, `node_count`, `edge_count`, `pattern_execution_duration_s` |
| 6.4 | System metrics: `neo4j_query_latency_ms`, `postgres_advisory_lock_wait_ms`, `argo_step_failures` |
| 6.5 | FP feedback loop: `threat_incident_feedback` table (incident_id, verdict, reporter, tenant_id, notes, created_at) — INSERT-only, no UPDATE; immutable audit log |
| 6.6 | Auto-quarantine (CP1-05 — per-tenant, NOT global): patterns with rolling-30d FP rate > 30% per tenant → insert row into `threat_pattern_suppressions` (tenant-scoped suppression), NOT `active=false` on the shared pattern. Global deactivation of a pattern requires security architect approval + manual update. |
| 6.7 | Per-tenant pattern suppression: `threat_pattern_suppressions` table (tenant_id, pattern_id, reason, until, auto_generated) |
| 6.8 | Pattern catalog API: `GET /api/v1/patterns` |
| 6.9 | Coverage API: `GET /api/v1/coverage` (MITRE tactic × CSP × Tier heatmap) |
| 6.10 | Alerting rules: pattern budget exceeded, tenant SLA breached, FP rate > threshold |

### Phase 7 — Shadow Mode → Transition (2 weeks)

**Week 1 — Shadow mode (read-only, no customer alerts):**
- threat-v1 runs in the Argo pipeline alongside `engines/threat/`
- Writes to `_v1` tables only; zero customer-facing output
- Compare detection output between engines daily; log divergences
- Fix divergences before proceeding

**Week 2 — Parallel mode (both engines visible, clearly labeled):**
- Customer sees both engines' alerts with source tag (`threat-v1`)
- Collect customer feedback on threat-v1 incidents specifically
- Tune pattern thresholds and suppression rules based on feedback

**Gate to switchover (all must pass):**
- threat-v1 produces ≥ all existing detections (zero regression)
- threat-v1 rolling-30d FP rate < 30% across enabled patterns
- No P0/P1 bugs open longer than 7 days
- Customer NPS on new threat-v1 incidents ≥ neutral

**Switchover:**
- Replace `engines/threat/` in Argo DAG with `engines/threat_v1/`
- Migrate open incidents from old tables to new (one-time migration script)
- Old engine tables remain readable for 90 days, then archived
- Old engine image kept in ECR for rollback capability

---

## 15. Decisions Log (Resolved)

All 7 open questions from the design review have been resolved. Decisions recorded here for audit trail.

| Question | Decision | Rationale |
|---|---|---|
| **Q1** Database isolation | New `_v1`-suffixed tables in existing `threat_engine_threat` DB | Simpler — no new connection config. Migrate to standalone DB if v1 outgrows existing DB. |
| **Q2** Graph isolation | Same Neo4j Aura instance; named database `threat_v1` | Shared Aura avoids new credential/endpoint. Named database isolates v1 graph from existing production graph. |
| **Q3** Resource scan resolution | Pipeline trigger: use passed `scan_run_id`. CDR trigger: most-findings query for non-CDR engines. | Pipeline already passes the correct scan_run_id for CSPM engines. CDR trigger needs cross-engine resolution because CDR runs independently. (See Section 3.2) |
| **Q4** MITRE tagging target | Write to YAML files via PR (not a separate override table) | YAML is the source of truth; changes are auditable in git; no extra runtime table to maintain. |
| **Q5** Phase 0 sequencing | Parallel — start patterns while tagging continues | First 5 patterns use the 507 already-tagged AWS rules. Phase 0 unlocks more patterns but does not block the first batch. |
| **Q6** Tier count | 3 tiers is correct | Path length is a risk_score dimension, not a tier. Adding tiers adds complexity without operational clarity. |
| **Q7** Crown jewel classification | Use `resource_inventory_identifier.asset_category` + `access_pattern` + `inventory_findings.criticality/environment/risk_score` | Inventory engine already has this taxonomy. No new classification logic needed — join the existing tables. (See Section 6) |

---

## 16. External Contracts — REST API

Full OpenAPI spec at `engines/threat_v1/api/openapi.yaml` (generated from FastAPI routes).

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/api/v1/incidents` | `threat:read` | Returns `IncidentListItem` — strips CDR PII fields (CP1-02) |
| GET | `/api/v1/incidents/{id}` | `threat:read` + `cdr:sensitive` (if incident has CDR events) | Returns `IncidentDetail` with full evidence |
| POST | `/api/v1/incidents/{id}/feedback` | `threat:write` + `feedback:write` | INSERT-only; immutable audit log. Rate-limited: 10 verdicts/user/24h (CP1-05) |
| POST | `/api/v1/incidents/{id}/actions` | — | **HTTP 501 Not Implemented in v1.** Execution model undefined — returns guidance text only. Scoped to Phase 8 (CP1-04) |
| GET | `/api/v1/patterns` | `threat:read` | Active patterns (filtered by per-tenant suppression table) |
| GET | `/api/v1/patterns/{id}` | `threat:read` | Pattern detail: tactic chain, MITRE, tier, test cases |
| POST | `/api/v1/crown-jewels` | `threat:write` | **Ownership validation required (CP1-03):** `resource_uid` must exist in `resource_inventory WHERE tenant_id = auth_ctx.tenant_id`. Returns 404 if not found (avoids confirming foreign resource existence) |
| DELETE | `/api/v1/crown-jewels/{resource_uid}` | `threat:write` | Same ownership validation; writes audit row to platform audit_logs |
| GET | `/api/v1/scan/status/{job_id}` | `threat:read` | Async scan status polling |
| GET | `/api/v1/coverage` | `threat:read` | MITRE tactic × CSP × Tier heatmap |
| GET | `/api/v1/health/live` | none | Liveness probe |
| GET | `/api/v1/health/ready` | none | Readiness probe (checks Postgres + Neo4j) |

**No ad-hoc Cypher endpoint (CP1-06).** `POST /api/v1/hunt/execute` with a free-form `cypher` body is explicitly excluded from v1. All query access is through predefined pattern execution and the incidents REST API.

All endpoints require `Authorization: Bearer <access_token>` via `require_permission()` (same pattern as all engines).

Webhooks are **not in v1 scope**. There is no webhook delivery infrastructure. External integrations consume the REST API directly.

---

## 17. Security Architecture Review — Findings & Decisions

**Review date:** 2026-05-10  
**Reviewer:** Security Architect (STRIDE + PASTA + OWASP SAMM + NIST CSF 2.0)  
**Status:** 8 CP-1 blockers resolved in sections above. Warnings tracked below.

### 17.1 CP-1 Blockers (All Resolved in Requirements)

| ID | Finding | Resolution Location |
|---|---|---|
| CP1-01 | PatternCompiler Cypher injection: all pattern values must be `$param` bindings, never interpolated | Section 5.3 + Section 5.5 (CI linter gate) |
| CP1-02 | Evidence JSONB PII exposure: `cdr_events[].actor_principal`, `source_ip`, `action` stripped from list endpoint | Section 9.6 (field exposure table) |
| CP1-03 | Crown jewel ownership: `POST /api/v1/crown-jewels` must validate `resource_uid` belongs to auth tenant | Section 16 (endpoint table) |
| CP1-04 | Actions endpoint execution model undefined: returns HTTP 501 in v1; scoped to Phase 8 | Section 16 (endpoint table) |
| CP1-05 | FP auto-quarantine was global: changed to per-tenant suppression via `threat_pattern_suppressions` | Section 14 Phase 6 step 6.6 |
| CP1-06 | Ad-hoc Cypher endpoint excluded: no `POST /api/v1/hunt/execute` in v1 | Section 16 (explicit exclusion note) |
| CP1-07 | Scan trigger ownership check missing: Step 0 validates `(scan_run_id, tenant_id, account_id)` in `scan_orchestration` | Section 10.3 execution flow |
| CP1-08 | Argo template used `v-latest` image tag (platform constitution violation) | Section 10.1 (fixed to pinned tag) |

### 17.2 Warnings (Fix Before Ship — Non-Blocking)

| ID | Warning | Where to fix |
|---|---|---|
| W-01 | Advisory lock hash: use `hashtext(tenant_id \|\| '\|' \|\| account_id)` not tenant_id alone | Section 11.1 |
| W-02 | Neo4j query timeout: set `session.run(query, timeout=500)` on all pattern Cypher | Section 11.3 |
| W-03 | Pattern startup crash: `upload_scenario_patterns.py` must catch per-pattern errors, not crash engine startup | Section 14 Phase 1 |
| W-04 | CDR multi-account resolution: document as intentional (CDR is tenant-wide, account_id join happens downstream) | ResourceResolver code comment |
| W-05 | Crown jewel audit log: write row to platform `audit_logs` on every CJ add/remove | Section 16 |
| W-06 | Inventory Threat tab cross-validation: BFF must re-validate incident_id belongs to auth tenant | Section 16 / UI architecture |
| W-07 | Pattern confidence gate: `confidence: theoretical` patterns must NOT produce `incident_class: active` | IncidentWriter, Section 9.4 |
| W-08 | Evidence schema evolution: define versioned migration path for `_schema_version` in a Phase 8 ADR | Section 9.6 note |
| W-09 | FP feedback rate limit: 10 verdicts/user/24h enforced at endpoint layer | Section 16 |
| W-10 | RS/RC gaps: file 3 gap tickets — T1562 auto-response, T1537 auto-response, recovery playbooks | Platform backlog |

### 17.3 STRIDE Summary

| Category | Finding | Severity |
|---|---|---|
| Spoofing | scan_run_id ownership check missing (S-01) | HIGH → fixed CP1-07 |
| Spoofing | Crown jewel ownership check missing (S-02) | CRITICAL → fixed CP1-03 |
| Tampering | PatternCompiler Cypher injection (T-03) | CRITICAL → fixed CP1-01 |
| Tampering | Neo4j PathTagger MERGE must include tenant_id filter (T-02) | HIGH → addressed in CP1-01 scope |
| Repudiation | Feedback table needs immutable audit log (R-01) | HIGH → fixed in Section 16 |
| Information Disclosure | Evidence JSONB PII on list endpoint (I-01) | CRITICAL → fixed CP1-02 |
| Information Disclosure | graph_query exposure to all users (I-02) | MEDIUM → fixed CP1-02 |
| Denial of Service | Global FP auto-quarantine (D implied) | HIGH → fixed CP1-05 |
| Denial of Service | No Neo4j query timeout at driver level (D-02) | HIGH → warning W-02 |
| Elevation of Privilege | Actions endpoint undefined execution model (E-01) | CRITICAL → fixed CP1-04 |
| Elevation of Privilege | Theoretical patterns can generate `active` incidents (E-02) | HIGH → warning W-07 |

### 17.4 PASTA Attack Trees (Top 3 Risks)

**Goal 1 — Cross-Tenant Data Read (CRITICAL):** PatternCompiler Cypher without `$tenant_id` param returns nodes from all tenants in shared Neo4j named DB. Mitigated by CP1-01 (parameterization linter).

**Goal 2 — Crown Jewel Spoofing (HIGH):** Attacker submits foreign resource_uid to crown-jewels API, contaminating detection logic. Mitigated by CP1-03 (inventory ownership check).

**Goal 3 — Detection Suppression via FP Feedback (HIGH):** Bulk FP verdicts trigger global pattern quarantine, silencing detections across all tenants. Mitigated by CP1-05 (per-tenant suppression only; global = human approval).

### 17.5 NIST CSF 2.0 Gap Tracker

| Function | Coverage | Gap |
|---|---|---|
| ID (Identify) | Full — ResourceResolver + CrownJewelClassifier | None |
| PR (Protect) | Strong — RBAC, parameterized queries, tenant isolation | `cdr:sensitive` field-level gating (CP1-02) |
| DE (Detect) | Strong — 3-tier patterns, CDR overlay, MITRE mapping | MITRE tagging 80% gap (Phase 0) |
| RS (Respond) | Partial — lifecycle SM, escalation | **RS gap: no automated containment.** `POST /actions` is 501 in v1. 3 gap tickets required (W-10) |
| RC (Recover) | Absent | **RC gap: no recovery playbooks in v1.** Explicit scope limitation. Phase 8. |

---

## Appendix A — Top 20 AWS MITRE Techniques (by rule count)

| Technique | Name | Rules | Tactic |
|---|---|---|---|
| T1562.001 | Impair Defenses: Disable/Modify Tools | 48 | defense_evasion |
| T1190 | Exploit Public-Facing Application | 31 | initial_access |
| T1531 | Account Access Removal | 23 | impact |
| T1485 | Data Destruction | 23 | impact |
| T1098.003 | Account Manipulation: Add Cloud Role | 22 | persistence |
| T1651 | Cloud Administration Command | 21 | execution |
| T1537 | Transfer Data to Cloud Account | 21 | exfiltration |
| T1562.007 | Disable Cloud Logs | 21 | defense_evasion |
| T1530 | Data from Cloud Storage | 20 | collection |
| T1552.005 | Cloud Instance Metadata API | 11 | credential_access |
| T1078.004 | Valid Accounts: Cloud Accounts | 12 | initial_access |
| T1595.002 | Active Scanning: Vulnerability Scanning | 18 | reconnaissance |
| T1087.004 | Account Discovery: Cloud Account | 13 | discovery |
| T1098.001 | Additional Cloud Credentials | 12 | persistence |
| T1046 | Network Service Discovery | 10 | discovery |
| T1610 | Deploy Container | 10 | execution |
| T1136.003 | Create Cloud Account | 10 | persistence |
| T1072 | Software Deployment Tools | 11 | execution |
| T1563.001 | Remote Service Session Hijacking | 11 | lateral_movement |
| T1562.008 | Disable Cloud Audit Logs | 15 | defense_evasion |

## Appendix B — Graph Edge Types Available Today

| Category | Edge | Connects |
|---|---|---|
| exposure | internet_connected | Internet → Resource |
| exposure | exposed_through | Resource → Resource (via LB/proxy) |
| exposure | serves_traffic_for | Resource → Resource |
| privilege_escalation | assumes | Identity → IAMRole |
| privilege_escalation | grants_access_to | IAMRole → Resource |
| privilege_escalation | has_policy | Resource → PolicyDocument |
| lateral_movement | allows_traffic_from | SG → Resource |
| lateral_movement | attached_to | Resource → Resource |
| lateral_movement | connected_to | Resource → Resource |
| lateral_movement | provides_image_to | Registry → Container |
| lateral_movement | routes_to | RouteTable → Resource |
| lateral_movement | runs_on | Container → EC2 |
| data_access | backs_up_to | Resource → BackupStore |
| data_access | cached_by | Resource → Cache |
| data_access | replicates_to | Resource → Resource |
| data_access | stores_data_in | Resource → DataStore |
| execution | invokes | Function → Resource |
| execution | triggers | Event → Resource |
| execution | uses | Resource → Resource |
| data_flow | publishes_to | Resource → Queue/Topic |
| data_flow | resolves_to | DNS → Resource |
| data_flow | subscribes_to | Resource → Queue/Topic |
