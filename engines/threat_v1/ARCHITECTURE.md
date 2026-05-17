# Threat Engine v1 — Architecture Document

**Status:** Draft — 2026-05-10  
**Author:** Solution Architect  
**Engine directory:** `engines/threat_v1/`  
**Port:** 8021 (8020 = existing threat engine — parallel operation during transition)  
**Source of requirements:** `engines/threat_v1/REQUIREMENTS.md`  
**Supersedes:** `engines/threat/` (kept live until v1 validated per REQUIREMENTS.md §14)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Context (L1)](#2-system-context-l1)
3. [Container Architecture (L2)](#3-container-architecture-l2)
4. [Component Design (L3)](#4-component-design-l3)
5. [Data Architecture](#5-data-architecture)
6. [API Design](#6-api-design)
7. [Security Architecture](#7-security-architecture)
8. [Pattern DSL Specification](#8-pattern-dsl-specification)
9. [3-Pane UI Architecture](#9-3-pane-ui-architecture)
10. [Deployment Architecture](#10-deployment-architecture)
11. [Implementation Phases](#11-implementation-phases)
12. [Architecture Decision Records](#12-architecture-decision-records)

---

## 1. Executive Summary

### Problem

The existing threat engine (`engines/threat/`, port 8020) is a misconfigurations grouper, not a threat detection platform. Its specific limitations, confirmed by code inspection (2026-05-10):

| Capability | Status in v0 |
|---|---|
| Attack path chains (multi-hop) | BFS/DFS exists in `threat_analyzer.py` but not wired to Neo4j |
| CDR correlation | `CDRReader` class exists but never called |
| Active vs. passive incident distinction | No `incident_class` field — all detections are posture |
| Pattern-driven detection | 47 ad-hoc Cypher queries in DB; no YAML, no test cases |
| Crown jewel classification | `is_crown_jewel` flag does not exist |
| `on_attack_path` property | Does not exist in Neo4j or DB |
| Vulnerability findings in graph | `CVELoader` gated by optional env var; unreliable |
| CDR events as graph nodes | Not implemented |
| Incident lifecycle (SM) | No state machine; detections are immutable rows |
| UI investigation flow | Dead tabs in frontend; no Zone A/B/C architecture |

### Solution

threat_v1 adds five capabilities to the platform:

1. **Unified signal graph** — ResourceResolver joins misconfig + CVE + CDR findings across 6 DBs into a single Neo4j named database (`threat_v1`)
2. **3-tier PatternExecutor** — declarative YAML patterns compiled to parameterized Cypher detect Tier 1 (toxic combo), Tier 2 (partial path), and Tier 3 (full attack path to crown jewel)
3. **IncidentWriter** — deduplication, multi-pattern roll-up, CDR escalation state machine (posture → suspicious → active), and story generation
4. **REST API + BFF views** — four BFF views and a full incident REST surface gated by `threat:read` / `cdr:sensitive`
5. **Threat Center UI** — 3-pane investigation layout (Zone A filter sidebar, Zone B incident list, Zone C side panel) + inventory Threat tab with five new fields

### Key Design Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Named Neo4j database `threat_v1`, same Aura instance | Shared Aura avoids new credential provisioning; named DB isolates v1 graph from production graph during parallel run |
| 2 | New `_v1`-suffixed tables in existing `threat_engine_threat` DB | No new connection config; simpler ops during validation period |
| 3 | YAML patterns in git, Postgres at runtime | Same pipeline as check rules — auditable, testable, version-stamped |
| 4 | Hybrid graph node model (aggregated flags + finding nodes) | Flags enable sub-10ms Tier 1 matching; finding nodes carry Tier 2/3 evidence |
| 5 | Per-tenant FP suppression, not global pattern deactivation | Global suppression is a denial-of-service attack surface (CP1-05); see ADR-003 |
| 6 | Zone C is a side panel, not a popup | Side panels persist investigation state across incident list navigation; popups close on click-out (ADR-001) |

---

## 2. System Context (L1)

*Corresponds to C4 diagram page 1 (L1 System Context) in `engines/threat_v1/threat_v1_c4_architecture.drawio`.*

### Position in the Argo DAG

```
Discovery (8001)
    │
    ▼
Inventory (8022)
    │
    ▼
Check (8002) ──────────────────────────────────────┐
    │                                               │
    ▼                                               │ reads check_findings
Vulnerability (scanner)                             │
    │                                               │
    ▼                                               │
threat_v1 (8021) ◄──────────────────────────────────┘
    │              reads: check DB, vuln DB,
    │                     CDR DB, inventory DB,
    │                     IAM DB, datasec DB
    ▼
Risk (blast radius)
    │
    ▼
Compliance / IAM / DataSec / Network (parallel)
```

threat_v1 runs after Check and Vulnerability in the Argo DAG. It does not produce scan jobs — it consumes the results of upstream engines.

### External Actors

| Actor | Interaction | Protocol |
|---|---|---|
| Argo Workflows | Triggers `run_scan.py` with `--tenant-id`, `--account-id`, `--scan-run-id` | K8s pod (subprocess) |
| CDR Argo CronWorkflow | Triggers `--mode=cdr-update` every 3h after CDR scan completes | K8s pod (subprocess) |
| API Gateway | Routes `/api/v1/*` to threat_v1:8021; injects `X-Auth-Context` header | HTTP/1.1 internal |
| BFF (shared/api_gateway/bff/) | Calls threat_v1 REST API to assemble BFF views | HTTP/1.1 internal |
| Frontend (Next.js 15) | Fetches BFF views via `fetchView("threat_center")` | HTTPS/JSON |
| Neo4j Aura | Read/write graph operations via Bolt driver | neo4j+s:// Bolt |
| Threat DB (RDS) | Read/write `threat_incidents`, `threat_scenario_patterns`, `_v1` tables | PostgreSQL (psycopg2) |
| Platform audit_logs | Write crown jewel add/remove events (W-05) | PostgreSQL (psycopg2) |

### What threat_v1 Does NOT Do

- Does not run cloud API scans (no boto3/Azure SDK calls)
- Does not write to check DB, vuln DB, CDR DB, or inventory DB
- Does not expose a webhook endpoint (Phase 8 scope)
- Does not provide ad-hoc Cypher query execution (CP1-06)
- Does not execute automated containment actions (CP1-04; `POST /actions` returns HTTP 501)

---

## 3. Container Architecture (L2)

*Corresponds to C4 diagram page 2 (L2 Containers) in `engines/threat_v1/threat_v1_c4_architecture.drawio`.*

The engine ships as a single Docker image. Logical containers are Python modules within that image, not separate processes.

### Containers (Logical)

```
┌─────────────────────────────────────────────────────────────────────┐
│  engine-threat-v1 pod (threat-engine-engines namespace)             │
│                                                                     │
│  ┌──────────────────┐   ┌──────────────────┐                        │
│  │  FastAPI Server  │   │  run_scan.py     │                        │
│  │  :8021           │   │  (batch entry)   │                        │
│  │  api/            │   │                  │                        │
│  └────────┬─────────┘   └────────┬─────────┘                        │
│           │                      │                                  │
│           ▼                      ▼                                  │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    GraphBuilder                               │   │
│  │  ResourceResolver → MisconfigLoader → VulnLoader →           │   │
│  │  CDRLoader → CrownJewelClassifier → EdgeBuilder              │   │
│  │  Writes to: Neo4j named DB "threat_v1"                        │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                             │                                       │
│                             ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   PatternExecutor                             │   │
│  │  PatternRegistry → PatternCompiler → Tier1/2/3Matchers →     │   │
│  │  PerformanceGuard                                             │   │
│  │  Reads: threat_scenario_patterns (Postgres)                   │   │
│  │  Reads/Writes: Neo4j "threat_v1"                              │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                             │                                       │
│                             ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   IncidentWriter                              │   │
│  │  SeverityScorer → IncidentDeduper → LifecycleTransitioner →  │   │
│  │  StoryBuilder → FeedbackProcessor                             │   │
│  │  Writes to: threat_incidents (Postgres, _v1 tables)           │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  Pattern Catalog (YAML-on-disk)                               │   │
│  │  catalog/threat_patterns/{tier}/{csp}/PAT-*.yaml              │   │
│  │  Loaded by upload_scenario_patterns.py at engine startup      │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Container Responsibilities

| Container | Input | Output | Key Constraint |
|---|---|---|---|
| FastAPI Server | HTTP requests via gateway | JSON responses | `require_permission()` on every route |
| run_scan.py | Argo CLI args (`--tenant-id`, `--account-id`, `--scan-run-id`) | `threat_scan_runs_v1` status row | Ownership validation before any DB read (CP1-07) |
| GraphBuilder | 6 Postgres DBs | Neo4j `threat_v1` nodes + edges | Advisory lock per `hashtext(tenant_id || '\|' || account_id)` |
| PatternExecutor | Neo4j + `threat_scenario_patterns` | Detection candidates (in-memory) + `on_attack_path` flags | All Cypher parameterized; per-pattern 500ms p99 budget |
| IncidentWriter | Detection candidates | `threat_incidents` rows (upsert) | `ON CONFLICT (dedup_key) DO UPDATE`; per-tenant suppression only |
| Pattern Catalog | YAML files in git | `threat_scenario_patterns` table (via upload script) | YAML is source of truth; Postgres is runtime copy |

---

## 4. Component Design (L3)

*Corresponds to C4 diagram page 3 (L3 Engine Components) in `engines/threat_v1/threat_v1_c4_architecture.drawio`.*

### 4.1 GraphBuilder

| Component | Responsibility |
|---|---|
| `ResourceResolver` | Joins inventory + check + vuln + CDR findings per `(tenant_id, account_id)`. Selects best scan per engine (most findings, not latest timestamp — see REQUIREMENTS.md §3.2). For multi-CSP tenants: runs resolution per `(tenant_id, account_id)` pair, unions results. |
| `MisconfigLoader` | Reads `check_findings` where `status IN ('FAIL','WARN')`. Maps each finding to `MisconfigFinding` node. Copies `mitre_techniques` from `rule_metadata`. |
| `VulnLoader` | Reads `scan_vulnerabilities`. Infers `mitre_technique = T1190` when `cvss_score >= 9.0 AND attack_vector = 'NETWORK'`. Phase 0 heuristic (REQUIREMENTS.md §12.3). |
| `CDRLoader` | Reads `cdr_findings`. Produces `CDREvent` nodes (actor_principal, mitre_technique, event_time, source_ip, anomaly_score) and `CDRActor` nodes (actor_id normalized from actor_principal). |
| `CrownJewelClassifier` | Joins `resource_inventory_identifier` (asset_category, access_pattern) + `inventory_findings` (criticality, environment, risk_score, tags). Applies `is_crown_jewel()` logic per REQUIREMENTS.md §6.3. DB-driven; does not hardcode resource type lists. |
| `EdgeBuilder` | Reads materialized `inventory_relationships` table (not `resource_security_relationship_rules` directly). Writes edges using `relation_type` + `attack_path_category`. Only 22 edge types with `attack_path_category` set contribute to attack path traversal. |
| `PathTagger` | Runs after PatternExecutor Tier 3 matches. Sets `on_attack_path=true` on all Resource nodes that appear in a confirmed Tier 3 path. All MERGE statements include `$tenant_id` filter (T-02 mitigation). |

**Graph build idempotency:** All node and edge operations use `MERGE` on stable keys (`resource_uid`, `finding_id`). Spot preemption and retries produce identical graph state.

### 4.2 PatternExecutor

| Component | Responsibility |
|---|---|
| `PatternRegistry` | Loads active patterns from `threat_scenario_patterns` where `active = true` AND pattern not in `threat_pattern_suppressions` for the current tenant. Returns list of compiled `PatternModel` objects. |
| `PatternCompiler` | Translates YAML pattern fields into a parameterized Cypher template. **CP1-01 enforcement:** all values from pattern fields (`resource_types`, `check_rules_failing`, `edge_type`, condition values) are passed as `$parameter` bindings. No string interpolation or f-string concatenation into Cypher strings. Implemented as a parameterized template expander, not a string builder. |
| `Tier1Matcher` | Flag-based toxic combination detection. Reads aggregated boolean properties (`internet_exposed`, `has_critical_cve`, `has_high_misconfig`, `is_admin_role`, `cdr_actor_seen`) directly from Resource nodes. No graph traversal. Latency target: <10ms per pattern. |
| `Tier2Matcher` | Partial path detection. Evaluates whether `min_hops_for_tier2` of the required path hops are present even if the crown jewel target is not reached. Graph traversal limited to N hops where N = max hops in pattern. Latency target: <500ms per pattern. |
| `Tier3Matcher` | Full attack path detection. Traverses from entry Resource to crown jewel Resource following pattern-specified edges and conditions. Applies CDR overlay: counts distinct `mitre_technique` values on `CDREvent` nodes attached to path resources within `cdr_watch.window_minutes`. Sets `incident_class` based on CDR signal coverage. Latency target: <2s per pattern. |
| `PerformanceGuard` | Wraps each pattern execution with a timeout (`session.run(query, timeout=500)` — W-02). Tracks rolling p99 latency per pattern. Auto-quarantines patterns exceeding p99 budget for 3 consecutive runs: inserts into `threat_pattern_suppressions` (per-tenant, `auto_generated=true`) and flags for engineering review. |

### 4.3 IncidentWriter

| Component | Responsibility |
|---|---|
| `SeverityScorer` | Computes `risk_score` (0–100) and `severity` from detection tier, CDR signal state, path length, and pattern `scoring` overrides. Formula is configurable and auditable via `score_breakdown JSONB`. |
| `IncidentDeduper` | Groups detections by `(tenant_id, entry_resource_uid, target_resource_uid)` before computing `dedup_key`. Performs multi-pattern roll-up: highest tier wins; all matched patterns recorded in `evidence.matched_patterns[]`. Then checks `dedup_key` against `threat_incidents WHERE status != 'resolved'`. |
| `LifecycleTransitioner` | Applies the incident state machine (REQUIREMENTS.md §9.4). Transitions: `new → open`, `open → suspicious` (first CDR technique), `suspicious → active` (second CDR technique or `min_coverage` met), `active → resolved` (session terminated AND no CDR events 24h AND check findings fixed), `open → resolved` (check findings fixed), `resolved → reopened` (same `dedup_key` fires within 7 days). `confidence: theoretical` patterns cannot produce `incident_class: active` (W-07). |
| `StoryBuilder` | Populates `story_text` from the pattern's `story_template`. Interpolates `{entry_type}`, `{pivot_type}`, `{target_name}`, `{actor_line}` from detection context. Actor line is blank for posture class, populated for active class. |
| `FeedbackProcessor` | Handles `POST /api/v1/incidents/{id}/feedback`. INSERT-only into `threat_incident_feedback` (immutable audit log). Rate-limited: 10 verdicts per user per 24h (W-09 / CP1-05). Per-tenant FP rate tracked rolling 30d. When FP rate > 30% per tenant → inserts into `threat_pattern_suppressions` with `auto_generated=true`. Global pattern deactivation (`active=false` on shared pattern) requires security architect approval and manual update. |

---

## 5. Data Architecture

### 5.1 Graph Schema

**Node Labels and Properties**

| Label | Primary Key | Key Properties | Set By |
|---|---|---|---|
| `Resource` (+ type label) | `resource_uid` | `tenant_id`, `account_id`, `provider`, `region`, `resource_type`; flags: `internet_exposed`, `has_critical_cve`, `has_high_misconfig`, `is_admin_role`, `is_crown_jewel`, `cdr_actor_seen`, `on_attack_path` | GraphBuilder |
| `MisconfigFinding` | `finding_id` | `rule_id`, `severity`, `title`, `mitre_techniques[]`, `mitre_tactics[]`, `status` | MisconfigLoader |
| `VulnFinding` | `cve_id` | `cvss_score`, `epss_score`, `has_known_exploit`, `mitre_technique`, `package`, `fixed_version` | VulnLoader |
| `CDREvent` | `finding_id` | `actor_principal`, `mitre_technique`, `mitre_tactic`, `event_time`, `source_ip`, `action`, `anomaly_score` | CDRLoader |
| `CDRActor` | `actor_id` | `tenant_id`, `last_seen`, `on_attack_path` | CDRLoader |

**Resource type labels applied at MERGE time (examples):**
`EC2Instance`, `S3Bucket`, `IAMRole`, `RDSInstance`, `LambdaFunction`, `KMSKey`, `SecretsManagerSecret`, `EKSCluster`, `ServiceAccount`, `VPC`

**Edge Types**

| Edge | From → To | Attack Path Category | Source |
|---|---|---|---|
| `HAS_MISCONFIG` | Resource → MisconfigFinding | — (finding attachment) | MisconfigLoader |
| `HAS_CVE` | Resource → VulnFinding | — (finding attachment) | VulnLoader |
| `TRIGGERED_ON` | Resource → CDREvent | — (event attachment) | CDRLoader |
| `PERFORMED` | CDRActor → CDREvent | — | CDRLoader |
| `internet_connected` | Internet → Resource | `exposure` | EdgeBuilder |
| `exposed_through` | Resource → Resource | `exposure` | EdgeBuilder |
| `serves_traffic_for` | Resource → Resource | `exposure` | EdgeBuilder |
| `assumes` | Identity → IAMRole | `privilege_escalation` | EdgeBuilder |
| `grants_access_to` | IAMRole → Resource | `privilege_escalation` | EdgeBuilder |
| `has_policy` | Resource → PolicyDocument | `privilege_escalation` | EdgeBuilder |
| `allows_traffic_from` | SG → Resource | `lateral_movement` | EdgeBuilder |
| `attached_to` | Resource → Resource | `lateral_movement` | EdgeBuilder |
| `connected_to` | Resource → Resource | `lateral_movement` | EdgeBuilder |
| `provides_image_to` | Registry → Container | `lateral_movement` | EdgeBuilder |
| `routes_to` | RouteTable → Resource | `lateral_movement` | EdgeBuilder |
| `runs_on` | Container → EC2 | `lateral_movement` | EdgeBuilder |
| `backs_up_to` | Resource → BackupStore | `data_access` | EdgeBuilder |
| `cached_by` | Resource → Cache | `data_access` | EdgeBuilder |
| `replicates_to` | Resource → Resource | `data_access` | EdgeBuilder |
| `stores_data_in` | Resource → DataStore | `data_access` | EdgeBuilder |
| `invokes` | Function → Resource | `execution` | EdgeBuilder |
| `triggers` | Event → Resource | `execution` | EdgeBuilder |
| `uses` | Resource → Resource | `execution` | EdgeBuilder |

**Note:** The source table for edges is `inventory_relationships` (materialized edges), not `resource_security_relationship_rules` (extraction rules). EdgeBuilder reads `inventory_relationships.relation_type`, `from_uid`, `to_uid`, `attack_path_category`.

**Named Database:** `threat_v1` within the existing Neo4j Aura instance (`neo4j+s://17ec5cbb.databases.neo4j.io`). All Cypher must include `$tenant_id` parameter in every node filter.

### 5.2 Threat DB Schema (New Tables)

**`threat_incidents`** (full DDL in REQUIREMENTS.md §9.1)

| Column | Type | Notes |
|---|---|---|
| `incident_id` | UUID PK | `gen_random_uuid()` |
| `pattern_id` | VARCHAR(32) | PAT-AWS-001 |
| `tenant_id` | VARCHAR(128) NOT NULL | FK to `tenants` |
| `account_id` | VARCHAR(512) | Multi-CSP: OCI OCIDs are long |
| `tier` | SMALLINT NOT NULL | 1 / 2 / 3 |
| `incident_class` | VARCHAR(16) NOT NULL | posture / suspicious / active |
| `severity` | VARCHAR(16) NOT NULL | critical / high / medium / low |
| `pattern_version` | SMALLINT NOT NULL | Snapshot at incident creation |
| `input_scan_runs` | JSONB NOT NULL | `{check, vuln, cdr, inventory: scan_run_ids}` |
| `risk_score` | SMALLINT | 0–100 |
| `score_breakdown` | JSONB | Component scores (auditable) |
| `entry_resource_uid` | VARCHAR(512) | |
| `attack_path` | JSONB | Ordered list of resource_uids |
| `target_resource_uid` | VARCHAR(512) | Crown jewel |
| `mitre_tactics` | JSONB | [TA0001, TA0006, TA0009] |
| `mitre_techniques` | JSONB | [T1190, T1552.005, T1530] |
| `tactic_chain` | JSONB | Ordered chain |
| `actor_principal` | VARCHAR(512) | From CDR; PII-gated (CP1-02) |
| `cdr_event_ids` | JSONB | CDR finding IDs that fired |
| `story_text` | TEXT | Human-readable narrative |
| `evidence` | JSONB | Full evidence (schema v1) |
| `recommendations` | JSONB | Ordered action list |
| `status` | VARCHAR(16) | new / open / suspicious / active / resolved / reopened |
| `first_seen_at` | TIMESTAMPTZ | |
| `last_seen_at` | TIMESTAMPTZ | |
| `resolved_at` | TIMESTAMPTZ | |
| `dedup_key` | VARCHAR(256) GENERATED STORED | sha256(pattern_id \| tenant_id \| entry_uid \| target_uid) |

Unique index: `(dedup_key) WHERE status != 'resolved'`

**`threat_scenario_patterns`** (runtime copy of YAML patterns)

| Column | Type | Notes |
|---|---|---|
| `pattern_id` | VARCHAR(32) PK | PAT-AWS-001 |
| `version` | SMALLINT | From YAML `version` field |
| `tier` | SMALLINT | 1 / 2 / 3 |
| `severity_base` | VARCHAR(16) | |
| `confidence` | VARCHAR(16) | confirmed / theoretical / emerging |
| `csps` | JSONB | [aws] / [azure] / [all] |
| `mitre_tactics` | JSONB | |
| `mitre_techniques` | JSONB | |
| `tactic_chain_order` | JSONB | |
| `pattern_yaml` | TEXT | Full YAML source |
| `compiled_cypher` | TEXT | Parameterized Cypher template |
| `active` | BOOLEAN DEFAULT TRUE | Global active flag (human-only) |
| `deprecated_at` | TIMESTAMPTZ | |
| `created_at` | TIMESTAMPTZ | |
| `updated_at` | TIMESTAMPTZ | |

**`threat_scan_runs_v1`**

| Column | Type | Notes |
|---|---|---|
| `run_id` | UUID PK | |
| `scan_run_id` | UUID NOT NULL | From Argo / scan_orchestration |
| `tenant_id` | VARCHAR(128) NOT NULL | |
| `account_id` | VARCHAR(512) | |
| `status` | VARCHAR(16) | running / completed / failed |
| `mode` | VARCHAR(16) | full / cdr-update |
| `graph_build_duration_s` | INTEGER | |
| `pattern_execution_duration_s` | INTEGER | |
| `node_count` | INTEGER | |
| `edge_count` | INTEGER | |
| `incidents_written` | INTEGER | |
| `started_at` | TIMESTAMPTZ | |
| `completed_at` | TIMESTAMPTZ | |
| `error_detail` | TEXT | |

**`threat_pattern_suppressions`** (per-tenant, CP1-05)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | VARCHAR(128) NOT NULL | Per-tenant scope — not global |
| `pattern_id` | VARCHAR(32) NOT NULL | FK to threat_scenario_patterns |
| `reason` | TEXT | |
| `until` | TIMESTAMPTZ | NULL = indefinite |
| `auto_generated` | BOOLEAN | true = created by FeedbackProcessor |
| `created_at` | TIMESTAMPTZ | |

**`threat_crown_jewels`** (customer-defined crown jewels)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `tenant_id` | VARCHAR(128) NOT NULL | |
| `resource_uid` | VARCHAR(512) NOT NULL | Ownership-validated (CP1-03) |
| `reason` | TEXT | |
| `created_by` | VARCHAR(256) | User ID from AuthContext |
| `created_at` | TIMESTAMPTZ | |
| UNIQUE | `(tenant_id, resource_uid)` | |

**`threat_incident_feedback`** (immutable audit log)

| Column | Type | Notes |
|---|---|---|
| `id` | UUID PK | |
| `incident_id` | UUID NOT NULL | FK to threat_incidents |
| `tenant_id` | VARCHAR(128) NOT NULL | |
| `verdict` | VARCHAR(16) | true_positive / false_positive |
| `reporter` | VARCHAR(256) | User ID from AuthContext |
| `notes` | TEXT | |
| `created_at` | TIMESTAMPTZ | INSERT-only; no UPDATE ever |

### 5.3 Cross-Engine DB Reads

| Source DB | Table(s) Read | Join Key | Used By |
|---|---|---|---|
| `threat_engine_check` | `check_findings`, `rule_metadata` | `resource_uid + tenant_id + account_id` | MisconfigLoader |
| `threat_engine_vulnerability` | `scan_vulnerabilities` | `resource_uid + tenant_id + account_id` | VulnLoader |
| `threat_engine_cdr` | `cdr_findings` | `resource_uid + tenant_id` | CDRLoader |
| `threat_engine_inventory` | `resource_inventory`, `inventory_relationships`, `resource_inventory_identifier`, `inventory_findings` | `resource_uid + tenant_id` | ResourceResolver, EdgeBuilder, CrownJewelClassifier |
| `threat_engine_iam` | `iam_findings` | `resource_uid + tenant_id + account_id` | CrownJewelClassifier (`has_admin_policy` flag) |
| `threat_engine_datasec` | `datasec_findings` (PII/PHI tags) | `resource_uid + tenant_id` | CrownJewelClassifier (sensitive data stores) |

**All reads are read-only.** threat_v1 writes only to `threat_engine_threat` (`_v1` tables) and Neo4j.

### 5.4 scan_run_id Flow

`scan_run_id` is the single UUID per pipeline run passed from Argo to all engines (platform constitution §DB Design). threat_v1 receives it via `--scan-run-id` CLI arg. It:

- Validates against `scan_orchestration` table (CP1-07)
- Passes it to ResourceResolver for best-scan selection (pipeline trigger: use passed `scan_run_id` directly; CDR trigger: most-findings query per REQUIREMENTS.md §3.2)
- Records it in `threat_scan_runs_v1.scan_run_id`
- Stores the set of input scan_run_ids per engine in `threat_incidents.input_scan_runs JSONB`

---

## 6. API Design

*Full OpenAPI spec generated at `engines/threat_v1/api/openapi.yaml`. Source of truth is FastAPI routes.*

All endpoints require `Authorization: Bearer <access_token>` cookie → `X-Auth-Context` → `require_permission()`.

### Endpoint Table

| Method | Path | Permission | Response Model | Notes |
|---|---|---|---|---|
| GET | `/api/v1/incidents` | `threat:read` | `IncidentListItem` | CDR PII fields stripped (CP1-02). Supports: `?tier=`, `?status=`, `?severity=`, `?csp=`, `?page=`, `?limit=` |
| GET | `/api/v1/incidents/{id}` | `threat:read` + `cdr:sensitive` (if CDR events present) | `IncidentDetail` | Full evidence including `graph_query`. `cdr:sensitive` checked at field level. |
| POST | `/api/v1/incidents/{id}/feedback` | `threat:write` + `feedback:write` | `FeedbackAck` | INSERT-only. Rate-limited: 10 verdicts/user/24h (W-09). |
| POST | `/api/v1/incidents/{id}/actions` | — | HTTP 501 | **Not Implemented (CP1-04)**. Returns guidance text only. Execution model undefined. Phase 8 scope. |
| GET | `/api/v1/patterns` | `threat:read` | `PatternListItem[]` | Active patterns filtered by per-tenant `threat_pattern_suppressions`. |
| GET | `/api/v1/patterns/{id}` | `threat:read` | `PatternDetail` | Full pattern: tactic chain, MITRE, tier, test case descriptions. |
| POST | `/api/v1/crown-jewels` | `threat:write` | `CrownJewelRecord` | Ownership validation: resource_uid MUST exist in `resource_inventory WHERE tenant_id = auth_ctx.tenant_id`. Returns 404 if not found (avoids confirming foreign resource — CP1-03). Writes audit row. |
| DELETE | `/api/v1/crown-jewels/{resource_uid}` | `threat:write` | 204 | Same ownership validation. Writes audit row to platform `audit_logs` (W-05). |
| GET | `/api/v1/scan/status/{job_id}` | `threat:read` | `ScanStatus` | Async scan status polling against `threat_scan_runs_v1`. |
| GET | `/api/v1/coverage` | `threat:read` | `CoverageHeatmap` | MITRE tactic × CSP × Tier heatmap. Derived from active patterns. |
| GET | `/api/v1/health/live` | none | `{"status":"ok"}` | Process liveness. No external dependencies checked. |
| GET | `/api/v1/health/ready` | none | `{"status":"ok","checks":{...}}` | Checks Postgres connectivity + Neo4j Bolt connectivity. |

**Explicitly excluded (CP1-06):** `POST /api/v1/hunt/execute` with free-form `cypher` body. No ad-hoc Cypher endpoint exists in v1 or any future version without security architect approval.

**Webhooks:** Not in v1. External integrations use the REST API directly.

### Response Models (PII Boundary)

**`IncidentListItem`** — returned by `GET /incidents`

| Field | Included | Required Permission |
|---|---|---|
| `incident_id`, `pattern_id`, `tier`, `incident_class`, `severity`, `status` | Yes | `threat:read` |
| `mitre_tactics`, `mitre_techniques`, `tactic_chain` | Yes | `threat:read` |
| `entry_resource_uid`, `attack_path`, `target_resource_uid` | Yes | `threat:read` |
| `evidence.misconfig_findings` | Yes | `threat:read` |
| `evidence.vuln_findings` | Yes | `threat:read` |
| `evidence.cdr_events[].mitre_technique` | Yes | `threat:read` |
| `evidence.path_resources` | Yes | `threat:read` |
| `evidence.matched_patterns` | Yes | `threat:read` |
| `evidence.cdr_events[].actor_principal` | **Stripped** | `cdr:sensitive` (detail only) |
| `evidence.cdr_events[].source_ip` | **Stripped** | `cdr:sensitive` (detail only) |
| `evidence.cdr_events[].action` | **Stripped** | `cdr:sensitive` (detail only) |
| `evidence.graph_query` | **Stripped** | detail endpoint only |

**`IncidentDetail`** — returned by `GET /incidents/{id}`

Same as `IncidentListItem` plus:
- `evidence.cdr_events[].actor_principal` (requires `cdr:sensitive`)
- `evidence.cdr_events[].source_ip` (requires `cdr:sensitive`)
- `evidence.cdr_events[].action` (requires `cdr:sensitive`)
- `evidence.graph_query` (requires `threat:read`; parameterized Cypher with bound params)
- `story_text` (full narrative)
- `recommendations` (ordered action list)
- `score_breakdown` (risk score components)

Enforcement: two distinct Pydantic models. `strip_sensitive_fields()` from shared auth extended for threat_v1.

### BFF Views

The API Gateway BFF assembles these views by calling the threat_v1 REST API:

| BFF View | BFF Path | Calls | Used By |
|---|---|---|---|
| `threat_center` | `/gateway/api/v1/views/threat_center` | `GET /api/v1/incidents` | Zone B incident list, Zone A filter counts |
| `incident_detail` | `/gateway/api/v1/views/incident_detail/{id}` | `GET /api/v1/incidents/{id}` | Zone C investigation panel |
| `threat_graph` | `/gateway/api/v1/views/threat_graph` | `GET /api/v1/incidents?on_attack_path=true` | Graph visualization overlay |
| `inventory_asset_threat` | `/gateway/api/v1/views/inventory_asset_threat/{uid}` | `GET /api/v1/incidents?resource_uid={uid}` | Inventory Threat tab |

BFF views must not add fallback data or mock data to mask engine gaps (platform constitution §BFF).

---

## 7. Security Architecture

### 7.1 CP-1 Security Blockers (All Resolved)

| ID | Finding | Severity | Mitigation | Location |
|---|---|---|---|---|
| CP1-01 | PatternCompiler Cypher injection via pattern field interpolation | CRITICAL | All pattern values as `$parameter` bindings; CI linter rejects interpolated Cypher; `$tenant_id` presence check on every compiled query | REQUIREMENTS.md §5.3 + §5.5 |
| CP1-02 | Evidence JSONB PII exposure on list endpoint | CRITICAL | Two Pydantic models (`IncidentListItem` vs `IncidentDetail`); `actor_principal`, `source_ip`, `action` stripped from list; detail requires `cdr:sensitive` | REQUIREMENTS.md §9.6 |
| CP1-03 | Crown jewel ownership spoofing | CRITICAL | `POST /crown-jewels` validates `resource_uid` in `resource_inventory WHERE tenant_id = auth_ctx.tenant_id`; returns 404 on mismatch | REQUIREMENTS.md §16 |
| CP1-04 | Actions endpoint undefined execution model | CRITICAL | `POST /incidents/{id}/actions` returns HTTP 501; no execution capability in v1; scoped to Phase 8 with separate security review | REQUIREMENTS.md §16 |
| CP1-05 | Global FP auto-quarantine (detection suppression attack surface) | HIGH | Auto-quarantine writes to `threat_pattern_suppressions` (per-tenant, `auto_generated=true`); global `active=false` requires security architect approval + manual update | REQUIREMENTS.md §14 Phase 6.6 |
| CP1-06 | Ad-hoc Cypher endpoint | HIGH | `POST /api/v1/hunt/execute` excluded from v1 and all future versions without security architect approval | REQUIREMENTS.md §16 |
| CP1-07 | scan_run_id ownership check missing | HIGH | Step 0 of `run_scan.py` validates `(scan_run_id, tenant_id, account_id)` against `scan_orchestration`; aborts if not found | REQUIREMENTS.md §10.3 |
| CP1-08 | `:latest` image tag in Argo template | HIGH | All Argo templates use pinned tags `yadavanup84/engine-threat-v1:v-threat-v1-phase{N}`; never `:latest` | REQUIREMENTS.md §10.1 |

### 7.2 Warnings (Fix Before Ship)

| ID | Warning | Target |
|---|---|---|
| W-01 | Advisory lock hash: `hashtext(tenant_id \|\| '\|' \|\| account_id)` not tenant_id alone | `run_scan.py` concurrency section |
| W-02 | Neo4j query timeout: `session.run(query, timeout=500)` on all pattern Cypher | PatternExecutor driver wrapper |
| W-03 | Pattern startup crash: `upload_scenario_patterns.py` must catch per-pattern errors | Engine startup sequence |
| W-04 | CDR multi-account resolution: document as intentional in code comment | ResourceResolver |
| W-05 | Crown jewel audit log on every add/remove | `DELETE /crown-jewels/{uid}` handler |
| W-06 | Inventory Threat tab BFF must re-validate incident_id belongs to auth tenant | BFF `inventory_asset_threat` view |
| W-07 | `confidence: theoretical` patterns must NOT produce `incident_class: active` | LifecycleTransitioner guard |
| W-08 | Evidence schema evolution: define versioned migration path for `_schema_version` | Phase 8 ADR |
| W-09 | FP feedback rate limit: 10 verdicts/user/24h | FeedbackProcessor endpoint layer |
| W-10 | RS/RC gaps: file 3 gap tickets (T1562 auto-response, T1537 auto-response, recovery playbooks) | Platform backlog |

### 7.3 STRIDE Threat Model

| Category | ID | Finding | Severity | Status |
|---|---|---|---|---|
| Spoofing | S-01 | scan_run_id ownership check missing | HIGH | Fixed → CP1-07 |
| Spoofing | S-02 | Crown jewel resource_uid ownership check missing | CRITICAL | Fixed → CP1-03 |
| Tampering | T-01 | PatternCompiler Cypher injection via YAML field interpolation | CRITICAL | Fixed → CP1-01 |
| Tampering | T-02 | Neo4j PathTagger MERGE without tenant_id filter | HIGH | Fixed → in CP1-01 scope (all MERGE include `$tenant_id`) |
| Repudiation | R-01 | Feedback table lacked immutable audit log | HIGH | Fixed → INSERT-only table in §16 |
| Information Disclosure | I-01 | Evidence JSONB PII on list endpoint | CRITICAL | Fixed → CP1-02 |
| Information Disclosure | I-02 | `graph_query` exposure to non-privileged users | MEDIUM | Fixed → CP1-02 (detail endpoint only) |
| Denial of Service | D-01 | Global FP auto-quarantine silences detections across all tenants | HIGH | Fixed → CP1-05 (per-tenant suppression) |
| Denial of Service | D-02 | No Neo4j query timeout at driver level | HIGH | Warning → W-02 |
| Elevation of Privilege | E-01 | Actions endpoint undefined execution model | CRITICAL | Fixed → CP1-04 (HTTP 501) |
| Elevation of Privilege | E-02 | Theoretical patterns generate `active` class incidents | HIGH | Warning → W-07 |

### 7.4 PASTA Attack Trees (Top 3 Adversary Goals)

**Goal 1 — Cross-Tenant Data Read (CRITICAL)**

- Adversary objective: read another tenant's incident data or graph nodes
- Attack path: submit crafted pattern YAML with `resource_types` value containing Cypher fragment → PatternCompiler interpolates into query string → Cypher executes without `$tenant_id` filter → all tenants' Resource nodes returned
- Counter-measure: CP1-01 (parameterization linter in CI gates on every PR); all compiled Cypher validated for `$tid` / `$tenant_id` presence before merge

**Goal 2 — Crown Jewel Spoofing (HIGH)**

- Adversary objective: mark a foreign tenant's resource as their own crown jewel, contaminating detection logic to generate false incidents against a competitor's assets
- Attack path: `POST /api/v1/crown-jewels` with known foreign `resource_uid` → GraphBuilder sets `is_crown_jewel=true` on foreign node → Tier 3 patterns fire against wrong target
- Counter-measure: CP1-03 (inventory ownership join before insert); 404 on mismatch avoids confirming foreign resource existence

**Goal 3 — Detection Suppression via Bulk FP Feedback (HIGH)**

- Adversary objective: bulk-submit false-positive verdicts to trigger auto-quarantine of high-value detection patterns, silencing them across all tenants
- Attack path: compromised account submits 30d worth of FP verdicts → FeedbackProcessor triggers `active=false` on shared pattern → zero detections for pattern across entire platform
- Counter-measure: CP1-05 (suppression is per-tenant only; global deactivation requires security architect approval + manual action); W-09 (10 verdicts/user/24h rate limit)

### 7.5 NIST CSF 2.0 Coverage

| Function | Coverage | Gap |
|---|---|---|
| GV (Govern) | RBAC, audit logs, permission matrix | No formal policy document in v1 |
| ID (Identify) | ResourceResolver + CrownJewelClassifier + inventory join | None for v1 scope |
| PR (Protect) | RBAC at every layer, parameterized queries, `strip_sensitive_fields()`, tenant isolation | `cdr:sensitive` field-level gating (CP1-02) ships with v1 |
| DE (Detect) | 3-tier PatternExecutor, CDR overlay, MITRE mapping, 30 patterns | MITRE tagging 80% gap (Phase 0 closes for top 500 rules) |
| RS (Respond) | Lifecycle SM, escalation (posture → active) | **RS gap:** no automated containment; `POST /actions` is HTTP 501 in v1. Gap tickets required (W-10) |
| RC (Recover) | Absent | **RC gap:** no recovery playbooks in v1. Explicit scope limitation. Phase 8. |

### 7.6 RBAC Matrix — Threat Endpoints (5 Roles × Endpoints)

| Endpoint | platform_admin | org_admin | tenant_admin | analyst | viewer |
|---|---|---|---|---|---|
| `GET /incidents` | 200 | 200 | 200 | 200 | 403 |
| `GET /incidents/{id}` (no CDR) | 200 | 200 | 200 | 200 | 403 |
| `GET /incidents/{id}` (CDR events, `cdr:sensitive`) | 200 full | 200 full | 200 full | 200 (CDR PII stripped) | 403 |
| `POST /incidents/{id}/feedback` | 200 | 200 | 200 | 200 | 403 |
| `POST /incidents/{id}/actions` | 501 | 501 | 501 | 501 | 403 |
| `GET /patterns` | 200 | 200 | 200 | 200 | 403 |
| `GET /patterns/{id}` | 200 | 200 | 200 | 200 | 403 |
| `POST /crown-jewels` | 200 | 200 | 200 | 403 | 403 |
| `DELETE /crown-jewels/{uid}` | 200 | 200 | 200 | 403 | 403 |
| `GET /coverage` | 200 | 200 | 200 | 200 | 403 |
| `GET /scan/status/{job_id}` | 200 | 200 | 200 | 200 | 403 |
| `GET /health/live` | 200 | 200 | 200 | 200 | 200 |
| `GET /health/ready` | 200 | 200 | 200 | 200 | 200 |

---

## 8. Pattern DSL Specification

*Full pattern schema: REQUIREMENTS.md §5.3. This section documents the compilation rules and tier hierarchy.*

### 8.1 YAML Pattern Schema

Every pattern is one YAML file at `catalog/threat_patterns/{tier}/{csp}/PAT-{CSP}-{NNN}.yaml`.

**Required top-level fields:**

| Field | Type | Notes |
|---|---|---|
| `id` | string | Stable pattern ID, e.g. `PAT-AWS-001` |
| `version` | integer | Increment on any meaningful change |
| `tier` | integer | 1 / 2 / 3 |
| `severity_base` | string | critical / high / medium / low |
| `confidence` | string | confirmed / theoretical / emerging |
| `mitre_tactics` | list | TA-prefixed tactic IDs |
| `mitre_techniques` | list | T-prefixed technique IDs |
| `tactic_chain_order` | list | Ordered tactic names |
| `csps` | list | [aws] / [azure] / [gcp] / [all] |
| `entry` | object | Entry node spec (see below) |
| `target` | object | Target node spec (Tier 2/3 only) |
| `tests.positive` | object | Positive test case (mandatory before merge) |
| `tests.negative` | object | Negative test case (mandatory before merge) |

**`entry` / `target` / `hops[*].target` node spec:**

| Field | Type | Notes |
|---|---|---|
| `node_type` | string | Always `Resource` |
| `resource_types` | list | EC2Instance, S3Bucket, IAMRole, etc. |
| `conditions` | object | Key-value conditions on Resource node properties |
| `conditions.check_rules_failing` | list | rule_ids from check_findings (OR semantics) |
| `conditions.internet_exposed` | bool | Aggregated flag on Resource node |
| `conditions.is_crown_jewel` | bool | Target-only; required on all Tier 3 target specs |

**`hops` (Tier 2/3 only):**

| Field | Type | Notes |
|---|---|---|
| `edge_type` | string | From `resource_security_relationship_rules` |
| `target` | object | Node spec for hop destination |

**`cdr_watch` (Tier 3 optional; activates CDR overlay):**

| Field | Type | Notes |
|---|---|---|
| `techniques` | list | MITRE technique IDs to watch |
| `window_minutes` | integer | CDR event lookback window |
| `min_coverage` | float | 0.0–1.0; fraction of techniques required for active class |
| `tactic_order_required` | bool | Tactics must appear in chain order |

**`scoring` overrides:**

| Field | Type | Notes |
|---|---|---|
| `posture_severity` | string | Override severity when no CDR match |
| `active_severity` | string | Override severity when CDR match fires |
| `path_length_bonus` | bool | Longer paths score higher |

### 8.2 Compilation Rules

**CP1-01 is the single highest-priority rule for PatternCompiler.**

| Rule | Description |
|---|---|
| Parameterized values only | Every value derived from `resource_types`, `check_rules_failing`, `edge_type`, `conditions.*` MUST appear as `$param` in compiled Cypher. No f-strings, no `%s`, no `.format()` |
| `$tenant_id` mandatory | Every compiled Cypher query MUST contain `$tenant_id` or `$tid` as a parameter in the WHERE clause of the first MATCH. CI gate validates this. |
| Template expander model | PatternCompiler is implemented as: select from a library of safe Cypher templates keyed by hop count + pattern tier; substitute `$params` for all values. It is NOT a Cypher string builder. |
| No user-supplied Cypher | Pattern YAML files contain no raw Cypher. The PatternCompiler is the only component that generates Cypher. |
| Timeout on every execution | `session.run(compiled_cypher, params, timeout=500)` — W-02 |

**Example (correct vs. incorrect):**

```python
# WRONG — pattern field interpolated into Cypher string
cypher = f"MATCH (r:Resource {{resource_type: '{entry_type}', tenant_id: $tid}})"

# CORRECT — all values as $params
cypher = "MATCH (r:Resource {resource_type: $entry_type, tenant_id: $tid})"
session.run(cypher, entry_type=entry_type, tid=tenant_id, timeout=500)
```

### 8.3 3-Tier Hierarchy

| Tier | Name | Cypher Class | CDR Overlay | Latency Target | Incident Class |
|---|---|---|---|---|---|
| Tier 1 | Toxic Combination | Single-node property check; no traversal | None | < 10ms | posture (severity ≤ HIGH) |
| Tier 2 | Partial Attack Path | Multi-hop traversal; crown jewel not required; `min_hops_for_tier2` hops present | Optional; posture only | < 500ms | posture (severity = MEDIUM) |
| Tier 3 | Full Attack Path | Complete entry → crown jewel traversal | Required for escalation to active | < 2s | posture / suspicious / active |

**Tier 3 CDR signal grading:**

| CDR Signal State | `incident_class` | Severity |
|---|---|---|
| 0 CDR signals on path | posture | HIGH |
| 1 CDR technique observed (below `min_coverage`) | suspicious | HIGH |
| ≥2 CDR techniques OR `min_coverage` met | active | CRITICAL |

### 8.4 Pattern Authoring Workflow

```
1. Engineer creates:
     catalog/threat_patterns/{tier}/{csp}/PAT-{CSP}-{NNN}.yaml

2. Local validation (CLI at engines/threat_v1/cli/):
     threat-v1 pattern validate <path>   # Pydantic schema check
     threat-v1 pattern compile <path>    # Cypher generation (dry-run)
     threat-v1 pattern test <path>       # positive + negative test runner

3. PR submitted — CI runs:
     - YAML schema validation (Pydantic models)
     - Cypher parameterization linter (rejects interpolated values)
     - $tenant_id presence check on every compiled query
     - Cypher compilation against Neo4j test fixture
     - MITRE technique ID validation against ATT&CK catalog
     - Positive test fires on fixture within tier latency budget
     - Negative test does NOT fire on fixture

4. Review gates (both mandatory before merge):
     - Detection engineer sign-off
     - Security architect review for any new tactic chain (ATT&CK + D3FEND)

5. Merge → engine startup:
     upload_scenario_patterns.py loads YAML to threat_scenario_patterns
     Per-pattern errors caught and logged; engine does NOT crash (W-03)
```

### 8.5 v1 Pattern Library Targets

| Tier | Count | CSP Focus | Example Pattern |
|---|---|---|---|
| Tier 1 | 10 | AWS-first | EC2 with `internet_exposed + has_critical_cve + is_admin_role` |
| Tier 2 | 10 | AWS-first | EC2 → IAMRole path present but S3 target not reached |
| Tier 3 | 10 | AWS (507 tagged rules available) | Capital One: EC2 (IMDSv1) → IAMRole (admin) → S3 (crown jewel) |
| **Total v1** | **30** | | 30 patterns with positive + negative tests + security review |

Additional patterns ship in Phase 8. Count is not compromised for test coverage.

---

## 9. 3-Pane UI Architecture ("Threat Center")

*Corresponds to C4 diagram page 4 (L3 UI Architecture) in `engines/threat_v1/threat_v1_c4_architecture.drawio` and `engines/threat_v1/threat_v1_ui_flow.drawio`.*

### 9.1 Layout — 3 Zones

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Zone A                │  Zone B                │  Zone C               │
│  Filter Sidebar        │  Incident List          │  Investigation Panel  │
│  (220px fixed)         │  (flex, scrollable)     │  (400px, side panel)  │
│                        │                         │                       │
│  ● Tier (1/2/3)        │  ┌─────────────────┐   │  [9 sections]         │
│  ● Status              │  │ Incident card   │   │                       │
│  ● Severity            │  │ • tier badge    │   │  Always visible;      │
│  ● CSP                 │  │ • severity      │   │  no blank space;      │
│  ● MITRE Tactic        │  │ • entry→target  │   │  no empty states      │
│  ● Incident Class      │  │ • incident_class│   │                       │
│  ● Attack Path Only    │  │ • first_seen    │   │  Click incident →     │
│                        │  └─────────────────┘   │  Zone C updates       │
│  Counts update on      │  (click → Zone C)       │  in place             │
│  filter change         │                         │                       │
└─────────────────────────────────────────────────────────────────────────┘
```

**Zone C is a side panel, NOT a popup or modal.** See ADR-001.

### 9.2 Zone C — Investigation Panel (9 Sections)

Zone C must have no blank space at any time. All 9 sections are present for every incident; sections collapse gracefully when data is absent (show placeholder text, never empty space).

| Section | Content | Data Source |
|---|---|---|
| 1. Header | `incident_class` badge, severity chip, tier badge, status | `threat_incidents` |
| 2. Story | `story_text` narrative | `IncidentDetail.story_text` |
| 3. Attack Path | Horizontal hop chain with resource type icons; entry → pivot(s) → target | `evidence.path_resources` |
| 4. MITRE Chain | Tactic sequence with technique badges | `mitre_tactics`, `mitre_techniques` |
| 5. Misconfig Evidence | Table of failing check rules with severity | `evidence.misconfig_findings` |
| 6. CVE Evidence | CVE list with CVSS, EPSS, exploit flag | `evidence.vuln_findings` |
| 7. CDR Activity | Actor activity timeline; PII gated (requires `cdr:sensitive`) | `evidence.cdr_events` |
| 8. Recommendations | Ordered action list with MITRE remediation links | `recommendations` |
| 9. Matched Patterns | Pattern ID, version, match timestamp | `evidence.matched_patterns` |

### 9.3 Node Click Behavior

When a user clicks a resource node in the attack path (Section 3):

1. An inline `HopCard` expands below the clicked node showing resource metadata (resource_type, region, account_id, key flags)
2. A "View Full Asset" link navigates to `/inventory/assets/{resource_uid}?from=threat`
3. No slide-over modal, no popup. The HopCard is inline within Zone C. See ADR-002.

### 9.4 Inventory Threat Tab — 5 New Fields

The inventory asset detail view gains a new Threat tab when `on_attack_path=true`. This tab surfaces:

| Field | Source | Notes |
|---|---|---|
| `on_attack_path` | Neo4j Resource node property | Set by PathTagger after Tier 3 match |
| `incident_ids[]` | `threat_incidents WHERE entry_resource_uid = uid OR target_resource_uid = uid` | BFF join |
| `hop_position` | `evidence.path_resources[].position` | 0 = entry, N = target |
| `enabling_technique_ids[]` | `mitre_techniques` from all incidents for this resource | Aggregate |
| `cdr_event_count` | Count of `CDREvent` nodes attached to this resource in Neo4j | Graph query |

BFF view `inventory_asset_threat/{uid}` must re-validate that all `incident_id` values belong to `auth_ctx.tenant_id` before returning (W-06).

The Threat tab is hidden (not rendered) when `on_attack_path=false` and `incident_ids` is empty.

### 9.5 BFF Views Summary

| View | BFF Path | Assembles | Frontend Page |
|---|---|---|---|
| `threat_center` | `/gateway/api/v1/views/threat_center` | Incident list + filter counts | `/threat` |
| `incident_detail` | `/gateway/api/v1/views/incident_detail/{id}` | Full Zone C data for one incident | `/threat` (Zone C) |
| `threat_graph` | `/gateway/api/v1/views/threat_graph` | On-attack-path nodes for graph overlay | `/threat` (graph view) |
| `inventory_asset_threat` | `/gateway/api/v1/views/inventory_asset_threat/{uid}` | 5 threat fields for inventory Threat tab | `/inventory/assets/{uid}` |

---

## 10. Deployment Architecture

### 10.1 Kubernetes

| Parameter | Value |
|---|---|
| Namespace | `threat-engine-engines` |
| Deployment name | `engine-threat-v1` |
| Service port | 8021 |
| Manifest path | `deployment/aws/eks/engines/engine-threat-v1.yaml` |
| Image naming | `yadavanup84/engine-threat-v1:v-threat-v1-phase{N}` |
| Never use | `:latest` (CP1-08 + platform constitution) |
| Resource limits | Required: `requests` + `limits` on every container spec |
| Probes | `livenessProbe: GET /api/v1/health/live`, `readinessProbe: GET /api/v1/health/ready` |

**Image tag convention per phase:**

| Phase | Tag |
|---|---|
| Phase 1 foundations | `v-threat-v1-phase1` |
| Phase 2 graph builder | `v-threat-v1-phase2` |
| Phase 3 pattern executor | `v-threat-v1-phase3` |
| Phase 4 incident management | `v-threat-v1-phase4` |
| Phase 5 pattern library | `v-threat-v1-phase5` |
| Phase 6 validation | `v-threat-v1-phase6` |
| Shadow mode | `v-threat-v1-shadow1` |

### 10.2 Argo Workflow Position

```yaml
# Argo DAG step (engines/threat_v1 Argo template fragment)
- name: threat-v1-scan
  dependencies: [check-scan, vulnerability-scan]
  template: threat-v1-scan-template
  arguments:
    parameters:
      - name: tenant_id
        value: "{{inputs.parameters.tenant_id}}"
      - name: account_id
        value: "{{inputs.parameters.account_id}}"
      - name: scan_run_id
        value: "{{inputs.parameters.scan_run_id}}"
```

Template spec (`engines/threat_v1` container):
- `image: yadavanup84/engine-threat-v1:v-threat-v1-phase{N}` (pinned tag)
- `command: ["python", "-m", "run_scan"]`
- `args: ["--tenant-id={{inputs.parameters.tenant_id}}", "--account-id={{inputs.parameters.account_id}}", "--scan-run-id={{inputs.parameters.scan_run_id}}"]`

**CDR CronWorkflow trigger** (separate Argo CronWorkflow, runs after CDR scan completes):
- Same image, additional arg: `--mode=cdr-update`
- CDR trigger waits up to 5 minutes if full pipeline holds the advisory lock for the same tenant; exits cleanly if exceeded (retries on next CDR cycle — 3h)

### 10.3 Concurrency Model

| Mechanism | Detail |
|---|---|
| Per-tenant advisory lock | `pg_advisory_lock(hashtext(tenant_id || '\|' || account_id))` — hash must include account_id (W-01) |
| Lock scope | Held during entire graph build; released on completion or exception |
| Cross-trigger behavior | CDR trigger waits max 5min; full pipeline trigger always takes precedence |
| Incident upserts | `ON CONFLICT (dedup_key) DO UPDATE` — safe for concurrent writes across tenants |
| No Redis, no distributed lock manager | Advisory lock on existing Postgres is sufficient for v1 batch model |

### 10.4 Failure Modes

| Failure | Behavior |
|---|---|
| Neo4j unavailable at scan start | Fail fast; `threat_scan_runs_v1.status = failed`; Argo retries on next trigger |
| Postgres unavailable | Fail fast |
| Individual pattern execution error | Log + skip pattern + continue; error counted in per-pattern metrics |
| Pattern Cypher timeout (500ms) | Skip pattern; count as timeout; triggers auto-quarantine if repeated 3 consecutive runs |
| Argo SIGTERM / spot preemption | Next trigger does full graph rebuild (all operations idempotent via MERGE / ON CONFLICT) |
| Stale resource nodes (>90 days, no findings) | Nightly reaper CronWorkflow deletes Resource nodes where `last_seen < NOW() - 90d` and no finding nodes attached |

### 10.5 Neo4j Connection

- Aura URI: `neo4j+s://17ec5cbb.databases.neo4j.io`
- Named database: `threat_v1` (isolated from existing production graph in default database)
- Credentials: resolved from AWS Secrets Manager (platform constitution: credential resolution via Secrets Manager, never bare env vars)
- Connection configured with `optional: false` — silent Neo4j credential failures are unacceptable

---

## 11. Implementation Phases

*Full phase detail: REQUIREMENTS.md §14. This section maps phases to dependencies and sequencing.*

### Phase Map

| Phase | Name | Duration | Depends On | Deliverable |
|---|---|---|---|---|
| 0 | MITRE Tagging | 1 week (parallel with Phase 1) | Existing catalog | ≥500 additional MITRE-tagged rules; CVE T1190 heuristic; CDR cloudtrail → technique map |
| 1 | Foundations | 1 week | — | Project structure, graph schema DDL, Pattern DSL Pydantic validators, `upload_scenario_patterns.py` |
| 2 | GraphBuilder | 1.5 weeks | Phase 1 | ResourceResolver, MisconfigLoader, VulnLoader, CDRLoader, EdgeBuilder, CrownJewelClassifier, PathTagger |
| 3 | PatternExecutor | 1.5 weeks | Phase 2 | GraphAdapter, PatternRegistry, PatternCompiler, Tier1/2/3Matchers, PatternExecutor orchestrator |
| 4 | Incident Management | 1 week | Phase 3 | `threat_incidents` DDL, SeverityScorer, IncidentDeduper, IncidentWriter, StoryBuilder, `run_scan.py` full pipeline |
| 5 | Pattern Library v1 | 2 weeks | Phase 4 + Phase 0 (partial) | 10 Tier 1 + 10 Tier 2 + 10 Tier 3 patterns; security architect review gate on all 30 |
| 6 | Validation & Observability | 1.5 weeks | Phase 5 | Pattern test harness, per-pattern metrics, per-tenant metrics, FP feedback loop, auto-quarantine, pattern/coverage API |
| 7 (Shadow) | Shadow Mode | 1 week | Phase 6 | Parallel run alongside `engines/threat/`; shadow output comparison; zero customer-facing alerts |
| 7 (Parallel) | Parallel Mode | 1 week | Shadow validation | Both engines visible with source tags; customer feedback collection |
| UI | Threat Center | Alongside Phase 4–6 | Phase 4 API | Zone A/B/C components, HopCard, inventory Threat tab, BFF views |

### Phase 0 Sequencing Detail

Phase 0 runs in parallel with Phase 1. The first 5 Tier 3 patterns (Phase 5) can be authored using the 507 already-tagged AWS rules — Phase 0 is not a hard blocker for Phase 5 start, but unlocks the remaining 25 patterns. Patterns must not be authored for untagged rules — the MITRE technique field cannot be inferred without tagging.

### Phase 7 Gate Criteria (Switchover to v1 as Primary)

All must pass before replacing `engines/threat/` in the Argo DAG:

| Gate | Threshold |
|---|---|
| Detection coverage | threat-v1 produces ≥ all existing detections from v0 (zero regression) |
| FP rate | Rolling 30d FP rate < 30% across all enabled patterns |
| Open P0/P1 bugs | 0 older than 7 days |
| Customer NPS | ≥ neutral on new threat-v1 incidents |

**Switchover steps:**

1. Replace `engines/threat/` in Argo DAG with `engines/threat_v1/`
2. Run one-time migration script to move open incidents from old tables to `threat_incidents`
3. Old engine tables remain readable for 90 days, then archived
4. Old engine image kept in ECR for rollback capability

---

## 12. Architecture Decision Records

### ADR-001: Zone C — Side Panel, Not Popup

**Date:** 2026-05-10  
**Status:** Accepted  
**Context:** The Threat Center requires a detail view for each incident. Two implementation options were evaluated: (A) popup/modal that opens on incident click, (B) persistent side panel that updates in place.

**Decision:** Zone C is a persistent side panel (ADR confirmed in design session 2026-05-10).

| Factor | Popup (A) | Side Panel (B) |
|---|---|---|
| Investigation continuity | Lost on click-out or ESC | Preserved across incident list navigation |
| Multiple incident comparison | Impossible | Scroll Zone B while Zone C holds current |
| Keyboard navigation | Trap focus in modal | Zone B remains navigable |
| URL-addressability | Requires modal URL state | Incident ID in URL path (deep-linkable) |
| Scroll state loss | Yes — modal re-mounts | No — panel persists in layout |

**Consequences:** Zone C must be 400px fixed-width column in the layout tree, not a z-index overlay. The 3-column layout shifts at mobile breakpoints (Zone A collapses, Zone C becomes full-screen).

---

### ADR-002: Node Click → Inline HopCard + Inventory Redirect

**Date:** 2026-05-10  
**Status:** Accepted  
**Context:** When a user clicks a resource node in the Zone C attack path visualization, they need to see resource metadata and optionally navigate to the full inventory asset detail view.

**Decision:** Node click expands an inline `HopCard` within Zone C Section 3 (attack path). The HopCard shows resource metadata (resource_type, region, account_id, key flags). A "View Full Asset" link navigates to `/inventory/assets/{resource_uid}?from=threat`. No slide-over modal. No second panel.

**Rationale:**

| Option | Problem |
|---|---|
| Open new tab | Loses Zone C investigation context |
| Slide-over modal | Third overlapping layer confuses navigation depth |
| Replace Zone C content | Loses incident detail; back button breaks expectation |
| Inline HopCard + redirect link | Preserves Zone C; gives quick metadata; redirect is explicit user action |

**`?from=threat` query param:** The inventory asset page uses this to render a "Back to Threat Center" breadcrumb and pre-select the Threat tab.

**Consequences:** HopCard component is part of the Zone C attack path section, not a standalone component. It receives `resource_uid` as prop and fetches metadata from the BFF `inventory_asset_threat/{uid}` view.

---

### ADR-003: Per-Tenant FP Suppression (Not Global Pattern Deactivation)

**Date:** 2026-05-10  
**Status:** Accepted (CP1-05)  
**Context:** The FeedbackProcessor needs to respond when a pattern generates a high rate of false positive verdicts. Two options: (A) set `active=false` on the shared `threat_scenario_patterns` row (global deactivation), (B) insert a per-tenant row in `threat_pattern_suppressions`.

**Decision:** Auto-quarantine is always per-tenant (Option B). Global deactivation (`active=false` on shared pattern) requires security architect approval and a manual update.

**Threat model:** Option A is a denial-of-service attack surface. A compromised account submitting 30 days of FP verdicts would silence a high-value detection pattern for all tenants on the platform (PASTA Goal 3). This attack has no recovery path for other tenants.

**Implementation:**

```
FeedbackProcessor.process():
    if rolling_30d_fp_rate(tenant_id, pattern_id) > 0.30:
        INSERT INTO threat_pattern_suppressions
            (tenant_id, pattern_id, reason, auto_generated)
        VALUES (:tid, :pid, 'FP rate > 30% rolling 30d', true)
        ON CONFLICT (tenant_id, pattern_id) DO UPDATE
            SET reason = EXCLUDED.reason, created_at = NOW();
        # Do NOT update threat_scenario_patterns.active
```

**Consequences:** PatternRegistry must join `threat_pattern_suppressions` on `(tenant_id, pattern_id)` when loading active patterns. A suppressed pattern for Tenant A still fires for Tenant B.

---

### ADR-004: Parameterized Cypher Only — No Ad-Hoc Query Endpoint

**Date:** 2026-05-10  
**Status:** Accepted (CP1-01 + CP1-06)  
**Context:** Threat hunting requires querying the Neo4j graph. One option was to expose `POST /api/v1/hunt/execute` accepting a `cypher` body. The existing v0 engine has 47 ad-hoc Cypher queries in the DB, which are difficult to audit and have no parameterization enforcement.

**Decision:** No ad-hoc Cypher endpoint exists in threat_v1. All graph queries are produced by PatternCompiler from validated YAML patterns. Pre-defined hunt queries (from `threat_hunt_queries` table) are executed server-side via named query IDs, not by sending Cypher strings from the client.

**Threat model:**
- Sending raw Cypher from client to server is equivalent to SQL injection: any tenant data visible to the Neo4j connection is accessible
- In a shared named database, a missing `$tenant_id` filter in ad-hoc Cypher returns cross-tenant nodes
- There is no safe client-side Cypher validation approach

**Consequences:** Pattern authors use the CLI tooling (`threat-v1 pattern compile`) to develop and test Cypher. Custom hunt queries must be written as named patterns, reviewed via PR, and loaded to `threat_hunt_queries`. This is a more friction-heavy developer experience but eliminates an entire injection attack class.

---

### ADR-005: Two Pydantic Response Models for Incident Evidence (PII Protection)

**Date:** 2026-05-10  
**Status:** Accepted (CP1-02)  
**Context:** The `evidence` JSONB field in `threat_incidents` contains CDR event data including `actor_principal` (email/ARN), `source_ip`, and `action`. This is PII-equivalent data that must be access-controlled. The simplest implementation would use one response model with optional fields, but optional fields in a JSON API are easily forgotten or inconsistently applied.

**Decision:** Two distinct Pydantic response models: `IncidentListItem` (list endpoint) and `IncidentDetail` (single incident endpoint). The models differ structurally — `IncidentListItem` does not have slots for PII fields, making omission impossible to bypass. `IncidentDetail` includes PII fields but the endpoint additionally checks `cdr:sensitive` permission before populating them.

**Why two models, not one model with `Optional` fields:**

| Approach | Risk |
|---|---|
| One model, `Optional` fields, conditional exclude | Future developer adds a new endpoint, imports one model, forgets to call `strip_sensitive_fields()` — PII leaks |
| Two models, structural separation | New endpoint author must explicitly choose `IncidentDetail` and the `cdr:sensitive` check — the type system makes omission visible |

**`evidence._schema_version`:** The `evidence` JSONB carries a `_schema_version` integer. When the schema evolves, the version is bumped. Migration path for schema evolution is a Phase 8 ADR (W-08). Both response models must handle older schema versions gracefully (return available fields, log warning for unknown schema version).

**Consequences:** Any new endpoint that returns incident evidence must explicitly choose which model to use. The choice must be reviewed in the security review gate. There is no shared base model with PII fields.

---

*End of Architecture Document*

**Key file paths for implementation:**

- Requirements: `engines/threat_v1/REQUIREMENTS.md`
- C4 diagrams: `engines/threat_v1/threat_v1_c4_architecture.drawio`
- UI flow diagram: `engines/threat_v1/threat_v1_ui_flow.drawio`
- Engine package: `engines/threat_v1/threat_v1/`
- Pattern catalog: `catalog/threat_patterns/` (to be created in Phase 1)
- K8s manifest: `deployment/aws/eks/engines/engine-threat-v1.yaml` (to be created in Phase 1)
- Argo pipeline: `deployment/aws/eks/argo/cspm-pipeline.yaml` (to be updated in Phase 4)
- DB schema: `shared/database/schemas/threat_v1_schema.sql` (to be created in Phase 1)
- Existing v0 engine (reference): `engines/threat/`
