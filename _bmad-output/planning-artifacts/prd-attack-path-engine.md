---
title: "PRD — Attack Path Engine"
type: prd
status: draft
version: "1.0"
date: "2026-05-15"
author: "Anup Yadave"
engine: "engine-attack-path"
port: 8025
pipeline_stage: 6.5
depends_on:
  - graph-build (stage 6)
consumed_by:
  - engine-risk (stage 7)
  - engine-threat-narrative (stage 8)
  - shared/api_gateway/bff/attack_paths.py
  - frontend/src/app/threats/attack-paths/
---

# PRD: Attack Path Engine

## 1. Problem Statement

CSPM platforms today surface thousands of individual findings — misconfigurations, CVEs, IAM
permission gaps, exposed network ports — but they present each finding in isolation. A security
analyst staring at 4,200 findings cannot answer the one question that matters operationally:
"Which of these actually lets an attacker reach our customer data?"

The platform currently has no way to show:
- Which misconfigs and IAM gaps chain together into a traversable route to a sensitive resource
- Which resources sit at the intersection of multiple such routes (choke points)
- How long a dangerous path has been open
- What a single remediation action buys in terms of paths blocked

This product requirement describes an Attack Path Engine that discovers, scores, deduplicates,
and persists attack paths — chains of exploitable relationships from external entry points to
crown jewel assets. It enables operators to answer the operational question: "What do I fix first
to eliminate the most attacker-reachable risk?"

### 1.1 Why This Matters Now

Three trends make this urgent:

1. **Graph infrastructure exists.** The platform already runs Neo4j Aura with resource nodes,
   IAM edges (ASSUMES, CAN_ACCESS), network edges (CONNECTED_TO, EXPOSES), and CVE nodes. The
   raw data for path discovery is in place. No additional discovery work is needed.

2. **Competitive gap is widening.** Wiz launched "Security Graph" in 2022; Orca has had attack
   path analysis since 2021. Both are cited in analyst evaluations. Customers explicitly ask for
   it during sales calls. Without it the platform cannot close enterprise deals.

3. **Risk engine is limited without paths.** The current risk score is per-resource additive.
   It does not model whether a high-risk resource is actually reachable from the internet or sits
   behind compensating controls. Attack path signals are the missing input that makes risk scores
   meaningful to CISOs.

---

## 2. Goals

### 2.1 Primary Goals

**G1 — Attack Path Discovery:**
Discover all structural paths from external entry points (Internet, OnPrem, VPN, PeerAccount,
Vendor, K8sExternal) to crown jewel assets by traversing the Neo4j resource graph. Cover all
six CSPs supported by the platform.

**G2 — Prioritised Scoring:**
Score each path using a Probability × Impact formula (not additive summation) so operators
get a defensible ranking rather than a flat list sorted by hop count.

**G3 — Noise Reduction via Deduplication:**
Reduce 5,000+ raw traversal results to fewer than 200 representative paths per tenant via
three-phase deduplication: exact hash dedup, subpath absorption, and convergence grouping.

**G4 — Choke Point Identification:**
Surface the top 10 nodes whose remediation would break the most paths. Give operators a
"fix one, break many" lever.

**G5 — Path History and Aging:**
Track each path's `first_seen_at`, score trajectory, and node composition across scans so
analysts know how long a path has been open and whether it is getting worse.

**G6 — Risk Engine Integration:**
Write `is_on_attack_path`, `is_choke_point`, and `blast_radius_count` signals to the
`resource_security_posture` table so the risk engine can incorporate attack-path context into
its resource risk scores.

**G7 — Competitive Parity:**
Match Wiz Security Graph and Orca attack path analysis on feature surface, path quality, and
UI presentation depth within the scope of this sprint.

### 2.2 Non-Goals

The following are explicitly out of scope for this engine:

- **Threat detection / behavioral analysis** — detection of active intrusions stays in
  `engine-threat` (MITRE T1/T2 incident patterns). Attack path engine is a structural analysis,
  not a detection engine.
- **Runtime behavioral signals beyond CDR elevation** — CDR actor presence is consumed as a
  probability booster, but the CDR engine remains responsible for producing those signals.
- **Risk score computation** — the risk engine (`engine-risk`) owns the final risk score
  formula. This engine provides inputs, not outputs, to the risk score.
- **Remediation execution** — the engine surfaces what to fix; execution is handled by
  `secops-fix` / `vul-fix`. Remediation suggestions per path are a P2 future item.
- **Path suppression UI** — storing suppression state is a P2 item. Not in scope for v1.
- **Cross-cloud paths (AWS→Azure)** — requires cross-cloud IAM trust detection. Deferred to P1
  follow-on sprint.

---

## 3. User Personas

### 3.1 Security Analyst (`analyst` role)

**Job to be done:** Triage the most dangerous exposure in a cloud environment. The analyst
reviews daily scan results, investigates specific paths, and understands per-hop evidence so
they can write a meaningful finding ticket.

**How they use this product:**
- Opens the Attack Paths list filtered to critical severity
- Reads the path summary: chain type, depth, time open, CDR actor present
- Drills into a path to read the per-hop story: what edge exists, why it is traversable, which
  misconfig or CVE enables each hop
- Uses the choke points panel to identify which one fix breaks the most paths
- Exports evidence to a ticket

**Pain point today:** Has to mentally assemble attack chains from 10+ individual check findings.
No way to know which findings are related to each other or which ones are on a traversable route.

### 3.2 Tenant Admin (`tenant_admin` role)

**Job to be done:** Configure what matters to their organisation. Ensure the platform's crown
jewel classification matches their actual data sensitivity designations.

**How they use this product:**
- Reviews the Crown Jewels list to verify auto-classification is correct
- Manually tags or untags resources via the PATCH endpoint (e.g., "this S3 bucket holds only
  build artifacts — it is not PII")
- Monitors how manual overrides affect path counts and choke points

**Pain point today:** No way to tell the platform "this database matters more than that one."
Risk scores are uniform across resource types with no organisational weighting.

### 3.3 CISO / Viewer (`viewer` role)

**Job to be done:** Understand posture at a glance. Report to the board: "How many critical
attack paths does our cloud environment have, and are we improving?"

**How they use this product:**
- Reads KPIs on the Attack Paths summary panel: total critical paths, choke points, longest
  open path age
- Looks at the trend chart: is the critical path count going up or down week-over-week?
- Does not need per-hop detail — summary numbers are sufficient

**Pain point today:** The existing risk dashboard shows resource counts and severity buckets
but does not answer "could an attacker actually GET to our crown jewels right now?"

---

## 4. Functional Requirements

### FR1 — Crown Jewel Auto-Classification

The engine must automatically classify resources as crown jewels based on resource type and
associated posture signals without any manual configuration.

Auto-classification criteria (resource matches ANY condition = `is_crown_jewel: true`):

| Resource Type | Condition |
|---|---|
| s3.bucket, blob.container, gcs.bucket, oci.object_storage | data_classification IN (pii, financial, credentials) |
| rds.instance, aurora.cluster, cloud_sql.instance, oci.autonomous_db | always |
| secretsmanager.secret, ssm.parameter (SecureString) | always |
| iam.role, iam.user | is_admin_role=true OR has_wildcard_policy=true |
| eks.cluster, aks.cluster, gke.cluster | always |
| ecr.repository, acr.registry, gcr.repository | always |
| sagemaker.endpoint, bedrock.model | always |
| redshift.cluster, elasticsearch.domain | always |
| kms.key, key_vault.key | always |
| cloudformation.stack | has admin IAM role permissions |

Classification runs at the start of each scan before path traversal. Results are written to
`resource_security_posture.is_crown_jewel` and as a Neo4j node property.

Acceptance criterion: At least 90% of known-sensitive resources in the test tenant are
classified as crown jewels without manual intervention (crown jewel recall ≥ 90%).

### FR2 — Manual Crown Jewel Override

Tenant admins, org admins, and platform admins must be able to manually tag or untag any
resource as a crown jewel via the `PATCH /api/v1/crown-jewels/{resource_uid}` endpoint.

- Override is stored in `crown_jewel_overrides` table with the user email (`set_by`) and a
  reason string.
- Manual overrides always take precedence over auto-classification.
- A manual `is_crown_jewel: false` override suppresses auto-classification for that resource
  until the override is removed.
- Changes take effect in the next scan run. The engine reads overrides during the classification
  phase before traversal begins.

### FR3 — Reverse BFS Path Traversal

The engine must traverse the Neo4j resource graph backward from each crown jewel to external
entry points using a bounded depth-first traversal.

Traversal parameters:
- Direction: backward (crown jewel → origin), following PATH edges in reverse
- Maximum depth: 7 hops
- Termination condition: reaching a VirtualNode (Internet, OnPrem, VPN, PeerAccount, Vendor,
  K8sExternal) OR reaching an internet-exposed resource
- Query limit: LIMIT 500 raw paths per crown jewel (Cypher-level limit to prevent Neo4j OOM)
- Query timeout: 30 seconds (enforced at Neo4j driver level)

Rationale for reverse traversal: Crown jewels are ~100–200 nodes per tenant. Internet-exposed
resources may be thousands. Starting from the smaller set is more efficient and guarantees
every result terminates at a crown jewel.

### FR4 — External Entry Point Types

The engine must recognise and correctly label six categories of external origin:

| Entry Point Type | Description | Example |
|---|---|---|
| `internet` | Resource directly internet-exposed (is_internet_exposed=true or EXPOSES edge from Internet:VirtualNode) | EC2 with 0.0.0.0/0 SG rule |
| `onprem` | Reachable via DirectConnect, ExpressRoute, or FastConnect | VPC peered to corporate network |
| `vpn` | Reachable via customer VPN gateway | Site-to-site VPN endpoint |
| `peer_account` | Reachable from a peered AWS/Azure/GCP account | VPC peering / Shared VPC |
| `vendor` | Reachable from a third-party managed service | Cross-account role for vendor |
| `k8s_external` | Exposed via LoadBalancer or NodePort Kubernetes service | EKS LoadBalancer service |

Entry point type determines the base probability in the scoring formula (see FR5).

### FR5 — Probability × Impact Scoring

Each path receives a numeric score from 0 to 100 computed as:

```
path_score = round(min(100, P(path) × I(path) × 100))
```

Severity buckets:
- Critical: score ≥ 80
- High: 60–79
- Medium: 40–59
- Low: < 40

**Probability P(path):**

Base probability by entry point type:
- internet: 0.90
- vpn / onprem: 0.60
- peer_account: 0.40
- vendor / k8s_external: 0.30

Per-hop multipliers (cumulative product):
- CVE with EPSS > 0.70: × 0.95
- CVE with EPSS 0.30–0.70: × 0.80
- Critical misconfig on node: × 0.85
- High misconfig on node: × 0.75

Mitigating control discounts (reduce probability but never eliminate path):
- WAF protected: × 0.80
- MFA required: × 0.50
- Permission boundary present: × 0.70

**CDR elevation:** If any node on the path has `has_active_cdr_actor=true`, multiply final
probability by 1.40 (capped at 1.0). This reflects that an active threat actor already on the
path makes traversal significantly more likely.

**Impact I(path):**

Base by crown jewel type:
- data: 1.00
- secrets: 0.95
- identity: 0.90
- infra_control: 0.85
- ai_model: 0.85
- code: 0.80
- other: 0.60

Data classification multiplier:
- pii: × 1.20
- financial / credentials: × 1.15

Blast radius multiplier:
- blast_radius_count > 50: × 1.30
- blast_radius_count > 10: × 1.15

Encryption gap (data at rest not KMS-protected):
- encryption_type IN (none, sse): × 1.10

Both `probability_score` and `impact_score` are stored separately in `attack_paths` so the
UI can display them independently. Operators can filter "high impact regardless of probability"
to find latent risk.

### FR6 — CDR Actor Elevation

If a CDR actor has been observed active on any node in a path (sourced from
`resource_security_posture.has_active_cdr_actor`), the path's probability score is boosted
by × 1.40 (floor of 1.0).

The path record stores `has_active_cdr_actor: true` and each node in `attack_path_nodes` stores
`cdr_actor_active` and `cdr_actor_uid` for the per-hop story display.

This signal is read from `resource_security_posture` — written by `engine-cdr`. The attack path
engine does NOT query the CDR engine directly.

### FR7 — Mitigating Control Discounts

The scoring model must reduce path probability (but never set it to zero) when a mitigating
control is present on a path node. Paths remain in the findings set even if fully mitigated —
the control could be removed at any time.

Controls and their probability multipliers:
- WAF protection (`waf_protected=true`): × 0.80
- MFA enforcement (`mfa_required=true`): × 0.50
- IAM permission boundary (`has_permission_boundary=true`): × 0.70

The combined effect of all three controls on a single node would reduce probability to
0.90 × 0.80 × 0.50 × 0.70 = 0.252 — a substantial reduction, but not elimination.

### FR8 — Three-Phase Deduplication

Raw Cypher results can return thousands of paths. The engine must reduce this to a manageable
set before writing to the database.

**Phase 1 — Exact dedup:**
Compute `sha256("|".join(node_uids))`. If two paths share the same hash, keep the one with
the higher score.

**Phase 2 — Subpath absorption:**
For each path, check if any shorter path is a suffix of it. If the shorter path's entry node
is NOT independently internet-exposed, absorb the shorter path into the longer one. The longer
path stores `absorbed_count` indicating how many subpaths were folded in.

Rationale: A 2-hop path `EC2 → S3` that is a suffix of `Internet → EC2 → S3` is not an
independent exposure — the EC2 is only reachable because of the longer path. Absorbing it
reduces noise without losing information.

**Phase 3 — Convergence grouping:**
Paths that share the same `(crown_jewel_uid, last-2-node-types)` tail are assigned a common
`group_id`. The highest-scoring path in the group is marked `is_representative: true`. The
penultimate node in the shared tail is identified as the `choke_node_uid` for that group.

The BFF default view shows only representative paths with a badge: "3 similar paths." The full
group is expandable in the UI.

Target: fewer than 200 representative paths per tenant after all three phases.

### FR9 — Choke Point Detection

After deduplication, the engine must identify the top 10 nodes that appear as `choke_node_uid`
across the most distinct `group_id` values.

For each choke point node, compute:
- `paths_blocked_if_fixed`: count of representative paths this node appears in as choke_node
- `avg_path_score`: average score of those paths

Results are written to `resource_security_posture.is_choke_point=true` and
`choke_point_path_count` for the top 10 nodes.

The `GET /api/v1/choke-points` endpoint returns the list sorted by `paths_blocked_if_fixed`
descending.

### FR10 — Per-Hop Path Story

The `GET /api/v1/attack-paths/{path_id}` endpoint must return a full per-hop story stored in
`attack_path_nodes`. For each hop the story includes:

- `hop_index`: position in the path (0 = entry point, N = crown jewel)
- `node_uid`, `node_name`, `node_type`: resource identity
- `edge_to_next`: type of edge to the next hop (ASSUMES, CAN_ACCESS, CONNECTED_TO, EXPOSES)
- `edge_category`: attack path category (initial_access, privilege_escalation, data_access,
  lateral_movement, credential_access)
- `traversal_reason`: human-readable explanation of why this hop is traversable
  (e.g., "EC2 has IamInstanceProfile with role web-prod-role attached")
- `policy_statement`: for IAM edges, the relevant policy JSON (actions, resource, effect)
- `sg_rule`: for network edges, the relevant SG rule (port, protocol, cidr)
- `misconfigs`: list of check findings on this node with rule_id, severity, title, remediation
- `cves`: list of CVEs on this node with cve_id, epss, cvss, in_kev
- `threat_detections`: list of MITRE threat detections on this node
- `cdr_actor_active`, `cdr_actor_uid`: CDR actor state

This data is populated at scan time from the Neo4j query evidence collection phase and stored
in `attack_path_nodes`. The endpoint reads from the DB, not from Neo4j at query time.

### FR11 — Path History and Aging

The engine must maintain a history of each path's score and composition across scans.

At the end of each scan run, for every surviving path the engine writes a row to
`attack_path_history` with:
- `path_id`, `scan_run_id`, `score`, `severity`, `node_uids`, `node_count`, `recorded_at`

Node composition changes are detectable by comparing `node_uids` across history rows. Score
trajectory is plotted in the UI trends view.

The `attack_paths` table stores:
- `first_seen_at`: timestamp of the first scan run that found this path
- `last_seen_at`: timestamp of the most recent scan run that found this path
- `open_days`: computed as days between first_seen_at and last_seen_at (returned by API)

A path that disappears from scan results has its `status` updated to `resolved`. A path that
reappears after being resolved gets `first_seen_at` reset.

### FR12 — resource_security_posture Table

The `resource_security_posture` table in `threat_engine_inventory` DB acts as the central
pre-computed merge table for all security signals per resource per scan.

Each engine writes its columns after completing its scan step. The attack path engine reads
this table during scoring (to get per-node posture signals) and writes back after completing
path analysis (attack path signals).

Columns written by each engine:

| Column Group | Written By |
|---|---|
| is_internet_exposed, entry_point_type, waf_protected, network_detail | engine-network-security |
| is_admin_role, has_wildcard_policy, has_permission_boundary, mfa_required | engine-iam |
| data_classification, can_access_pii, can_write_data, exfil_path_exists | engine-datasec |
| has_active_cdr_actor, cdr_actor_last_seen, cdr_risk_score | engine-cdr |
| volume_encrypted, encryption_type, cert_expiry_date | graph-build step |
| is_crown_jewel, is_on_attack_path, is_choke_point, attack_path_count | engine-attack-path |
| max_epss, critical_misconfig_count, high_misconfig_count | engine-attack-path |

Schema: see architecture document section 7.1.

### FR13 — Risk Engine Integration

After completing path analysis and choke point detection, the engine must update
`resource_security_posture` with the following fields for consumption by `engine-risk`:

- `is_on_attack_path` (BOOLEAN): true if this resource appears in any active attack path
- `is_choke_point` (BOOLEAN): true if this resource is a top-10 choke point
- `attack_path_count` (INTEGER): number of attack paths this resource appears in
- `blast_radius_count` (INTEGER): count of crown jewels reachable from this resource
- `crown_jewel_count` (INTEGER): number of crown jewels this resource is on paths to

These signals are the primary attack-path inputs to the risk engine scoring formula. The risk
engine reads them from `resource_security_posture` directly (no API call to attack-path engine
at query time).

### FR14 — RBAC Enforcement

All endpoints must enforce `require_permission()` using the `engine_auth` shared library.

New permissions to be seeded in the Django platform migration:
- `attack_path:read` — all roles (platform_admin, org_admin, tenant_admin, analyst, viewer)
- `attack_path:write` — platform_admin, org_admin, tenant_admin only (crown jewel tagging)

Permission matrix:

| Endpoint | analyst | tenant_admin | org_admin | platform_admin | viewer |
|---|---|---|---|---|---|
| GET /attack-paths | full list | full list | full list | full list | summary KPIs only |
| GET /attack-paths/{id} (path story) | allowed | allowed | allowed | allowed | 403 |
| GET /crown-jewels | allowed | allowed | allowed | allowed | allowed |
| PATCH /crown-jewels/{uid} | 403 | allowed | allowed | allowed | 403 |
| GET /choke-points | allowed | allowed | allowed | allowed | 403 |
| GET /attack-paths/trends | allowed | allowed | allowed | allowed | allowed |

Viewer role restriction: `GET /attack-paths` returns only KPI summary fields
(`total`, `kpis{}`). The `paths[]` array is omitted from the response body for viewer.

### FR15 — All CSP Coverage

The engine must support all six CSPs without CSP-specific code paths in the traversal layer:

- AWS, Azure, GCP, OCI, AliCloud, IBM Cloud

CSP-agnostic approach: the traversal algorithm operates on Neo4j nodes and edges using the
`resource_security_posture` signals regardless of the `provider` column value. Crown jewel
classification uses a CSP-normalised `resource_type` format (`s3.bucket`, `blob.container`,
`gcs.bucket` etc.) that is already normalised by the inventory engine.

The engine does not call any CSP SDK directly. All cloud signals are pre-computed in Neo4j
(by graph-build) and in `resource_security_posture` (by upstream engines) before this engine runs.

---

## 5. Non-Functional Requirements

### 5.1 Performance

- `GET /api/v1/attack-paths` (list, top 50 representative): < 200ms p99 (DB query, no Neo4j)
- BFF `GET /api/v1/views/attack-paths`: < 500ms p99 end-to-end
- Scan job (crown jewel classification + traversal + dedup + write): < 3 minutes for a tenant
  with 5,000 resources and 150 crown jewels
- Neo4j traversal query: 30-second timeout enforced at driver level; Argo step does not retry
  on timeout (retry=0)

### 5.2 Reliability

- Scan step failure must not break the Argo pipeline for downstream engines (risk, narrative).
  If the attack-path step fails, risk runs with no `is_on_attack_path` signals (acceptable
  degradation).
- Engine startup health check must pass within 10 seconds of pod start.
- DB connection pool: minimum 2, maximum 10 connections.

### 5.3 Scalability

- Engine is stateless (all state in Neo4j + PostgreSQL). Horizontal scaling via K8s replica
  increase is supported.
- Single replica is sufficient for the initial deployment. Argo scan steps are serialised per
  tenant, so concurrent scans for multiple tenants require multiple replicas.

### 5.4 Security

- All DB queries scoped by `tenant_id` from `AuthContext.engine_tenant_id`. No cross-tenant
  data access is possible by construction.
- `POST /api/v1/internal/scan` requires `X-Internal-Secret` header. This endpoint is not
  registered in the gateway PUBLIC_PREFIXES and is not externally routable.
- `path_id` is a sha256 hash — not guessable. Combined with `WHERE tenant_id = $tid`, path ID
  guessing attacks are not a meaningful threat vector.
- `crown_jewel_overrides.set_by` records the user email for every manual override. This is an
  immutable audit record — updates create a new row, not an in-place update.

### 5.5 Observability

- Structured JSON logs (INFO level for scan lifecycle events, ERROR for exceptions)
- Log fields: `scan_run_id`, `tenant_id`, `account_id`, `engine=attack-path`
- Metrics emitted per scan: crown_jewel_count, raw_paths_before_dedup, final_path_count,
  critical_path_count, choke_point_count, scan_duration_seconds
- Health endpoints: `/api/v1/health/live` (liveness) and `/api/v1/health/ready` (readiness)

---

## 6. Success Metrics

### 6.1 Quality Metrics

| Metric | Target | Measurement |
|---|---|---|
| Crown jewel recall | ≥ 90% | Known-sensitive resources in test tenant correctly auto-classified |
| Path count after dedup | < 200 representative paths per tenant | Measured on test tenant with 5,000+ resources |
| BFF response time (attack paths list) | < 500ms p99 | Load test with 50 concurrent requests |
| Cross-tenant leakage | 0 incidents | RBAC test matrix: 5 roles × 8 endpoints |
| Internal scan endpoint exposure | Not reachable from external | Gateway curl test returns 404 |

### 6.2 Operational Metrics

| Metric | Target | Notes |
|---|---|---|
| Choke point fix effectiveness | ≥ 1 path broken per choke point remediation | Verified by re-running scan after choke point fix |
| Scan step duration | < 3 minutes | Argo step timeout set to 5 minutes |
| Path score stability | < 10% score drift between consecutive scans when no config changes | Validates scoring consistency |
| CDR elevation accuracy | CDR actor present → probability always boosted | Unit test: every path with active CDR actor has P × 1.40 applied |

### 6.3 Business Metrics (30-day post-launch)

- Attack paths page is opened in ≥ 60% of analyst sessions (engagement)
- At least one choke point remediation tracked per active tenant per sprint (activation)
- Critical path count trending down in demo tenant (product narrative)
- Mention in at least 2 sales deal notes as differentiator vs. Wiz/Orca (competitive)

---

## 7. Competitive Context

### 7.1 Wiz Security Graph

Wiz's toxic combinations feature surfaces paths between misconfigs that create critical
exposure. Key differentiators of our approach:
- We use reverse BFS (more complete, lower noise)
- We store per-hop path story with traversal_reason (Wiz shows graph, we show narrative)
- We explicitly model CDR actor elevation (real-time signal, not just static posture)
- We expose choke points as a first-class feature

### 7.2 Orca Attack Path Analysis

Orca uses a similar reverse graph approach. Their published algorithm is the basis for our
reverse BFS design. Key differentiators:
- We use the `resource_security_posture` shared table — upstream engines pre-compute signals
  rather than Orca's monolithic side-scanning agent
- We store P and I separately — Orca surfaces a single risk score
- Our dedup algorithm is documented and auditable (stored `absorbed_count`, `group_id`)

### 7.3 Gap to Close

Features that are out of scope for v1 but required for full competitive parity:
- Cross-cloud paths (AWS→Azure via cross-account trust) — P1
- Path suppression (mark known-acceptable paths) — P2
- Remediation impact preview ("fix this misconfig, score drops from 87 to 42") — P2
- Push notifications for new critical paths — P2

---

## 8. Pipeline Position and Dependencies

```
Discovery(1) → Inventory(2) → Check(3) → Threat(4)
    → [IAM / Network / DataSec / CDR / Vuln](5, parallel)
    → Graph-Build(6)
    → Attack-Path(6.5)   ← THIS ENGINE
    → Risk(7)            ← reads is_on_attack_path from resource_security_posture
    → Narrative(8)
```

**Engine-attack-path must run AFTER:**
- graph-build (Neo4j nodes and edges must exist)
- engine-iam (for is_admin_role, has_wildcard_policy, mfa_required signals in posture table)
- engine-network-security (for is_internet_exposed, waf_protected signals)
- engine-datasec (for data_classification signals)
- engine-cdr cron (for has_active_cdr_actor signals)

**Engine-risk must run AFTER engine-attack-path:**
- Risk engine reads is_on_attack_path, is_choke_point, blast_radius_count from posture table
- Argo DAG dependency: `risk-scan.dependencies: [attack-path-scan]`

---

## 9. Argo Trigger

The engine is triggered by Argo Workflows via:

```
POST /api/v1/internal/scan
Body: { "scan_run_id": "...", "tenant_id": "...", "account_id": "..." }
Header: X-Internal-Secret: <value from threat-engine-secrets>
```

The endpoint is NOT exposed via the gateway. It returns `{ "job_id": "...", "status": "queued" }`.
The scan runs synchronously in the background; Argo polls the Argo step status (not a separate
status endpoint) to determine completion.

---

## 10. Open Questions

| Question | Priority | Owner |
|---|---|---|
| Should `resource_security_posture` live in `threat_engine_inventory` or a new shared DB? | P0 | Architect |
| How does graph-build populate `ENCRYPTED_BY` edges needed for cert_expiry scoring? | P0 | Graph-build team |
| Is `OnPrem` VirtualNode available in Neo4j today or does DirectConnect discovery need to run first? | P1 | Discovery team |
| What is the correct `X-Internal-Secret` rotation strategy for Argo → engine calls? | P1 | Security architect |
| Should choke point detection use a global top-10 or per-crown-jewel top-10? | P2 | Product |
