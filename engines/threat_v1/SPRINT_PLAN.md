# Threat Detection Engine v1 — Sprint Plan

**Status:** Approved for execution  
**Created:** 2026-05-10  
**Owner:** Product Manager (threat track)  
**References:**
- Requirements: `engines/threat_v1/REQUIREMENTS.md`
- Platform Constitution: `.claude/documentation/CSPM_CONSTITUTION.md`
- Quality Gates: `.claude/documentation/TESTING_QUALITY.md`
- Existing threat engine: `engines/threat/` (kept live — do not modify during this sprint)

**Hard prerequisite chain:** Sprint 0 → Sprint 1 → Sprint 2 → Sprint 3 → Sprint 4 → Sprint 5. No sprint may begin until its predecessor's gate passes. Sprint 1 is conditionally unblocked once S0-05 passes, even if other S0 stories are still in review.

**Current state of `engines/threat_v1/`:** Directory exists with empty module stubs (`graph/`, `detector/`, `patterns/`, `api/`, `database/`, `correlator/`, `schemas/`). No implementation exists. All stub `__init__.py` files are empty. No duplication risk with `engines/threat/` — the two engines share zero implementation code.

---

## Section 1 — Sprint Overview

| Sprint | Name | Duration | Stories | Hard Dependencies | Sprint Goal |
|--------|------|----------|---------|-------------------|-------------|
| Sprint 0 | MITRE Tagging Prerequisites | 1 week | S0-01 through S0-05 | None | Tag existing check rules with MITRE ATT&CK technique IDs so PatternExecutor has technique IDs to match. Coverage gate: ≥ 80% across AWS priority rule groups before Sprint 1 starts. |
| Sprint 1 | Foundation: Schema + GraphBuilder | 2 weeks | S1-01 through S1-08 | S0-05 must pass | Neo4j graph schema, Threat DB DDL (`_v1` tables), complete GraphBuilder that reads 6 engine DBs and populates Neo4j with resource nodes, finding nodes, and security edges. CP1 security gate before S1-04. |
| Sprint 2 | PatternExecutor + Incident Management | 2 weeks | S2-01 through S2-10 | S1-08 must pass | 3-tier pattern execution engine and full incident lifecycle: create, deduplicate, multi-pattern roll-up, state machine transitions, FP feedback. CP2 gate before S2-02. |
| Sprint 3 | 30 YAML Patterns | 1 week | S3-01 through S3-05 | S2-07 must pass (dedup_key exists) | Author, test, and merge 10 Tier-1 + 10 Tier-2 + 10 Tier-3 detection patterns. Pattern regression baseline locked before merge. |
| Sprint 4 | API Layer + BFF + Frontend | 2 weeks | S4-01 through S4-10 | S2-08 must pass (IncidentWriter exists) | Full REST API with RBAC, BFF view handlers, and Threat Center UI (3-pane: filter sidebar + incident list + 9-section detail panel). CP3 gate before S4-01. |
| Sprint 5 | Integration, QA, and Deployment | 1 week | S5-01 through S5-08 | S4-10 must pass (full stack complete) | End-to-end validation, RBAC matrix test, BFF contract coverage, load test (1,000-node graph, 30 patterns, < 2 min), EKS deploy, smoke test against live scan_run_id, post-deploy sign-off. CP4 gate before S5-05. |

**Total calendar duration:** ~9 weeks (2 engineers parallel: 1 backend + 1 security analyst for Sprint 0; then full squad)

---

## Section 2 — RACI Table (per story)

### Legend

| Code | Role | Responsibility |
|------|------|----------------|
| DEV | Developer (bmad-dev agent) | Writes code, unit tests, migration SQL |
| ARCH | Solution Architect (bmad-architect agent) | Reviews design, ADRs, graph schema |
| SA | Security Architect (bmad-security-architect agent) | STRIDE/PASTA/OWASP SAMM gate; Cypher injection review |
| PO | Product Owner (bmad-po agent) | Acceptance criteria authoring; story sign-off |
| QA | QA Engineer (bmad-qa agent) | AC verification; integration + contract tests |
| DL | Dev Lead (human reviewer) | PR merge approval; pattern logic review |
| SR | Security Reviewer (bmad-security-reviewer agent) | OWASP Top 10, SLSA, CCM domain, field-stripping review |

**RACI key:** R = Responsible (does the work) | A = Accountable (signs off) | C = Consulted (must be asked before starting) | I = Informed (notified on completion)

---

### Sprint 0 — MITRE Tagging Prerequisites

| Story ID | Title | R | A | C | I | Gate | Notes |
|----------|-------|---|---|---|---|------|-------|
| S0-01 | Tag 181 EC2 rules with MITRE techniques (0% → 100% target) | DEV | PO | SA, ARCH | DL, QA | PO acceptance criteria written before DEV starts. ARCH consult for technique mapping accuracy. | Highest-value gap: EC2 is the primary attack entry point. Technique family: T1190, T1021.004, T1552.005, T1595. Use domain heuristic from REQUIREMENTS §7.3 for bulk auto-tag; manual review for all `aws-ec2-public-*` and `aws-ec2-imds*` rules. |
| S0-02 | Tag 133 IAM rules with MITRE techniques (26% → 100% target) | DEV | PO | SA | DL, QA | PO acceptance criteria written before DEV starts. | Technique family: T1078.004, T1548, T1098.003. Root account rules → T1078.004. Admin policy rules → T1548. `allows_privilege_escalation` rules → T1548.002. |
| S0-03 | Tag 66 S3 rules with MITRE techniques (13% → 100% target) | DEV | PO | SA | DL, QA | PO acceptance criteria written before DEV starts. | Technique family: T1530, T1537. `block_public_access` → T1530. Replication/cross-account → T1537. |
| S0-04 | Fix `cve_attack_mappings` DDL extra-comma bug in vuln DB | DEV | DL | SA, SR | PO, QA | SR must be consulted before any vuln DB migration. | DDL has broken `UNIQUE(cve_id,,)` — remove extra comma. Add `mitre_techniques JSONB` column to `scan_vulnerabilities`. Wire NVD parser heuristic: CVSS ≥ 9.0 + `attackVector=NETWORK` → T1190. Migration SQL file required; apply via kubectl exec per CLAUDE.md pattern. |
| S0-05 | Validate MITRE coverage ≥ 80% across AWS priority rule groups | QA | DL | ARCH, SA | PO | Sprint 1 is BLOCKED until this gate passes. | Query `rule_metadata` YAMLs in `catalog/rule/aws_rule_check/` across ec2, iam, s3, paas subdirs. Write coverage script in `engines/threat_v1/scripts/check_mitre_coverage.py`. Output: per-group coverage table. Must show EC2 ≥ 80%, IAM ≥ 80%, S3 ≥ 80%. |

---

### Sprint 1 — Foundation: Schema + GraphBuilder

**Pre-sprint gate (CP-1):** SA must review and sign off on: (a) Neo4j graph schema, (b) cross-engine DB read pattern, (c) scan_run_id ownership validation design. CP-1 sign-off required before S1-04 begins.

| Story ID | Title | R | A | C | I | Gate | Notes |
|----------|-------|---|---|---|---|------|-------|
| S1-01 | Neo4j graph schema (node labels, edge types, property contracts, indexes) | DEV, ARCH | ARCH | SA | DL, PO | CP-1 gate: SA reviews schema before S1-04 starts. | Define: `(:Resource)`, `(:MisconfigFinding)`, `(:VulnFinding)`, `(:CDREvent)`, `(:CDRActor)` node types with all properties from REQUIREMENTS §4.1. Define edge types from §4.2. Create indexes on `resource_uid`, `tenant_id`, `is_crown_jewel`, `on_attack_path`. Use named database `threat_v1` on existing Neo4j Aura instance — do NOT use the production graph. Write schema as `engines/threat_v1/scripts/neo4j_schema.cypher`. |
| S1-02 | Threat DB DDL migration (`threat_incidents`, `threat_scenario_patterns`, `threat_scan_runs_v1`, `threat_pattern_suppressions`, `threat_crown_jewels`, `threat_incident_feedback`) | DEV | DL | SA, SR | PO, QA | SR must be consulted before migration SQL is written. Migration must follow CSPM_CONSTITUTION §2 (standard columns, IMMUTABLE generated columns). | `dedup_key` column is `GENERATED ALWAYS AS (...) STORED` — expression must be IMMUTABLE (sha256 of text concat is IMMUTABLE — safe). Verify with `CREATE TABLE` locally before applying. Migration file: `shared/database/migrations/threat_v1_001_new_tables.sql`. Update schema SQL: `shared/database/schemas/threat_schema.sql`. Apply via kubectl exec on a pod with threat DB access. Check `kubectl logs -l job-name=threat-v1-migration` ends with "MIGRATION COMPLETE". |
| S1-03 | Project structure + `requirements.txt` + Dockerfile + K8s manifest (`engine-threat-v1.yaml`) | DEV | DL | ARCH, SA | PO | SLSA Level 1-2: pinned base image (python:3.11-slim-bookworm), no `:latest`. | Port 8021 (8020 = existing engine). Dockerfile build context = repo root. Manifest: `deployment/aws/eks/engines/engine-threat-v1.yaml` with `readinessProbe`, `livenessProbe`, `resources.requests`, `resources.limits`. Image tag placeholder: `yadavanup84/engine-threat-v1:v-threat-v1-phase1` — never `:latest` (CP1-08). `engines/threat_v1/main.py` FastAPI app with `/api/v1/health/live` and `/api/v1/health/ready`. |
| S1-04 | `ResourceResolver` + `MisconfigLoader` (reads check DB) | DEV | DL | SA, SR | PO, QA | CP-1 gate must be signed off before this story begins. SR consulted for cross-DB read pattern and tenant_id scoping. | `ResourceResolver.resolve(tenant_id, account_id)`: selects best scan_run_id per engine using most-findings query (REQUIREMENTS §3.2). `MisconfigLoader`: reads `check_findings` for the resolved scan_run_id, scoped by `tenant_id + account_id`. JSONB columns are already dicts — never call `json.loads()`. Writes to `engines/threat_v1/threat_v1/graph/` module. |
| S1-05 | `VulnLoader` + `CDRLoader` (reads vuln DB + CDR DB) | DEV | DL | SA, SR | PO, QA | SR consulted for CDR data access (actor_principal is PII — do not log). | `VulnLoader`: reads `scan_vulnerabilities` with resolved scan_run_id for tenant. `CDRLoader`: reads `cdr_findings` for tenant (CDR is tenant-wide, account_id join happens downstream — document as intentional per W-04). Writes to `engines/threat_v1/threat_v1/graph/` module. |
| S1-06 | `CrownJewelClassifier` + `EdgeBuilder` (completes graph from inventory) | DEV | DL | ARCH, SA | PO, QA | ARCH consulted for edge type mapping from `inventory_relationships` table. | `CrownJewelClassifier`: implements `is_crown_jewel()` logic from REQUIREMENTS §6.3 — joins `resource_inventory_identifier` + `inventory_findings`. Uses `asset_category`, `access_pattern`, `criticality`, `environment`, `risk_score`, `tags`. `EdgeBuilder`: reads `inventory_relationships` materialized edge table (not `resource_relationship_rules` directly) for `attack_path_category` edges. Sets `is_crown_jewel=true` on target Resource nodes. Writes to `engines/threat_v1/threat_v1/graph/` module. |
| S1-07 | `scan_run_id` ownership validation — Step 0 in `run_scan.py` (CP1-07) | DEV | SA | SR | DL, PO | SA accountable: this is a security gate, not a feature. SR consulted. | First operation in `run_scan.py` before any DB reads: `SELECT 1 FROM scan_orchestration WHERE scan_run_id = :scan_run_id AND tenant_id = :tenant_id AND account_id = :account_id`. If no row: abort with structured log (level=ERROR, include scan_run_id), return exit code 1. Argo will not retry a non-zero exit on ownership failure. Prevents Argo parameter tampering from triggering cross-tenant graph builds. Per-tenant advisory lock: `hashtext(tenant_id || '|' || account_id)` (not tenant_id alone — W-01). |
| S1-08 | GraphBuilder integration test (assert node/edge counts for known scan_run_id) | QA, DEV | QA | ARCH | DL, PO | Must use real DB with real scan_run_id — no mocks. | Test file: `engines/threat_v1/tests/integration/test_graph_builder.py`. Assertions: Resource node count ≥ 1, MisconfigFinding node count ≥ 1, at least 1 edge present, `tenant_id` property set on all Resource nodes, no cross-tenant nodes visible. Verifies Neo4j named database `threat_v1` is isolated from production graph. |

---

### Sprint 2 — PatternExecutor + Incident Management

**Pre-sprint gate (CP-2):** SA reviews PatternCompiler Cypher safety design — specifically the parameterized template expander approach and the CI linter gate that rejects string-interpolated Cypher. CP-2 sign-off required before S2-02 begins.

| Story ID | Title | R | A | C | I | Gate | Notes |
|----------|-------|---|---|---|---|------|-------|
| S2-01 | Pattern DSL YAML schema + `PatternRegistry` loader | DEV | ARCH | SA, PO | DL, QA | PO writes acceptance criteria for YAML schema completeness before DEV starts. | Pydantic model for full YAML schema from REQUIREMENTS §5.3: all fields including `id`, `version`, `tier`, `severity_base`, `confidence`, `mitre_tactics`, `mitre_techniques`, `tactic_chain_order`, `csps`, `entry`, `hops`, `target`, `cdr_watch`, `scoring`, `tests`. `PatternRegistry.load_active_patterns(tenant_id)`: loads from `threat_scenario_patterns` table filtered by active=true, excludes patterns in `threat_pattern_suppressions` for that tenant. Writes to `engines/threat_v1/threat_v1/patterns/` module. |
| S2-02 | `PatternCompiler` — Cypher compilation with `$parameter` bindings; CI linter gate | DEV | SA | SR, ARCH | DL, QA | CP-2 gate must be signed off before this story begins. SR reviews compiled output. This is the highest-security story in the entire sprint plan. | CP1-01 enforcement: PatternCompiler is a parameterized template expander, NOT a string builder. All runtime values from pattern YAML (`resource_types`, `check_rules_failing`, `edge_type`, condition values) must be passed as `$param` bindings. CI linter: `engines/threat_v1/scripts/cypher_parameterization_linter.py` — rejects any compiled Cypher string containing an interpolated pattern value. Tenant_id filter presence check: all compiled Cypher must contain `$tid` or `$tenant_id` parameter. Neo4j query timeout: `session.run(query, timeout=500)` on every pattern execution (W-02). |
| S2-03 | Tier 1 Matcher (toxic combo — single Cypher query per pattern, flag-based) | DEV | DL | ARCH, SA | PO, QA | ARCH consulted for flag-based matching design (no graph traversal). | Matches on aggregated boolean flags on Resource nodes: `internet_exposed`, `has_critical_cve`, `has_high_misconfig`, `is_admin_role`, `is_crown_jewel`, `cdr_actor_seen`. Latency target: < 10ms per pattern. Single Cypher query per pattern — no traversal. Produces `incident_class=posture`, severity up to HIGH. |
| S2-04 | Tier 2 Matcher (multi-signal — graph traversal, 2–5 hop paths) | DEV | DL | ARCH, SA | PO, QA | ARCH consulted for hop-coverage scoring logic. | Fires when `min_hops_for_tier2` of the required hops in a Tier 3 pattern are observed, even if crown jewel not reached. Latency target: < 500ms per pattern. Produces early warning incident, `incident_class=posture`, severity MEDIUM. |
| S2-05 | Tier 3 Matcher (full path — CDR event correlation + graph) | DEV | DL | ARCH, SA, SR | PO, QA | SR consulted for CDR event correlation design (PII data touched during matching). | Full chain from entry node to crown jewel via attack-path-category edges. CDR signal grading from REQUIREMENTS §8: 0 CDR signals = `posture` HIGH; 1 CDR technique below `min_coverage` = `suspicious` HIGH; ≥2 CDR techniques OR `min_coverage` met = `active` CRITICAL. CDR watch window in `cdr_watch.window_minutes`. Tactic order check if `tactic_order_required=true`. Latency target: < 2s per pattern. |
| S2-06 | `PerformanceGuard` (circuit breaker: max 30s per pattern, max 200 path results) | DEV | DL | ARCH, SA | PO, QA | ARCH + SA consulted. **SR-001 fix**: global `active=false` is FORBIDDEN. | Per-pattern circuit breaker: timeout at 30s, result cap at 200 paths. Patterns exceeding p99 budget (500ms) for 3 consecutive runs: INSERT per-tenant row into `threat_pattern_suppressions` (auto_generated=true, reason='performance_guard') — **NEVER** set `active=false` on the shared `threat_scenario_patterns` row (CP1-05). Log WARNING with pattern_id and tenant_id. Count per-pattern metrics: `fire_count`, `match_latency_ms`, `error_count`. Unit test MUST assert no UPDATE to `threat_scenario_patterns.active` is issued. |
| S2-07 | `SeverityScorer` + `IncidentDeduper` (sha256 fingerprint, tier roll-up, posture→active escalation) | DEV | DL | SA, SR | PO, QA | SR consulted for dedup key design (prevents incident flooding). | `SeverityScorer`: configurable formula (auditable, not hardcoded). `IncidentDeduper`: roll-up key is `(tenant_id, entry_resource_uid, target_resource_uid)` — group BEFORE computing dedup_key. Primary pattern = highest tier. `dedup_key = sha256(pattern_id|tenant_id|entry_uid|target_uid)`. Evidence `matched_patterns[]` records all matched patterns. Escalation: posture → suspicious on first CDR technique; suspicious → active on second technique OR `min_coverage` met. `confidence=theoretical` patterns must NOT produce `incident_class=active` (W-07). |
| S2-08 | `IncidentWriter` + `LifecycleTransitioner` (advisory lock, upsert, state machine) | DEV | DL | SA, SR | PO, QA | SR consulted for advisory lock and upsert design. SA consulted for concurrency model. | Advisory lock: `pg_advisory_lock(hashtext(tenant_id || '|' || account_id))` before incident writes. Released on completion or exception. Incident upsert: `ON CONFLICT (dedup_key) DO UPDATE` — sets `last_seen_at`, escalates `incident_class` and `severity` if higher tier fires. `resolved → reopened` when same dedup_key fires within 7 days of resolution. `active → resolved` requires: actor session terminated AND no CDR events for 24h AND check findings fixed. Lifecycle state machine matches REQUIREMENTS §9.4 exactly. |
| S2-09 | `StoryBuilder` (human-readable narrative from hop chain) | DEV | PO | ARCH | DL, QA | PO reviews narrative output quality before sign-off. | Populates `story_text` from pattern `story_template` field. Posture variant: no actor line. Active variant: includes actor principal, observed techniques, event count, time window. Template interpolation uses resource metadata from graph — never raw resource_uid in user-facing text. |
| S2-10 | `FeedbackProcessor` — per-tenant suppression only; writes to `threat_pattern_suppressions` (CP1-05) | DEV | SA | SR, DL | PO, QA | SA accountable: global pattern mutation is a security issue (CP1-05). SR consulted. | FeedbackProcessor reads from `threat_incident_feedback` (INSERT-only, immutable audit log). If rolling-30d FP rate for a pattern within a tenant exceeds 30%: insert row into `threat_pattern_suppressions` (tenant-scoped). Never set `active=false` on the shared pattern. Global deactivation requires SA approval + manual update. Rate limit: 10 verdicts/user/24h enforced at endpoint layer. |

---

### Sprint 3 — 30 YAML Patterns

**Review gate:** All 30 patterns must be reviewed by both ARCH and DL for logic correctness before merge. SA signs off on each new tactic chain (ATT&CK + D3FEND check per CLAUDE.md Security Frameworks Constitution).

| Story ID | Title | R | A | C | I | Gate | Notes |
|----------|-------|---|---|---|---|------|-------|
| S3-01 | 10 Tier-1 patterns (toxic combos across AWS/Azure/K8s) | DEV | DL | ARCH, SA, PO | QA | PO writes acceptance criteria per pattern (positive + negative test case required). ARCH + DL review all 10 before merge. | Priority patterns: (1) EC2 internet-exposed + critical CVE; (2) IAMRole admin + MFA disabled + CDR actor seen; (3) S3 public + crown jewel; (4) RootAccount + active key + activity CDR; (5) K8s ClusterAdmin bound to ServiceAccount; (6) Lambda + public URL + secrets env vars; (7) RDS public + no encryption; (8) EKS + privileged pod + host network; (9) AzureVM + public IP + admin role; (10) GCP SA + owner role + external key. Each must have positive test case and negative test case. Files in `catalog/threat_patterns/tier1/`. |
| S3-02 | 10 Tier-2 patterns (multi-hop partial paths: 2–3 hop chains) | DEV | DL | ARCH, SA, PO | QA | Same gate as S3-01. S2-07 (dedup_key) must be merged before patterns can be tested. | Priority patterns: (1) EC2 → IAMRole via `assumes`; (2) Lambda → SecretsManager via `uses`; (3) EKS pod → ClusterAdmin via RBAC; (4) S3 replication → external account; (5) EC2 → RDS via SG; (6) IAM → S3 via policy; (7) AzureSP → KeyVault via role; (8) GCP SA → BigQuery via IAM; (9) K8s ServiceAccount → API server; (10) EC2 → SSM parameter store via instance profile. |
| S3-03 | 10 Tier-3 patterns (full path: entry → pivot → crown jewel) | DEV | DL | ARCH, SA, PO | QA | Same gate as S3-01. Patterns must use only AWS where all three signals (misconfig + vuln + CDR) are available — per REQUIREMENTS §14 Phase 5.3 guidance. | Priority patterns: (1) PAT-AWS-001: IMDSv1 EC2 → admin IAMRole → PII S3 (Capital One pattern); (2) EC2 + critical CVE + public SG → IAMRole → RDS; (3) Lambda + env secret → SecretsManager admin → RDS; (4) Public EKS endpoint → ClusterAdmin SA → prod namespace secrets; (5) RootAccount key active → IAM full access → S3 + RDS all data; (6) EC2 public + IMDSv1 → IAMRole → cross-account STS; (7) GitHub Actions OIDC → prod IAMRole → S3 data (OIDC attack chain); (8) AzureVM + public IP + MSI → KeyVault → DB credentials; (9) GCP CE + default SA + public → BigQuery + GCS; (10) SSM automation + misconfigured runbook → IAM escalation → data. |
| S3-04 | Pattern regression test baseline (golden JSON for each pattern's expected findings on test data) | QA | QA | ARCH, DL | PO | Baseline must be committed to `tests/regression/baselines/threat_pattern_counts.json` before Sprint 4 starts. | Baseline file format: `{ "PAT-AWS-001": {"tier": 3, "min_fires": 0, "max_fires": null, "test_graph_fires": 1} }`. "min_fires" on production data is 0 (may not be present). "test_graph_fires" is 1 on the positive test fixture. Negative test case must produce 0. Run via `pytest engines/threat_v1/tests/regression/`. |
| S3-05 | Pattern catalog CI gate (YAML schema validation, Cypher linter, tenant_id filter check) | DEV | DL | SA, ARCH | PO, QA | Must be wired to CI before any S3-01/02/03 pattern merges. Gate blocks merge on failure. | CI gate checks per pattern file in `catalog/threat_patterns/`: (a) Pydantic schema validation passes; (b) PatternCompiler.compile() succeeds without error; (c) Cypher parameterization linter finds no string-interpolated values; (d) compiled Cypher contains `$tid` or `$tenant_id`; (e) MITRE technique IDs valid against ATT&CK catalog; (f) positive test fires on fixture graph within tier latency budget; (g) negative test does NOT fire. Failing CI blocks PR merge. |

---

### Sprint 4 — API Layer + BFF + Frontend

**Pre-sprint gate (CP-3):** SR reviews all endpoint + auth + RBAC design before any S4 API story begins. SA confirms evidence model and PII field exposure rules are implemented correctly per CP1-02.

| Story ID | Title | R | A | C | I | Gate | Notes |
|----------|-------|---|---|---|---|------|-------|
| S4-01 | Core API endpoints (`GET /incidents`, `GET /incidents/{id}`, `GET /scan/status/{job_id}`, `GET /health/*`) with `require_permission()` | DEV | DL | SA, SR | PO, QA | CP-3 gate must be signed off before this story begins. SR reviewed in CP-3. | Every endpoint: `Depends(require_permission("threat:read"))`. Health endpoints: no auth. `GET /incidents`: returns `IncidentListItem` list (strips CDR PII). `GET /incidents/{id}`: returns `IncidentDetail`; additionally checks `cdr:sensitive` if `cdr_event_ids` populated. FastAPI router in `engines/threat_v1/threat_v1/api/`. Standard error response format per CONSTITUTION §5.2. |
| S4-02 | Two Pydantic response models: `IncidentListItem` (strips PII) vs `IncidentDetail` (with `cdr:sensitive`) | DEV | SA | SR | DL, PO, QA | SA accountable: PII field exposure is a security decision. SR consulted. | `IncidentListItem`: includes `misconfig_findings`, `vuln_findings`, `cdr_events[].mitre_technique`, `path_resources`, `matched_patterns`. Strips: `cdr_events[].actor_principal`, `cdr_events[].source_ip`, `cdr_events[].action`, `graph_query`. `IncidentDetail`: all fields included when caller has `cdr:sensitive`. `strip_sensitive_fields()` from shared auth extended for threat engine. Models in `engines/threat_v1/threat_v1/schemas/`. |
| S4-03 | Crown jewel `POST /api/v1/crown-jewels` + `DELETE /api/v1/crown-jewels/{resource_uid}` with ownership validation (CP1-03) | DEV | SA | SR, DL | PO, QA | SA accountable: ownership validation is a security gate (CP1-03). SR consulted. | `POST`: `require_permission("threat:write")`. Validate `resource_uid` exists in `resource_inventory WHERE tenant_id = auth_ctx.tenant_id`. If not found: return 404 (avoids confirming foreign resource existence). Write to `threat_crown_jewels` table. Write audit row to platform `audit_logs` on add/remove (W-05). `DELETE`: same ownership validation. |
| S4-04 | Actions endpoint `POST /api/v1/incidents/{id}/actions` returning HTTP 501 (CP1-04) | DEV | PO | SA | DL, QA | SA consulted: must confirm 501 response with guidance text is sufficient for v1. | Returns `{"error": "not_implemented", "message": "Automated response actions are not available in v1. Please follow the recommendations in this incident's recommendations field.", "detail": {}}`. HTTP 501. No execution logic. Scoped to Phase 8. `require_permission("threat:write")` still enforced — 501 is not a bypass. |
| S4-05 | BFF view handlers: `/views/threat_center`, `/views/incident_detail/{id}`, `/views/threat_graph` | DEV | DL | ARCH, SR | PO, QA | SR consulted for BFF data aggregation (no PII in BFF aggregates for list views). | Follows `fetchView(page)` pattern in `shared/api_gateway/bff/`. `threat_center` view: KPI cards (open incidents, active incidents, patterns fired, crown jewels at risk), severity breakdown, incident list (IncidentListItem shape — no PII), top tactic chains. `incident_detail`: full evidence including CDR events — calls engine with `cdr:sensitive` check. `threat_graph`: resource UIDs + edge types for graph visualization. No fallback data, no mock data (CONSTITUTION §4.1). |
| S4-06 | BFF view: `/views/inventory_asset_threat/{uid}` (Threat tab on inventory asset page) | DEV | DL | SR, ARCH | PO, QA | SR consulted: BFF must re-validate incident_id belongs to auth tenant (W-06). | Returns 5 new fields for inventory asset Threat tab: `on_attack_path` (bool), `incident_ids` (list), `hop_position` (int), `enabling_technique_ids` (list), `cdr_event_count` (int). BFF re-validates each incident_id belongs to `auth_ctx.tenant_id` before including. No PII in this view — actor_principal and source_ip are excluded. |
| S4-07 | Threat Center page: Zone A (filter sidebar) + Zone B (incident list) + Zone C (9-section detail panel) | DEV | PO | ARCH, DL | QA, SA | PO reviews UX fidelity against `threat_v1_ui_flow.drawio`. | Wired to BFF via `fetchView("threat_center")`. Zone A: filter by tier (1/2/3), incident_class (posture/suspicious/active), severity, CSP, tactic. Zone B: sortable incident list (severity badge, resource name, tactic chain, last_seen_at) — skeleton screens while loading. Zone C: 9-section panel (summary, entry resource, attack path visualization, evidence, CDR events, recommendations, MITRE mapping, patterns matched, crown jewel detail). Click row in Zone B → Zone C updates without page navigation (side-panel pattern per CONSTITUTION §3.3). Risk score 0–100 prominent. Severity colors from CONSTITUTION §3.2. |
| S4-08 | `ScenarioCard` component — wire to real BFF data (already exists in frontend, currently mocked) | DEV | PO | DL | QA | PO confirms mock data is fully replaced. No mock data may remain after this story. | Locate existing ScenarioCard in frontend. Replace mock data with `fetchView("threat_center")` kpi_cards and patterns. Verify no `_is_mock` or `_fallback` flags in response. Verify empty state shows meaningful message + CTA when no incidents exist. |
| S4-09 | Incident detail page (`/threats/[id]`) — wire attack path + hop table + CDR tab | DEV | PO | SR, DL | QA | SR consulted: CDR tab shows PII only to `cdr:sensitive` role — enforce in component, not just BFF. | Wire existing `/threats/[id]` page to `fetchView("incident_detail/{id}")`. Attack path visualization: graph/node visualization per CONSTITUTION §3.5. Hop table: resource_uid, resource_type, position, role (entry/pivot/target). CDR tab: shows actor_principal, source_ip, action only when caller has `cdr:sensitive` — frontend checks role before rendering PII fields. |
| S4-10 | Inventory asset Threat tab — wire 5 new fields from `/views/inventory_asset_threat/{uid}` | DEV | PO | DL | QA | PO confirms all 5 fields render correctly and Threat tab appears on asset detail page. | Wire inventory asset detail page Threat tab to BFF view. Show `on_attack_path` as badge (red = on path). Show incident_ids as clickable links to `/threats/[id]`. Show hop_position as "Position N of M in attack chain". Show technique_ids as MITRE technique badges. Show cdr_event_count as count badge. |

---

### Sprint 5 — Integration, QA, and Deployment

**Pre-deploy gate (CP-4):** SR final sign-off confirming no CP-1 regressions. SA confirms cross-engine DB reads are still correctly scoped by tenant_id. Gate required before S5-05 (Docker build + EKS deploy).

| Story ID | Title | R | A | C | I | Gate | Notes |
|----------|-------|---|---|---|---|------|-------|
| S5-01 | E2E integration test: trigger scan → GraphBuilder → PatternExecutor → IncidentWriter → assert findings in DB | QA | QA | ARCH, DL | PO, SA | Must use real scan_run_id with actual tenant data — no mocks. Follows TESTING_QUALITY §Level 5. | Test file: `engines/threat_v1/tests/e2e/test_threat_v1_pipeline.py`. Trigger: `run_scan.py --tenant-id=<id> --account-id=<id> --scan-run-id=<known-id>`. Assertions: at least 1 incident created in `threat_incidents`; graph has ≥ 10 Resource nodes; `incident_class` in (posture, suspicious, active); `entry_resource_uid` is not null; `dedup_key` is unique across returned incidents; `threat_scan_runs_v1.status = completed`. |
| S5-02 | RBAC matrix test (5 roles × all threat-v1 endpoints; viewer gets 403 on `cdr:sensitive`) | QA | QA | SR | DL, SA | SR consulted for role/permission matrix. Follows TESTING_QUALITY §Level 4. 100% RBAC coverage required. | Test file: `engines/threat_v1/tests/rbac/test_threat_v1_rbac.py`. Matrix: viewer (403 on cdr:sensitive detail endpoint, 200 on incidents list), analyst (200 all read endpoints), tenant_admin (200 read + write), unauthenticated (401 all). Crown jewel write: viewer 403, analyst 403, tenant_admin 200. Feedback: rate limit enforced at 10/user/24h. |
| S5-03 | BFF contract tests (100% coverage per TESTING_QUALITY §Level 3) | QA | QA | DL | PO | Every BFF view handler for threat-v1 must have a contract test. 100% required before merge. | Test files in `tests/bff/`. Contract for `threat_center` view: required fields `[kpi_cards, severity_breakdown, findings]`. KPI cards: `[open_incidents, active_incidents, patterns_fired, crown_jewels_at_risk]`. Findings: `[incident_id, severity, tier, incident_class, entry_resource_uid, tactic_chain, last_seen_at]`. No `_is_mock` or `_fallback` fields. Contract for `incident_detail`: `[incident_id, evidence, attack_path, story_text, recommendations, mitre_techniques]`. Verify `actor_principal` absent from list endpoint, present in detail for `cdr:sensitive`. |
| S5-04 | Load test (1,000-node graph, 30 patterns, assert < 2 min total runtime) | QA | QA | ARCH | DL, PO | Follows TESTING_QUALITY §Level 8 performance baselines. | Load test: seed 1,000 Resource nodes in test Neo4j DB (use named database `threat_v1_test`). Run all 30 patterns (10 per tier). Assert: total execution time < 2 minutes; no individual pattern exceeds 30s; Tier 1 per-pattern median < 10ms; Tier 2 per-pattern < 500ms; Tier 3 per-pattern < 2s. BFF `threat_center` view p95 < 500ms. |
| S5-05 | Docker build + EKS deploy (image tag: `v-threat-v1-phase1`, NEVER `:latest`) | DEV | DL | SA, SR | PO | CP-4 gate must pass before this story begins. SLSA: pinned base image, build from repo root. | Build: `docker build -t yadavanup84/engine-threat-v1:v-threat-v1-phase1 -f engines/threat_v1/Dockerfile .`. Push: `docker push yadavanup84/engine-threat-v1:v-threat-v1-phase1`. Apply: `kubectl apply -f deployment/aws/eks/engines/engine-threat-v1.yaml`. Rollout: `kubectl rollout status deployment/engine-threat-v1 -n threat-engine-engines`. Pod image tag verification: `kubectl get pods -n threat-engine-engines -o custom-columns='NAME:.metadata.name,IMAGE:.spec.containers[0].image' | grep threat-v1` — must show `v-threat-v1-phase1`. If VSCode linter reverted YAML tag: `kubectl set image deployment/engine-threat-v1 threat-v1=yadavanup84/engine-threat-v1:v-threat-v1-phase1`. |
| S5-06 | Smoke test against existing scan_run_id with real tenant data | QA, DL | DL | SA | PO | Uses latest scan_run_id from `scan_orchestration` for tenant with real AWS data. | Run `run_scan.py` against the latest production scan_run_id from `scan_orchestration` (query in `latest_scan_run_ids.md`). Assertions: ownership validation passes (no abort); graph builds without error; at least 1 incident created; at least 1 Tier-1 pattern fires; `error_count` across all patterns = 0; no cross-tenant data in results (verify all returned tenant_ids match auth tenant). |
| S5-07 | Post-deploy validation (health check + logs + BFF smoke — mandatory per constitution) | DEV, QA | DL | SR | PO, SA | Follows TESTING_QUALITY §Level 10 checklist. Any failure triggers immediate rollback. | Check 0: pod image tag matches `v-threat-v1-phase1`. Check 1: `GET /api/v1/health/live` → `{"status": "ok"}`. Check 2: `GET /api/v1/health/ready` → `{"status": "ready"}` (Neo4j + Postgres reachable). Check 3: `kubectl logs -l app=engine-threat-v1 --since=60s | grep -c ERROR` → 0. Check 4: BFF `GET /gateway/api/v1/views/threat_center` → 200, `kpi_cards` non-null. Check 5: `incident_count > 0` for latest scan_run_id. Failure on any check: immediate rollback via `kubectl rollout undo deployment/engine-threat-v1`. |
| S5-08 | Decision gate — if smoke test passes: approve full pipeline integration (add threat-v1 step to `cspm-pipeline.yaml`) | DL, ARCH | DL | SA, PO | QA | All of S5-01 through S5-07 must pass. SA confirms no CP-1 regressions. | Add Argo DAG step `threat-v1-scan` to `deployment/aws/eks/argo/cspm-pipeline.yaml`. Step runs AFTER existing threat engine step (parallel operation during transition). Image: `yadavanup84/engine-threat-v1:v-threat-v1-phase1`. Args: `--tenant-id`, `--account-id`, `--scan-run-id` from Argo parameters. Add CDR Argo CronWorkflow trigger (Trigger B from REQUIREMENTS §10.2) with `--mode=cdr-update`. engine-threat (v0) remains live — do not remove until Phase 7 shadow mode completes. |

---

## Section 3 — Security Checkpoint Map

### CP-1 — Before Sprint 1 coding begins (before S1-04)

**Owner:** SA (Security Architect)  
**Timing:** Must be completed before S1-04 begins. S1-01 through S1-03 may proceed in parallel while CP-1 is in progress.

**Review scope:**

| Item | What SA Reviews | Pass Criteria |
|------|----------------|---------------|
| Neo4j graph schema | Node labels, edge types, property contracts, index definitions | No cross-tenant properties on nodes without tenant_id. Named database `threat_v1` isolated from production graph. |
| Cross-engine DB read pattern | ResourceResolver reading check DB, vuln DB, CDR DB, inventory DB | Each read is parameterized, scoped by `tenant_id + account_id`. No raw SQL string interpolation. No `json.loads()` on JSONB. |
| scan_run_id ownership validation | Step 0 in `run_scan.py` (S1-07 design) | Validation runs BEFORE any DB reads. Abort on missing row. Advisory lock uses `hashtext(tenant_id || '|' || account_id)` — not tenant_id alone. |
| Concurrency model | Advisory lock design, Trigger B wait behavior | Max wait 5 minutes for CDR trigger if full pipeline holds lock. Clean exit on timeout. |

**Deliverable:** SA writes a signed CP-1 sign-off note in the Sprint 1 PR thread before S1-04 is assigned to DEV.

---

### CP-2 — Before S2-02 begins (PatternCompiler design)

**Owner:** SA (Security Architect)  
**Timing:** Must be completed before S2-02 begins. S2-01 may proceed while CP-2 is in progress.

**Review scope:**

| Item | What SA Reviews | Pass Criteria |
|------|----------------|---------------|
| PatternCompiler design | Parameterized template expander approach — is it string-concat or pure param binding? | No f-string or `.format()` calls that embed pattern YAML values into Cypher strings. All values pass as `$param`. |
| Cypher parameterization linter | Linter logic — does it catch all injection vectors? | Linter must reject: f-strings, `.format()`, `%`-formatting, and `+` concatenation in Cypher strings. |
| tenant_id filter presence check | All compiled Cypher contains `$tid` or `$tenant_id` | CI gate rejects any compiled Cypher without tenant filter. No exceptions. |
| Neo4j query timeout | `session.run(query, timeout=500)` enforcement | Timeout set at driver level, not just at PerformanceGuard level. |

**Deliverable:** SA writes a signed CP-2 sign-off note in the Sprint 2 PR thread before S2-02 is assigned to DEV.

---

### CP-3 — Before any Sprint 4 API story begins (endpoint + auth + RBAC design)

**Owner:** SR (Security Reviewer) with SA confirmation  
**Timing:** Must be completed before S4-01 begins.

**Review scope:**

| Item | What SR Reviews | Pass Criteria |
|------|----------------|---------------|
| All endpoint permissions | `require_permission()` on every endpoint; no bypass | All 12 endpoints from REQUIREMENTS §16 have correct permission. `/health/*` exempt. |
| PII field exposure | `IncidentListItem` vs `IncidentDetail` split | `actor_principal`, `source_ip`, `action` absent from list endpoint. Present in detail only with `cdr:sensitive`. `graph_query` absent from list endpoint. |
| Crown jewel ownership validation | CP1-03: `resource_uid` validated against caller's tenant | Returns 404 (not 403) for foreign resource_uid to avoid existence confirmation. |
| FP feedback rate limiting | 10 verdicts/user/24h — where enforced | Rate limit at endpoint layer, not DB layer. |
| Evidence JSONB schema version | `_schema_version` field present | Schema version 1 in all evidence JSONB. Evolution plan referenced (W-08). |
| Audit log on sensitive read | BFF routes that expose `cdr:sensitive` data emit audit log | Follows CONSTITUTION §1.3a. JSON via `logging.getLogger("api-gateway.audit")`. |

**Deliverable:** SR writes a signed CP-3 sign-off note in the Sprint 4 PR thread before S4-01 is assigned to DEV.

---

### CP-4 — Before Sprint 5 deploy (S5-05)

**Owner:** SR (Security Reviewer) + SA confirmation  
**Timing:** Must be completed before S5-05 (Docker build + EKS deploy).

**Review scope:**

| Item | What SR/SA Reviews | Pass Criteria |
|------|-------------------|---------------|
| CP-1 regression check | Neo4j queries still have tenant_id filters | SA re-runs parameterization linter on all Cypher generated during Sprint 4 additions. |
| No `DEV_BYPASS_AUTH` introduced | Grep entire new engine code | `grep -r "DEV_BYPASS_AUTH" engines/threat_v1/` returns 0 results. |
| No `:latest` image tag | Grep Dockerfile and K8s manifest | `grep ":latest" deployment/aws/eks/engines/engine-threat-v1.yaml` returns 0 results. |
| SLSA Level 1-2 compliance | Pinned base image, build from repo root | Dockerfile uses `python:3.11-slim-bookworm` (or pinned SHA). Build context = repo root. |
| FP feedback isolation | `threat_pattern_suppressions` is tenant-scoped | No global `active=false` set by automated FP feedback. Query the table to verify. |
| Audit logs shipping | Sensitive read audit logs going to `audit_log` table | Not just `print()` — using `logging.getLogger("api-gateway.audit")` with JSON serialize. |

**Deliverable:** SR + SA write signed CP-4 sign-off notes in the Sprint 5 deploy PR thread before S5-05 begins.

---

## Section 4 — Definition of Done (per sprint)

### Sprint 0 — Done When

1. `catalog/rule/aws_rule_check/ec2/` rules: ≥ 80% have `mitre_attack.technique` populated in YAML.
2. `catalog/rule/aws_rule_check/iam/` rules: ≥ 80% have `mitre_attack.technique` populated.
3. `catalog/rule/aws_rule_check/s3/` rules: ≥ 80% have `mitre_attack.technique` populated.
4. `cve_attack_mappings` DDL extra-comma bug fixed; migration applied and verified via `kubectl logs` ending with "MIGRATION COMPLETE".
5. `scan_vulnerabilities.mitre_techniques JSONB` column exists in vuln DB.
6. `engines/threat_v1/scripts/check_mitre_coverage.py` runs and produces per-group coverage table showing all three AWS groups ≥ 80%.
7. S0-05 gate passed and documented — Sprint 1 unblocked.

### Sprint 1 — Done When

1. `engines/threat_v1/scripts/neo4j_schema.cypher` defines all node types, edge types, and indexes; applied to `threat_v1` named database on Aura.
2. Migration `shared/database/migrations/threat_v1_001_new_tables.sql` applied: `threat_incidents`, `threat_scenario_patterns`, `threat_scan_runs_v1`, `threat_pattern_suppressions`, `threat_crown_jewels`, `threat_incident_feedback` tables exist. Migration log shows "MIGRATION COMPLETE".
3. `dedup_key` column is `GENERATED ALWAYS AS` with IMMUTABLE expression — verified by `\d threat_incidents` in psql showing column type STORED.
4. `engines/threat_v1/main.py` returns 200 on `GET /api/v1/health/live` and `GET /api/v1/health/ready`.
5. `run_scan.py` Step 0 ownership validation aborts with logged error when `(scan_run_id, tenant_id, account_id)` not in `scan_orchestration` — verified by unit test.
6. `ResourceResolver`, `MisconfigLoader`, `VulnLoader`, `CDRLoader`, `CrownJewelClassifier`, `EdgeBuilder` implemented and importable without errors.
7. S1-08 integration test passes: node count ≥ 1, edge count ≥ 1, all Resource nodes have `tenant_id` property, no cross-tenant data.
8. CP-1 signed off by SA before S1-04 was started (documented in PR thread).

### Sprint 2 — Done When

1. `PatternRegistry.load_active_patterns(tenant_id)` loads patterns from `threat_scenario_patterns` and excludes suppressed patterns for the tenant.
2. `PatternCompiler` compiled Cypher passes the parameterization linter with 0 violations. Linter CI gate is wired.
3. Tier 1, Tier 2, Tier 3 matchers implemented and callable without errors.
4. `PerformanceGuard` circuit breaker: patterns exceeding 30s are skipped and logged. Auto-quarantine inserts row to suppression log, not global `active=false`.
5. `IncidentWriter` upsert: `ON CONFLICT (dedup_key) DO UPDATE` verified by integration test (two writes with same dedup_key produce one row, with `last_seen_at` updated).
6. Incident state machine: posture → suspicious → active transitions verified by unit test with CDR event injection.
7. `confidence=theoretical` patterns produce posture or suspicious `incident_class`, never active — unit test verifies.
8. `FeedbackProcessor` writes only to `threat_pattern_suppressions` (tenant-scoped) — verified by unit test checking no `active=false` is set on shared pattern.
9. CP-2 signed off by SA before S2-02 was started (documented in PR thread).

### Sprint 3 — Done When

1. All 30 pattern YAML files committed to `catalog/threat_patterns/` (10 per tier).
2. Every pattern has a positive test case and a negative test case — both pass in CI.
3. CI gate (S3-05) is wired: no PR to `catalog/threat_patterns/` merges without all 7 CI checks passing.
4. Pattern regression baseline `tests/regression/baselines/threat_pattern_counts.json` committed with golden JSON for all 30 patterns.
5. ARCH and DL have reviewed all 30 patterns and confirmed logic correctness — documented in PR review threads.
6. SA has signed off on each new tactic chain (ATT&CK + D3FEND check) — documented in PR review threads.

### Sprint 4 — Done When

1. All 12 REST API endpoints from REQUIREMENTS §16 implemented with correct `require_permission()` — except `/api/v1/patterns/{id}` and `/api/v1/coverage` which are observability endpoints (deferred to Phase 6 of REQUIREMENTS build plan but included in S4 scope here; if deferred, explicit PO sign-off required).
2. `IncidentListItem` response verified to NOT include `actor_principal`, `source_ip`, `action`, `graph_query` — automated test in `tests/security/test_pii_stripping.py`.
3. Crown jewel POST validated: foreign resource_uid returns 404, own resource_uid returns 201, audit row written to platform `audit_logs`.
4. BFF view handlers for `threat_center`, `incident_detail/{id}`, `threat_graph`, `inventory_asset_threat/{uid}` all return 200 with non-null required fields.
5. `fetchView("threat_center")` called from frontend returns real data — no mock data, no `_is_mock` flag.
6. Threat Center page renders Zone A, Zone B, Zone C. Zone C updates on row click without page navigation.
7. CDR tab in incident detail hides `actor_principal` and `source_ip` for `analyst` role; shows them for `tenant_admin` and above.
8. Inventory asset Threat tab shows all 5 new fields for an asset that is on an attack path.
9. CP-3 signed off by SR before S4-01 was started (documented in PR thread).

### Sprint 5 — Done When

1. E2E integration test passes: at least 1 incident in `threat_incidents` after `run_scan.py` execution against live scan_run_id.
2. RBAC matrix test passes: all 5 roles × all endpoints verified, 0 unexpected 200s or 403s.
3. BFF contract tests pass: 100% coverage for all 4 threat-v1 BFF view handlers.
4. Load test passes: 1,000-node graph + 30 patterns < 2 minutes total. No pattern exceeds 30s.
5. Pod running `yadavanup84/engine-threat-v1:v-threat-v1-phase1` — confirmed via `kubectl get pods` image check.
6. Post-deploy validation (S5-07) passes all 5 checks — no ERROR in logs, health endpoints return ready, BFF smoke returns non-null kpi_cards.
7. S5-08 decision gate passed: `cspm-pipeline.yaml` updated with `threat-v1-scan` step, CDR CronWorkflow trigger added.
8. CP-4 signed off by SR + SA before S5-05 was started (documented in PR thread).

---

## Section 5 — Risk Register

| # | Risk | Likelihood | Impact | Mitigation | Owner |
|---|------|------------|--------|-----------|-------|
| R-01 | MITRE tagging delay — S0-01/02/03 take longer than 1 week, blocking Sprint 1 start (S0-05 gate fails) | Medium | High | Auto-tag heuristic from REQUIREMENTS §7.3 accelerates bulk tagging. First 10 patterns in S3-01 use the 507 already-tagged AWS rules — partially unblocks pattern authoring. Sprint 1 stories S1-01 through S1-03 do not require MITRE tags and can proceed while S0 completes. | DEV, DL |
| R-02 | Neo4j Aura connection limits — `threat_v1` named database shares the same Aura instance as production graph; concurrent scans may exhaust connection pool | Medium | Medium | Use named database `threat_v1` (separate from production named DB). Set connection pool limit in Neo4j driver config. Per-tenant advisory lock in Postgres serializes graph builds — prevents N simultaneous graph writes per tenant. Add `maxConnectionPoolSize` to driver config during S1-01. Monitor Aura metrics dashboard during S5-04 load test. | ARCH, DEV |
| R-03 | Cypher injection regression — a future pattern PR bypasses the CI linter (e.g., linter has a false-negative on a new Python construct for string building) | Low | Critical | CI linter (S3-05) tests against a positive injection example as part of its own test suite — linter must reject that example. Pattern review gate (ARCH + DL) is a second layer. SA re-runs linter check at CP-4. The linter is pinned to a specific version of the Cypher AST parser. | SA, SR |
| R-04 | CDR PII exposure on list endpoint — a code change in the BFF or IncidentWriter accidentally includes `actor_principal` or `source_ip` in the list response | Medium | Critical | Two mitigations: (a) two separate Pydantic models (`IncidentListItem` vs `IncidentDetail`) — field exclusion is structural, not conditional; (b) automated security test in `tests/security/test_pii_stripping.py` runs on every build. CP-3 and CP-4 include explicit PII strip verification. | SR, SA |
| R-05 | Pattern false-positive rate exceeds 30% — patterns fire on legitimate configurations, triggering per-tenant auto-suppression and reducing detection coverage | Medium | High | (a) Every pattern requires a negative test case before merge; (b) `confidence=theoretical` patterns produce posture-only incidents (never active); (c) auto-suppression is per-tenant only — 1 noisy tenant does not suppress patterns for others; (d) Phase 7 shadow mode validates FP rate before customer-facing rollout; (e) ARCH + DL pattern review gate catches obvious FP-prone patterns before they ship. | ARCH, DL, QA |
| R-06 | Graph size performance — a tenant with 100,000+ resources exceeds the < 45 min scan budget from REQUIREMENTS §11.2 | Low | Medium | Performance budget is defined per tier in REQUIREMENTS §11.2. PerformanceGuard circuit breaker caps per-pattern execution at 30s. Load test in S5-04 validates at 1,000 nodes. For very large tenants: add `LIMIT` clause to ResourceResolver queries as a safety cap; document as a known v1 limitation. Full 100K-resource validation deferred to Phase 7. | ARCH, QA |
| R-07 | Cross-engine DB credential sprawl — `threat_v1` engine reads 4 separate DBs (check, vuln, CDR, inventory); if any DB credential rotates, engine breaks silently | Medium | Medium | All DB credentials come from AWS Secrets Manager (`threat-engine/` path prefix). Engine uses `engine_common.db.get_connection()` which reads from Secrets Manager at startup — rotation requires pod restart (not code change). Document in `SECRETS-CREDENTIALS.md` that threat-v1 requires 4 DB credentials. Add readiness probe check for all 4 DB connections in `GET /api/v1/health/ready`. | DEV, DL |
| R-08 | v1 API surface — `POST /api/v1/incidents/{id}/actions` returns 501 but enterprise customers expect automated response in a Tier-1 CNAPP product | High | Medium | CP1-04 explicitly scoped to Phase 8. The 501 response includes a `message` field with remediation guidance text. PO communicates to enterprise customer prospects that v1 is detection-first. Phase 8 roadmap item filed. Recommendations JSONB in every incident provides manual action guidance. | PO |

---

## Section 6 — Validation Gate (Pre-Pipeline Integration)

### Gate Trigger

S5-08 is the decision gate. Full pipeline integration (adding `threat-v1-scan` step to `cspm-pipeline.yaml`) is approved only after this gate passes. The gate requires S5-01 through S5-07 to all pass first.

### Smoke Test Specification

**Target:** The existing scan_run_id from tenant `my-tenant` that has real AWS cloud data. Use latest scan_run_id from `scan_orchestration` per `latest_scan_run_ids.md`.

**Execution:**

```bash
# Get latest scan_run_id for the AWS tenant
kubectl exec -n threat-engine-engines deployment/engine-check -- python3 -c "
import psycopg2, os
conn = psycopg2.connect(host=os.environ['CHECK_DB_HOST'], user=os.environ['CHECK_DB_USER'],
    password=os.environ['CHECK_DB_PASS'], dbname=os.environ['CHECK_DB_NAME'])
cur = conn.cursor()
cur.execute(\"SELECT scan_run_id FROM check_findings WHERE tenant_id = 'my-tenant' GROUP BY scan_run_id ORDER BY count(*) DESC LIMIT 1\")
print(cur.fetchone()[0])
"

# Run threat-v1 scan against that scan_run_id
kubectl exec -n threat-engine-engines deployment/engine-threat-v1 -- python3 -m run_scan \
  --tenant-id my-tenant \
  --account-id 588989875114 \
  --scan-run-id <above scan_run_id>
```

**Pass Criteria (all must be met):**

| Assertion | Query / Check | Pass Threshold |
|-----------|--------------|----------------|
| Ownership validation passes | `run_scan.py` does not abort at Step 0 | No "OWNERSHIP VALIDATION FAILED" in logs |
| Graph populated | `MATCH (r:Resource {tenant_id: 'my-tenant'}) RETURN count(r)` in Neo4j `threat_v1` DB | ≥ 10 Resource nodes |
| At least 1 incident created | `SELECT count(*) FROM threat_incidents WHERE tenant_id = 'my-tenant'` | ≥ 1 incident |
| Tier-1 pattern fires | `SELECT count(*) FROM threat_incidents WHERE tenant_id = 'my-tenant' AND tier = 1` | ≥ 1 Tier-1 incident |
| No pattern execution errors | Count ERROR lines in `run_scan.py` output | 0 pattern execution errors |
| Scan run marked complete | `SELECT status FROM threat_scan_runs_v1 WHERE tenant_id = 'my-tenant' ORDER BY created_at DESC LIMIT 1` | `status = completed` |
| No cross-tenant leakage | `SELECT DISTINCT tenant_id FROM threat_incidents` | Only `my-tenant` present |
| Engine health post-scan | `GET /api/v1/health/ready` after scan completes | `{"status": "ready"}` |

**Failure definition:** Any single assertion failing above constitutes a gate failure. The gate is binary — pass or fail.

### Rollback Plan

If the smoke test fails:

1. Do NOT add `threat-v1-scan` to `cspm-pipeline.yaml`.
2. Do NOT remove `engine-threat` (existing engine) from the pipeline.
3. Capture full `run_scan.py` output and Neo4j state for debugging.
4. Triage failure within 24 hours — classify as: (a) graph build failure, (b) pattern execution failure, (c) incident write failure, (d) infrastructure failure.
5. Fix root cause in a targeted patch sprint (1–3 days), not by modifying the gate criteria.
6. Re-run the full smoke test from scratch after the fix — not just the failing assertion.
7. If graph build fails due to Neo4j Aura connectivity: check Aura console for connection limits, restart engine pod, verify `health/ready` shows Neo4j connected before re-running.
8. If pattern execution fails with Cypher error: run parameterization linter on the failing pattern, check for tenant_id filter presence, do NOT bypass the pattern — fix it.
9. `kubectl rollout undo deployment/engine-threat-v1 -n threat-engine-engines` if pod is in error state.
10. Document the failure, the fix applied, and the re-test result in the Sprint 5 retrospective.

---

## Appendix A — Story Count Summary

| Sprint | Stories | DEV effort | Notes |
|--------|---------|-----------|-------|
| Sprint 0 | 5 (S0-01 to S0-05) | ~1 week (1 security analyst + 1 DEV parallel) | Parallel with Sprint 1 setup where possible |
| Sprint 1 | 8 (S1-01 to S1-08) | ~2 weeks (1 backend DEV + ARCH consult) | CP-1 gate before S1-04 |
| Sprint 2 | 10 (S2-01 to S2-10) | ~2 weeks (1 backend DEV) | CP-2 gate before S2-02 |
| Sprint 3 | 5 (S3-01 to S3-05) | ~1 week (1 DEV + detection engineer) | All 30 patterns + CI gate |
| Sprint 4 | 10 (S4-01 to S4-10) | ~2 weeks (1 backend + 1 frontend DEV) | CP-3 gate before S4-01 |
| Sprint 5 | 8 (S5-01 to S5-08) | ~1 week (QA + DEV + DL) | CP-4 gate before S5-05 |
| **Total** | **46 stories** | **~9 weeks** | 2-engineer parallel team |

## Appendix B — New Files Created by This Sprint

| File | Sprint | Purpose |
|------|--------|---------|
| `engines/threat_v1/scripts/check_mitre_coverage.py` | S0-05 | Coverage validation script |
| `engines/threat_v1/scripts/neo4j_schema.cypher` | S1-01 | Neo4j node/edge/index definitions for `threat_v1` DB |
| `engines/threat_v1/scripts/cypher_parameterization_linter.py` | S2-02 | CI gate: rejects string-interpolated Cypher |
| `shared/database/migrations/threat_v1_001_new_tables.sql` | S1-02 | DDL for all new v1 tables |
| `shared/database/schemas/threat_schema.sql` | S1-02 | Updated with new v1 tables |
| `deployment/aws/eks/engines/engine-threat-v1.yaml` | S1-03 | K8s Deployment + Service manifest |
| `engines/threat_v1/main.py` | S1-03 | FastAPI app with health endpoints |
| `engines/threat_v1/run_scan.py` | S1-07 | Scan entry point with ownership validation as Step 0 |
| `engines/threat_v1/requirements.txt` | S1-03 | Python dependencies |
| `engines/threat_v1/Dockerfile` | S1-03 | Pinned base image, repo-root build context |
| `catalog/threat_patterns/tier1/*.yaml` | S3-01 | 10 Tier-1 pattern files |
| `catalog/threat_patterns/tier2/*.yaml` | S3-02 | 10 Tier-2 pattern files |
| `catalog/threat_patterns/tier3/*.yaml` | S3-03 | 10 Tier-3 pattern files |
| `tests/regression/baselines/threat_pattern_counts.json` | S3-04 | Pattern regression golden baseline |
| `engines/threat_v1/tests/integration/test_graph_builder.py` | S1-08 | GraphBuilder integration test |
| `engines/threat_v1/tests/e2e/test_threat_v1_pipeline.py` | S5-01 | Full pipeline E2E test |
| `engines/threat_v1/tests/rbac/test_threat_v1_rbac.py` | S5-02 | RBAC matrix test |
| `tests/bff/test_threat_center_view.py` | S5-03 | BFF contract test |
| `tests/security/test_pii_stripping.py` | S4-02 | PII field exclusion security test |
| `tests/post_deploy/validate_threat_v1_deploy.sh` | S5-07 | Post-deploy validation script |

## Appendix C — What Already Exists (Do Not Duplicate)

| Existing asset | Location | Status | v1 action |
|----------------|----------|--------|-----------|
| `GraphBuilder` + `exposure_loader.py` + `cve_loader.py` | `engines/threat/threat_engine/graph/` | Live | Do not modify. v1 writes to named Neo4j DB `threat_v1` — no conflict. |
| `ThreatDetector`, `DriftDetector` | `engines/threat/threat_engine/detector/` | Live | Do not modify. v1 uses `PatternExecutor` in separate module. |
| `threat_findings`, `threat_detections`, `threat_report` tables | `threat_engine_threat` DB | Live | v1 writes only to `_v1`-suffixed new tables. No writes to existing tables. |
| ScenarioCard component | `frontend/` | Exists, mocked | Wire to real BFF in S4-08 — do not replace the component, only the data source. |
| `/threats/[id]` page | `frontend/` | Exists, partially wired | Wire to real BFF in S4-09 — do not replace the page, only the data source. |
| `mitre_technique_reference` table | `threat_engine_threat` DB | 102 curated rows | Keep as-is. Additional columns from `threat_mitre_technique_ref_001.sql` already applied. |
| Empty stub `__init__.py` files | `engines/threat_v1/threat_v1/graph/`, `detector/`, `patterns/`, `api/`, `database/`, `correlator/`, `schemas/` | Empty stubs | Replace with real implementation in Sprint 1-4. Do not delete — import paths are set. |
