# Security Review — Pre-Implementation Gate
## threat_v1 Engine

**Reviewer:** Security Reviewer agent (bmad-security-reviewer)
**Date:** 2026-05-10
**Review stage:** Pre-implementation design gate (before Sprint 1 coding begins)
**Frameworks applied:** OWASP SAMM, OWASP Top 10, STRIDE, PASTA, NIST CSF 2.0, CSA CCM v4, SLSA Level 1-2

---

## 1. Review Summary

### Artifacts Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `engines/threat_v1/ARCHITECTURE.md` | 1,054 | System design, component design, API surface, security architecture, deployment |
| `engines/threat_v1/SPRINT_PLAN.md` | 420 | 46 stories across 6 sprints, CP checkpoints, RACI, DoD |
| `engines/threat_v1/REQUIREMENTS.md` | 1,383 | Full requirements inc. Sections 16 (API) and 17 (Security Review) |
| `.claude/documentation/CSPM_CONSTITUTION.md` | 556 | Platform constitution (supreme rule set) |
| `.claude/documentation/TESTING_QUALITY.md` | 745 | 10-level quality gate specification |
| `engines/threat/threat_engine/api_server.py` (lines 3013–3050) | reference | Existing `POST /api/v1/hunt/execute` endpoint — the CP1-06 gap this engine must NOT repeat |

**Total lines reviewed:** 4,158 + reference code inspection

### Verdict

**APPROVED WITH CONDITIONS**

The design and sprint plan are architecturally sound and demonstrate a high level of security awareness. All 8 CP-1 blockers identified in the security architecture review (REQUIREMENTS.md §17) have been documented with mitigations, and 6 of 8 are fully resolved in the architecture. The remaining 2 (CP1-01 and CP1-05) are correctly identified as high-risk and have strong mitigation plans but require implementation-level verification.

Development may proceed under the specific sprint-by-sprint conditions listed in Section 10.

---

## 2. OWASP SAMM Implementation Function Checklist

### Secure Build

| Practice | Addressed? | Location | Gap |
|----------|-----------|----------|-----|
| Pinned base image (no `latest`) | YES | ARCHITECTURE.md §10.1, SPRINT_PLAN.md S1-03 | S1-03 specifies `python:3.11-slim-bookworm` — PASS |
| `requirements.txt` pins all direct deps to exact versions | PARTIAL | SPRINT_PLAN.md S1-03 mentions creating `requirements.txt` | No story explicitly mandates `==` version pinning for ALL deps. Gap: S1-03 note says "Python dependencies" but does not state exact-version requirement. Dev must confirm no `>=` bounds on direct deps. |
| No `pip install` at container runtime | NOT STATED | Dockerfile story (S1-03) | No explicit prohibition in story notes. Must be confirmed in Dockerfile review during CP-1. |
| Dockerfile does not `curl \| sh` | NOT STATED | S1-03 | No story explicitly checks this. Add to CP-4 SLSA checklist. |
| Build triggered from pinned commit SHA | NOT STATED | S5-05 | CI/CD pipeline setup not covered — sprint plan describes manual `docker build`. SLSA Level 2 requires build provenance. Gap ticket required. |
| Cypher parameterization linter in CI | YES | S2-02, S3-05 | Strong coverage — linter + $tenant_id presence check + pattern CI gate. |

### Secure Deployment

| Practice | Addressed? | Location | Gap |
|----------|-----------|----------|-----|
| Post-deploy mandatory health check | YES | S5-07 | Explicitly defined: 5-check post-deploy validation script with rollback trigger on any failure. Matches TESTING_QUALITY §Level 10. PASS |
| Image tag verification after rollout | YES | S5-05, S5-07 | `kubectl get pods` image tag check specified. PASS |
| No `:latest` in K8s manifest | YES | ARCHITECTURE.md §10.1, S1-03 | `yadavanup84/engine-threat-v1:v-threat-v1-phase1` pinned. PASS |
| readinessProbe + livenessProbe in manifest | YES | ARCHITECTURE.md §10.1, S1-03 | Both probes specified. PASS |
| Resource limits on all containers | YES | ARCHITECTURE.md §10.1 | `requests` + `limits` required. PASS |
| Secrets from AWS Secrets Manager (not bare env vars) | YES | ARCHITECTURE.md §10.5 | "Credentials resolved from AWS Secrets Manager" stated. PASS |

### Defect Management

| Practice | Addressed? | Location | Gap |
|----------|-----------|----------|-----|
| Security defect tracking (dedicated story) | PARTIAL | ARCHITECTURE.md §7.2 (W-01 through W-10) | 10 warnings documented. W-10 requires filing 3 gap tickets for RS/RC gaps. However, there is no dedicated sprint story for "security defect tracking setup" or "open warning resolution sprint." Warnings are tracked in the architecture doc but there is no formal tracking story. Recommend adding a WARN-resolution story to Sprint 5 or labeling each warning with a GitHub issue reference before S5-08. |
| Warning-to-story traceability | PARTIAL | Sprint stories reference some warnings (W-01, W-02, W-05, W-06, W-07, W-09) | W-03, W-04, W-08, W-10 have no corresponding sprint story. W-03 (startup crash protection) and W-08 (evidence schema migration plan) should be explicit ACs. See findings table. |

---

## 3. OWASP Top 10 Risk Assessment

| OWASP Item | Applicable? | Addressed? | Story Ref | Gap |
|-----------|-------------|-----------|----------|-----|
| A01 Broken Access Control | YES — HIGH | YES | S4-01, S5-02, S1-07 | `require_permission()` on all endpoints; CP1-03 ownership validation; scan_run_id ownership (CP1-07). One gap: `GET /api/v1/scan/status/{job_id}` — architecture does not specify whether `job_id` is validated to belong to auth tenant before returning status. See finding SR-006. |
| A02 Cryptographic Failures | YES — MEDIUM | YES | S1-02 (dedup_key), ARCHITECTURE.md §5.2 | `dedup_key` is SHA256 (PASS). No plaintext secrets in logs (stated in ARCHITECTURE.md §10.5). Neo4j uses `neo4j+s://` (TLS). PostgreSQL sslmode not explicitly stated for cross-engine reads. See finding SR-007. |
| A03 Injection | YES — CRITICAL | YES | S2-02, S3-05, CP-2 | Cypher injection (CP1-01) has the strongest mitigation of any item: template expander + CI linter + $tenant_id presence check + CP-2 SA gate. SQL injection: cross-engine reads use parameterized `%s` (stated in REQUIREMENTS §3.2 SQL block). PASS. |
| A04 Insecure Design | YES — CRITICAL | YES | S4-02, ADR-005 | PII exposure (CP1-02): two-model structural separation is the correct design. Not "strip at runtime" but "structurally absent from list model." PASS. Actions endpoint (CP1-04): HTTP 501 is correct. PASS. |
| A05 Security Misconfiguration | YES — MEDIUM | PARTIAL | S1-03, S5-05 | K8s manifest: no `privileged: true` constraint stated explicitly in sprint stories (though constitution prohibits it). SLSA: base image pinned. Gap: no story verifies `runAsNonRoot: true` or drops `CAP_SYS_ADMIN` in the new manifest. See finding SR-008. |
| A06 Vulnerable & Outdated Components | YES — LOW | PARTIAL | S1-03 | `requirements.txt` created in S1-03. No automated dependency scan (Dependabot, Safety, or pip-audit) story. For a new engine this is LOW risk at sprint start but should be added before Shadow Mode. |
| A07 Identification and Authentication Failures | YES — CRITICAL | YES | S1-07 (CP1-07), S4-01, S4-03 | scan_run_id spoofing: Step 0 ownership validation before any DB read (CP1-07). Crown jewel ownership: 404 on mismatch (CP1-03). All endpoints gated by `require_permission()`. Health endpoints correctly excluded. PASS. |
| A08 Software and Data Integrity Failures | YES — HIGH | YES | S2-02, S3-05 | YAML patterns go through: Pydantic schema validation + PatternCompiler compilation check + CI linter. Pattern authoring workflow has 7 CI gate checks before merge. PASS. |
| A09 Security Logging and Monitoring Failures | YES — MEDIUM | PARTIAL | S5-07, ARCHITECTURE.md §10.5 | Scan start/end logged with scan_run_id and tenant_id (stated). ERROR level for ownership failure (S1-07). CDR sensitive-read audit log to `audit_logs` table referenced (CP-3 checklist). Gap: no explicit story for structured JSON audit log shipping to durable store for the new engine's sensitive reads (per CSPM_CONSTITUTION §1.3a "ship-gate within 1 sprint of permission going live"). See finding SR-009. |
| A10 Server-Side Request Forgery | LOW | YES (N/A) | ARCHITECTURE.md §2 | Engine makes no outbound HTTP calls to user-supplied URLs. No cloud SDK calls (reads from DB, writes to Neo4j/Postgres). SSRF surface is minimal. PASS. |

---

## 4. CP-1 Blocker Verification Table

| CP | Description | In Architecture? | Story | AC# | Gap |
|----|-------------|-----------------|-------|-----|-----|
| CP1-01 | PatternCompiler Cypher injection via pattern field interpolation | YES — ARCHITECTURE.md §7.1, §8.2 | S2-02 (implementation), S3-05 (CI gate) | S2 DoD item 2: "compiled Cypher passes the parameterization linter with 0 violations." S3-05 gate: all 7 CI checks including $tenant_id presence. | No AC explicitly states that PatternCompiler is implemented as a "template expander from a library of safe templates" vs. a string builder — only that output is linted. Recommend adding a code review AC that confirms the compiler implementation approach, not just its output. |
| CP1-02 | Evidence JSONB PII exposure on list endpoint | YES — ARCHITECTURE.md §6, ADR-005 | S4-02 (models), S4-09 (frontend) | S4 DoD item 2: automated test in `tests/security/test_pii_stripping.py`. CP-3 checklist. | PASS — two-model structural approach + automated test is the strongest possible mitigation. No gap. |
| CP1-03 | Crown jewel ownership spoofing | YES — ARCHITECTURE.md §6, §7.1 | S4-03 | S4 DoD item 3: "foreign resource_uid returns 404, own returns 201, audit row written." CP-3 checklist. | PASS. 404 (not 403) correctly avoids existence confirmation. |
| CP1-04 | Actions endpoint undefined execution model | YES — ARCHITECTURE.md §2, §6 | S4-04 | S4-04 notes: HTTP 501 with guidance text. `require_permission("threat:write")` still enforced. | PASS. Correctly noted that 501 does not bypass auth. |
| CP1-05 | Global FP auto-quarantine is a detection suppression attack surface | YES — ARCHITECTURE.md §4.3, ADR-003 | S2-10 | S2 DoD item 8: "FeedbackProcessor writes only to `threat_pattern_suppressions` (tenant-scoped) — verified by unit test checking no `active=false` is set on shared pattern." | Gap: S2-06 (PerformanceGuard) says patterns exceeding p99 budget "insert row into auto-quarantine log and set `active=false` in `threat_scenario_patterns`." This contradicts CP1-05. The per-pattern auto-quarantine on PERFORMANCE grounds sets global `active=false`, not per-tenant. The CP1-05 mitigation is for FP feedback — but performance-based global quarantine is a separate denial-of-service surface. See BLOCKER finding SR-001. |
| CP1-06 | Ad-hoc Cypher endpoint | YES — ARCHITECTURE.md §2, ADR-004 | None needed (exclusion) | ARCHITECTURE.md §6 explicitly excludes `POST /api/v1/hunt/execute`. | VERIFIED against existing threat engine: `engines/threat/threat_engine/api_server.py` line 3013 has `POST /api/v1/hunt/execute` accepting a raw `cypher: Optional[str]` body with NO `require_permission()` decorator. threat_v1 correctly excludes this. PASS — but note that the existing v0 endpoint remains live and unprotected during parallel operation. See finding SR-002. |
| CP1-07 | scan_run_id ownership check missing | YES — ARCHITECTURE.md §3, §10.3 | S1-07 | S1 DoD item 5: "run_scan.py Step 0 ownership validation aborts with logged error when tuple not in scan_orchestration — verified by unit test." | PASS. Well-specified: SELECT 1 before any DB reads, ERROR level log, exit code 1. |
| CP1-08 | `:latest` image tag in Argo template | YES — ARCHITECTURE.md §10.1, §10.2 | S1-03, S5-05 | CP-4 checklist: `grep ":latest" deployment/aws/eks/engines/engine-threat-v1.yaml` must return 0 results. | PASS. Pinned phase-based tags documented. |

---

## 5. API Security Review

| Method | Path | Permission | Auth Checked? | Rate Limited? | PII Risk | Notes |
|--------|------|-----------|--------------|--------------|---------|-------|
| GET | `/api/v1/incidents` | `threat:read` | YES — `require_permission()` | NO | LOW — PII stripped in IncidentListItem | Returns IncidentListItem model: actor_principal/source_ip/action absent by design |
| GET | `/api/v1/incidents/{id}` | `threat:read` + `cdr:sensitive` (conditional) | YES | NO | HIGH — full CDR PII in IncidentDetail | Field-level check on cdr:sensitive. Two model types enforced. |
| POST | `/api/v1/incidents/{id}/feedback` | `threat:write` + `feedback:write` | YES | YES — 10/user/24h | NONE | Rate limit specified at endpoint layer (W-09). INSERT-only table. |
| POST | `/api/v1/incidents/{id}/actions` | `threat:write` | YES | NO | NONE | Returns HTTP 501. Auth still enforced (correctly). CP1-04. |
| GET | `/api/v1/patterns` | `threat:read` | YES | NO | NONE | Filtered by per-tenant suppression join. |
| GET | `/api/v1/patterns/{id}` | `threat:read` | YES | NO | NONE | Pattern detail. No PII. |
| POST | `/api/v1/crown-jewels` | `threat:write` | YES | NO | NONE | Ownership-validates resource_uid against resource_inventory WHERE tenant_id = auth. Returns 404 on mismatch. CP1-03. |
| DELETE | `/api/v1/crown-jewels/{resource_uid}` | `threat:write` | YES | NO | NONE | Same ownership validation. Audit log written. |
| GET | `/api/v1/scan/status/{job_id}` | `threat:read` | YES | NO | NONE | GAP: job_id is not validated to belong to auth tenant before returning status. A tenant could poll status of another tenant's scan if they guess the job_id (UUID — low probability but architectural violation). See finding SR-006. |
| GET | `/api/v1/coverage` | `threat:read` | YES | NO | NONE | Aggregate heatmap. No per-tenant data leakage risk stated. |
| GET | `/api/v1/health/live` | none | NO (intentional) | NO | NONE | Liveness probe — correct to exclude auth. |
| GET | `/api/v1/health/ready` | none | NO (intentional) | NO | NONE | Readiness probe — correct to exclude auth. |

**`POST /api/v1/hunt/execute` exclusion verified:** Explicitly excluded from v1 API in ARCHITECTURE.md §6 and §2. ADR-004 documents the rationale. PASS.

**`POST /api/v1/incidents/{id}/actions` confirmed:** Returns HTTP 501 with guidance text. Auth still checked. CP1-04. PASS.

**`POST /api/v1/crown-jewels` ownership validation confirmed:** Resource_uid validated against resource_inventory WHERE tenant_id = auth_ctx.tenant_id. 404 on mismatch (avoids existence confirmation). CP1-03. PASS.

**Missing permission stories:** All 12 endpoints in the table above have permission annotations in the architecture. S4-01 creates the core endpoints with `require_permission()`. PASS.

---

## 6. Multi-Tenancy Compliance Check

| Table | tenant_id column? | Queries scoped by tenant_id? | Story enforcing this? |
|-------|------------------|-----------------------------|-----------------------|
| `threat_incidents` | YES — `VARCHAR(128) NOT NULL` | YES — IncidentDeduper groups by tenant_id; all reads scoped | S2-07, S4-01 |
| `threat_scenario_patterns` | NO — shared table (intentional — patterns are global) | N/A — patterns are not tenant data | PatternRegistry filters suppressions per tenant; this is correct |
| `threat_scan_runs_v1` | YES — `VARCHAR(128) NOT NULL` | YES — Step 0 validates tenant_id before write | S1-07 |
| `threat_pattern_suppressions` | YES — `VARCHAR(128) NOT NULL`, PRIMARY constraint includes tenant_id | YES — PatternRegistry joins on (tenant_id, pattern_id) | S2-01, S2-10, ADR-003 |
| `threat_crown_jewels` | YES — `VARCHAR(128) NOT NULL`, UNIQUE on (tenant_id, resource_uid) | YES — ownership validated before write (CP1-03) | S4-03 |
| `threat_incident_feedback` | YES — `VARCHAR(128) NOT NULL` | YES — INSERT-only, always includes tenant_id | S2-10 |
| Neo4j Resource nodes | YES — `tenant_id` property on every node | YES — `$tenant_id` or `$tid` parameter required in every compiled Cypher | S2-02, S3-05 CI gate |
| Neo4j CDREvent nodes | YES — tenant_id on Resource parent; CDREvent attached via edge | PARTIAL — CDREvent finding_id is from cdr_findings; tenant_id is on the Resource node, not on CDREvent itself | CDRLoader reads cdr_findings scoped by tenant_id, so nodes entered are scoped — but a MATCH on CDREvent label alone without traversing from a tenant-scoped Resource would be unscoped. Cypher CI linter must catch this pattern. See finding SR-003. |
| Neo4j CDRActor nodes | YES — `tenant_id` property | YES — stated in ARCHITECTURE.md §5.1 | CDRLoader |

**Cross-engine DB reads (MisconfigLoader, VulnLoader, CDRLoader):** All reads in REQUIREMENTS.md §3.2 include `WHERE tenant_id = :tenant_id` in the SQL blocks. Parameterized queries used (`%s`-style). PASS.

**Constitution §2.5 cross-engine DB access:** The architecture explicitly reads 5 other engine DBs directly (check DB, vuln DB, CDR DB, inventory DB, IAM DB). This violates CSPM_CONSTITUTION §2.5 which states "Cross-engine data access happens via HTTP API, not direct DB queries. Never query another engine's DB from a different engine's code." See BLOCKER finding SR-004.

---

## 7. Secret/Credential Hygiene Review

| Item | Status | Evidence |
|------|--------|---------|
| Neo4j credentials via env vars (not hardcoded) | PASS | ARCHITECTURE.md §10.5: "Credentials resolved from AWS Secrets Manager (platform constitution: credential resolution via Secrets Manager, never bare env vars)" |
| Cross-engine DB credentials (check, vuln, CDR, inventory, IAM) via env vars | PASS | ARCHITECTURE.md §10.5 references Secrets Manager; risk register R-07 documents that threat_v1 requires 4 DB credentials and states they come from Secrets Manager |
| K8s secrets story for all required env vars | PARTIAL | R-07 says "Document in SECRETS-CREDENTIALS.md that threat-v1 requires 4 DB credentials." No sprint story creates the K8s secrets or references which Secrets Manager paths are used. Add a story or sub-task in S1-03 to document all required env vars and confirm they exist in Secrets Manager before deploy. |
| `credential_ref` stripped from list responses | NOT APPLICABLE | threat_incidents does not have a `credential_ref` column (engine reads credentials from other DBs but does not store them in its own findings). No `credential_ref` exposure risk for this engine. PASS. |
| No credentials baked into image layers | NOT VERIFIED | No story explicitly runs `docker history --no-trunc` as a SLSA check. Add to CP-4 SLSA checklist. |
| Neo4j URI in code | PASS | URI `neo4j+s://17ec5cbb.databases.neo4j.io` is in architecture doc only (documentation). The code must load this from env/Secrets Manager. Verify during CP-1 review. |

---

## 8. Test Coverage Assessment

| Requirement | Story | Coverage Status | Gap |
|-------------|-------|----------------|-----|
| BFF contract tests: 100% per TESTING_QUALITY §Level 3 | S5-03 | COVERED — explicit contract for all 4 BFF view handlers: `threat_center`, `incident_detail`, `threat_graph`, `inventory_asset_threat` | Contract specifies `actor_principal` absent from list endpoint, present in detail for cdr:sensitive — correct |
| RBAC matrix test: 5 roles × all endpoints | S5-02 | COVERED — test file `engines/threat_v1/tests/rbac/test_threat_v1_rbac.py` specified | Includes: viewer 403 on cdr:sensitive, analyst read-only, unauthenticated 401, crown jewel write 403 for viewer/analyst |
| Pattern regression baseline: 0 drift | S3-04 | COVERED — `tests/regression/baselines/threat_pattern_counts.json` with golden JSON per pattern | Must be committed before Sprint 4 starts (per DoD) |
| Integration E2E: GraphBuilder → PatternExecutor → IncidentWriter chain | S5-01 | COVERED — `engines/threat_v1/tests/e2e/test_threat_v1_pipeline.py` | Uses real scan_run_id per constitution. 8 assertions including cross-tenant check |
| Security: Cypher injection attempt | S3-05 | COVERED — CI linter must reject a positive injection example as part of its own test suite (R-03 mitigation) | Gap: no dedicated `tests/security/test_cypher_injection.py` file listed in Appendix B. The linter CI gate tests this at compile time but a runtime injection attempt test should be in `tests/security/`. See finding SR-010. |
| Security: cross-tenant read attempt | S5-06, S5-01 | COVERED — S5-01 assertion 7: "SELECT DISTINCT tenant_id FROM threat_incidents returns only my-tenant" | Also S5-06: "no cross-tenant data in results." |
| PII strip test | S4-02 | COVERED — `tests/security/test_pii_stripping.py` | Runs on every build per S4 DoD item 2. |
| GraphBuilder integration test | S1-08 | COVERED — verifies tenant_id on all Resource nodes, no cross-tenant nodes | Real DB + real scan_run_id required |
| Unit test: confidence=theoretical cannot produce incident_class=active | S2-07 | COVERED — S2 DoD item 7 | Unit test required |
| Unit test: FeedbackProcessor does not set global active=false | S2-10 | COVERED — S2 DoD item 8 | Unit test required |
| Load test: 1,000-node graph + 30 patterns < 2 min | S5-04 | COVERED | Named database `threat_v1_test` for isolation |

---

## 9. Findings and Blockers

| ID | Severity | Finding | File/Section | Recommendation |
|----|----------|---------|-------------|----------------|
| SR-001 | CRITICAL | PerformanceGuard global `active=false` is a denial-of-service vector not covered by CP1-05 | SPRINT_PLAN.md S2-06: "set `active=false` in `threat_scenario_patterns`" | S2-06 story contradicts CP1-05. Performance-triggered quarantine must also be per-tenant (insert into `threat_pattern_suppressions` with `auto_generated=true`, same as FP feedback). Setting global `active=false` for performance reasons is an admin action requiring SA approval — same rule as FP feedback. Fix: change S2-06 to insert into `threat_pattern_suppressions` (per-tenant, `auto_generated=true`, reason='performance_p99_exceeded') instead of setting `active=false`. Update S2 DoD item 4 accordingly. |
| SR-002 | HIGH | Existing `POST /api/v1/hunt/execute` in v0 engine (`engines/threat/`) has NO `require_permission()` decorator and accepts raw Cypher strings | `engines/threat/threat_engine/api_server.py` line 3013 | This endpoint is unauthenticated and allows ad-hoc Cypher execution during the parallel operation period. While threat_v1 correctly excludes this endpoint, the v0 endpoint remains exposed. Require a fix PR for v0 before shadow mode begins (Phase 7). At minimum, add `require_permission("threat:read")` to the `execute_hunt` function and restrict the `cypher` body parameter to authenticated callers. This is not a blocker for threat_v1 Sprint 1 but must be tracked as a separate security fix. |
| SR-003 | HIGH | CDREvent nodes in Neo4j do not carry tenant_id as a first-class property — a Cypher query matching `(:CDREvent)` directly without traversing from a tenant-scoped Resource node would return all tenants' events | ARCHITECTURE.md §5.1, §4.1 | Add `tenant_id` as a property on CDREvent nodes in addition to the existing Resource→CDREvent edge path. Update the CI linter to also check that any MATCH starting at CDREvent includes `$tenant_id` filter. Add a specific negative test in S1-08 that attempts to read CDREvent nodes without tenant filter and verifies 0 results. |
| SR-004 | HIGH | Direct cross-engine DB reads violate CSPM_CONSTITUTION §2.5 ("Never query another engine's DB from a different engine's code") | ARCHITECTURE.md §5.3, CSPM_CONSTITUTION.md §2.5 | The architecture explicitly reads 5 other engine DBs directly (check, vuln, CDR, inventory, IAM). This is a deliberate design decision (REQUIREMENTS.md §11 "Technical Decisions") but is a documented constitution exception. An ADR must be written and signed off by the Architect before Sprint 1 begins, documenting the justification (graph builders require bulk data that would be prohibitively slow over HTTP), the scope (read-only, threat_v1 does not write to other engine DBs), and any mitigating controls (parameterized queries, tenant_id scoping). Without an ADR this is a constitution violation. |
| SR-005 | HIGH | CSPM_CONSTITUTION §1.3a requires audit logs on READ for data classified as sensitive (cdr:sensitive) to be shipped to a durable store within 1 sprint of the permission going live | CSPM_CONSTITUTION.md §1.3a, SPRINT_PLAN.md (no story covers this) | No sprint story creates the audit log shipping mechanism for `cdr:sensitive` reads in threat_v1. CP-3 checklist mentions "BFF routes that expose cdr:sensitive data emit audit log" but does not specify durable store delivery. Add an explicit acceptance criterion to S4-05 (BFF views) or S5-07 (post-deploy): "cdr:sensitive reads emit audit log to platform `audit_log` table using `logging.getLogger('api-gateway.audit')` with JSON format per CONSTITUTION §1.3a." |
| SR-006 | MEDIUM | `GET /api/v1/scan/status/{job_id}` does not specify whether `job_id` is validated to belong to auth tenant before returning status | ARCHITECTURE.md §6 endpoint table | Add ownership validation to this endpoint: `SELECT 1 FROM threat_scan_runs_v1 WHERE run_id = :job_id AND tenant_id = :auth_tenant_id`. Return 404 if not found. Add to S4-01 acceptance criteria and S5-02 RBAC test matrix. |
| SR-007 | MEDIUM | PostgreSQL sslmode is not explicitly stated for cross-engine DB connections | ARCHITECTURE.md §5.3, CSPM_CONSTITUTION.md §7.2 | Add explicit `sslmode=require` to all psycopg2 connection strings in cross-engine DB readers (MisconfigLoader, VulnLoader, CDRLoader, CrownJewelClassifier, EdgeBuilder). This should use the same `engine_common.db.get_connection()` helper as other engines, which should already enforce SSL. Verify in CP-1 review that the shared connection helper mandates SSL. |
| SR-008 | MEDIUM | K8s manifest for engine-threat-v1 does not have an explicit story to verify `runAsNonRoot: true` or security context settings | ARCHITECTURE.md §10.1, CSPM_CONSTITUTION.md §7.3 | Add to S1-03 acceptance criteria: "Manifest does not set `privileged: true`, `hostNetwork: true`. `securityContext.runAsNonRoot: true` set." Add to CP-4 checklist. |
| SR-009 | MEDIUM | W-03 (upload_scenario_patterns.py crash protection) and W-08 (evidence schema evolution plan) have no corresponding sprint story or AC | ARCHITECTURE.md §7.2, SPRINT_PLAN.md | W-03: add to S1-04 or pattern catalog loading story as explicit AC: "per-pattern errors in upload_scenario_patterns.py are caught and logged; engine startup does not abort." W-08: a Phase 8 ADR reference is correct but the `_schema_version` field must be in the evidence schema from day 1 — add to S2-09 (StoryBuilder) AC. |
| SR-010 | MEDIUM | No dedicated runtime Cypher injection security test in `tests/security/` | SPRINT_PLAN.md Appendix B, TESTING_QUALITY.md §Level 9 | Add `tests/security/test_cypher_injection.py` to Appendix B and S5-01 scope. Test should attempt to craft a pattern-derived value containing Cypher syntax and verify the compiled query still uses parameterized binding (not that the value is sanitized — it should never reach the Cypher string). |
| SR-011 | MEDIUM | Requirements.txt version pinning not explicitly mandated in S1-03 story notes | SPRINT_PLAN.md S1-03, SLSA Level 1-2 | Add explicit AC to S1-03: "All direct dependencies in requirements.txt use exact version pins (`==`). No `>=` without upper bound on direct dependencies." Verify at CP-1. |
| SR-012 | LOW | W-04 (CDR multi-account resolution documented as intentional) has no story | SPRINT_PLAN.md, ARCHITECTURE.md §7.2 | Add code comment requirement to S1-05 (CDRLoader) AC: "CDR is tenant-wide; account_id join happens downstream via resource_uid — document as intentional in CDRLoader code per W-04." Low risk but traceability matters. |
| SR-013 | LOW | No story for SLSA build provenance (Level 2 requirement — build triggered from pinned commit SHA) | SPRINT_PLAN.md, CSPM_CONSTITUTION.md §7.1 | SLSA Level 2 requires build provenance from a pinned commit SHA, not a floating branch. Current sprint plan documents manual `docker build` steps. Add a note to S5-05 or S5-08 to configure CI/CD pipeline to produce a SLSA Level 2 provenance attestation for the `v-threat-v1-phase1` image. Can be a tech debt ticket if CI/CD is not yet set up. |
| SR-014 | LOW | CSA CCM v4 mapping not explicitly stated for new finding types in threat_v1 | CSPM_CONSTITUTION.md §7.1, Security Reviewer checklist | The threat incident is not a check rule (no CCM mapping required per rule). However, the threat-v1 engine itself touches multiple CCM domains. The sprint plan should document CCM domain coverage: IVS-01 (network isolation incidents), IAM-01/02 (privilege escalation incidents), DSP-07 (data access incidents). Add one-line CCM mapping to S3-01/02/03 (pattern authoring) PO acceptance criteria. |

---

## 10. Pre-Implementation Sign-off

I, the Security Reviewer (bmad-security-reviewer), have reviewed the threat_v1 architecture document (1,054 lines), sprint plan (420 lines), and requirements document (1,383 lines), cross-referenced against the CSPM Platform Constitution, Testing Quality Constitution, and the existing threat engine codebase. Development **MAY PROCEED** subject to the following conditions:

### Before Sprint 0 Begins (immediate)

1. **[SR-004 — HIGH]** Write and obtain Architect sign-off on an ADR documenting the exception to CSPM_CONSTITUTION §2.5 (direct cross-engine DB reads). The ADR must state: read-only scope, parameterized queries, tenant_id filter on every read, and the performance justification. File at `.claude/documentation/ARCHITECTURE-DECISIONS.md`. This ADR must exist before S1-04 begins.

### Before Sprint 1 Begins (before any S1-04 coding)

2. **[SR-001 — CRITICAL]** Change S2-06 (PerformanceGuard) description and DoD item 4 to state: performance-triggered quarantine inserts into `threat_pattern_suppressions` (per-tenant, `auto_generated=true`) instead of setting global `active=false`. Update ARCHITECTURE.md §4.2 PerformanceGuard bullet to match. This must be confirmed before CP-2 (the SA sign-off that covers PatternExecutor design).

3. **[SR-003 — HIGH]** Add `tenant_id` property to CDREvent node definition in ARCHITECTURE.md §5.1 and the neo4j_schema.cypher script (S1-01). Update CDRLoader (S1-05) to set `tenant_id` on every CDREvent node merge. Update the CI parameterization linter (S2-02) to reject any MATCH on CDREvent label without a `$tenant_id` or `$tid` parameter in the same query.

4. **[SR-011 — MEDIUM]** Add exact-version pinning requirement to S1-03 acceptance criteria before story is assigned to DEV.

### Before Sprint 2 Begins (CP-2 gate)

5. **[SR-001 — CRITICAL already filed above]** CP-2 SA sign-off must verify the PerformanceGuard implementation uses per-tenant suppression, not global `active=false`.

6. **[SR-007 — MEDIUM]** During CP-2, SA must verify that `engine_common.db.get_connection()` enforces `sslmode=require` for all psycopg2 connections. If not, add `sslmode=require` explicitly to every cross-engine DB connection in the GraphBuilder loader classes.

### Before Sprint 4 Begins (CP-3 gate)

7. **[SR-006 — MEDIUM]** Add `tenant_id` ownership validation to `GET /api/v1/scan/status/{job_id}` before S4-01 is coded. Add to CP-3 endpoint review scope.

8. **[SR-005 — HIGH]** Add explicit AC to S4-05 (BFF views) for durable audit log shipping on `cdr:sensitive` reads per CSPM_CONSTITUTION §1.3a. CP-3 sign-off must confirm this AC is implemented.

9. **[SR-008 — MEDIUM]** Add security context ACs to S1-03 manifest story before CP-3. Alternatively, add to CP-3 manifest review checklist.

### Before Sprint 5 Deploy (CP-4 gate)

10. **[SR-002 — HIGH]** Before shadow mode begins (Phase 7), file and merge a security fix for `POST /api/v1/hunt/execute` in `engines/threat/threat_engine/api_server.py` to add `require_permission("threat:read")` and remove the unauthenticated `cypher` parameter. This is not a blocker for Sprint 5 deployment of threat_v1 but must be resolved before the parallel operation period.

11. **[SR-010 — MEDIUM]** Add `tests/security/test_cypher_injection.py` to Appendix B and confirm it is implemented during Sprint 5. Add to CP-4 security regression check scope.

12. **[SR-009 — MEDIUM]** W-03 and W-08 resolution must be verified at CP-4: startup crash protection AC in pattern loader, and `_schema_version` field present in first evidence row written by IncidentWriter.

### Ongoing (any sprint)

13. **[SR-014 — LOW]** Add one-line CSA CCM v4 domain mapping to pattern authoring acceptance criteria (S3-01, S3-02, S3-03 PO AC) before patterns are authored.

14. **[SR-012 — LOW]** Add the W-04 code comment requirement to S1-05 (CDRLoader) AC.

15. **[SR-013 — LOW]** File a tech debt ticket for SLSA Level 2 build provenance before S5-08 (pipeline integration decision gate). Does not block Sprint 5 deployment.

---

*This review was performed against design artifacts only. Implementation-level verification will be performed at each CP gate (CP-1 through CP-4) per the sprint plan. The Security Reviewer must be re-engaged at each CP gate for sign-off.*

*Key files reviewed:*
- `/Users/apple/Desktop/threat-engine/engines/threat_v1/ARCHITECTURE.md`
- `/Users/apple/Desktop/threat-engine/engines/threat_v1/SPRINT_PLAN.md`
- `/Users/apple/Desktop/threat-engine/engines/threat_v1/REQUIREMENTS.md`
- `/Users/apple/Desktop/threat-engine/.claude/documentation/CSPM_CONSTITUTION.md`
- `/Users/apple/Desktop/threat-engine/.claude/documentation/TESTING_QUALITY.md`
- `/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api_server.py` (lines 3013–3050)
