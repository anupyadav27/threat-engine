# Security Architect Design Review — threat_v1 Engine
## CP-1 Gate Artifact

**Reviewer:** Security Architect (bmad-security-architect agent)
**Date:** 2026-05-10
**Scope:** Pre-implementation design gate for threat_v1 — all 6 sprints (Sprint 0 through Sprint 5)
**Gate:** CP-1 (Before Sprint 1 coding begins) — this document IS the CP-1 gate artifact
**Artifacts reviewed:**
- `engines/threat_v1/REQUIREMENTS.md` (1,383 lines)
- `engines/threat_v1/ARCHITECTURE.md` (1,054 lines)
- `engines/threat_v1/SPRINT_PLAN.md` (420 lines)
- `engines/threat_v1/SECURITY_REVIEW_PRE_IMPL.md` (249 lines, SR-001 through SR-014)
- `.claude/documentation/CSPM_CONSTITUTION.md`
- `engines/threat/threat_engine/api_server.py` (v0 surface, lines 3013–3050)

---

## 1. Threat Model — STRIDE

The REQUIREMENTS.md §17.3 produced an initial STRIDE table. This review extends it with findings from SR-001 through SR-014 and adds the advisory lock collision threat (W-01), the PerformanceGuard DoS vector (SR-001), and the Actions endpoint implication surface (CP1-04/E-01).

| ID | Category | Threat | Component | Likelihood | Impact | Control | CP Status |
|----|----------|--------|-----------|------------|--------|---------|-----------|
| S-01 | Spoofing | scan_run_id spoofing via Argo parameter tampering triggers cross-tenant graph build | run_scan.py Step 0 | MEDIUM | CRITICAL | Step 0 ownership check: `SELECT 1 FROM scan_orchestration WHERE scan_run_id=:sid AND tenant_id=:tid AND account_id=:aid` before any DB read. Abort with ERROR log and exit code 1 on miss. | RESOLVED — CP1-07, S1-07 |
| S-02 | Spoofing | Crown jewel resource_uid spoofing — tenant A submits a foreign resource_uid to `POST /crown-jewels`, contaminating graph detection logic to fire patterns against a competitor's crown jewels | crown-jewels endpoint | MEDIUM | HIGH | Ownership validation: `SELECT 1 FROM resource_inventory WHERE resource_uid=:uid AND tenant_id=:auth_tid`. Return 404 on mismatch (avoids confirming foreign resource existence). | RESOLVED — CP1-03, S4-03 |
| S-03 | Spoofing | Scan status job_id enumeration — tenant B polls `GET /scan/status/{job_id}` with a guessed UUID and receives Tenant A's scan state | scan/status endpoint | LOW | MEDIUM | Add ownership validation: `SELECT 1 FROM threat_scan_runs_v1 WHERE run_id=:job_id AND tenant_id=:auth_tid`. Return 404 on mismatch. | CONDITION — SR-006, must be in S4-01 ACs |
| T-01 | Tampering | Cypher injection via PatternCompiler string interpolation — malicious YAML value containing Cypher syntax passed as f-string into compiled query bypasses tenant_id filter and returns cross-tenant nodes | PatternCompiler | LOW (CI gate) | CRITICAL | PatternCompiler is a parameterized template expander, not a string builder. All runtime values from YAML fields are `$param` bindings. CI linter rejects any compiled Cypher containing interpolated values. $tenant_id presence check on every compiled query. | RESOLVED — CP1-01, S2-02, S3-05 |
| T-02 | Tampering | PathTagger MERGE without tenant_id filter writes `on_attack_path=true` to wrong tenant's nodes in shared Neo4j named database | PathTagger | LOW | HIGH | All MERGE statements in PathTagger include `$tenant_id` filter. Covered by CP1-01 scope: CI linter validates $tenant_id presence on ALL compiled Cypher including PathTagger queries. | RESOLVED — in CP1-01 scope |
| T-03 | Tampering | Cypher injection via pattern DSL field interpolation — specifically `resource_types`, `check_rules_failing`, `edge_type`, or condition values passed as string concat into Cypher query template | PatternCompiler, PatternDSL | LOW (CI gate) | CRITICAL | Same control as T-01. Template expander model: Cypher template is pre-written with `$resource_type` etc. as placeholders; pattern YAML values are bound as parameters at runtime via `session.run()`. No f-string or `.format()` call in Cypher generation. | RESOLVED — CP1-01 |
| R-01 | Repudiation | Feedback verdict with no audit trail — `incident_class` escalation or de-escalation without immutable log allowing denial of who submitted which verdict | FeedbackProcessor | MEDIUM | MEDIUM | `threat_incident_feedback` is INSERT-only (no UPDATE ever). All feedback rows include `tenant_id`, `reporter` (user ID from AuthContext), `created_at`. Rate-limited at 10/user/24h. | RESOLVED — S2-10, Section 16 |
| R-02 | Repudiation | Crown jewel add/remove without audit — customer adds a resource as crown jewel, later denies it, no audit trail | crown-jewels endpoint | MEDIUM | MEDIUM | Audit row written to platform `audit_logs` on every `POST /crown-jewels` and `DELETE /crown-jewels/{uid}`. Includes actor_id, tenant_id, resource_uid, action, timestamp. | RESOLVED — W-05, S4-03 |
| I-01 | Information Disclosure | CDR event PII (`actor_principal`, `source_ip`, `action`) leaked via incident list API — analyst-role caller receives full CDR actor identity in list response | GET /incidents list endpoint | HIGH (without mitigation) | HIGH | Two distinct Pydantic response models: `IncidentListItem` strips PII fields structurally (not conditionally). `actor_principal`, `source_ip`, `action` have no slots in `IncidentListItem`. `IncidentDetail` includes them, but endpoint additionally checks `cdr:sensitive` permission. | RESOLVED — CP1-02, S4-02, ADR-005 |
| I-02 | Information Disclosure | Cross-engine DB read leaking other tenants' findings — CDREvent node in Neo4j without first-class tenant_id property; a Cypher query starting at CDREvent label without traversal from a tenant-scoped Resource returns events from all tenants | CDRLoader, PatternExecutor | MEDIUM | HIGH | Add `tenant_id` property to CDREvent nodes at MERGE time. CI linter must also reject any MATCH starting at CDREvent without `$tenant_id` parameter. Negative test in S1-08 validates zero results when CDREvent queried without tenant filter. | CONDITION — SR-003 must be resolved before S1-05 |
| I-03 | Information Disclosure | `graph_query` field in evidence JSONB exposed to all `threat:read` callers on the list endpoint — reveals compiled Cypher structure usable for reconnaissance | GET /incidents list | LOW | MEDIUM | `graph_query` stripped from `IncidentListItem` model. Only present in `IncidentDetail` at the single-incident GET endpoint which requires `threat:read`. | RESOLVED — CP1-02 |
| D-01 | Denial of Service | Advisory lock hash collision — if lock uses only `tenant_id` hash (bigint), two different `(tenant_id, account_id)` pairs from the same tenant could collide, causing one to block the other or a lock to be released by the wrong holder | pg_advisory_lock | LOW | MEDIUM | Advisory lock must use `hashtext(tenant_id || '|' || account_id)`, not `hashtext(tenant_id)` alone. The `||` with a separator character prevents prefix-extension collisions. | CONDITION — W-01 must be verified in S1-07 ACs |
| D-02 | Denial of Service | PerformanceGuard setting global `active=false` on `threat_scenario_patterns` when a pattern exceeds p99 budget — starves all other tenants of that detection, including those with no performance problem | PerformanceGuard | HIGH (current S2-06 wording) | HIGH | S2-06 currently specifies `active=false` on the shared pattern. This must be changed to: insert into `threat_pattern_suppressions` (per-tenant, `auto_generated=true`, reason=`performance_p99_exceeded`). Global deactivation requires SA approval and manual update only. | BLOCKER — SR-001 must be fixed in S2-06 before CP-2 |
| D-03 | Denial of Service | No Neo4j query timeout at driver level — a runaway pattern Cypher query consumes the connection and eventually exhausts the Aura session pool | PatternExecutor, Neo4j driver | MEDIUM | MEDIUM | `session.run(compiled_cypher, params, timeout=500)` on every pattern execution. PerformanceGuard circuit breaker: cap per-pattern execution at 30s, result cap at 200 paths. | WARNING — W-02 |
| E-01 | Elevation of Privilege | Actions endpoint stub returning HTTP 200 (or HTTP 501 without auth check) could imply a future execution surface — if the endpoint silently drops the `require_permission()` decorator, it creates an unauthenticated execution hook | POST /incidents/{id}/actions | LOW (by design) | CRITICAL (if bypassed) | `POST /incidents/{id}/actions` returns HTTP 501 with guidance text. `require_permission("threat:write")` is still enforced — 501 is not an auth bypass. Explicitly noted in CP1-04 and S4-04. | RESOLVED — CP1-04, S4-04 |
| E-02 | Elevation of Privilege | Theoretical-confidence patterns generating `active` incident class — a pattern marked `confidence=theoretical` that fires CDR overlay produces `incident_class=active`, triggering automated containment workflows in future phases | LifecycleTransitioner | MEDIUM | MEDIUM | LifecycleTransitioner guard: `confidence=theoretical` patterns must NOT produce `incident_class=active`. Maximum class for theoretical patterns is `suspicious`. Enforced by unit test in S2 DoD item 7. | WARNING — W-07 |
| E-03 | Elevation of Privilege | Bulk FP feedback to trigger detection suppression — compromised analyst account submits 30 days of false-positive verdicts for a high-value detection pattern, triggering auto-quarantine and silencing it across the platform | FeedbackProcessor | MEDIUM | HIGH | Auto-quarantine is per-tenant only (insert into `threat_pattern_suppressions`). Global `active=false` requires SA approval and manual action. Rate limit: 10 verdicts/user/24h enforces minimum 3-day suppression cycle before any single user can influence rolling 30d rate. | RESOLVED — CP1-05, ADR-003 |

---

## 2. PASTA Attack Trees (Updated with SR Findings)

### PASTA Stage 1-7 Scope Declaration

**Business objectives:** Tenant isolation is absolute (no cross-tenant graph read or write), credential non-leakage (CDR PII accessible only to `cdr:sensitive` role), detection platform integrity (no adversary-controlled pattern suppression).

**Technical scope introduced by threat_v1:**
- 5 new cross-engine Postgres DB connections (check, vuln, CDR, inventory, IAM)
- 1 new Neo4j named database (`threat_v1` in shared Aura instance)
- 1 new scan entry point (`run_scan.py`) invoked by Argo with attacker-controllable parameters
- 1 new REST API (port 8021) with 12 endpoints, 2 Pydantic response models, `cdr:sensitive` gating
- 1 new YAML pattern DSL compiled to Cypher via PatternCompiler

### AT-1: Cross-Tenant Data Read (CRITICAL)

**Adversary goal:** Read another tenant's incident data or Neo4j graph nodes.

```
Adversary Goal: Read Tenant B's threat incidents / graph nodes
    │
    ├── Path 1 — PatternCompiler injection (PRIMARY RISK BEFORE CP1-01)
    │     Step 1: Author or compromise a YAML pattern file
    │     Step 2: Set resource_types field to contain Cypher fragment:
    │             "EC2Instance'] MATCH (x:Resource WHERE true"
    │     Step 3: PatternCompiler interpolates via f-string
    │     Step 4: Compiled Cypher has no effective $tenant_id filter
    │     Step 5: Neo4j returns all tenants' Resource nodes
    │     MITIGATION: Template expander model (no f-string); CI linter rejects
    │     RESIDUAL RISK after CP1-01: Near-zero (linter + SA gate at CP-2)
    │
    ├── Path 2 — CDREvent direct MATCH (SR-003 — OPEN AT REVIEW TIME)
    │     Step 1: Craft Cypher that MATCHes CDREvent label directly
    │             without traversing from a tenant-scoped Resource
    │     Step 2: CDREvent nodes have no tenant_id property
    │     Step 3: All tenants' CDR events returned
    │     MITIGATION: Add tenant_id property to CDREvent at MERGE time
    │             CI linter extended to reject CDREvent MATCH without $tenant_id
    │     STATUS: BLOCKER — must be resolved before S1-05 (CDRLoader)
    │
    ├── Path 3 — BFF incident_id injection (W-06)
    │     Step 1: Caller submits a known incident_id belonging to Tenant B
    │             via BFF view /inventory_asset_threat/{uid}
    │     Step 2: BFF fetches incident detail without tenant_id re-validation
    │     Step 3: Tenant A reads Tenant B's incident evidence
    │     MITIGATION: BFF must re-validate each incident_id belongs to
    │             auth_ctx.tenant_id before including in response
    │     STATUS: WARNING — W-06, must be explicit AC in S4-06
    │
    └── Path 4 — scan_run_id parameter tampering (S-01)
          Step 1: Adversary-controlled Argo parameter sets scan_run_id
                  to a UUID that belongs to Tenant B's scan
          Step 2: run_scan.py proceeds without ownership check
          Step 3: ResourceResolver reads Tenant B's findings
          MITIGATION: Step 0 ownership check before any DB read (CP1-07)
          STATUS: RESOLVED
```

### AT-2: Crown Jewel Spoofing (HIGH)

**Adversary goal:** Contaminate the threat detection logic to generate false incidents against a competitor's infrastructure, or suppress detection of their own resources by marking them as "already tracked."

```
Adversary Goal: Mark foreign resource as crown jewel / manipulate detection scope
    │
    ├── Path 1 — Direct ownership bypass (PRIMARY RISK BEFORE CP1-03)
    │     Step 1: Enumerate a competitor's resource_uid
    │             (ARNs are guessable from account IDs for known services)
    │     Step 2: POST /api/v1/crown-jewels { "resource_uid": "<foreign_arn>" }
    │     Step 3: Without ownership validation, GraphBuilder sets
    │             is_crown_jewel=true on the foreign node
    │     Step 4: Tier 3 patterns fire targeting the foreign resource
    │             as if it were the attacker's own crown jewel
    │     MITIGATION: CP1-03 — JOIN against resource_inventory WHERE
    │             tenant_id = auth_ctx.tenant_id; 404 on mismatch
    │     STATUS: RESOLVED
    │
    ├── Path 2 — Response oracle (MITIGATED BY 404 NOT 403)
    │     Step 1: Submit foreign resource_uid to POST /crown-jewels
    │     Step 2: If server returns 403 → resource exists (existence confirmed)
    │             If server returns 404 → existence unknown
    │     MITIGATION: Always 404 on mismatch (never 403)
    │     STATUS: RESOLVED — CP1-03 specifies 404
    │
    └── Path 3 — Pattern manipulation via crown jewel mis-classification
          Step 1: Attacker discovers that their own production DB resource
                  is NOT classified as crown jewel (risk_score < 80,
                  not in secrets/data_store category)
          Step 2: Attacker submits DELETE /crown-jewels/{uid} on their own
                  legitimate crown jewel to suppress Tier 3 patterns
          Step 3: CrownJewelClassifier no longer marks that resource
                  as target, Tier 3 patterns do not fire
          MITIGATION: Crown jewel deletion requires threat:write permission
                  (analyst role cannot delete); audit row written on every
                  delete; CrownJewelClassifier DB-driven classification
                  still applies independent of customer tags
          STATUS: PARTIALLY MITIGATED — analyst cannot delete (RBAC),
                  but tenant_admin can suppress their own resource.
                  Acceptable for v1; note in gap log.
```

### AT-3: Detection Suppression via Bulk FP Feedback (HIGH)

**Adversary goal:** Silence a high-value detection pattern across the entire platform by triggering auto-quarantine.

```
Adversary Goal: Suppress detection of a critical attack pattern platform-wide
    │
    ├── Path 1 — Bulk FP feedback from compromised account (BEFORE CP1-05)
    │     Step 1: Adversary compromises analyst-role account for any tenant
    │     Step 2: Submits 30+ FP verdicts for a critical pattern
    │             (e.g., PAT-AWS-001 — Capital One pattern)
    │     Step 3: FeedbackProcessor sets active=false on shared pattern row
    │     Step 4: Pattern disabled globally — all tenants lose detection
    │     MITIGATION: CP1-05 — auto-quarantine inserts into
    │             threat_pattern_suppressions (tenant-scoped) only
    │             Global active=false requires SA approval + manual update
    │     STATUS: RESOLVED — ADR-003
    │
    ├── Path 2 — PerformanceGuard exploitation (SR-001 — OPEN AT REVIEW TIME)
    │     Step 1: Adversary intentionally creates a large, high-cardinality
    │             graph state (many resources, many edges) for their tenant
    │     Step 2: A critical detection pattern exceeds p99 budget (500ms)
    │             for 3 consecutive runs on their tenant
    │     Step 3: Current S2-06 wording: PerformanceGuard sets
    │             active=false on the shared pattern row
    │     Step 4: Pattern disabled globally — all other tenants lose detection
    │     MITIGATION: Change S2-06 to insert into threat_pattern_suppressions
    │             (per-tenant) instead of setting global active=false
    │     STATUS: BLOCKER — SR-001 must be fixed before CP-2
    │
    └── Path 3 — Rate limit bypass via multi-account coordination
          Step 1: Adversary controls 10+ compromised analyst accounts
                  across same tenant (purchased or phished)
          Step 2: Each account submits 10 FP verdicts/24h (rate limit)
          Step 3: Combined 100+ FP verdicts/24h accelerates rolling 30d
                  rate above 30% threshold within 10 days
          Step 4: Per-tenant suppression fires (contained to their tenant)
          MITIGATION: Per-tenant suppression only affects the attacker's
                  own tenant — other tenants unaffected. Rate limit
                  slows attack without stopping it for the victim's tenant.
          NOTE: This is an acceptable residual risk for v1. The attacker
                  suppresses detection only against themselves. Phase 8
                  should add per-tenant FP anomaly alerting.
          STATUS: ACCEPTABLE for v1 — residual risk acknowledged
```

### AT-4: Denial of Detection via PerformanceGuard Exploitation (SR-001 Scenario)

**Adversary goal:** Trigger global pattern deactivation to silence the detection platform for all tenants simultaneously.

```
Adversary Goal: Silence threat detection engine platform-wide
    │
    ├── Step 1 — Prerequisites
    │     Attacker has a valid tenant account (free trial or compromised account)
    │     Attacker knows which pattern they want to suppress
    │             (pattern IDs are visible to threat:read role via GET /patterns)
    │
    ├── Step 2 — Attack execution (CURRENT S2-06 VULNERABILITY)
    │     Attacker's tenant has AWS account with many resources
    │     Attacker provisions many EC2 instances with complex IAM role chains
    │     This creates a high-cardinality graph state
    │     Pattern PAT-AWS-001 traversal on this graph exceeds 500ms p99
    │     PerformanceGuard (current S2-06 wording) sets
    │             threat_scenario_patterns.active=false
    │
    ├── Step 3 — Impact
    │     Pattern PAT-AWS-001 disabled globally
    │     All tenants lose Capital One attack path detection
    │     No customer-visible alert that detection was suppressed
    │     Recovery requires SA approval + manual re-enable
    │
    ├── MITIGATION (required — SR-001 BLOCKER)
    │     Change PerformanceGuard to insert into threat_pattern_suppressions
    │             (tenant_id = attacker's tenant, pattern_id = target pattern,
    │             auto_generated = true, reason = 'performance_p99_exceeded')
    │     Global active=false: human-only, requires SA approval
    │     Additional defense: `LIMIT 200` on all Tier 3 traversals caps
    │             maximum graph traversal time regardless of graph cardinality
    │
    └── D3FEND countermeasure
          D3-ADH (Application Deadzone): Per-tenant circuit breaking ensures
                  one tenant's performance cannot affect another tenant's
                  detection coverage.
```

---

## 3. MITRE ATT&CK for Cloud Mapping

The following maps the 8 CP-1 threat scenarios to MITRE ATT&CK for Cloud, extending the D3FEND coverage analysis.

| CP Scenario | MITRE Technique | MITRE ID | MITRE Tactic | D3FEND Countermeasure |
|-------------|----------------|----------|--------------|----------------------|
| S-01: scan_run_id spoofing → cross-tenant graph build | Valid Accounts: Cloud Accounts | T1078.004 | Initial Access | D3-MFA Multi-Factor Authentication + D3-OAM Object Access Monitoring (scan_orchestration ownership check) |
| S-02: Crown jewel spoofing → contaminate detection logic | Data Manipulation: Transmitted Data Manipulation | T1565.002 | Impact | D3-OAM Object Access Monitoring (resource_inventory ownership join) |
| T-03: Cypher injection via pattern DSL field interpolation | Exploit Public-Facing Application | T1190 | Initial Access | D3-FAPA Filter Application Policy (parameterization linter as CI gate) |
| I-01: CDR event PII leaked via incident list API | Unsecured Credentials | T1552 | Credential Access | D3-ACM Account Credential Management (field-level RBAC gating on cdr:sensitive) |
| I-02: Cross-engine DB read leaking tenant findings (CDREvent SR-003) | Data from Cloud Storage | T1530 | Collection | D3-OAM Object Access Monitoring (tenant_id property on CDREvent nodes) |
| D-01: Advisory lock hash collision causing DoS / lock release by wrong tenant | Endpoint Denial of Service | T1499 | Impact | D3-ADH Application Deadzone (composite hash key `tenant_id||'|'||account_id`) |
| D-02: PerformanceGuard global active=false (SR-001) | Impair Defenses: Disable or Modify Cloud Firewall | T1562.007 | Defense Evasion | D3-ADH Application Deadzone (per-tenant circuit breaker pattern) |
| E-01: Actions endpoint implication surface (stub returning wrong status) | Valid Accounts | T1078 | Defense Evasion | D3-UAA User Account Authentication (require_permission enforced even on 501 response) |

---

## 4. MITRE D3FEND Defensive Coverage

For each ATT&CK technique detected or defended by threat_v1, the corresponding D3FEND technique and implementation detail:

| ATT&CK Technique | ATT&CK ID | D3FEND Technique | D3FEND ID | Implementation in threat_v1 | Sprint Story |
|-----------------|-----------|-----------------|-----------|---------------------------|--------------|
| Valid Accounts: Cloud Accounts | T1078.004 | Multi-Factor Authentication | D3-MFA | IAM engine findings: `no_mfa` flag surfaced in GraphBuilder; IAMRole nodes with `is_admin_role=true` AND `cdr_actor_seen=true` → Tier 1 toxic combo PAT-AWS-002 | S3-01 (Tier 1 patterns), S1-06 (CrownJewelClassifier IAM flags) |
| Exploit Public-Facing Application | T1190 | Filter Application Policy | D3-FAPA | Network engine findings (`internet_exposed` flag on Resource nodes); check rules for public SG ingress; PatternCompiler CI linter as injection prevention gate | S1-04 (MisconfigLoader), S2-02 (linter), S3-03 (PAT-AWS-001) |
| Cloud Instance Metadata API | T1552.005 | Credential Hardening | D3-CH | IMDSv1 rules (`aws-ec2-imdsv1-enabled`) surfaced via check_findings into MisconfigFinding nodes; entry condition for Capital One Tier 3 pattern | S3-03 (PAT-AWS-001) |
| Data from Cloud Storage | T1530 | Object Access Monitoring | D3-OAM | CDR events (GetObject, ListBuckets) surfaced as CDREvent nodes; cdr_watch in Tier 3 patterns monitors S3 access technique coverage; is_crown_jewel=true on sensitive data stores | S1-05 (CDRLoader), S3-03 (Tier 3 patterns) |
| Network Sniffing / Traffic Analysis | T1040 | Network Traffic Filtering | D3-NTF | Network engine check findings (VPC Flow Logs disabled → T1040 detection gap) surfaced as MisconfigFinding nodes in graph; Tier 1 pattern for internet-exposed resource with no flow log monitoring | S3-01 (Tier 1 patterns) |
| Transfer Data to Cloud Account | T1537 | Data Loss Prevention | D3-DLP | CDR events for cross-account S3 replication; CDREvent nodes with T1537 technique; Tier 2 partial path pattern via replicates_to edge | S3-02 (Tier 2 patterns) |
| Account Manipulation: Add Cloud Role | T1098.003 | Account Attribute Modification Detection | D3-AAMD | CDR events for IAM role modification; CDRActor nodes with T1098.003 technique; escalates posture → active on CDR overlay | S1-05 (CDRLoader), S2-05 (Tier 3 CDR overlay) |
| Impair Defenses: Disable Cloud Logs | T1562.007 | Log Management | D3-LM | Check findings for CloudTrail disabled, VPC Flow Logs disabled; MisconfigFinding nodes with T1562.007 technique; Tier 1 toxic combo: internet-exposed + logging disabled | S3-01 (Tier 1 patterns) |

**D3FEND Coverage Gaps (detection-without-defense):**

| ATT&CK Technique | Gap | NIST CSF Function | Gap Ticket Required |
|-----------------|-----|-------------------|---------------------|
| T1562.007 (Disable Cloud Logs) | Detection: YES (check rule fires). Automated response: NO (POST /actions is 501 in v1). | RS — Respond | YES — W-10 gap ticket |
| T1537 (Transfer Data to Cloud Account) | Detection: YES (CDR event + Tier 2 pattern). Automated containment: NO. | RS — Respond | YES — W-10 gap ticket |
| T1078.004 (Cloud Accounts — MFA disabled) | Detection: YES. Automated MFA enforcement: NO. Recovery playbook: NO. | RC — Recover | YES — W-10 gap ticket |

---

## 5. MITRE D3FEND Defensive Coverage (Platform-Level)

| ATT&CK | D3FEND Technique | Implementation in threat_v1 | Sprint Story |
|--------|-----------------|---------------------------|--------------|
| T1078 (Valid Accounts) | D3-UAA User Account Authentication | require_permission() on every endpoint; scan_run_id ownership validation (CP1-07) | S1-07, S4-01 |
| T1078.004 (Cloud Accounts) | D3-MFA Multi-Factor Authentication | IAM engine MFA check feeds into GraphBuilder is_admin_role flag; Tier 1 pattern fires on admin+MFA-disabled | S3-01 |
| T1190 (Exploit Public-Facing App) | D3-FAPA Filter Application Policy | Network engine internet_exposed flag; check_findings FAIL for public SG; PatternCompiler injection prevention | S2-02, S3-03 |
| T1040 (Network Sniffing) | D3-NTF Network Traffic Filtering | VPC Flow Logs check rule → MisconfigFinding node → Tier 1 combo with internet_exposed | S3-01 |
| T1021 (Remote Services) | D3-PH Port Hopping Detection | Network engine SSH/RDP-open-to-internet check rules → MisconfigFinding → entry condition in patterns | S3-01, S3-02 |
| T1530 (Data from Cloud Storage) | D3-OAM Object Access Monitoring | CDREvent nodes for GetObject/ListBuckets; cdr_watch on Tier 3 patterns for S3 crown jewels | S1-05, S3-03 |
| T1552.005 (Instance Metadata API) | D3-CH Credential Hardening | IMDSv1 check rule → MisconfigFinding; entry condition for Capital One pattern | S3-03 |

---

## 6. OWASP SAMM Design Function Assessment

### Scoring Scale: 0 = None, 1 = Ad-hoc, 2 = Defined/Repeatable, 3 = Optimized/Measured

### Threat Assessment: Score 3 (Optimized)

**Justification:** threat_v1 has the most comprehensive threat assessment of any engine in this platform:
- STRIDE threat model table with 15 entries (REQUIREMENTS.md §17.3, extended in this document)
- PASTA attack trees for 4 adversary goals (REQUIREMENTS.md §17.4, extended with AT-4)
- MITRE ATT&CK/D3FEND mapping per detection tier
- Security architect gate (CP-1 through CP-4) with explicit blockers and conditions
- Per-sprint security checkpoints with owner, timing, and pass criteria
- Risk register with 8 entries including likelihood/impact/mitigation/owner

**Gap from score 3:** No automated regression test that runs the full threat model against code changes (this would require a dedicated security regression suite per TESTING_QUALITY §Level 9). Currently addressed manually at each CP gate.

**Target maintained:** Score 3.

### Security Requirements: Score 2 (Defined)

**Justification:**
- All 8 CP-1 blockers documented with specific, testable resolution criteria
- 10 warnings (W-01 through W-10) tracked with story-level traceability (W-01, W-02, W-05, W-06, W-07, W-09 have corresponding sprint stories)
- RBAC matrix defined for all 5 roles × all 12 endpoints (ARCHITECTURE.md §7.6)
- PII field exposure table with permission requirements per field (REQUIREMENTS.md §9.6)
- Evidence schema versioning planned (`_schema_version` field)

**Gap from score 3:** W-03, W-04, W-08, W-10 do not have explicit sprint stories. W-10 RS/RC gap tickets not yet filed. Score is 2 until these gaps are closed.

**Target for v1:** Score 2 is acceptable. Score 3 requires automated security requirement validation (tool-enforced, not document-enforced).

### Security Architecture: Score 2 (Defined)

**Justification:**
- ADR-001 through ADR-005 document key security-relevant architectural decisions with threat model rationale
- ADR-003 (per-tenant FP suppression) and ADR-004 (no ad-hoc Cypher) are specifically security-motivated decisions
- Two-model Pydantic approach (ADR-005) is a security architecture pattern, not just an API design choice
- cross-engine DB read pattern documented as constitution exception (SR-004) — ADR-006 in this document formalizes it
- Provider isolation: threat_v1 has no cloud SDK calls (no boto3, no Azure SDK) — zero SSRF surface

**Gap from score 3:** The PatternCompiler template expander design is described but not formally specified as an architectural pattern with invariants. A formal specification (e.g., "PatternCompiler MUST satisfy: no f-string contains a pattern YAML value as computed string") would enable automated verification. Score 3 requires this level of specification.

**Target for v1:** Score 2 on all three practices. Minimum requirement met.

---

## 7. CSA CCM v4 Domain Mapping

| Component | CCM Domain | CCM Control ID | Control Description | Satisfied? |
|-----------|-----------|----------------|--------------------|-----------| 
| `require_permission()` on all endpoints | Identity & Access Management | IAM-01 | Identity and access management policy | YES — 5-role RBAC with 27 permissions enforced at every endpoint |
| `cdr:sensitive` field-level permission | Identity & Access Management | IAM-02 | Privileged user identity | YES — `cdr:sensitive` is a data-classification permission enforced at field level |
| Crown jewel ownership validation | Identity & Access Management | IAM-09 | User access authorization | YES — resource_uid validated against resource_inventory WHERE tenant_id = auth_tid before write |
| Multi-tenant isolation (tenant_id on all tables) | Data Security and Privacy | DSP-01 | Security and Privacy Policy | YES — tenant_id NOT NULL on all new v1 tables; every query parameterized with tenant_id |
| CDR PII field gating (actor_principal, source_ip) | Data Security and Privacy | DSP-07 | Sensitive Data Protection | YES — IncidentListItem structurally excludes PII fields; IncidentDetail requires cdr:sensitive |
| Audit logs on sensitive reads (§1.3a) | Data Security and Privacy | DSP-10 | Audit Logging | CONDITION — audit log for cdr:sensitive reads must be in S4-05 ACs (SR-005) |
| PatternCompiler Cypher parameterization | Infrastructure & Virtualization Security | IVS-01 | Audit Logging / Intrusion Detection | YES — CI linter as continuous control; $tenant_id presence check enforced at CI |
| Per-tenant advisory lock | Infrastructure & Virtualization Security | IVS-06 | Network Security | YES — `pg_advisory_lock(hashtext(tenant_id||'|'||account_id))` prevents concurrent graph build for same tenant |
| VPC Flow Logs check rules → Tier 1 pattern | Infrastructure & Virtualization Security | IVS-07 | Network Architecture | YES — detection gap (no flow logs) surfaced as Tier 1 toxic combo; maps to T1040 |
| Pattern regression baseline | Change Control and Configuration Management | CCC-04 | Software Development Lifecycle | YES — `tests/regression/baselines/threat_pattern_counts.json` golden baseline |
| Pattern CI gate (7 checks before merge) | Change Control and Configuration Management | CCC-09 | Change Management Technology | YES — S3-05 CI gate: schema validation, linter, positive/negative test, latency budget |
| `threat_incident_feedback` INSERT-only | Audit Assurance and Compliance | AAC-02 | Audit / Log Tampering Protection | YES — INSERT-only table; no UPDATE ever; immutable audit log |
| Threat intelligence in `mitre_technique_reference` | Threat and Vulnerability Management | TVM-01 | Antivirus / Malware Protection | YES — 102 curated ATT&CK technique rows; techniques are first-class in all findings |
| CVE heuristic → T1190 tagging | Threat and Vulnerability Management | TVM-07 | Vulnerability Management | PARTIAL — Phase 0 heuristic (CVSS≥9 + network AV = T1190) is an approximation; full NVD parser wiring needed |
| SLSA Level 1-2 build controls | Supply Chain Management | STA-09 | Supply Chain Governance | PARTIAL — pinned base image (Level 1) specified; build provenance attestation (Level 2) deferred to tech debt |
| K8s securityContext (runAsNonRoot) | Infrastructure & Virtualization Security | IVS-04 | OS Hardening / Base Controls | CONDITION — SR-008 must add runAsNonRoot=true to S1-03 ACs |
| Secrets Manager for all credentials | Cryptography, Encryption & Key Management | CEK-01 | Encryption and Key Management | YES — Neo4j credentials via Secrets Manager; all DB credentials via Secrets Manager |

---

## 8. NIST CSF 2.0 Coverage

| Function | Category | Subcategory | Satisfied? | Gap | Story |
|----------|----------|------------|-----------|-----|-------|
| **GV — Govern** | GV.OC Organizational Context | GV.OC-01 Mission understood | PARTIAL | No formal security policy document for threat_v1 in v1 | None — deferred to Phase 8 |
| GV | GV.SC Supply Chain Risk | GV.SC-04 Suppliers assessed | PARTIAL | SLSA Level 2 build provenance not yet automated | SR-013 tech debt ticket |
| **ID — Identify** | ID.AM Asset Management | ID.AM-01 Asset inventories maintained | YES | ResourceResolver joins 6 DBs to enumerate all cloud resources per tenant | S1-04, S1-05, S1-06 |
| ID | ID.AM Asset Management | ID.AM-05 Assets prioritized based on risk | YES | CrownJewelClassifier: asset_category + criticality + risk_score drives priority | S1-06 |
| ID | ID.RA Risk Assessment | ID.RA-01 Vulnerabilities identified | YES | VulnLoader reads CVE findings; is_crown_jewel + has_critical_cve → Tier 1 pattern | S1-05, S3-01 |
| ID | ID.RA Risk Assessment | ID.RA-04 Risk and impact considered | YES | MITRE tactic chains drive pattern tier and severity; attack path drives risk_score | S2-07, S3-01/02/03 |
| **PR — Protect** | PR.AC Access Control | PR.AC-01 Identities and credentials managed | YES | require_permission() at every endpoint; 5-role RBAC | S4-01 |
| PR | PR.AC Access Control | PR.AC-03 Remote access managed | YES | API Gateway AuthMiddleware → X-Auth-Context → engine RBAC; no SSRF (no outbound SDK calls) | S4-01 |
| PR | PR.DS Data Security | PR.DS-01 Data-at-rest protected | YES | dedup_key is SHA256 (irreversible); no credentials stored in threat_incidents | S1-02 |
| PR | PR.DS Data Security | PR.DS-02 Data-in-transit protected | YES | neo4j+s:// Bolt with TLS; sslmode=require for Postgres | SR-007 (condition) |
| PR | PR.DS Data Security | PR.DS-05 Protections against data leaks | YES | IncidentListItem structural PII exclusion; cdr:sensitive field-level gating | S4-02 |
| PR | PR.IP Information Protection | PR.IP-01 Baseline configuration established | YES | K8s manifest with readinessProbe, livenessProbe, resource limits | S1-03 |
| **DE — Detect** | DE.CM Continuous Monitoring | DE.CM-01 Networks monitored | PARTIAL | Network engine findings surfaced in graph; Tier 1 pattern for unmonitored internet-facing resources | S3-01 |
| DE | DE.CM Continuous Monitoring | DE.CM-03 Personnel activity monitored | YES | CDREvent nodes capture actor_principal activity; cdr_actor_seen flag on Resource nodes | S1-05, S2-05 |
| DE | DE.CM Continuous Monitoring | DE.CM-07 Monitoring for unauthorized personnel | YES | CDRActor nodes track actor identity; Tier 3 CDR overlay detects active actors on attack paths | S2-05 |
| DE | DE.AE Adverse Event Analysis | DE.AE-01 Event baseline established | YES | Pattern regression baseline; per-pattern fire_count metrics as baseline | S3-04, S6 (observability) |
| DE | DE.AE Adverse Event Analysis | DE.AE-03 Event data aggregated | YES | Evidence JSONB aggregates misconfig + CVE + CDR signals per incident | S2-07, S2-09 |
| DE | DE.AE Adverse Event Analysis | DE.AE-06 Information correlated | YES | 3-tier correlation: Tier 1 (flags), Tier 2 (partial path), Tier 3 (CDR overlay) | S2-03/04/05 |
| **RS — Respond** | RS.MA Incident Management | RS.MA-01 Incident response plan activated | PARTIAL | Incident lifecycle SM: posture → suspicious → active. No automated containment. | S2-08 |
| RS | RS.CO Communications | RS.CO-02 Incidents reported | PARTIAL | story_text narrative + recommendations JSONB per incident. No outbound alerting in v1. | S2-09 |
| RS | RS.MI Mitigation | RS.MI-01 Incidents contained | GAP | POST /actions returns HTTP 501 in v1. No automated containment. Gap ticket W-10 required. | None in v1 — Phase 8 |
| RS | RS.MI Mitigation | RS.MI-02 Incidents mitigated | GAP | Recommendations JSONB provides manual guidance only. No automated remediation. | None in v1 — Phase 8 |
| **RC — Recover** | RC.RP Recovery Planning | RC.RP-01 Recovery plan executed | GAP | No recovery playbooks in v1. Explicit scope limitation per REQUIREMENTS §17.5. | None in v1 — Phase 8 |
| RC | RC.CO Communications | RC.CO-01 Recovery communicated | GAP | No recovery communication plan in v1. | None in v1 — Phase 8 |

**RS/RC Gap Mandate:** Per the Security Frameworks Constitution, engines covering DE without an RS path must log the gap explicitly. The 3 gap tickets required by W-10 are:
1. T1562.007 auto-response gap (disable cloud logs → auto-re-enable via remediation engine)
2. T1537 auto-response gap (data exfiltration → automated isolation)
3. Recovery playbook gap (Phase 8 ADR required)

These tickets must exist in the platform backlog before Sprint 5 S5-08 (pipeline integration gate).

---

## 9. Architecture Decisions Review

### ADR-001: Zone C — Side Panel, Not Popup

**Security consideration:** No material security concern. Side panels persist URL state (incident ID in URL path), enabling deep-linking. This creates an information disclosure surface if the URL contains the incident_id and is shared with an unauthorized user. Mitigation: the incident detail endpoint enforces `threat:read` permission before returning data. A shared URL with the incident_id does not bypass auth. The BFF `incident_detail/{id}` view must re-validate tenant_id ownership on every call (covered by W-06).

**SA verdict:** No security blocker. Implementation should confirm URL-based incident_id always goes through authenticated BFF endpoint.

### ADR-002: Node Click — Inline HopCard + Inventory Redirect

**Security consideration:** The inventory redirect (`/inventory/assets/{resource_uid}?from=threat`) must not bypass RBAC at the inventory asset detail page. The `?from=threat` parameter is a navigation hint only — it must not grant elevated permissions or skip auth on the inventory page. Verify that the inventory asset detail page enforces its own `require_permission()` independently and does not trust the `?from=threat` parameter for access control decisions.

**SA verdict:** No blocker, but requires explicit note in S4-10 (inventory Threat tab) acceptance criteria: "The inventory asset page enforces its own permission check independent of the ?from=threat query parameter. The parameter affects only navigation UX (breadcrumb, active tab selection), never access control."

### ADR-003: Per-Tenant FP Suppression (Not Global Pattern Deactivation)

**Security consideration:** This ADR is the primary control for CP1-05 and the D-01/E-03 STRIDE threats. It correctly addresses the detection suppression attack surface. However, ARCHITECTURE.md §4.2 PerformanceGuard description still says "set `active=false` in `threat_scenario_patterns`" — this contradicts the ADR. The contradiction creates a risk that the implementation follows the component description rather than the ADR.

**SA verdict:** This ADR must be explicitly confirmed as the governing rule over the S2-06 story description AND the ARCHITECTURE.md §4.2 PerformanceGuard component description. S2-06 must be updated to match ADR-003 before CP-2. SR-001 is a blocker until both S2-06 and ARCHITECTURE.md §4.2 are corrected.

### ADR-004: Parameterized Cypher Only — No Ad-Hoc Query Endpoint

**Security consideration:** This ADR is the primary control for T-01, T-03, and the cross-tenant graph read attack tree (AT-1). It correctly eliminates an entire injection attack class. The existing v0 engine has an unauthenticated `POST /api/v1/hunt/execute` at line 3013 — verified in review. During parallel operation, this v0 endpoint remains exploitable. SR-002 requires this to be fixed before shadow mode begins.

**SA verdict:** ADR-004 CONFIRMED as primary control for T-01/T-03. ADR must be considered binding for all future phases. Any `POST /hunt/execute` or similar ad-hoc query endpoint in any future phase requires a new ADR with explicit SA approval.

### ADR-005: Two Pydantic Response Models for Incident Evidence

**Security consideration:** This ADR is the primary control for I-01 and I-02. The structural separation approach (field exclusion by model design, not conditional filtering) is the correct implementation. The key risk is that a future developer adds a third endpoint that imports `IncidentDetail` but forgets to check `cdr:sensitive` before populating PII fields. The ADR does not specify what happens when a new endpoint is added.

**SA verdict:** ADR-005 CONFIRMED as primary control for I-01/I-02. Add to ADR: "Any new endpoint returning incident evidence must choose between IncidentListItem and IncidentDetail. The choice must be noted in the endpoint's story acceptance criteria and reviewed at the applicable CP gate. No shared base model with PII fields may be created."

### ADR-006: Cross-Engine Direct DB Reads (NEW — This Document Serves as Acceptance Artifact for SR-004)

**Decision:** GraphBuilder reads 5 engine databases directly (check, vuln, CDR, inventory, IAM) instead of via HTTP API.

**Rationale:** Graph build is a batch operation within the same pipeline run. HTTP API round-trips to 5 engines would add 5–15 minutes of latency per scan (5 × N resources × round-trip overhead) and would require 5 separate service discovery configurations, auth token management for inter-engine calls, and retry logic. The batch nature of graph build makes direct DB reads appropriate.

**Security constraints (all mandatory):**
1. Read-only Postgres role per source DB — threat_v1 must NOT have INSERT/UPDATE/DELETE privileges on check, vuln, CDR, inventory, or IAM databases
2. Parameterized queries only — no string concatenation in any cross-engine SQL (`%s`-style psycopg2 binding minimum; prefer named parameters)
3. `tenant_id` filter mandatory on every cross-engine query — no query reads from any source DB without `WHERE tenant_id = :tenant_id`
4. `sslmode=require` on all psycopg2 connections — enforced in `engine_common.db.get_connection()` helper or explicitly set in each connection string
5. No cross-engine writes — threat_v1 writes ONLY to `threat_engine_threat` (`_v1` tables) and Neo4j `threat_v1` named database

**CSPM Constitution §2.5 exception:** This ADR documents the justified exception. The exception is narrowly scoped to the GraphBuilder batch operation. The threat_v1 REST API must NOT make direct DB calls to other engine databases (all API-time reads go through the threat_v1 DB only — incidents, patterns, suppressions, crown jewels, scan run status are all in `threat_engine_threat`).

**Accepted by:** Security Architect (this document, 2026-05-10). Architect must countersign in `.claude/documentation/ARCHITECTURE-DECISIONS.md`.

---

## 10. CP-1 Gate Decision

### CP-1 (Before Sprint 1 Starts — Before S1-04)

**Status: APPROVED WITH CONDITIONS**

Sprint 0 (MITRE tagging) may start immediately. Stories S1-01, S1-02, and S1-03 may start in parallel with CP-1 conditions being resolved. **S1-04 is BLOCKED until all CP-1 conditions are cleared.**

**Conditions that must be true before S1-04 begins:**

| # | Condition | Source | Story ID | Verification |
|---|-----------|--------|----------|-------------|
| C1 | CDREvent node definition updated in ARCHITECTURE.md §5.1 to include `tenant_id` as a first-class property. CDRLoader (S1-05) story ACs updated to require `tenant_id` set on every CDREvent MERGE. CI parameterization linter extended to reject any Cypher MATCH starting at CDREvent without `$tenant_id`. | SR-003 | S1-01 (schema) + S1-05 (CDRLoader) | SA reviews updated §5.1 and S1-05 ACs before assigning S1-04 |
| C2 | ADR-006 (cross-engine direct DB reads) written to `.claude/documentation/ARCHITECTURE-DECISIONS.md` and countersigned by Architect. This document (SECURITY_ARCHITECT_REVIEW.md) serves as the Security Architect acceptance artifact for ADR-006. | SR-004 | None (documentation task) | ADR exists in ARCHITECTURE-DECISIONS.md before S1-04 assigned |
| C3 | sslmode=require confirmed in `engine_common.db.get_connection()` helper. If not present in the shared helper, explicit `sslmode=require` added to all cross-engine DB connection strings in the GraphBuilder loader classes (S1-04, S1-05, S1-06 ACs). | SR-007 | S1-04, S1-05, S1-06 | CP-1 SA review of engine_common helper |
| C4 | S1-03 acceptance criteria updated to include: `securityContext.runAsNonRoot: true` in K8s manifest, no `privileged: true`, no `hostNetwork: true`. All direct dependencies in requirements.txt use exact version pins (`==`). | SR-008, SR-011 | S1-03 | SA reviews updated S1-03 ACs |
| C5 | Advisory lock design in S1-07 confirmed to use `hashtext(tenant_id || '|' || account_id)` not `hashtext(tenant_id)` alone. Update S1-07 story notes if they do not already reflect this. | W-01 | S1-07 | SA reviews S1-07 ACs |

### CP-2 (Before Sprint 2 S2-02 Begins — PatternCompiler)

**Status: CONDITIONS DEFINED**

S2-01 (PatternRegistry) may start. **S2-02 is BLOCKED until all CP-2 conditions are cleared.**

**Conditions that must be true before S2-02 begins:**

| # | Condition | Source | Story ID | Verification |
|---|-----------|--------|----------|-------------|
| C6 | S2-06 (PerformanceGuard) story description and DoD item 4 updated to specify: performance-triggered quarantine inserts into `threat_pattern_suppressions` (per-tenant, `auto_generated=true`, reason=`performance_p99_exceeded`) instead of setting global `active=false`. ARCHITECTURE.md §4.2 PerformanceGuard bullet updated to match. | SR-001 | S2-06 | SA confirms S2-06 notes and §4.2 are corrected before CP-2 sign-off |
| C7 | PatternCompiler design review: SA confirms the implementation approach is a parameterized template expander from a library of safe Cypher templates, not a string builder. Code review AC added to S2-02: "Reviewer must confirm no f-string, `.format()`, `%`-formatting, or `+` concatenation appears in any method that generates Cypher strings." | SR finding on CP1-01 | S2-02 | CP-2 SA review of PatternCompiler design spec |
| C8 | CI Cypher linter test specification signed off: linter must (a) reject f-strings, (b) reject `.format()`, (c) reject `%`-formatting, (d) reject `+` concatenation in Cypher generation, (e) reject MATCH on CDREvent without `$tenant_id`. Linter's own test suite must include a positive injection example that the linter correctly rejects. | SR-001, SR-003, SR-010 | S2-02, S3-05 | SA reviews linter test spec before S2-02 coded |

### CP-3 (Before Sprint 4 API Stories Begin)

**Status: CONDITIONS DEFINED**

**Conditions that must be true before S4-01 begins:**

| # | Condition | Source | Story ID | Verification |
|---|-----------|--------|----------|-------------|
| C9 | Two-model evidence approach (`IncidentListItem` / `IncidentDetail`) implementation reviewed. S4-02 code must confirm structural separation (not conditional field filtering). `tests/security/test_pii_stripping.py` file listed in Appendix B and confirmed to run on every build. | CP1-02, ADR-005 | S4-02 | SR reviews S4-02 implementation design before story begins |
| C10 | Crown jewel ownership validation query reviewed: SQL query in S4-03 must use parameterized `%s`-style or named parameter; must JOIN `resource_inventory WHERE tenant_id = %s AND resource_uid = %s`; must return 404 (not 403) on mismatch. | CP1-03 | S4-03 | SR reviews S4-03 query before coding begins |
| C11 | Audit log for cdr:sensitive reads confirmed in S4-05 ACs: "cdr:sensitive reads emit audit log to platform `audit_log` table via `logging.getLogger('api-gateway.audit')` with JSON format per CSPM_CONSTITUTION §1.3a. Required fields: timestamp, user_id, tenant_id, endpoint, asset_id_or_principal, result, request_id." | SR-005 | S4-05 | SR reviews S4-05 ACs before story assigned |
| C12 | scan/status job_id ownership check added to S4-01 ACs: `SELECT 1 FROM threat_scan_runs_v1 WHERE run_id=:job_id AND tenant_id=:auth_tid`; return 404 on mismatch. Added to S5-02 RBAC test matrix. | SR-006 | S4-01, S5-02 | SR confirms ownership check is in S4-01 ACs |
| C13 | K8s security context verified in CP-3 manifest review: `runAsNonRoot: true` present, no `privileged: true`, no `hostNetwork: true`. | SR-008 | S1-03 (or CP-3 checklist) | SR confirms manifest during CP-3 review |

### CP-4 (Before Sprint 5 Deploy — Before S5-05)

**Status: CONDITIONS DEFINED**

**Conditions that must be true before S5-05 (Docker build + EKS deploy):**

| # | Condition | Source | Story ID | Verification |
|---|-----------|--------|----------|-------------|
| C14 | All CRITICAL and HIGH SR findings resolved: SR-001 (global active=false), SR-003 (CDREvent tenant_id), SR-004 (ADR-006), SR-005 (audit log), SR-007 (sslmode). No HIGH finding unresolved at this gate. | Multiple | Multiple | SA + SR joint sign-off |
| C15 | Cypher injection penetration test passed: `tests/security/test_cypher_injection.py` runs and verifies that a pattern-derived value containing Cypher syntax reaches `session.run()` as a bound parameter, not as part of the query string. | SR-010 | S5-01 scope | SA reviews test result |
| C16 | Cross-tenant read attempt test passed: S5-01 assertion 7 (`SELECT DISTINCT tenant_id FROM threat_incidents` returns only `my-tenant`) and S5-06 cross-tenant check both pass. CDREvent cross-tenant negative test (S1-08 addition) passes. | SR-003 | S1-08, S5-01, S5-06 | QA confirms in S5-01 results |
| C17 | SLSA Level 1 build provenance confirmed: pinned base image (`python:3.11-slim-bookworm`), build from repo root, no `pip install` at container runtime, no `curl | sh` in Dockerfile. SLSA Level 2 tech debt ticket filed. | SR-013, SLSA | S1-03, S5-05 | SR confirms during CP-4 checklist |
| C18 | FP feedback isolation verified: `SELECT COUNT(*) FROM threat_scenario_patterns WHERE active=false` has not increased since Sprint 2 began. No automated process has set `active=false` on any pattern. | SR-001 | S2-06, S2-10 | SA queries DB before S5-05 |
| C19 | `grep -r "DEV_BYPASS_AUTH" engines/threat_v1/` returns 0 results. | Platform Constitution | All | SA runs grep in CP-4 checklist |
| C20 | W-10 gap tickets filed: 3 gap tickets in platform backlog for T1562.007 auto-response, T1537 auto-response, and recovery playbooks. Tickets linked in PR thread before S5-08. | W-10 | None (backlog) | SA confirms tickets exist |

### Gate Status Summary

| Gate | Sprint | Status | Blocking Story | Conditions |
|------|--------|--------|---------------|-----------|
| CP-1 | Before S1-04 | APPROVED WITH CONDITIONS | S1-04 | C1, C2, C3, C4, C5 (5 conditions) |
| CP-2 | Before S2-02 | CONDITIONS DEFINED | S2-02 | C6, C7, C8 (3 conditions) |
| CP-3 | Before S4-01 | CONDITIONS DEFINED | S4-01 | C9, C10, C11, C12, C13 (5 conditions) |
| CP-4 | Before S5-05 | CONDITIONS DEFINED | S5-05 | C14–C20 (7 conditions) |

---

## 11. Sign-off

I, the Security Architect, have reviewed the threat_v1 architecture for STRIDE threats (15 threat entries across 6 categories), PASTA attack trees (4 adversary goals including the PerformanceGuard denial-of-detection scenario identified in SR-001), MITRE ATT&CK for Cloud technique mapping (8 CP-1 scenarios mapped with D3FEND countermeasures), OWASP SAMM Design Function (scored 2–3 across three practices), CSA CCM v4 domain coverage (16 domains assessed), and NIST CSF 2.0 function coverage (all 5 functions assessed; RS and RC gaps explicitly acknowledged).

The security review findings SR-001 through SR-014 from the pre-implementation security reviewer have been evaluated. This review extends those findings with four additional threats (S-03, D-01, D-02, the PerformanceGuard AT-4 attack tree) and adds ADR-006 (cross-engine direct DB reads) as the formal acceptance artifact for SR-004.

**BLOCKERS identified in this review that are not yet resolved:**

1. SR-001 (CRITICAL): S2-06 (PerformanceGuard) description specifies global `active=false` which contradicts CP1-05 and ADR-003. This creates a denial-of-detection attack surface. Must be corrected before CP-2 (C6).

2. SR-003 (HIGH): CDREvent nodes in Neo4j do not carry `tenant_id` as a first-class property. A Cypher MATCH starting at CDREvent without traversing from a tenant-scoped Resource returns events from all tenants. Must be resolved in S1-01 schema and S1-05 CDRLoader before S1-04 can begin (C1).

3. SR-004 (HIGH): Cross-engine direct DB reads violate CSPM_CONSTITUTION §2.5. ADR-006 in Section 9 of this document provides the Security Architect acceptance of this architecture exception. Architect must countersign in ARCHITECTURE-DECISIONS.md before S1-04 begins (C2).

**CP-1 Gate: APPROVED WITH CONDITIONS**

Development of Sprint 1 MAY PROCEED for stories S1-01, S1-02, and S1-03. Story **S1-04 (ResourceResolver + MisconfigLoader) IS BLOCKED** until the following conditions are met:

- C1: CDREvent node gets `tenant_id` property in schema + S1-05 ACs updated + CI linter extended (SR-003)
- C2: ADR-006 countersigned by Architect in ARCHITECTURE-DECISIONS.md (SR-004)
- C3: sslmode=require confirmed in engine_common helper or explicit in cross-engine connection strings (SR-007)
- C4: S1-03 ACs updated with runAsNonRoot=true and exact-version pip pinning (SR-008, SR-011)
- C5: Advisory lock hash in S1-07 confirmed to use composite key (W-01)

Sprint 0 (MITRE tagging, stories S0-01 through S0-05) is unblocked and may begin immediately.

---

*Security Architect agent — bmad-security-architect*
*Review date: 2026-05-10*
*CP-1 gate artifact for threat_v1 (all 6 sprints)*

*Files reviewed:*
- `/Users/apple/Desktop/threat-engine/engines/threat_v1/REQUIREMENTS.md`
- `/Users/apple/Desktop/threat-engine/engines/threat_v1/ARCHITECTURE.md`
- `/Users/apple/Desktop/threat-engine/engines/threat_v1/SPRINT_PLAN.md`
- `/Users/apple/Desktop/threat-engine/engines/threat_v1/SECURITY_REVIEW_PRE_IMPL.md`
- `/Users/apple/Desktop/threat-engine/.claude/documentation/CSPM_CONSTITUTION.md`
- `/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api_server.py` (lines 3000–3080)
