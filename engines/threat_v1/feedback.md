

You are a senior staff engineer reviewing and improving a threat 
detection engine design document. The doc is at:

  engines/threat_v1/REQUIREMENTS.md
  
(Adjust path if different — find the file titled "Threat Detection 
Engine v1 — Requirements & Proposed Solution".)

Your job is to apply a specific set of revisions to that document. 
Do NOT rewrite the whole doc. Make surgical, additive edits that 
preserve the existing structure, tone, and section numbering.

═══════════════════════════════════════════════════════════════════
CONTEXT YOU MUST INTERNALIZE FIRST
═══════════════════════════════════════════════════════════════════

The doc describes a 3-tier threat detection engine:
- Tier 1: single-node toxic combos
- Tier 2: partial attack paths  
- Tier 3: full attack paths from entry → crown jewel
- CDR overlay escalates posture incidents to active incidents
- YAML patterns → Postgres → Cypher execution against Neo4j
- Findings: misconfig + vuln + CDR, all MITRE-tagged

The doc is good. These edits address gaps that would cause production 
problems: missing lifecycle states, multi-pattern roll-up, FP feedback, 
performance budgets, cross-account limitations, and observability.

═══════════════════════════════════════════════════════════════════
EDITS TO APPLY (in this order)
═══════════════════════════════════════════════════════════════════

═══ EDIT 1: Add a third incident_class value ═══

Currently the doc has only `posture` and `active`. Add `suspicious` 
as the middle state.

In Section 8 (Detection Tiers), add to the Tier 3 description:

  CDR signal grading within Tier 3:
    - 0 CDR signals on path  → incident_class=posture, severity=HIGH
    - 1 CDR technique observed → incident_class=suspicious, severity=HIGH
    - ≥2 CDR techniques OR cdr_watch.min_coverage met 
      → incident_class=active, severity=CRITICAL

In Section 9.1 (threat_incidents table), update the comment on 
incident_class field:
  
  incident_class VARCHAR(16) NOT NULL,  -- posture / suspicious / active

In Section 9.2 (Deduplication Rules), update the escalation row:

  | Posture incident exists, 1st CDR technique fires | Escalate: 
    incident_class → suspicious, severity unchanged |
  | Suspicious incident exists, additional CDR technique fires | 
    Escalate: incident_class → active, severity → critical |

═══ EDIT 2: Add Section 9.4 — Incident Lifecycle State Machine ═══

Insert after Section 9.3, before Section 10:

  ### 9.4 Incident Lifecycle State Machine
  
  Incidents progress through explicit states. Transitions are 
  triggered by graph state changes, CDR observations, or operator 
  actions.
States:
new          -- just created, not yet visible
open         -- visible to customer, action required
suspicious   -- 1 CDR signal (sub-state of open)
active       -- 2+ CDR signals (sub-state of open)
contained    -- actor neutralized, watching for re-occurrence
resolved     -- underlying findings fixed, no active signals
reopened     -- previously resolved, same dedup_key fires within 7d

Transitions:
new → open                        on first detection
open (posture) → suspicious        first CDR technique observed
suspicious → active                second CDR technique OR
min_coverage met
active → contained                 actor session revoked AND
no CDR events for 1h
contained → resolved               no CDR events for 24h AND
underlying findings fixed
open → resolved                    underlying findings fixed
resolved → reopened                same dedup_key fires within 7d
  
  Auto-transitions run every 5 minutes via a scheduled job 
  (IncidentLifecycleManager).

═══ EDIT 3: Add Section 9.5 — Multi-Pattern Roll-up ═══

Insert after the new Section 9.4:

  ### 9.5 Multi-Pattern Roll-up
  
  A single resource or path may match multiple patterns 
  simultaneously. Without roll-up logic, customers see N alerts 
  for one underlying problem.
  
  Roll-up key: `(tenant_id, entry_resource_uid, target_resource_uid)`
  
  Rules:
  - All patterns matching the same roll-up key produce ONE incident
  - The incident inherits the highest tier among matched patterns
  - Severity = max severity across patterns in roll-up
  - All matched patterns recorded in evidence as 
    `evidence.matched_patterns[]`
  - Story_text uses the highest-tier pattern's template
  
  Example:
Resource X matches:
PAT-AWS-T1-007 (Tier 1, severity=HIGH)
PAT-AWS-T2-003 (Tier 2, severity=HIGH)
PAT-AWS-T3-001 (Tier 3, severity=CRITICAL)
Result: 1 incident
tier = 3
pattern_id = PAT-AWS-T3-001 (primary)
severity = critical
evidence.matched_patterns = [PAT-AWS-T1-007, PAT-AWS-T2-003,
PAT-AWS-T3-001]

═══ EDIT 4: Add Section 9.6 — Evidence Schema ═══

Insert after the new Section 9.5:

  ### 9.6 Evidence JSONB Schema
  
  The `evidence` field in threat_incidents follows this structure:
  
```yaml
  evidence:
    misconfig_findings:
      - finding_id: <sha256>
        rule_id: aws-ec2-imdsv1-enabled
        severity: high
        resource_uid: <arn>
        mitre_techniques: [T1552.005]
    
    vuln_findings:
      - cve_id: CVE-2024-xxxx
        cvss_score: 9.8
        epss_score: 0.87
        resource_uid: <arn>
    
    cdr_events:
      - finding_id: <sha256>
        actor_principal: alice@corp.com
        mitre_technique: T1530
        event_time: 2026-05-10T08:42:01Z
        action: GetObject
    
    path_resources:
      - resource_uid: <arn>
        resource_type: EC2Instance
        position: 0
        role: entry
      - resource_uid: <arn>
        resource_type: IAMRole
        position: 1
        role: pivot
      - resource_uid: <arn>
        resource_type: S3Bucket
        position: 2
        role: target
    
    matched_patterns:
      - pattern_id: PAT-AWS-T3-001
        pattern_version: 3
        match_timestamp: 2026-05-10T09:02:35Z
    
    graph_query: <cypher_with_params>
```
  
  This schema is the contract between the threat engine and the 
  UI/API. Changes are versioned via `evidence._schema_version`.

═══ EDIT 5: Add pattern versioning fields ═══

In Section 5.3 (YAML Pattern Schema), add at the top of the YAML 
example, just under `id`:

  version: 1                     # Bump on any meaningful change
  deprecated_at: null            # ISO datetime when retired
  tenant_eligibility:
    plans: [enterprise, premium] # null = all plans
    feature_flag: null           # optional gate

In Section 9.1 (threat_incidents table), add these columns before 
"-- Lifecycle":

    pattern_version     SMALLINT NOT NULL,
    input_scan_runs     JSONB NOT NULL,   -- {check, vuln, cdr, inventory}

Update Section 11 row "Pattern storage" to note:
  
  Pattern versions tracked in YAML and snapshotted on incident creation 
  for reproducibility.

═══ EDIT 6: Add Section 5.5 — Pattern Authoring Workflow ═══

Insert after Section 5.4 (Pattern Storage Flow), before Section 6:

  ### 5.5 Pattern Authoring Workflow
  
  Patterns are authored as YAML files, reviewed via PR, and 
  validated by automation before merge.
Workflow:
1. Engineer creates pattern at:
catalog/threat_patterns/{tier}/{csp}/PAT-XXX-NNN.yaml
2. Local validation (CLI):
   threat-v1 pattern validate <path>      # YAML schema check
   threat-v1 pattern compile <path>       # Cypher generation
   threat-v1 pattern test <path>          # positive + negative

3. PR submitted; CI runs:
   - YAML schema validation (Pydantic)
   - Cypher compilation (against Neo4j test fixture)
   - MITRE technique ID validation (against ATT&CK catalog)
   - Positive test fires correctly on fixture graph
   - Negative test does NOT fire on fixture graph
   - Test latency within tier budget

4. Review gate:
   - Detection engineer review (mandatory)
   - Security architect review for new tactic chains (mandatory)

5. Merge → upload_scenario_patterns.py runs at engine startup, 
   loads YAML to threat_scenario_patterns table
  
  CLI tooling lives in `engines/threat_v1/cli/`.

═══ EDIT 7: Expand Section 11 (Technical Decisions) ═══

After the existing decision table, add three new subsections:

  ### 11.1 Concurrency Model
  
  - Per-tenant advisory lock during graph build (Postgres pg_advisory_lock)
  - Pattern execution parallel across tenants, serialized within tenant
  - Incident upsert: ON CONFLICT (dedup_key) UPDATE
  - Trigger B (CDR) waits if Trigger A (full pipeline) is running 
    for same tenant
  - Maximum wait: 5 minutes; if exceeded, Trigger B logs and skips
  
  ### 11.2 Performance Budgets
  
  Per-tenant scan duration targets:
  
  | Resource Count | Full Scan | Pattern Execution |
  |---|---|---|
  | < 1,000        | < 30s     | < 10s             |
  | 1,000–10,000   | < 5min    | < 1min            |
  | 10,000–100,000 | < 30min   | < 10min           |
  
  Per-pattern budget: median < 100ms, p99 < 500ms.
  Patterns exceeding p99 budget for 3 consecutive runs are 
  auto-quarantined and flagged for review.
  
  ### 11.3 Failure Modes
  
  | Failure | Behavior |
  |---|---|
  | Neo4j unavailable | Pipeline fails fast; alert on-call; no partial writes |
  | Postgres unavailable | Pipeline fails fast |
  | Pattern execution crash | Log + skip pattern + continue with others |
  | Argo workflow killed | Next trigger does full rebuild (idempotent) |
  | Stale resource nodes | Reaper job nightly: delete nodes with no findings >90d |

═══ EDIT 8: Add Section 15 — External Contracts ═══

Insert after Section 14 (Open Questions), before Appendix A:

  ## 15. External Contracts
  
  ### 15.1 REST API
  
  Full OpenAPI spec at `engines/threat_v1/api/openapi.yaml`.
  
  | Method | Path | Purpose |
  |---|---|---|
  | GET    | /api/v1/incidents | List with filters (tenant, status, severity, tier) |
  | GET    | /api/v1/incidents/{id} | Full detail with evidence |
  | POST   | /api/v1/incidents/{id}/feedback | FP/TP marking |
  | POST   | /api/v1/incidents/{id}/actions | Execute remediation |
  | GET    | /api/v1/patterns | Catalog (active patterns) |
  | GET    | /api/v1/patterns/{id} | Pattern detail |
  | POST   | /api/v1/crown-jewels | Customer-tagged crown jewel |
  | GET    | /api/v1/coverage | MITRE coverage map |
  
  ### 15.2 Webhooks
  
  Customers configure HTTPS endpoints to receive events:
  
  - `incident.created`
  - `incident.escalated` (posture → suspicious → active)
  - `incident.contained`
  - `incident.resolved`
  - `incident.reopened`
  
  Payload includes incident summary; full detail fetched via API.

═══ EDIT 9: Update Phase 6 — add FP feedback + observability ═══

In Section 13 (Build Plan), expand Phase 6:

  ### Phase 6 — Validation & Observability (1 week → 1.5 weeks)
  
  | Step | Deliverable |
  |---|---|
  | 6.1 | Pattern test harness (positive + negative case runner) |
  | 6.2 | Per-pattern metrics: fire_count, match_latency_ms, error_count, tp_count, fp_count |
  | 6.3 | Per-tenant metrics: graph_build_duration, node_count, edge_count, scan_duration |
  | 6.4 | System metrics: neo4j_query_latency, postgres_lock_wait, argo_failures |
  | 6.5 | FP feedback loop: threat_incident_feedback table + per-pattern FP rate (rolling 30d) |
  | 6.6 | Auto-quarantine: patterns with FP rate > 30% over 30d are flagged for review |
  | 6.7 | Per-tenant pattern allowlist/suppression |
  | 6.8 | Pattern catalog API endpoint (GET /api/v1/patterns) |
  | 6.9 | Coverage dashboard endpoint (GET /api/v1/coverage) |
  | 6.10 | Alerting rules: pattern budget exceeded, tenant SLA breached, high FP rate |

═══ EDIT 10: Add Q8 to Open Questions ═══

In Section 14, add as the last open question:

  **Q8 — Cross-account / cross-cloud paths**
  
  v1 joins findings on `tenant_id + account_id`, which means an 
  attack path crossing accounts (within or across providers) is 
  not detectable in v1.
  
  Real-world attacks that this misses:
  - AWS Account A compromised → assume role in Account B → exfil
  - Azure tenant → AWS via federated identity (OIDC, SAML)
  - GitHub Actions → AWS prod via workload identity
  
  *Recommendation:* Document as explicit v1 limitation. Phase 2 
  (post-launch) adds same-provider cross-account paths. Phase 3 
  adds cross-provider via federated identity.

═══ EDIT 11: Reduce Phase 5 scope ═══

In Section 13, Phase 5 — change pattern counts:

  | Step | Current | Revised |
  |---|---|---|
  | 5.1 Tier 1 patterns | 10–15 | 10 |
  | 5.2 Tier 2 patterns | 10–15 | 10 |
  | 5.3 Tier 3 patterns | 10–15 (5 immediate) | 10 (mostly AWS) |
  | Total | 30–45 | 30 |
  
  Rationale: 30 patterns at quality bar (positive + negative tests, 
  security review) is achievable in 2 weeks; 60+ is not. Subsequent 
  patterns ship in Phase 8 (post-v1).

═══ EDIT 12: Update Phase 7 — add shadow mode ═══

In Section 13, replace Phase 7 with:

  ### Phase 7 — Shadow Mode → Transition (2 weeks)
  
  Week 1: Shadow mode (read-only)
    - threat-v1 runs in parallel with engines/threat/
    - Writes to threat_v1 tables only
    - No customer-facing alerts
    - Compare detection output between engines daily
    - Fix divergences
  
  Week 2: Parallel mode (both visible)
    - Customer sees both engines' alerts (clearly labeled)
    - Customer feedback collected on threat-v1 incidents
    - Tune patterns based on feedback
  
  Gate to switchover:
    - threat-v1 produces ≥ all existing detections
    - threat-v1 FP rate < 30% across enabled patterns
    - No critical bugs open >7 days
    - Customer feedback positive on majority of new incidents
  
  Switchover:
    - Replace engines/threat/ in Argo DAG
    - Deprecate old engine (keep readable for 90 days)
    - Migrate any open incidents

═══ EDIT 13: Update Open Questions answers ═══

In Section 14:

  Q3 — REVISE recommendation:
    Use latest scan per engine (operationally), but snapshot the 
    chosen scan_run_ids per engine in 
    threat_scan_runs.input_scan_runs JSONB column for 
    reproducibility. This gives both freshness and audit trail.
  
  Q5 — REVISE recommendation:
    Phase 0 runs in parallel with Phase 1–3 (weeks 1–5), and MUST 
    complete before Phase 5 begins. The first 5 Tier 3 patterns 
    can use already-tagged AWS rules without waiting for Phase 0.

═══════════════════════════════════════════════════════════════════
EXECUTION INSTRUCTIONS
═══════════════════════════════════════════════════════════════════

1. Read the entire current REQUIREMENTS.md first. Confirm you 
   understand the existing structure before editing.

2. Apply all 13 edits in order. For each edit:
   - Show me the diff (before → after) in a code block
   - Explain in 1 sentence what the edit accomplishes
   - Wait for me to say "next" before proceeding to the next edit

3. After all edits applied, do a final pass:
   - Renumber sections if any are now out of sequence
   - Update the Table of Contents
   - Verify cross-references still resolve
   - Output the final unified document

4. If any edit conflicts with content already in the doc 
   (e.g., I've made changes since), STOP and ask me how to 
   resolve before continuing.

5. Do not invent new content beyond what is specified above. If 
   something is unclear, ask before guessing.

Start by reading the current doc and confirming the section 
numbers match what these edits assume. If section numbers have 
shifted, propose adjustments before making any changes.

How to Use This

Save the doc — make sure your REQUIREMENTS.md (or whatever you've named it) is in the project, committed.
Open Claude Code or Cursor in your project root.
Paste the prompt above as your message.
Drive it edit-by-edit — Claude shows the diff, you say "next", it proceeds.
Review each diff before approving. The structure makes it easy to catch hallucinations.

Variants
Shorter version (if you trust Claude to do all 13 at once)
At the end of the prompt, replace the "EXECUTION INSTRUCTIONS" section with:
Apply all 13 edits in a single pass. Show me the final document 
with all edits integrated. After the document, list the 13 edits 
applied as a checklist so I can verify each was made.
Even shorter — just the headlines
If you want a quick fix without 13 detailed prescriptions, here's a one-shot version:
Review engines/threat_v1/REQUIREMENTS.md and apply these 
improvements as additive edits, preserving structure:

1. Add 'suspicious' as a third incident_class between posture 
   and active (1 CDR signal = suspicious; 2+ = active).

2. Add Section 9.4 specifying the incident lifecycle state 
   machine (new → open → suspicious → active → contained → 
   resolved → reopened) with auto-transition rules.

3. Add Section 9.5 specifying multi-pattern roll-up: same 
   roll-up key (tenant_id, entry_uid, target_uid) produces ONE 
   incident; highest tier wins; all patterns in evidence.

4. Add Section 9.6 with the evidence JSONB schema spec.

5. Add `version`, `deprecated_at`, `tenant_eligibility` to the 
   pattern YAML schema. Add `pattern_version` and `input_scan_runs` 
   columns to threat_incidents.

6. Add Section 5.5 specifying pattern authoring workflow (CLI 
   commands, PR review, CI checks, security architect gate).

7. Add Section 11.1 (concurrency model with Postgres advisory 
   locks), 11.2 (performance budgets per tenant size), 11.3 
   (failure mode handling).

8. Add Section 15 specifying REST API endpoints and webhook 
   events for external integration.

9. Expand Phase 6 to include FP feedback loop, per-pattern auto-
   quarantine at >30% FP rate, full Prometheus metrics spec, and 
   alerting rules.

10. Add Q8 to Open Questions: cross-account/cross-cloud paths 
    are NOT supported in v1 — document as explicit limitation, 
    plan as Phase 2/3 work.

11. Reduce Phase 5 scope from 30–45 patterns to 30 patterns 
    total (10 per tier).

12. Replace Phase 7 with explicit shadow mode (read-only) → 
    parallel mode (visible) → switchover, with gate criteria.

13. Revise Q3 recommendation: use latest-scan-per-engine BUT 
    snapshot input_scan_runs in threat_scan_runs for 
    reproducibility. Revise Q5: Phase 0 runs in parallel with 
    Phase 1–3, must complete before Phase 5.

For each edit, show me the diff in a code block before applying. 
Wait for my confirmation between major sections.