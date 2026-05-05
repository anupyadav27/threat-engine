# Sprint — Investigation Journey Unification (JNY-01 … JNY-18)

**Sprint code:** JNY
**Duration:** 4 weeks (D1–D28) — extended from 3 weeks to add contract testing layers + BFF-only migration
**ADR:** [ADR-INVESTIGATION-JOURNEY-UNIFICATION.md](../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md)
**Lead orchestration:** `cspm-orchestrator` + `bmad-sm`
**Sign-off:** `bmad-architect`, `cspm-platform-context`, `bmad-security-architect`, `cspm-standards-guardian`

---

## 1. Goal

Convert the 13 posture/security engine pages from list-only views to a **unified investigation experience** that matches the Inventory Asset and Threat Center journeys already shipped. After this sprint, every entity (asset, threat, finding, identity, technique, scenario) has a canonical URL and every list row is a clickable pivot into cross-engine context.

## 2. Outcome (definition of done)

- [ ] All 33 findings in the [ADR Findings Master Matrix](../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#22-consolidated-bug--gap-inventory-33-items) are either fixed, accepted with story file, or explicitly deferred with reason.
- [ ] Every list row in IAM, Network, DataSec, Encryption, Container, DB, AI Security has a `<PivotLink>` to the relevant entity detail page.
- [ ] `/finding/[engine]/[id]` exists with the 5-tab template (Overview · Resource Context · Related Findings · Compliance · Remediation) for at least 3 engines.
- [ ] No 404/500 from any tab in the Inventory Asset, Threat Center, or CIEM Identity journeys (live test from a fresh browser).
- [ ] Frontend image, gateway image, threat-engine image all rebuilt and deployed; image tags committed in K8s manifests.
- [ ] [stories/README.md](stories/README.md) updated with sprint outcome row.

## 3. Sequencing rules

```
Phase A (D1–D3) ──── Phase B (D4–D8) ──── Phase D (D10–D14) ──── Phase G (D18–D21)
   │                    │                       ▲                       ▲
   ▼                    ▼                       │                       │
JNY-01  JNY-02  JNY-03  JNY-05  JNY-06          │                       │
JNY-04 ─────────────────┘                       │                       │
                                                │                       │
                        Phase C (D6–D12) ───────┤                       │
                        JNY-07  JNY-08          │                       │
                                                │                       │
                        Phase E (D12–D17) ──────┤                       │
                        JNY-11                  │                       │
                                                │                       │
                        Phase F (D15–D20) ──────┤                       │
                        JNY-12                  │                       │
                                                JNY-09  JNY-10
```

**Hard rules:**
- Phase A blocks every other phase. No story in B-G enters dev until A is done + deployed.
- JNY-05 must publish the universal `/finding/[engine]/[id]` *page contract* before JNY-06 (BFF) starts coding.
- JNY-07 (PivotLink) must publish the *component contract* before JNY-08 (rollout) starts.

## 4. Story files

| ID | Title | Phase | Lead CSPM agent | Lead BMad | Est | Story file |
|---|---|---|---|---|---|---|
| JNY-01 | Threat DB: `mitre_technique_reference` schema + seed | A | `threat` + `cspm-db-engineer` | `bmad-dev` | M | [JNY-01_*.md](stories/JNY-01_mitre-technique-reference-schema.md) |
| JNY-02 | BFF fix: `/inventory/asset/{uid}/blast-radius` 500 | A | `inventory` + `cspm-bff-dev` | `bmad-dev` | M | [JNY-02_*.md](stories/JNY-02_inventory-blast-radius-bff-fix.md) |
| JNY-03 | Django: grant `ciem:sensitive` to platform_admin | A | `cspm-django-engineer` + `cspm-rbac-guardian` | `bmad-security-po` | S | [JNY-03_*.md](stories/JNY-03_ciem-sensitive-permission-grant.md) |
| JNY-04 | Build & push frontend, gateway, threat images; rollout | A | `cspm-deploy` | n/a | S | [JNY-04_*.md](stories/JNY-04_sprint-images-rollout.md) |
| JNY-05 | Universal finding route `/finding/[engine]/[id]` + 5-tab template | B | `cspm-ui-dev` + `cspm-bff-dev` | `bmad-architect` + `bmad-dev` | L | [JNY-05_*.md](stories/JNY-05_universal-finding-route.md) |
| JNY-06 | Universal BFF: `GET /api/v1/views/finding/{engine}/{id}` | B | `cspm-bff-dev` + each engine agent | `bmad-dev` | L | [JNY-06_*.md](stories/JNY-06_universal-finding-bff.md) |
| JNY-07 | PivotLink primitive component | B | `cspm-ui-dev` | `bmad-dev` + `bmad-agent-ux-designer` | M | [JNY-07_*.md](stories/JNY-07_pivot-link-primitive.md) |
| JNY-08 | Wire PivotLink in 7 posture engine row tables | C | `cspm-ui-dev` + each engine agent | `bmad-dev` | L | [JNY-08_*.md](stories/JNY-08_pivot-link-rollout-7-engines.md) |
| JNY-09 | Threat UI bug fixes (stopPropagation, SLA undefined, deprecated /threat_detail) | D | `cspm-ui-dev` + `threat` | `bmad-dev` | S | [JNY-09_*.md](stories/JNY-09_threat-ui-bug-fixes.md) |
| JNY-10 | CIEM Stage 2 empty-data root cause + actor_principal normalization | D | `ciem` agent | `bmad-dev` | M | [JNY-10_*.md](stories/JNY-10_ciem-stage2-actor-principal-fix.md) |
| JNY-11 | EngineShell + EmptyState + RefreshBus shared primitives | E | `cspm-ui-dev` + `cspm-standards-guardian` | `bmad-architect` + `bmad-dev` | M | [JNY-11_*.md](stories/JNY-11_shared-engine-shell-primitives.md) |
| JNY-12 | `/risk/scenario/[id]` + `/vulnerability/agents/[id]` detail routes | F | `risk` + `vulnerability` + `cspm-ui-dev` | `bmad-dev` | L | [JNY-12_*.md](stories/JNY-12_risk-vuln-detail-routes.md) |
| JNY-13 | BFF Layer 1+2 — black-box tests + Pydantic models (53 BFF views) | H | `cspm-bff-dev` | `bmad-qa` | L | [JNY-13_*.md](stories/JNY-13_bff-contract-tests-pydantic.md) |
| JNY-14 | UI ↔ BFF contract diff tool (Layer 3) + CI gate (Layer 4) | H | `cspm-ui-dev` + `cspm-bff-dev` | `bmad-architect` + `bmad-dev` | M | [JNY-14_*.md](stories/JNY-14_ui-bff-contract-diff-ci-gate.md) |
| JNY-15 | Engine Layer 0+2 — black-box tests + Pydantic models (~150 engine endpoints) | H | each engine agent + `cspm-qa-engineer` | `bmad-dev` + `bmad-qa` | XL | [JNY-15_*.md](stories/JNY-15_engine-contract-tests-pydantic.md) |
| JNY-16 | Direct-engine UI bypass contract diff (Layer 3 extension) | H | `cspm-ui-dev` + engine agents | `bmad-dev` | M | [JNY-16_*.md](stories/JNY-16_direct-engine-bypass-contract-diff.md) |
| JNY-17 | Migrate 4 direct-engine bypasses to BFF views | H | `cspm-ui-dev` + `cspm-bff-dev` + engine agents | `bmad-dev` | M | [JNY-17_*.md](stories/JNY-17_migrate-bypasses-to-bff.md) |
| JNY-18 | Constitution §UI-Backend amendment + ESLint BFF-only rule | H | `cspm-standards-guardian` | `bmad-architect` | S | [JNY-18_*.md](stories/JNY-18_constitution-eslint-bff-only-rule.md) |

## 4.5 Sprint-wide security review checkpoints

These run **in addition to** the per-story quality gate (§5). Failure at a checkpoint blocks all stories in the affected phase.

| CP | Day | Reviewer | Purpose | Blocks |
|---|---|---|---|---|
| **CP-1** Design gate | D2 | `bmad-security-architect` + `cspm-security-reviewer` | STRIDE on JNY-01/02/03 design — new DB table, BFF fix, permission grant | Phase B/C cannot start |
| **CP-2** Schema gate | D7 | `bmad-security-architect` + `cspm-rbac-guardian` | Pydantic response models for JNY-05/06/13/15 — no PII leak, tenant scoping correct, output validation pattern approved | Phase D/E/F cannot start |
| **CP-3** Auth termination gate | D14 | `bmad-security-architect` (A) + `cspm-security-reviewer` | Bearer/API-key auth migration plan for JNY-17 — STRIDE replay on new chain | JNY-17 implementation cannot start |
| **CP-4** Pre-deploy gate | D27 | `bmad-security-reviewer` + `cspm-security-reviewer` | OWASP Top 10 + SLSA + CCM mapping final go/no-go | Phase G (deploy) cannot start |

For full RACI per story see [ADR §4.3](../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#43-sprint-team-assignment-raci).

## 5. Quality gate (every story)

```
dev complete
  ↓
cspm-code-reviewer            ← CSPM patterns, standard columns
  ↓ pass
cspm-security-reviewer        ← OWASP + CSPM (tenant isolation, no-bypass)
+ bmad-security-reviewer      ← SLSA, CCM mapping
  ↓ pass
cspm-qa-engineer              ← findings ingestion, BFF shape
+ bmad-qa                     ← AC verification
  ↓ pass
cspm-deploy                   ← build/push/apply/rollout
  ↓ pass
cspm-integration-tester       ← cross-engine threading, scan_run_id
  ↓ pass
SPRINT-LEVEL exit gate (all 12 stories): manual UI walk-through of all 14 engine pages on staging, no 4xx/5xx in browser network tab during the walk
```

## 5.5 Running the sprint — agent invocation

The 18 stories + 33 sub-tasks aren't run by humans assigning JIRA tickets — they're run by invoking the right agent for each role. Two ways to drive this:

### Option 1 — Slash command (recommended)

```
/jny-kickoff JNY-01 design
/jny-kickoff JNY-15.7
/jny-kickoff JNY-08 dev
```

The [`/jny-kickoff`](../commands/jny-kickoff.md) command:
1. Reads the story file + the RACI from [ADR §4.3](../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#43-sprint-team-assignment-raci)
2. For each agent on the RACI, constructs a prompt that loads `.claude/agents/<agent>.md` as persona + the story file as work order + constitution + phase-specific task
3. Invokes via `Agent(subagent_type=general-purpose)` — runs in parallel where the phase allows (multi-engine fan-out, parallel reviewers)
4. Collects per-agent `*_handoff_*.md` files at the end of each phase
5. Halts at security checkpoints (CP-1..CP-4) until human reviewer confirms

Sequential within a story: **design → dev → review → qa**. Parallel across stories in the same phase.

### Option 2 — Direct helper

If you want to invoke a single agent without the orchestrator:

```bash
python3 .claude/scripts/invoke_cspm_agent.py \
  --agent threat-engine \
  --story JNY-01 \
  --task "Review the mitre_technique_reference schema design for STRIDE issues"
```

That outputs a self-contained prompt to stdout. Pass it to `Agent(subagent_type=general-purpose, prompt=...)`.

### Why this wrapper exists

The CSPM and BMad agents under `.claude/agents/*.md` are valid Claude Code subagents (with `name`, `description`, `autoApprove` frontmatter). In environments where they aren't surfaced as `subagent_type` values, this wrapper preserves their persona by injecting the agent file content as the prompt's leading context. Cost: one extra read per invocation. Benefit: 100% agent-binding-map fidelity without waiting for harness changes.

When the agents do become available as native `subagent_type` values, the wrapper is a 5-line patch (`invoke_cspm_agent.py` swaps the prompt for a direct subagent dispatch).

## 6. Risks & mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| `mitre_technique_reference` seed data sourcing — STIX/MITRE official feed cadence may not match deploy window | JNY-01 slips → blocks B/C/D phases | Bundle a static seed CSV with the migration; refresh monthly via cron later. |
| Universal `/finding/[engine]/[id]` BFF must read 11 different finding tables — schema drift across engines | JNY-06 sprawls | Standard columns are guaranteed (CSPM_CONSTITUTION §Database). BFF reads ONLY standard columns + `finding_data` JSONB; per-engine overrides via plugin map. |
| PivotLink rollout (JNY-08) touches 7 page files = 7 PR review rounds | review fatigue | One PR per engine, but route through `bmad-dev-story` template so reviewer churn is mechanical (find/replace pattern). |
| AssetContextCard fan-out times out in posture engine row clicks | UX regression | Aggregator already has 2s per-engine timeout + graceful `available: false`; reuse as-is. |
| CIEM Stage 2 fix (JNY-10) reveals deeper actor_principal normalization issue across engines | scope creep | Time-box JNY-10 to 3 days; if root-cause hits the writer pipeline, spin off STORY-CIEM-NN and ship JNY with Stage-2-empty workaround. |

## 7. Out of scope (deferred)

- **G-9 / G-10 / G-22** — CWPP/CNAPP empty data, multi-hop attack chains. These are upstream pipeline data gaps, not journey gaps. Track separately via `cspm-pipeline-engineer`.
- **G-21** — Configuration tab scrubber validation. Wait for an asset with credential fields to land in the catalog.
- **G-26** — `attack_chain` batched endpoint. Performance-only; ship after we measure real load.
- **G-27 / G-28** — Compliance per-control + Risk scenario cross-links. Will be covered by JNY-12 and a follow-up sprint after seeing JNY usage telemetry.
- **G-29** — SecOps/Vuln sub-route exhaustive walk-through. Spin off `STORY-SECOPS-VAL` if needed.
- **G-30 / G-31** — Audit logs. Already deferred per design as ship-gate, not dev-start-gate.

## 8. Image tag plan

| Image | Current | Sprint exit |
|---|---|---|
| cspm-frontend | `v-frontend-journey1` | `v-frontend-jny-sprint` |
| api-gateway | `v-gateway-journey1` | `v-gateway-jny-sprint` |
| engine-threat | (deployed: `v-di-sprint3` per K8s) | `v-threat-jny-mitre-ref` |
| engine-inventory | `v-inventory-auth` | `v-inventory-jny-blast-radius` |
| cspm-backend | `v-di-sprint3` | `v-backend-jny-ciem-perm` |

`cspm-deploy` agent updates [memory/MEMORY.md](../../.claude/projects/-Users-apple-Desktop-threat-engine/memory/MEMORY.md) image tag table at sprint exit.

## 9. Sprint exit checklist

- [ ] All 12 stories in `done` state with story files moved per [planning-lifecycle rule](../rules/planning-lifecycle.md)
- [ ] [stories/README.md](stories/README.md) "Completed Sprints" row added: `| Investigation Journey Unification (JNY-01–12) | YYYY-MM-DD | summary |`
- [ ] [memory/MEMORY.md](../../.claude/projects/-Users-apple-Desktop-threat-engine/memory/MEMORY.md) image tags updated
- [ ] [memory/ui_investigation_journeys_architecture.md](../../.claude/projects/-Users-apple-Desktop-threat-engine/memory/ui_investigation_journeys_architecture.md) updated to reflect L1/L2/L3 unification
- [ ] [.claude/documentation/API-REFERENCE.md](../documentation/API-REFERENCE.md) entries added for `/finding/{engine}/{id}` and `/risk/scenario/{id}`
- [ ] Manual UI walk-through video recorded — every engine list, every row click, every detail page
