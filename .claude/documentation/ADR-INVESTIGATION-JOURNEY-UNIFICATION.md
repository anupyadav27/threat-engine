# ADR — Investigation Journey Unification Across All Engines

**Status:** Proposed (2026-05-04)
**Authors:** Validated end-to-end against the running platform (cluster-deployed engines + local gateway + local frontend).
**Supersedes / extends:**
- [ui_investigation_journeys_architecture.md](../../../.claude/projects/-Users-apple-Desktop-threat-engine/memory/ui_investigation_journeys_architecture.md) (Asset + Threat journeys, design)
- [inventory_asset_investigation_journey.md](../../../.claude/projects/-Users-apple-Desktop-threat-engine/memory/inventory_asset_investigation_journey.md)
- [threat_center_investigation_journey.md](../../../.claude/projects/-Users-apple-Desktop-threat-engine/memory/threat_center_investigation_journey.md)
- [ui_journey_data_model.md](../../../.claude/projects/-Users-apple-Desktop-threat-engine/memory/ui_journey_data_model.md)
- [CSPM_CONSTITUTION.md](./CSPM_CONSTITUTION.md) §UI Competitive Standards

**Audience:** `cspm-orchestrator`, `bmad-architect`, `cspm-ui-dev`, `cspm-bff-dev`, all per-engine CSPM agents.

---

## 1. Context

We finished implementing two specialty investigation journeys (Inventory Asset + Threat Center) and validated all 14 tabs end-to-end. We then walked the remaining 12 posture/security engines (IAM, DataSec, Network, Encryption, Container, DB, AI, CIEM, Compliance, Risk, CNAPP, CWPP, SecOps, Vulnerability) and confirmed they ship as **list/section-tab pages with no per-finding deep-dive route**, no cross-engine pivot, and no consistent click-through pattern.

The result: the platform delivers two world-class investigation flows (matching Wiz/Orca for assets and threats) and ten table-of-rows pages that *cannot* answer the analyst's next question without a manual URL-bar pivot. This is the largest gap to enterprise-grade UX competitive parity.

This ADR consolidates all 33 findings across both Sprints (the journey sprint just shipped + the posture engines) and proposes a unified architecture that makes every finding/asset/identity row an investigable entity.

---

## 2. Findings Master Matrix

### 2.1 Per-engine investigation maturity (current state)

| Engine | List page | Section tabs | Deep-dive route | Cross-engine pivot | Score |
|---|---|---|---|---|---|
| Inventory | ✅ | ✅ Architecture/Graph/Overview | ✅ `/inventory/[assetId]` 8 tabs | ✅ Threats/CIEM/Compliance from tabs | **A** |
| Threat | ✅ | ✅ 4 sub-tabs (Command Room/Attack Map/Graph/Trends) | ✅ `/threats/[threatId]` 6 tabs | ⚠️ blocked by 2 bugs | **A-** |
| CIEM | ✅ | ✅ Overview/Detection Rules/Log Sources | ✅ `/ciem/identity/[principal]` (Stage 2) | ⚠️ stage 2 returns empty data | **B** |
| Compliance | ✅ | sub-routes `[framework]`, `matrix`, `remediation` | partial (framework drill) | ❌ no cross-engine | **B-** |
| Network Security | ✅ | ✅ 7 tabs incl. graph | ❌ none | ❌ no row click-through | **C** |
| IAM | ✅ | ✅ 5 tabs (Findings/Roles/Access/PrivEsc) | ❌ none | ❌ no row click-through | **C** |
| Database Security | ✅ | ✅ 6 tabs | ❌ none | ❌ | **C** |
| Encryption | ✅ | ✅ 5 tabs (+ key-detail sub-route) | ❌ partial | ❌ | **C** |
| AI Security | ✅ | ✅ 4 tabs (5070 findings) | ❌ none | ❌ | **C** |
| DataSec | ✅ | ✅ 6 tabs (+ lineage sub-route) | ❌ partial | ❌ | **C** |
| Container Security | ✅ | ✅ 6 tabs | ❌ none | ❌ | **C** |
| Risk | ✅ | ✅ 4 tabs (FAIR + ALE) | ❌ none | ❌ | **C+** |
| CNAPP | ✅ | ✅ 8 pillar tabs | ❌ none (aggregator) | n/a | **C** |
| CWPP | ✅ | ✅ 5 tabs | ❌ none | ❌ | **C** |
| SecOps | ✅ | ✅ 5 tabs (+ scanId, dast, sca sub-routes) | partial | ❌ | **C+** |
| Vulnerability | ⚠️ agent-picker only | ❌ | partial (agents/cves/scans) | ❌ | **D** |

### 2.2 Consolidated bug & gap inventory (33 items)

| # | Severity | Type | Engine(s) | Issue | Source |
|---|---|---|---|---|---|
| **G-1** | 🔴 P0 | DB | Threat | `mitre_technique_reference` table missing — TechniqueDetailModal returns 500 | live test |
| **G-2** | 🔴 P0 | BFF | Inventory | `/api/v1/views/inventory/asset/{uid}/blast-radius` returns 500 | live test |
| **G-3** | 🟡 P1 | Auth | Inventory | `/api/v1/views/inventory/asset/{uid}/ciem` requires `ciem:sensitive` perm not in default platform_admin | live test |
| **G-4** | 🟡 P1 | UI | Threat | TechniqueDetailModal click is swallowed by parent NodeInvestigationPanel — needs `e.stopPropagation()` | code review at [page.jsx:1131](frontend/src/app/threats/[threatId]/page.jsx:1131) |
| **G-5** | 🟢 P3 | UI | Threat | Remediation tab shows literal "undefined d left" when SLA absent | live test |
| **G-6** | 🟡 P1 | Engine | CIEM | Stage 2 identity profile returns empty findings/hourly/dow for principals listed in Stage 1 — likely actor_principal format mismatch | live test |
| **G-7** | 🟢 P2 | UI | CIEM | `/ciem` rows wire `onClick` only — no `<a href>` so middle-click/open-in-tab broken | code review at [ciem/page.jsx:454](frontend/src/app/ciem/page.jsx:454) |
| **G-8** | 🟢 P3 | UI | Threat | Frontend calls deprecated `/api/v1/views/threat_detail` (404) parallel to working `/views/threats/{id}` | network log |
| **G-9** | 🟡 P2 | Data | CWPP | All workload tabs empty (containers/images/hosts/serverless/runtime = 0) | live test |
| **G-10** | 🟡 P2 | Data | CNAPP | Score 0/100; all 7 pillars empty (depends on upstream pillar engines populating) | live test |
| **G-11** | 🟡 P2 | UI/BFF | Vulnerability | "Could not load agent list" — no agents endpoint or graceful fallback | live test |
| **G-12** | 🟡 P1 | UX gap | IAM | No `resource_uid` click → `/inventory/[uid]` from finding row (5,000 rows orphaned) | analysis |
| **G-13** | 🟡 P1 | UX gap | Network | Same as G-12 | analysis |
| **G-14** | 🟡 P1 | UX gap | DataSec | Same as G-12 | analysis |
| **G-15** | 🟡 P1 | UX gap | Encryption | Same as G-12 | analysis |
| **G-16** | 🟡 P1 | UX gap | Container Security | Same as G-12 | analysis |
| **G-17** | 🟡 P1 | UX gap | Database Security | Same as G-12 (128 rows orphaned) | analysis |
| **G-18** | 🟡 P1 | UX gap | AI Security | Same as G-12 (5,070 rows orphaned) | analysis |
| **G-19** | 🟡 P1 | UX gap | All posture | No `rule_id` click → `/misconfig?rule_id=...` from finding rows | analysis |
| **G-20** | 🟡 P1 | UX gap | All posture | No per-finding detail route — analyst cannot see related threats/blast-radius/compliance for a single posture finding | analysis |
| **G-21** | 🟡 P2 | Data | Inventory | Configuration tab scrubber not validated (sample assets had no credential fields) | spec gap |
| **G-22** | 🟡 P2 | Data | Inventory + Threat | Sample data is 1-hop chains; multi-hop attack paths not exercisable | data gap |
| **G-23** | 🟢 P3 | UI | All engines | "Refresh" button repeated; no global refresh bus | analysis |
| **G-24** | 🟡 P2 | UI | All engines | KPI strip + tab counts duplicated as boilerplate per engine — no shared shell | code review |
| **G-25** | 🟢 P3 | UI | All engines | Empty-state visuals are 90% identical text; no shared `EmptyState` component | code review |
| **G-26** | 🟡 P2 | DB | Threat | `attack_chain` enrichment relies on per-step lookup; no batched endpoint | spec |
| **G-27** | 🟢 P3 | UX | Compliance | Framework drill shows controls list but no per-control finding click-through to engines | analysis |
| **G-28** | 🟢 P3 | UX | Risk | Risk scenarios don't link to underlying threat detections / failed compliance controls | analysis |
| **G-29** | 🟢 P3 | UX | CWPP/CNAPP/SecOps/Vuln | Sub-routes exist (`/secops/[scanId]`, `/vulnerability/agents`, `/cves`, `/scans`) but not exercised in this validation | coverage gap |
| **G-30** | 🟡 P2 | Audit | Inventory CIEM tab | W-1 audit log not wired (pre-shipped per design as "ship-gate") | spec deferral |
| **G-31** | 🟡 P2 | Audit | Threat status PATCH | W-2 audit trail not wired | spec deferral |
| **G-32** | 🟡 P2 | UI | Threat | Frontend not rebuilt — sprint code in working tree but image tag still `v-frontend-journey1` | deploy gap |
| **G-33** | 🟡 P2 | Gateway | All BFF | Gateway not rebuilt — sprint BFF code (`asset_context.py`, `ciem_identity.py`, `technique_detail.py`) in working tree but image tag still `v-gateway-journey1` | deploy gap |

---

## 3. Architecture Decision

### 3.1 Decision

We will adopt a **two-axis investigation journey model**: every analyst entity (finding, asset, identity, technique, framework, scenario, agent, scan) is reachable via a **canonical detail route** AND linkable from any other engine's row, modal, or graph node via a shared **PivotLink** primitive. The model has three layers:

**L1 — Entity Routes (canonical detail pages).** Every analyst entity gets one URL that is the source of truth for "everything we know about this thing":

| Entity | Canonical route | Deep-dive structure |
|---|---|---|
| Asset | `/inventory/[uid]` | 8 tabs (already shipped) |
| Threat | `/threats/[id]` | 6 tabs (already shipped) |
| Identity | `/ciem/identity/[principal]` | 5 stages (Stage 1+2 shipped, 3-5 pending) |
| **Finding** *(new — universal)* | `/finding/[engine]/[finding_id]` | 5 tabs: Overview · Resource Context · Related Findings · Compliance · Remediation |
| **Technique** *(new)* | `/threats/technique/[id]` | MITRE detail + D3FEND + affected count + compliance |
| Framework | `/compliance/[framework]` (exists) | Controls + failing list (already partial) |
| Risk Scenario | `/risk/scenario/[id]` *(new)* | FAIR breakdown + driving findings + mitigations |
| Workload | `/cwpp/workload/[type]/[uid]` *(new)* | Inventory + runtime + image findings |
| Code Scan | `/secops/[scanId]` (exists) | Already routed |
| Vulnerability Agent | `/vulnerability/agents/[id]` (exists) | Already routed |

**L2 — PivotLink primitive.** A single React component:

```jsx
<PivotLink to="asset" id={resourceUid} provider={provider} />
<PivotLink to="threat" id={threatId} />
<PivotLink to="finding" engine="iam" id={findingId} />
<PivotLink to="technique" id="T1530" />
```

Renders an `<a>` (real href, supports middle-click), shows the entity icon + truncated name, opens a hover tooltip with engine + severity, and emits a click event for telemetry. Replaces every `onClick={() => router.push(...)}` and every bare text cell of resource_uid / rule_id / principal across all 14 engine pages.

**L3 — AssetContextCard slot.** Reuse the existing `frontend/src/components/shared/AssetContextCard.jsx` (built in sprint) on every per-finding detail page (Resource Context tab). Single source of truth for "what else does this resource have going on." Calls the existing `/api/v1/asset-context/{uid}` aggregator (works today, returns cross-engine summary in 2s with graceful degradation).

### 3.1.b Contract testing layers (the safety net)

The L1-L3 entity model only delivers value if every contract is enforced. We add **five** test layers, all of which run in CI before merge:

```
                       ┌─────────────────────────────┐
Layer 4 — CI gate      │ Schema drift detector       │ ← fails build on shape change
                       └──────────────▲──────────────┘
                                      │
Layer 3 — Contract diff               │
        UI consumed paths   ←→   BFF Pydantic models
        UI consumed paths   ←→   Engine Pydantic models  (for direct UI→engine bypasses)
                                      ▲
Layer 2 — Schema test                 │
        Pydantic response models on EVERY BFF endpoint
        Pydantic response models on EVERY engine endpoint
                                      ▲
Layer 1 — BFF black-box test          │
        Hit every BFF endpoint with parametrized inputs (~265 cases)
                                      ▲
Layer 0 — Engine black-box test       │
        Hit every engine endpoint via NLB ingress (~150 endpoints × 3 inputs)
```

**Failure modes each layer catches:**
- L0 catches engine drift (BFF returns wrong data because engine returns wrong data)
- L1 catches BFF crashes (500s, missing keys, broken aggregation)
- L2 catches typos and shape regressions at runtime (FastAPI validates output)
- L3 catches the silent killer — UI reads `data.attackPath.steps[0].technique` but BFF provides `mitre_technique`. AST-extract every property access in every page.jsx and diff against Pydantic schema set.
- L4 catches drift between PRs — if BFF shape changes without UI update or vice versa, build fails.

### 3.1.c BFF-only frontend rule (the architectural contract)

Industry best practice (BFF pattern, AWS Well-Architected, Netflix/Sam Newman) is that the frontend has **exactly one** allowed origin. We adopt this with a narrow exception list:

**Constitution amendment (proposed):**

> **§UI-Backend Contract:**
> 1. Frontend allowed origins: gateway NLB only.
> 2. Frontend allowed paths:
>    - `/gateway/api/v1/views/*` — BFF views
>    - `/gateway/api/v1/asset-context/*` — gateway-native aggregator
>    - `/cspm/api/auth/*` — auth handshake exception (login/logout/me/csrf/SSO callbacks ONLY)
>    - paths in `ALLOWED_DIRECT_ENGINE_BYPASSES` in `next.config.js` with attached ADR justification
> 3. Adding any new direct-engine bypass requires a `bmad-architect`-signed ADR.
> 4. ESLint rule fails the build if any frontend file fetches an engine prefix not on the allowed list.

**Verdict on existing bypasses:**

| Current bypass | Verdict | Action |
|---|---|---|
| `/cspm/api/auth/*` | ✅ KEEP — auth handshake | Lock down to `/login`, `/logout`, `/me`, `/csrf`, `/google/*`, `/saml/*`, `/register`, `/invite/accept` |
| `/onboarding/api/v1/cloud-accounts` | ❌ MIGRATE | Wrap as `GET /api/v1/views/onboarding/cloud_accounts` |
| `/vulnerability/api/v1/*` | ❌ MIGRATE | API-key auth is a deployment artifact; gateway already supports `Authorization: Bearer` |
| `/sbom/api/v1/*` | ❌ MIGRATE | Same as vulnerability |
| `/api/v1/agents/bootstrap` | ✅ KEEP — public bootstrap | Already in `PUBLIC_PATHS` |
| Stripe webhook | ✅ KEEP — webhook | Verified by `Stripe-Signature` HMAC |

### 3.2 Why this model

**It eliminates the orphaned-row problem in one PR per engine.** Every list row gets PivotLink wrapping; every detail page gets the AssetContextCard slot. No per-engine custom logic.

**It uses what already exists.** AssetContextCard, asset_context.py aggregator, fetchView pattern, ENGINE_URLS map, and the finished Inventory/Threat/CIEM journeys all become reusable primitives. No greenfield architecture.

**It matches the constitution.** No BFF fallbacks (G-fix), no merged data masking gaps, fail-loud for missing engines (existing `available: false` pattern in asset_context).

**It scales linearly.** New engine = new BFF view + register entity type in PivotLink + add Resource Context tab to its detail page. Three lines of work each.

### 3.3 What we explicitly reject

- ❌ **Per-engine bespoke detail pages** — would lock us into 12 different layouts and 12 BFF schemas. Reject in favor of universal `/finding/[engine]/[id]` with a 5-tab template.
- ❌ **Inline expand-row drawers** — 5,000 IAM findings + 5,070 AI findings = unscrollable nested state. Real route + real URL or no detail.
- ❌ **A new graph engine** — Neo4j security graph + asset_context aggregator already cover the cross-engine join. Don't double-build.
- ❌ **Modal-only detail (no URL)** — breaks copy-paste, breaks deep-linking, breaks browser back. URL-first.

---

## 4. Implementation Plan (one sprint, 4 weeks — extended for contract layers)

### 4.1 Sprint phases (must run in this order)

| Phase | Days | Track | Success criterion |
|---|---|---|---|
| **A — Hard blockers** | D1–D3 | DB + BFF | G-1, G-2, G-3, G-32, G-33 fixed; deploys green |
| **B — Universal finding route** | D4–D8 | Frontend + BFF | `/finding/[engine]/[id]` ships with 5-tab template; backed by `GET /api/v1/views/finding/{engine}/{id}` |
| **C — PivotLink rollout** | D6–D12 (parallel with B from D8) | Frontend | 7 engine pages wired; row clicks navigate; middle-click works |
| **D — UI bugs + UX polish** | D10–D14 | Frontend | G-4, G-5, G-7, G-8 fixed; graceful empty states |
| **E — Shared shell** | D12–D17 | Frontend | EngineShell layout, EmptyState component, RefreshBus reduce per-engine boilerplate |
| **F — Risk/Vuln/CWPP detail routes** | D15–D20 | Frontend + BFF | `/risk/scenario/[id]`, vulnerability agents wired |
| **G — Sprint deploy + audit logs** | D18–D21 | Deploy | New images for cspm-frontend, api-gateway, threat (technique table); G-30, G-31 audit logs |
| **H — Contract testing & BFF migration** | D8–D28 (mostly parallel) | Test infra + Bypasses | All 5 contract layers green; 4 direct bypasses migrated; ESLint gate live |

### 4.2 Story map (18 stories)

| Story ID | Title | Lead CSPM agent | Lead BMad | Phase | Est | Blockers |
|---|---|---|---|---|---|---|
| **JNY-01** | Threat DB: `mitre_technique_reference` schema migration | `threat` agent + `cspm-db-engineer` | `bmad-dev` | A | M | none |
| **JNY-02** | BFF fix: `/inventory/asset/{uid}/blast-radius` 500 | `inventory` agent + `cspm-bff-dev` | `bmad-dev` | A | M | none |
| **JNY-03** | Django: grant `ciem:sensitive` to platform_admin role | `cspm-django-engineer` + `cspm-rbac-guardian` | `bmad-security-po` | A | S | none |
| **JNY-04** | Build & push frontend + gateway + technique-table-fix images; rollout | `cspm-deploy` | n/a | A | S | JNY-01..03 |
| **JNY-05** | Universal finding route `/finding/[engine]/[id]` + 5-tab template | `cspm-ui-dev` + `cspm-bff-dev` | `bmad-dev` + `bmad-architect` | B | L | JNY-01 |
| **JNY-06** | Universal BFF: `GET /api/v1/views/finding/{engine}/{id}` | `cspm-bff-dev` + each engine agent (read-only) | `bmad-dev` | B | L | JNY-05 (contract) |
| **JNY-07** | PivotLink primitive component + storybook | `cspm-ui-dev` | `bmad-dev` + `bmad-agent-ux-designer` | B | M | none |
| **JNY-08** | Wire PivotLink in 7 posture engine row tables (IAM, Network, DataSec, Encryption, Container, DB, AI) | `cspm-ui-dev` + each engine agent | `bmad-dev` | C | L | JNY-07 |
| **JNY-09** | Threat UI bug fixes: stopPropagation on technique badge; SLA undefined; deprecated /threat_detail call removed | `cspm-ui-dev` + `threat` agent | `bmad-dev` | D | S | none |
| **JNY-10** | CIEM Stage 2 empty-data root-cause + actor_principal normalization | `ciem` agent | `bmad-dev` | D | M | none |
| **JNY-11** | EngineShell + EmptyState + RefreshBus shared primitives | `cspm-ui-dev` + `cspm-standards-guardian` | `bmad-dev` + `bmad-architect` | E | M | JNY-07 |
| **JNY-12** | `/risk/scenario/[id]` + `/vulnerability/agents/[id]` detail routes | `risk` agent + `vulnerability` agent + `cspm-ui-dev` | `bmad-dev` | F | L | JNY-05 |
| **JNY-13** | BFF Layer 1 (black-box) + Layer 2 (Pydantic models) for all 53 BFF views | `cspm-bff-dev` | `bmad-qa` | H | L | none |
| **JNY-14** | UI ↔ BFF contract diff tool (Layer 3) + CI gate (Layer 4) | `cspm-ui-dev` + `cspm-bff-dev` | `bmad-architect` + `bmad-dev` | H | M | JNY-13 |
| **JNY-15** | Engine Layer 0 + Layer 2 — black-box tests + Pydantic models for ~150 engine endpoints across 22 engines | each engine agent + `cspm-qa-engineer` | `bmad-dev` + `bmad-qa` | H | XL | none (parallel with JNY-13) |
| **JNY-16** | Direct-engine UI bypass contract diff (extend Layer 3 to onboarding, cspm-auth, vulnerability, sbom) | `cspm-ui-dev` + relevant engine agents | `bmad-dev` | H | M | JNY-15 |
| **JNY-17** | Migrate 4 direct-engine bypasses to BFF views (onboarding/cloud_accounts, vulnerability, sbom, +1) | `cspm-ui-dev` + `cspm-bff-dev` + relevant engine agents | `bmad-dev` | H | M | JNY-13 |
| **JNY-18** | Constitution §UI-Backend amendment + ESLint gate enforcing BFF-only frontend rule | `cspm-standards-guardian` | `bmad-architect` | H | S | JNY-17 |

### 4.3 Quality gates per the binding map

For every story:
1. `cspm-code-reviewer` — patterns, standard columns, no-fallback BFF
2. `cspm-security-reviewer` + `bmad-security-reviewer` — OWASP + STRIDE
3. `cspm-qa-engineer` + `bmad-qa` — AC verification
4. `cspm-deploy` — build/push/apply/rollout
5. `cspm-integration-tester` — cross-engine threading

No story merges without all 5.

---

## 4.3 Sprint Team Assignment (RACI)

Per the [AGENT_BINDING.md](./AGENT_BINDING.md) map, every story is assigned to a team — not a single owner. **R**=Responsible · **A**=Accountable · **C**=Consulted · **I**=Informed.

### 4.3.1 Per-story RACI

| Story | Engine agents | UI/BFF/Gateway | Security (design A) | Security (code R) | BMad lead | QA | Standards |
|---|---|---|---|---|---|---|---|
| JNY-01 | `threat`+`cspm-db-engineer` (R) | — | `bmad-security-architect` | `cspm-security-reviewer` | `bmad-dev` | `bmad-qa`+`cspm-qa-engineer` | `cspm-standards-guardian` |
| JNY-02 | `inventory` (C) | `cspm-bff-dev` (R) | — | `cspm-security-reviewer` | `bmad-dev` | `bmad-qa` | — |
| JNY-03 | — | `cspm-django-engineer`+`cspm-rbac-guardian` (R) | `bmad-security-architect` (A) | `bmad-security-reviewer` | `bmad-security-po` | `bmad-qa` | `cspm-rbac-guardian` |
| JNY-04 | — | `cspm-deploy` (R) | — | — | — | `cspm-integration-tester` | — |
| JNY-05 | `inventory`+`threat`+`ciem` (C) | `cspm-ui-dev` (R) | `bmad-security-architect` (A) | `cspm-security-reviewer` | `bmad-architect` (A)+`bmad-dev`+`bmad-agent-ux-designer` | `bmad-qa` | `cspm-standards-guardian` |
| JNY-06 | all 11 engine agents (C) | `cspm-bff-dev` (R) | `bmad-security-architect` (A) | `cspm-security-reviewer` | `bmad-dev` | `bmad-qa` | `cspm-standards-guardian` |
| JNY-07 | — | `cspm-ui-dev` (R) | — | — | `bmad-architect`+`bmad-agent-ux-designer`+`bmad-dev` | `bmad-qa` | — |
| JNY-08 | **7 sub-tasks** (each engine consulted) | `cspm-ui-dev` (R, coordinates) | — | — | `bmad-dev` | `bmad-qa` | `cspm-standards-guardian` |
| JNY-09 | `threat` (C) | `cspm-ui-dev` (R) | — | — | `bmad-dev` | `bmad-qa` | — |
| JNY-10 | `ciem` (R) | — | — | `cspm-security-reviewer` | `bmad-dev` | `bmad-qa` | — |
| JNY-11 | — | `cspm-ui-dev` (R) | — | — | `bmad-architect`+`bmad-dev` | `bmad-qa` | `cspm-standards-guardian` |
| JNY-12 | `risk`+`vulnerability` (R) | `cspm-ui-dev`+`cspm-bff-dev` (R) | — | `cspm-security-reviewer` | `bmad-dev` | `bmad-qa` | — |
| JNY-13 | all 11 engine agents (C) | `cspm-bff-dev` (R) | `bmad-security-architect` (A) | — | `bmad-qa` (A) | `bmad-qa`+`cspm-qa-engineer` | `cspm-standards-guardian` |
| JNY-14 | — | `cspm-ui-dev`+`cspm-bff-dev` (R) | — | — | `bmad-architect` (A)+`bmad-dev` | `bmad-qa` | `cspm-standards-guardian` |
| JNY-15 | **22 sub-tasks** (one per engine, each engine agent R) | — | `bmad-security-architect` (A) | — | `bmad-dev`+`bmad-qa` | `cspm-qa-engineer` (A)+`bmad-qa` | — |
| JNY-16 | `onboarding`+`vulnerability`+`cspm-django-engineer` (C) | `cspm-ui-dev`+`cspm-bff-dev` (R) | — | — | `bmad-dev` | `bmad-qa` | — |
| JNY-17 | **4 sub-tasks** (one per bypass) | `cspm-ui-dev`+`cspm-bff-dev` (R) | `bmad-security-architect` (A) | `cspm-security-reviewer` | `bmad-dev` | `bmad-qa` | `cspm-standards-guardian` |
| JNY-18 | — | `cspm-standards-guardian` (R) | — | — | `bmad-architect` (A) | `bmad-qa` | `cspm-standards-guardian` |

### 4.3.2 Multi-engine sub-task breakdown

**JNY-08 — PivotLink rollout × 7 engine pages:**
| Sub | Engine | Page file | Lead |
|---|---|---|---|
| JNY-08.1 | IAM | `frontend/src/app/iam/page.jsx` | `iam` (C) + `cspm-ui-dev` (R) |
| JNY-08.2 | Network Security | `frontend/src/app/network-security/page.jsx` | `network-security` (C) + `cspm-ui-dev` (R) |
| JNY-08.3 | DataSec | `frontend/src/app/datasec/page.jsx` | `datasec` (C) + `cspm-ui-dev` (R) |
| JNY-08.4 | Encryption | `frontend/src/app/encryption/page.jsx` | `encryption` (C) + `cspm-ui-dev` (R) |
| JNY-08.5 | Container Security | `frontend/src/app/container-security/page.jsx` | `container-security` (C) + `cspm-ui-dev` (R) |
| JNY-08.6 | Database Security | `frontend/src/app/database-security/page.jsx` | `dbsec` (C) + `cspm-ui-dev` (R) |
| JNY-08.7 | AI Security | `frontend/src/app/ai-security/page.jsx` | `ai-security` (C) + `cspm-ui-dev` (R) |

**JNY-15 — Engine Layer 0+2 × 22 engines:**
Each engine agent owns Pydantic models + black-box tests for their own engine. Coordinator: `cspm-qa-engineer`. Pattern review: `bmad-security-architect` (one shared review approves the response-validation pattern, then 22 parallel implementations).

| # | Engine | Owner agent |
|---|---|---|
| JNY-15.1 | discoveries | `discoveries` |
| JNY-15.2 | inventory | `inventory` |
| JNY-15.3 | check | `check` |
| JNY-15.4 | threat | `threat` |
| JNY-15.5 | compliance | `compliance` |
| JNY-15.6 | iam | `iam` |
| JNY-15.7 | datasec | `datasec` |
| JNY-15.8 | encryption | `encryption` |
| JNY-15.9 | secops | `secops` |
| JNY-15.10 | risk | `risk` |
| JNY-15.11 | onboarding | `onboarding` |
| JNY-15.12 | rule | `cspm-rule-catalog-engineer` |
| JNY-15.13 | network-security | `network-security` |
| JNY-15.14 | ciem | `ciem` |
| JNY-15.15 | ai-security | `ai-security` |
| JNY-15.16 | container-security | `container-security` |
| JNY-15.17 | cnapp | `cnapp` |
| JNY-15.18 | cwpp | `cwpp` |
| JNY-15.19 | vulnerability | `vulnerability` |
| JNY-15.20 | dbsec | `dbsec` |
| JNY-15.21 | billing | `billing` |
| JNY-15.22 | platform-admin | `platform-admin` |

**JNY-17 — Bypass migration × 4:**
| Sub | Bypass | Engine agent | UI/BFF lead |
|---|---|---|---|
| JNY-17.1 | `/onboarding/api/v1/cloud-accounts` | `onboarding` (R) | `cspm-bff-dev`+`cspm-ui-dev` (R) |
| JNY-17.2 | `/vulnerability/api/v1/*` | `vulnerability` (R) | `cspm-bff-dev`+`cspm-ui-dev` (R) |
| JNY-17.3 | `/sbom/api/v1/*` | `vulnerability` (R) | `cspm-bff-dev`+`cspm-ui-dev` (R) |
| JNY-17.4 | Lock-down `/cspm/api/auth/*` to whitelist | `cspm-django-engineer` (R) | `cspm-gateway-dev` (R) |

### 4.3.3 Sprint-wide security review checkpoints

| Checkpoint | When | Reviewer | What |
|---|---|---|---|
| **CP-1 Design gate** | End of D2 (after JNY-01/02/03 design) | `bmad-security-architect` + `cspm-security-reviewer` | STRIDE on universal route + tenant scoping + permission grant |
| **CP-2 Schema gate** | End of D7 (JNY-05/06/13/15 schemas drafted) | `bmad-security-architect` + `cspm-rbac-guardian` | Pydantic response shapes — no PII leak, no cross-tenant, output-validation strategy |
| **CP-3 Auth-termination gate** | End of D14 (before JNY-17 starts) | `bmad-security-architect` (A) + `cspm-security-reviewer` | Gateway terminating Bearer/API-key for migrated bypasses; STRIDE replay against new chain |
| **CP-4 Pre-deploy gate** | D27 | `bmad-security-reviewer` + `cspm-security-reviewer` | OWASP + SLSA + CCM final go/no-go |

A failure at any checkpoint blocks all stories in that phase from proceeding to the next quality gate.

---

## 5. Constitution check

- ✅ **No BFF fallbacks** — fail-loud retained; asset_context aggregator already returns `available: false` per engine.
- ✅ **DB-first** — `mitre_technique_reference` becomes a real DB table, not a static map.
- ✅ **UI competitive standards** — every entity navigable, deep-linkable, copyable URL.
- ✅ **BFF vs gateway data split** — universal `/finding/{engine}/{id}` is BFF (read-only aggregation); writes stay on engine endpoints.
- ✅ **Pipeline order untouched** — no DAG changes.
- ✅ **Multi-cloud** — PivotLink takes `provider` param, scopes correctly.
- ✅ **Standard columns** — `finding_id`, `resource_uid`, `tenant_id`, `severity`, `status` are all already present per CSPM_CONSTITUTION §Database. New universal BFF reads only standard columns.

---

## 6. Open questions for review

1. **Story JNY-05 / JNY-06 contract:** does the universal `/finding/{engine}/{id}` route 5-tab template (Overview · Resource Context · Related Findings · Compliance · Remediation) lock us out of engine-specific tabs (e.g. CIEM "Activity Heatmap")? **Recommended answer:** No — engines may register additional tabs via plugin pattern; the 5 are the floor.

2. **Story JNY-08 rollout order:** ship all 7 PivotLink wires in one PR or phase by P1 severity? **Recommended:** one PR per engine to keep blast radius small, batched in a single mega-rollout day at end of phase C.

3. **Story JNY-12 scope:** should `/risk/scenario/[id]` link back to driving threat detections + failing compliance controls (close G-28)? **Recommended:** yes — that's the whole point of canonical detail pages. Add to AC.

---

## 7. Sign-off (per binding map)

| Role | Agent | Sign-off needed |
|---|---|---|
| Architecture | `bmad-architect` | ADR approved |
| Platform | `cspm-platform-context` | Constitution check pass |
| Security | `bmad-security-architect` + `cspm-security-reviewer` | STRIDE pass on universal `/finding/[engine]/[id]` route + auth enforcement |
| Standards | `cspm-standards-guardian` | Standard columns pass |
| Sprint planning | `bmad-sm` + `cspm-orchestrator` | Story dependencies verified |

---

## 8. Cross-references

- Sprint plan: [SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md](../planning/SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md)
- Stories: [.claude/planning/stories/JNY-01_*.md ... JNY-12_*.md](../planning/stories/)
- Constitution: [CSPM_CONSTITUTION.md](./CSPM_CONSTITUTION.md)
- Agent binding: [AGENT_BINDING.md](./AGENT_BINDING.md)
- Validation evidence: this conversation transcript + screenshots saved during the live walk-through.
