# Attack Path UI Redesign — Orchestration Plan

**Sprint:** AP-REDESIGN  
**Status:** planning  
**Date:** 2026-05-17  

---

## Design Decision: Inline Accordion + Investigation Journey

Replace the current two-panel layout (left list + right canvas) with an **inline accordion** pattern:

- Click a path row → expands inline below that row, showing canvas + attack story + node detail
- Click again → collapses back to list
- One row expanded at a time
- Hovering a node/edge → lightweight tooltip
- Clicking a node → AssetDetailMini panel appears below canvas (shared with Inventory)
- Grouping selector (5 options, client-side) replaces fixed "by crown jewel" grouping

### Key UX Principles
1. **Context never lost** — canvas stays visible when node is clicked (node detail appears below it)
2. **Attack story is structured** — step 1, step 2 per hop (from `steps[].traversal_reason` + worst finding)
3. **Choke bar is always visible** — top-5 as sticky chips, not buried in a collapsible section
4. **AssetDetailMini is shared** — same component in attack-paths (node click) and inventory (row click)
5. **No mock data** — 503 error state shown, never fallback data (CSPM Constitution)

---

## Data Source Mapping — Every UI Element

### KPI Bar
| Element | Field | Source |
|---------|-------|--------|
| Total Paths | `total` | BFF `attack-paths` list |
| Critical | `kpis.critical` | BFF |
| High | `kpis.high` | BFF |
| Confirmed | `kpis.confirmed_paths` | BFF |
| Likely *(new)* | `kpis.likely_paths` | AP-REDESIGN-01 (engine KPI gap) |
| Choke Points | `kpis.choke_points` | BFF |
| CDR Live | `kpis.paths_with_active_cdr` | BFF |

### Choke Bar (sticky top strip)
| Element | Field | Source |
|---------|-------|--------|
| Chip: node name | `choke_points_preview[].node_uid` (trimmed) | BFF (top-3 in list response) |
| Chip: breaks N | `choke_points_preview[].paths_blocked_if_fixed` | BFF |
| Full list on expand | `choke_points[]` | `GET /gateway/api/v1/choke-points?limit=5` |
| Click chip → filter | filter `paths[]` where `choke_node_uid === chip.node_uid` | client-side |

### Path List Row
| Element | Field | Source |
|---------|-------|--------|
| Severity badge | `severity` | BFF paths[] |
| Path score | `path_score` | BFF paths[] |
| Chain type | `chain_type` | BFF paths[] |
| Hops | `depth` | BFF paths[] |
| Open days | `open_days` | BFF paths[] (computed) |
| CDR LIVE badge | `has_active_cdr_actor` | BFF paths[] |
| Confidence badge | `confidence_level` | BFF paths[] |
| Group size | `group_size` | BFF paths[] |
| Entry type | `entry_point_type` | BFF paths[] (for grouping) |
| MITRE technique | `attack_technique_chain[0]` | BFF paths[] (for grouping) |

### Grouping Options (all client-side, no new BFF endpoint)
| Group By | Field Used | Values |
|----------|-----------|--------|
| Severity (default) | `severity` | critical / high / medium / low |
| Crown Jewel | `crown_jewel_uid` + `crown_jewel_type` | grouped by target asset |
| Entry Point | `entry_point_type` | internet / vpn / onprem / peer_account |
| Attack Technique | `attack_technique_chain[0]` | first MITRE technique ID |
| CDR Status | `has_active_cdr_actor` | Live / Dormant |

### Filter Pills
| Filter | Field | BFF Param |
|--------|-------|-----------|
| Severity tabs | `severity` | `severity=critical\|high\|medium\|low` |
| Confidence | `confidence_level` | `confidence_level=confirmed\|likely\|speculative` ← AP-REDESIGN-01 |
| Entry type | `entry_point_type` | `entry_point_type=internet\|...` |
| Search box | `attack_name` / `crown_jewel_uid` | `search=...` ← AP-REDESIGN-02 |

### Expanded Inline Row
| Element | Field | Source |
|---------|-------|--------|
| Canvas nodes | `steps[].node_uid/name/type/cdr_actor_active/misconfigs/cves` | detail endpoint `fetchView('attack-paths/{path_id}')` |
| Canvas edges | `steps[].edge_to_next/edge_category/traversal_reason` | detail endpoint |
| Node hover tooltip | `node_type`, `node_uid`, `misconfigs[0]`, `cves[0]` | from steps[] (already in memory after expand) |
| Edge hover tooltip | `edge_to_next`, `traversal_reason`, `sg_rule`, `policy_statement` | from steps[] |
| Attack story step N | `steps[i].hop_index`, `node_name`, `node_type`, `traversal_reason` | from steps[] |
| Story: worst finding | worst of `steps[i].misconfigs[0]` or `steps[i].cves[0]` by severity | client-side sort |
| Story: CDR badge | `steps[i].cdr_actor_active` | from steps[] |
| Story: edge label | `steps[i].edge_to_next` | from steps[] |

### Node Detail (AssetDetailMini — below canvas on node click)
| Tab | Fields | BFF Endpoint |
|-----|--------|-------------|
| Misconfigs | severity, title, rule_id, status | `fetchView('inventory/asset/{uid}/findings')` filtered `source_engine=check` |
| CVEs | rule_id (CVE ID), epss_score, cvss_score, in_kev, severity | same endpoint, `finding_type=cve` |
| CDR | mitre_technique_id, mitre_tactic, title, severity | same endpoint, `source_engine=cdr` |
| Posture | is_internet_exposed, is_in_private_subnet, is_encrypted_at_rest, is_on_attack_path, is_choke_point | `fetchView('inventory/asset/{uid}/posture')` |
| "View Full Asset" | — | link to `/inventory/{encoded_uid}` |

---

## Gap Analysis — What Needs to Be Built

### Engine Gaps (minor — AP-REDESIGN-01, AP-REDESIGN-02)
| Gap | Fix | Story |
|-----|-----|-------|
| `confidence_level` filter param missing from engine + BFF | Add WHERE clause to engine query; forward in BFF | AP-REDESIGN-01 |
| `likely_paths` + `speculative_paths` KPIs not computed | Add CASE WHEN counts to engine KPI query | AP-REDESIGN-01 |
| `search` param missing | Add ILIKE filter on `attack_name`, `crown_jewel_uid` | AP-REDESIGN-02 |

### BFF Gaps (AP-REDESIGN-01, AP-REDESIGN-02)
| Gap | Fix | Story |
|-----|-----|-------|
| `confidence_level` not forwarded from BFF to engine | Add param forwarding in `attack_paths.py` | AP-REDESIGN-01 |
| `search` not forwarded | Add param forwarding | AP-REDESIGN-02 |

### Frontend New Components (AP-REDESIGN-03, AP-REDESIGN-04, AP-REDESIGN-05)
| Component | File | Story |
|-----------|------|-------|
| `ChokeBar.jsx` | `frontend/src/app/threats/attack-paths/ChokeBar.jsx` | AP-REDESIGN-03 |
| `AttackPathRow.jsx` | `frontend/src/app/threats/attack-paths/AttackPathRow.jsx` | AP-REDESIGN-03 |
| `AttackPathExpanded.jsx` | `frontend/src/app/threats/attack-paths/AttackPathExpanded.jsx` | AP-REDESIGN-03 |
| `AttackStory.jsx` | `frontend/src/app/threats/attack-paths/AttackStory.jsx` | AP-REDESIGN-03 |
| `GroupBySelector.jsx` | `frontend/src/app/threats/attack-paths/GroupBySelector.jsx` | AP-REDESIGN-03 |
| `AssetDetailMini.jsx` | `frontend/src/components/shared/AssetDetailMini.jsx` | AP-REDESIGN-04 |
| `page.jsx` (attack-paths) | refactor existing | AP-REDESIGN-03 |
| `page.jsx` (inventory) | add inline expand | AP-REDESIGN-05 |

### Frontend Components Kept As-Is
| Component | Notes |
|-----------|-------|
| `NodeBox.jsx` | Add edge hover only; existing node hover tooltip stays |
| `EdgeArrow.jsx` | Add `onHover` prop to show edge tooltip |
| `PathDetailPanel.jsx` | Kept; accessible via "View Full Details" button in expanded row |
| `attack-paths.module.css` | Extend with new class names |

---

## Story Files

| ID | Title | Type | Depends On | Points |
|----|-------|------|-----------|--------|
| AP-REDESIGN-01 | Engine + BFF: confidence filter + KPIs | engine+BFF | none | 3 |
| AP-REDESIGN-02 | Engine + BFF: search param | engine+BFF | AP-REDESIGN-01 (same PR) | 2 |
| AP-REDESIGN-03 | Frontend: inline accordion attack paths page | UI | AP-REDESIGN-04 | 8 |
| AP-REDESIGN-04 | Frontend: AssetDetailMini shared component | UI | none | 5 |
| AP-REDESIGN-05 | Frontend: inventory inline expand | UI | AP-REDESIGN-04 | 3 |

**Total: 21 story points**

---

## Build Sequence (Local-First — Test Before Every Push)

```
Step 1 — Engine + BFF changes (AP-REDESIGN-01 + AP-REDESIGN-02)
  a. Edit engine routes.py + bff/attack_paths.py
  b. LOCAL TEST: npm run dev + port-forward engine-attack-path
     - Verify confidence_level filter returns correct subset
     - Verify search=<known attack_name> returns match
     - Verify KPIs include likely_paths + speculative_paths
  c. On local test pass → docker build → push → kubectl apply → post-deploy smoke
  d. Image: engine-attack-path:v-redesign-bff1 + api-gateway:v-redesign-bff1

Step 2 — AssetDetailMini component (AP-REDESIGN-04) — parallel with Step 1
  a. Create frontend/src/components/shared/AssetDetailMini.jsx
  b. LOCAL TEST: mount component in a test page with a real resource_uid
     - Verify all 4 tabs load data from real BFF
     - Verify viewer role: CDR tab hidden, EPSS = "—"
     - Verify "View Full Asset" links correctly
  c. On local test pass → commit (no deploy needed — it's a new component, not yet used in a live page)

Step 3 — Attack Paths Page Redesign (AP-REDESIGN-03) — depends on Step 2
  a. Refactor page.jsx + create ChokeBar, AttackPathRow, AttackPathExpanded, AttackStory, GroupBySelector
  b. LOCAL TEST golden path:
     - Load /threats/attack-paths → KPI bar + ChokeBar visible
     - Click choke chip → amber highlight + list filter active
     - Change GroupBy → groups re-render correctly
     - Type in search → debounced BFF call returns matching paths
     - Click path row → expands inline with canvas + attack story
     - Hover node → NodeTooltip appears
     - Click node → AssetDetailMini mounts with prefetched data
     - Click Misconfigs tab → findings render
     - Click CVEs tab → EPSS score colored correctly
     - Hover edge → EdgeTooltip with traversal_reason
     - Click "View Full Details" → PathDetailPanel opens
     - Click same row → collapses
     - Test with viewer role → no expand, restriction banner shown
  c. On local test pass → docker build frontend → push → kubectl apply

Step 4 — Inventory Inline Expand (AP-REDESIGN-05) — depends on Step 2
  a. Modify inventory/page.jsx row click handler
  b. LOCAL TEST:
     - Click inventory row → AssetDetailMini opens below (no navigation)
     - Switch tabs → correct data per tab
     - "View Full Details" → navigates to /inventory/[assetId]
     - Click same row → collapses
     - Filters + pagination still work
  c. On local test pass → docker build frontend → push → kubectl apply
```

### Image Bumps Required
| Step | Engine Image | Gateway Image | Frontend Image |
|------|-------------|--------------|----------------|
| 1 | `engine-attack-path:v-redesign-bff1` | `api-gateway:v-redesign-bff1` | — |
| 2 | — | — | commit only (not deployed standalone) |
| 3 | — | — | `cspm-frontend:v-redesign-ap1` |
| 4 | — | — | `cspm-frontend:v-redesign-inv1` |

---

## RBAC Matrix (all roles × all new endpoints)

| Role | Attack paths list | Attack paths detail | Asset findings | Asset posture |
|------|------------------|--------------------|--------------------|--------------|
| platform_admin | full | full | full | full |
| org_admin | full | full | full | full |
| tenant_admin | full | full | full | full |
| analyst | full | full | epss=null, CDR detail=null | full |
| viewer | KPI + choke bar only (no paths[]) | 403 | epss=null, detail=null | full |

---

## Security Gates Required

- `bmad-security-reviewer` — on PR-1 (engine endpoint changes)
- `bmad-security-reviewer` — on PR-3 (frontend: no credential_ref or policy_statement rendered raw)
- Constitution checks:
  - No mock data in BFF ✓ (all errors → 503)
  - `policy_statement` collapsed by default in attack story ✓
  - `credential_ref` never rendered ✓
  - Viewer role: KPI + choke bar only, no paths[] ✓
