# Story AP-REDESIGN-03: Frontend — Inline Accordion Attack Paths Page

**Epic:** Attack Path UI Redesign  
**Phase:** REDESIGN  
**Priority:** P0  
**Story Points:** 8  
**Status:** ready  
**Depends on:** AP-REDESIGN-04 (AssetDetailMini must exist)  
**Blocked by:** AP-REDESIGN-04 not merged  

---

## Context

Replace the current two-panel layout (left list + right canvas) with an inline accordion pattern:
- Path rows are flat, grouped by a user-selected dimension (default: severity)
- Clicking a row expands an inline section below that row showing: canvas + attack story + node detail
- Canvas nodes: hover → tooltip, click → AssetDetailMini below canvas
- Canvas edges: hover → tooltip with why-this-hop details
- Choke points move from collapsible section to sticky top bar (always visible)
- PathDetailPanel kept but only accessible via "View Full Details" button inside expanded row

**Route:** `/threats/attack-paths` — replace in-place, no v2 route.

---

## New Files

| File | Purpose |
|------|---------|
| `frontend/src/app/threats/attack-paths/ChokeBar.jsx` | Sticky top strip with top-5 choke point chips |
| `frontend/src/app/threats/attack-paths/AttackPathRow.jsx` | Clickable row — expand/collapse toggle |
| `frontend/src/app/threats/attack-paths/AttackPathExpanded.jsx` | Inline expansion: canvas + story + node detail |
| `frontend/src/app/threats/attack-paths/AttackStory.jsx` | Step-by-step attack narrative from steps[] |
| `frontend/src/app/threats/attack-paths/GroupBySelector.jsx` | Dropdown: 5 grouping dimensions |

## Modified Files

| File | Change |
|------|--------|
| `frontend/src/app/threats/attack-paths/page.jsx` | Rewrite layout: KPI bar + ChokeBar + filters + group headers + AttackPathRow list |
| `frontend/src/app/threats/attack-paths/NodeBox.jsx` | Add `onEdgeHover` passthrough for edge tooltip |
| `frontend/src/app/threats/attack-paths/EdgeArrow.jsx` | Add hover tooltip showing edge_to_next + traversal_reason snippet |
| `frontend/src/app/threats/attack-paths/attack-paths.module.css` | Add classes for accordion, story steps, choke bar |

## Kept Unchanged

| File | Notes |
|------|-------|
| `PathDetailPanel.jsx` | Kept; accessed via "View Full Details" button only |
| `ChokePointSection.jsx` | Remove from page — replaced by ChokeBar |

---

## Layout Spec

```
page.jsx
├── KPI Bar (6 cells, unchanged)
├── ChokeBar (sticky, always visible)
│    └── Top-5 choke chips [node_name → breaks N paths]
├── Filter + GroupBy Row
│    ├── Search box (attack_name / crown_jewel)
│    ├── Severity tabs (All / Critical / High / Medium / Low)
│    ├── Confidence pills (All / Confirmed / Likely / Speculative)
│    ├── Entry type pills (All / Internet / VPN / OnPrem / Peer)
│    └── GroupBy selector (Severity / Crown Jewel / Entry Point / Technique / CDR Status)
├── Group Section (per active group dimension)
│    ├── Group header: label + count badge (collapsible)
│    └── AttackPathRow (repeated)
│         ├── Row: sev badge | score | chain_type | hops | open_days | CDR badge | conf badge | group_size
│         └── AttackPathExpanded (when row is open)
│              ├── Canvas strip: NodeBox chain + EdgeArrow (compact, horizontal, scrollable)
│              │    ├── Node hover → NodeTooltip (type, uid, worst finding)
│              │    ├── Node click → sets selectedNodeStep → AssetDetailMini appears below
│              │    └── Edge hover → EdgeTooltip (edge_to_next, traversal_reason, sg_rule snippet)
│              ├── AttackStory
│              │    └── For each step: hop index circle → node name/type → traversal_reason (1 line) → worst finding badge → CDR badge
│              └── AssetDetailMini (when selectedNodeStep set)
│                   └── Tabs: Misconfigs | CVEs | CDR | Posture + [View Full Asset →]
└── Pagination (20 per page)
```

---

## Acceptance Criteria

### ChokeBar (AC-1 to AC-6)
- AC-1: Renders as a sticky bar below the KPI bar, always visible while scrolling path list
- AC-2: Shows top-5 choke points from `choke_points_preview[]` (from main fetchView response)
- AC-3: Each chip renders: node_uid (last 20 chars), "breaks N paths" (`paths_blocked_if_fixed`)
- AC-4: Clicking a chip filters the path list to rows where `choke_node_uid === chip.node_uid` AND highlights those rows with an amber left border
- AC-5: "Clear choke filter" × button resets to full list
- AC-6: "View all →" link fetches `/gateway/api/v1/choke-points?limit=10` and shows full list in a small overlay

### Filter & GroupBy Row (AC-7 to AC-14)
- AC-7: Search box debounced 400ms; triggers `fetchView('attack-paths', { search })` on change
- AC-8: Severity tabs filter client-side if paths already loaded; re-fetches with `severity` param if page resets
- AC-9: Confidence pills send `confidence_level` param to BFF (AP-REDESIGN-01 required)
- AC-10: GroupBy selector has 5 options: Severity (default) | Crown Jewel | Entry Point | Technique | CDR Status
- AC-11: Grouping is client-side — no new BFF endpoint. Groups derived from `paths[]` fields:
  - Severity → by `severity` field
  - Crown Jewel → by `crown_jewel_uid` + show `crown_jewel_type` + `data_classification`
  - Entry Point → by `entry_point_type`
  - Technique → by `attack_technique_chain[0]` (first MITRE technique ID)
  - CDR Status → by `has_active_cdr_actor`: "CDR Live" vs "Dormant"
- AC-12: Each group section has a collapsible header showing group label + count badge
- AC-13: All groups collapsed by default; clicking header expands
- AC-14: Active filter count badge shown on filter row ("3 filters active")

### AttackPathRow (AC-15 to AC-20)
- AC-15: Renders: severity badge | path_score | chain_type | depth (N hops) | open_days | CDR LIVE badge (if has_active_cdr_actor) | confidence badge | group_size ("N similar") 
- AC-16: Click anywhere on row → toggles expand/collapse of AttackPathExpanded below
- AC-17: Only ONE row can be expanded at a time — clicking a new row collapses the previous
- AC-18: Expanded row has a subtle left border accent matching severity color
- AC-19: "N similar" chip on row → clicking expands a mini list of group members (fetch with `group_id=X&representative_only=false`)
- AC-20: Row keyboard accessible (Enter/Space to expand, Escape to collapse)

### AttackPathExpanded (AC-21 to AC-32)
- AC-21: On row expand, fetches `fetchView('attack-paths/{path_id}')` to get `steps[]` (lazy — only on expand)
- AC-22: Shows loading skeleton (3 node boxes animated) while fetching steps[]
- AC-23: Canvas strip renders `steps[]` as horizontal chain: NodeBox per step + EdgeArrow between steps
- AC-24: Canvas strip is horizontally scrollable if path depth > 5 nodes
- AC-25: Node hover (NodeTooltip): node_type, short node_uid, worst misconfig or CVE title
- AC-26: Edge hover (EdgeTooltip): edge_to_next (capitalized), traversal_reason (first 80 chars), sg_rule.port+protocol if present
- AC-27: Node click → sets `selectedNodeStep`; `AssetDetailMini` mounts below canvas with `prefetchedMisconfigs`, `prefetchedCves`, `prefetchedThreats` from that step
- AC-28: Clicking same node again → deselects (AssetDetailMini unmounts)
- AC-29: "View Full Details →" button at bottom right → opens `PathDetailPanel` (existing component, unchanged)
- AC-30: Viewer role: canvas renders but no AssetDetailMini (node click is a no-op); "View Full Details" button absent (PathDetailPanel returns 403)
- AC-31: `policy_statement` is NOT rendered in canvas or story — only accessible in PathDetailPanel
- AC-32: `credential_ref` never rendered anywhere in this component tree

### AttackStory (AC-33 to AC-38)
- AC-33: Renders below canvas strip, above AssetDetailMini
- AC-34: For each `steps[i]`:
  - Hop circle: index number (1-based), colored by node's worst severity
  - Node name (truncated 30 chars) + node_type badge
  - Traversal reason: first 100 chars of `traversal_reason`, italic gray
  - Worst finding badge: if `cves` non-empty → show highest EPSS CVE ID + EPSS%; else show worst misconfig severity badge + title
  - CDR badge: if `cdr_actor_active` → red animated "CDR ACTIVE" badge
  - Edge label: `edge_to_next` in small caps between hops
- AC-35: Steps rendered vertically (not horizontally) — one step per row
- AC-36: Long paths (>6 hops) collapse middle steps with "… N more hops" expander
- AC-37: Empty `traversal_reason` → show edge type label instead ("Accesses via ASSUMES")
- AC-38: `policy_statement` content is NOT shown in story — show only the edge type label

### Viewer Role (AC-39 to AC-41)
- AC-39: Viewer sees KPI bar + ChokeBar only on initial load
- AC-40: Viewer sees path list rows (severity, score, chain_type) but no expand on click
- AC-41: Viewer sees restriction banner: "Contact your admin for investigation access"

### Performance (AC-42 to AC-44)
- AC-42: Main page load calls `fetchView('attack-paths')` once — no additional calls until row expanded
- AC-43: Detail fetch (`fetchView('attack-paths/{path_id}')`) is cached client-side in a `Map` keyed by path_id — re-opening same row doesn't re-fetch
- AC-44: AssetDetailMini Posture tab is lazy-fetched only on tab click (not on node click)

---

## Technical Notes

**GroupBy client-side implementation:**
```javascript
function groupPaths(paths, groupBy) {
  return paths.reduce((acc, path) => {
    let key;
    switch (groupBy) {
      case 'severity': key = path.severity; break;
      case 'crown_jewel': key = path.crown_jewel_uid; break;
      case 'entry_point': key = path.entry_point_type; break;
      case 'technique': key = path.attack_technique_chain?.[0] ?? 'unknown'; break;
      case 'cdr_status': key = path.has_active_cdr_actor ? 'CDR Live' : 'Dormant'; break;
    }
    if (!acc[key]) acc[key] = [];
    acc[key].push(path);
    return acc;
  }, {});
}
```

**Detail fetch cache:**
```javascript
const detailCache = useRef(new Map());
async function expandRow(path_id) {
  if (!detailCache.current.has(path_id)) {
    const detail = await fetchView(`attack-paths/${path_id}`);
    detailCache.current.set(path_id, detail);
  }
  setExpandedPathId(path_id);
  setExpandedDetail(detailCache.current.get(path_id));
}
```

**EdgeTooltip trigger:**
```jsx
<EdgeArrow
  edge={step}
  onHoverStart={(e) => setEdgeTooltip({ x: e.clientX, y: e.clientY, step })}
  onHoverEnd={() => setEdgeTooltip(null)}
/>
```

---

## Definition of Done
- [ ] ChokeBar always visible, top-5 chips, click → amber highlight + list filter
- [ ] GroupBy selector: 5 options, client-side grouping, group headers collapsible
- [ ] Search box: debounced, hits BFF with `search` param
- [ ] Confidence pills: hit BFF with `confidence_level` param
- [ ] AttackPathRow: click toggles expand, one row open at a time
- [ ] AttackPathExpanded: lazy fetches steps[], canvas renders nodes + edges
- [ ] Node hover: NodeTooltip with type + uid + worst finding
- [ ] Edge hover: EdgeTooltip with edge type + traversal_reason + sg_rule
- [ ] Node click: AssetDetailMini mounts below canvas with prefetched data
- [ ] AttackStory: per-hop step rows with traversal reason + worst finding + CDR badge
- [ ] PathDetailPanel accessible via "View Full Details" button only
- [ ] Viewer role: no expand, restriction banner
- [ ] Detail fetch cached in useRef Map (no re-fetch on same path)
- [ ] `policy_statement` and `credential_ref` never rendered in this component tree
- [ ] Local dev server test: full golden path (expand row → hover node → click node → see misconfigs → click edge → see reason)
- [ ] All 5 roles tested locally against real BFF
- [ ] No console errors or React key warnings
- [ ] `bmad-security-reviewer` gate: verify no credential leakage, no policy_statement in DOM
