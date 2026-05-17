# Story AP-P4-03: Path Detail Side Panel

## Status: ready

## Metadata
- **Phase**: P4 — UI
- **Epic**: Attack Path Engine
- **Points**: 5
- **Priority**: P1
- **Depends on**: AP-P4-01 (Attack Paths page triggers panel open), AP-P3-01 (BFF detail endpoint returns steps[])
- **Blocks**: nothing (terminal Phase 4 story)
- **RACI**: R=FE-DEV A=DL C=UX,SA I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — panel renders policy_statement and sg_rule JSONB which contains sensitive IAM/network detail; must enforce role-based field suppression.

## User Story

As a security analyst, I want a path detail side panel that opens when I click a path row, showing the per-hop story (traversal reason, misconfigs, CVEs, CDR actor badge per hop), a score trends chart showing how this path's risk has changed over time, and group membership info, so that I can build a complete remediation ticket without switching pages.

## Context

The PathDetailPanel is the deepest drill-down in the Attack Paths page. It calls `fetchView("attack-paths/{path_id}")` which returns the full `steps[]` array from `attack_path_nodes` with all per-hop evidence.

The panel opens as a slide-over (right-side drawer) without a full page navigation. It has two tabs: "Story" (per-hop narrative) and "Trends" (score history chart).

The traversal_reason text, misconfigs list, CVEs list, and policy_statement are the primary evidence for writing a remediation ticket. They must be clearly readable — not collapsed by default.

CDR active badge per hop is a red indicator because it means a real threat actor was observed at that node.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [x] RS  [ ] RC
ID.RA-5, DE.AE-2 (evidence for incident investigation), RS.AN-3 (forensic detail in per-hop story)

**CSA CCM v4 Domain(s)**
- SEF-01, GRC-05, IAM-09 (policy_statement rendered for IAM edges)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | policy_statement rendering | viewer role sees IAM policy actions and resource ARNs | policy_statement rendered only in PathDetailPanel; viewer receives 403 on detail endpoint (enforced in BFF); component checks role before rendering |
| Info Disclosure | sg_rule rendering | Analyst shares screen showing SG rule with source 0.0.0.0/0 | Intended — this is evidence the analyst needs; not a risk from platform perspective |
| Info Disclosure | cdr_actor_uid | Actor UID reveals internal resource naming | Rendered as-is — analyst needs this for investigation; no masking |

## MITRE ATT&CK Techniques Addressed
N/A — UI rendering; no finding logic.

## Acceptance Criteria

### Functional — Panel Layout
- [ ] AC-1: Component `frontend/src/app/threats/attack-paths/PathDetailPanel.jsx` created
- [ ] AC-2: Panel opens as a slide-over (right-side drawer, Tailwind `fixed inset-y-0 right-0`) when path row clicked in AP-P4-01
- [ ] AC-3: Panel header: path severity badge, path_score, chain_type, depth, "open for N days"
- [ ] AC-4: Two tabs: "Story" (default) and "Trends"
- [ ] AC-5: Close button (×) dismisses panel; pressing Escape also closes it

### Functional — Story Tab
- [ ] AC-6: Per-hop list rendered in order (hop_index 0 = entry point at top, last hop = crown jewel at bottom)
- [ ] AC-7: Each hop row shows: hop number, node_name, node_type badge, edge_to_next label, edge_category
- [ ] AC-8: `traversal_reason` text displayed prominently below node name — not collapsed
- [ ] AC-9: Misconfigs list per hop: each item shows rule_id, severity badge, title, remediation text
- [ ] AC-10: CVEs list per hop: each item shows cve_id, EPSS score, CVSS, "In KEV" badge if in_kev=true
- [ ] AC-11: CDR actor badge per hop: red "ACTIVE THREAT ACTOR" banner if cdr_actor_active=true, with cdr_actor_uid below
- [ ] AC-12: For IAM-edge hops: `policy_statement` rendered as a collapsible JSON code block (actions, resource, effect) — collapsed by default, "Show policy" expands
- [ ] AC-13: For network-edge hops: `sg_rule` rendered as a table (port, protocol, cidr) if sg_rule is present
- [ ] AC-14: Crown jewel hop (last): `data_classification` badge, `encryption_gap` text if present, `is_crown_jewel` crown icon
- [ ] AC-15: "This path absorbs N shorter routes" message if absorbed_count > 0

### Functional — Trends Tab
- [ ] AC-16: Line chart (recharts) showing `score` over time from `attack_path_history` — x-axis = recorded_at, y-axis = score (0–100)
- [ ] AC-17: Chart data fetched from engine `GET /api/v1/attack-paths/trends?path_id={path_id}`
- [ ] AC-18: Below chart: `first_seen_at` date ("Path discovered: April 28, 2026"), open duration ("Open for 17 days")
- [ ] AC-19: If score is trending up (latest > earliest): "Risk increasing" warning badge
- [ ] AC-20: Group info: "Part of group with N similar paths" — "Expand group" link opens path list filtered by group_id

### Security (must pass bmad-security-reviewer)
- [ ] AC-21: Component checks AuthContext role before rendering — if viewer, show "Access restricted" message (viewer can't reach this panel because fetchView detail returns 403, but add defensive check)
- [ ] AC-22: policy_statement code block is read-only display — no copy-to-clipboard of raw JSON that could be pasted into IAM (user education concern, not a hard AC)
- [ ] AC-23: No credential_ref rendered anywhere in the panel
- [ ] AC-24: trend chart data loaded lazily (only when Trends tab is clicked) — not loaded on panel open to avoid unnecessary API calls

## Technical Notes

**Component**: `frontend/src/app/threats/attack-paths/PathDetailPanel.jsx`

**Data fetch for Story tab**: `fetchView("attack-paths/${path_id}")` — returns `steps[]` from BFF.

**Data fetch for Trends tab**: Lazy — only when Trends tab clicked. Call `getFromEngine("/api/v1/attack-paths/trends?path_id=${path_id}")` or equivalent.

**recharts pattern** (already used in other pages):
```jsx
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
```

**Panel width**: `w-[640px]` (wider than standard NodeInvestigationPanel to accommodate per-hop evidence list).

**Keyboard accessibility**: Escape key listener via `useEffect`. Focus trap inside panel while open.

**Collapsed policy_statement**: Use `<details><summary>Show policy</summary><pre>{JSON.stringify(step.policy_statement, null, 2)}</pre></details>` — native HTML, no component needed.

## Key Files
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/PathDetailPanel.jsx` (create new)
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/page.jsx` (modify — wire `setSelectedPathId` to trigger PathDetailPanel)

## Definition of Done
- [ ] PathDetailPanel.jsx committed
- [ ] Story tab renders per-hop evidence (traversal_reason, misconfigs, CVEs, CDR badge, policy_statement collapsed)
- [ ] Trends tab renders recharts line chart with score history
- [ ] Escape key and close button dismiss panel
- [ ] CDR active hop shows red "ACTIVE THREAT ACTOR" banner
- [ ] Crown jewel hop shows data_classification badge and encryption gap if present
- [ ] absorbed_count > 0 shows "absorbs N shorter routes" message
- [ ] Group info renders with group_size
- [ ] Trends data fetched lazily on tab click
- [ ] viewer role: "Access restricted" shown (defensive check)
- [ ] No credential_ref rendered
- [ ] Frontend image built with new tag, pushed, manifest updated (if separate from AP-P4-01/P4-02)
- [ ] bmad-security-reviewer: no BLOCKERS