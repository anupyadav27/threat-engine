# Story AP-P4-01: Attack Paths Page

## Status: ready

## Metadata
- **Phase**: P4 — UI
- **Epic**: Attack Path Engine
- **Points**: 8
- **Priority**: P1
- **Depends on**: AP-P3-01 (BFF fetchView("attack-paths") returns correct shape)
- **Blocks**: AP-P4-02 (choke point section is part of this page), AP-P4-03 (path detail panel opens from this page)
- **RACI**: R=FE-DEV A=DL C=UX,SA I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (new page with data from security engine — RBAC rendering, no sensitive field exposure in UI).

## User Story

As a security analyst, I want an Attack Paths page at `/threats/attack-paths` that shows a left panel with the full path list grouped by crown jewel, and a right panel canvas showing the selected path's hop chain, so that I can triage the most dangerous exposures at a glance and drill into any path for per-hop detail without leaving the page.

## Context

This page is the primary UI surface for the Attack Path Engine. It competes with Wiz Security Graph and Orca attack path analysis. The existing file at `frontend/src/app/threats/attack-paths/page.jsx` is a stub — this story replaces it with a fully functional page.

Design principles (per CSPM Constitution — UI competes with Wiz/Orca):
- Skeleton screens while data loads (no empty white box)
- Severity colors consistent: critical=red, high=orange, medium=yellow, low=gray
- CDR active shown in red badge ("LIVE THREAT")
- Risk score/severity prominent in left panel row
- Side-panel drilldown to existing NodeInvestigationPanel on node click

Data source: `fetchView("attack-paths")` — BFF call only. No direct engine API calls from this component.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
ID.RA-5 (risk visible to operators), DE.AE-2 (events analyzed via attack path context)

**CSA CCM v4 Domain(s)**
- SEF-01 (Security Event Analysis), IVS-01, DSP-07

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | path list rendering | UI renders raw policy_statement JSONB (IAM policy) in path list | Path list shows only summary fields; policy_statement rendered only in PathDetailPanel (AP-P4-03) |
| Info Disclosure | viewer in UI | viewer role sees paths[] in client-side state even though API returns summary-only | Component checks role from auth context; if viewer, renders only KPI bar — no path list |

## MITRE ATT&CK Techniques Addressed
N/A — UI rendering; no finding logic.

## Acceptance Criteria

### Functional — Page Layout
- [ ] AC-1: File `frontend/src/app/threats/attack-paths/page.jsx` replaced (existing stub removed)
- [ ] AC-2: Page has top KPI bar with 5 metrics: total paths, critical count, choke points count, longest open path (days), paths with active CDR actor
- [ ] AC-3: Left panel: path list rows. Each row shows: severity badge, path_score, chain_type label ("Internet → Data"), depth, open_days, CDR active indicator (red "LIVE" badge if has_active_cdr_actor)
- [ ] AC-4: Left panel: paths grouped by crown_jewel_uid — group header shows crown jewel name, type badge (data/secrets/identity/infra/ai/code), and count of paths to that crown jewel
- [ ] AC-5: Right panel: path canvas — sequence of node boxes connected by edge arrows with edge type labels (ASSUMES, CAN_ACCESS, CONNECTED_TO, EXPOSES)
- [ ] AC-6: Each node box in canvas shows: resource name, resource type icon, misconfig count badge, CVE count badge, CDR active badge (red if cdr_actor_active)
- [ ] AC-7: Filter bar above left panel: severity filter (All/Critical/High/Medium/Low), entry point type filter (All/Internet/VPN/OnPrem/Peer)
- [ ] AC-8: Clicking a node box in the canvas opens the existing `NodeInvestigationPanel` (slide-over) with the node's resource_uid — reuses the component from inventory investigation journey

### Functional — Data
- [ ] AC-9: Page calls `fetchView("attack-paths")` for list data — no direct engine API calls
- [ ] AC-10: `representative_only=true` query param sent by default — shows only representative paths with "N similar" badge on collapsed groups
- [ ] AC-11: "N similar paths" badge on a grouped row expands to show all group members (calls `fetchView("attack-paths")` with group_id filter)
- [ ] AC-12: Skeleton screen displayed while initial fetch is in progress (not a blank page)
- [ ] AC-13: Empty state shown if no paths exist: "No attack paths found for this tenant. Run a full pipeline scan to discover paths." — no mock data

### Functional — Viewer Role
- [ ] AC-14: viewer role sees KPI bar only (from `{ total, kpis }` response) — path list not rendered
- [ ] AC-15: viewer role sees message below KPI bar: "Contact your admin for full path details"

### Security (must pass bmad-security-reviewer)
- [ ] AC-16: No policy_statement JSONB or sg_rule JSONB rendered on this page (only in PathDetailPanel — AP-P4-03)
- [ ] AC-17: No credential_ref fields rendered anywhere on this page
- [ ] AC-18: path_id used as React key (not array index) — prevents stale rendering
- [ ] AC-19: AuthContext role checked before rendering path list — not based on API response shape alone

### Image Tag (mandatory)
- [ ] AC-20: Frontend image rebuilt and pushed with new tag (no `latest`) after this page ships
- [ ] AC-21: K8s manifest updated with new frontend image tag

### Health Check (mandatory)
- [ ] AC-22: `/threats/attack-paths` page loads without console errors
- [ ] AC-23: `GET /api/v1/health/live` returns 200 on gateway after deploy

## Technical Notes

**File**: `frontend/src/app/threats/attack-paths/page.jsx`

**Data fetch pattern** (same as other threat pages):
```javascript
import { fetchView } from '@/lib/api';
const data = await fetchView('attack-paths');
```

**Path canvas**: Build a simple horizontal chain of `<NodeBox>` components connected by `<EdgeArrow>` components. No graph library needed for the canvas — it is a linear sequence, not a DAG diagram. For Phase 4 v1, paths are always left-to-right linear chains.

**Severity color tokens** (use existing Tailwind classes for consistency):
- critical: `bg-red-100 text-red-800 border-red-300`
- high: `bg-orange-100 text-orange-800 border-orange-300`
- medium: `bg-yellow-100 text-yellow-800 border-yellow-300`
- low: `bg-gray-100 text-gray-600 border-gray-300`

**CDR active badge**: `bg-red-500 text-white text-xs px-1 py-0.5 rounded animate-pulse` — the pulse animation signals real-time threat.

**Choke point section** is a separate component implemented in AP-P4-02 — this story adds a placeholder `<ChokePointSection />` import.

**Path detail panel** is implemented in AP-P4-03 — this story triggers `setSelectedPathId(path_id)` on row click.

**NodeInvestigationPanel**: Already exists from inventory investigation journey (`story-UI-INV-DI-08`). Import and reuse — do not create a new panel.

## Key Files
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/page.jsx` (replace stub)
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/NodeBox.jsx` (create new — node in canvas)
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/EdgeArrow.jsx` (create new — edge in canvas)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/cspm-portal.yaml` (update frontend image tag)

## Definition of Done
- [ ] page.jsx committed and rendering real data from fetchView("attack-paths")
- [ ] KPI bar renders total, critical, choke_points, longest_open_days, paths_with_active_cdr
- [ ] Path list grouped by crown jewel renders correctly
- [ ] Severity filter and entry_point_type filter working
- [ ] CDR active paths show red "LIVE" badge
- [ ] Node click opens NodeInvestigationPanel
- [ ] Skeleton screen shown while loading
- [ ] Empty state shown when no paths
- [ ] viewer role sees only KPI bar (tested with viewer JWT)
- [ ] Frontend image built with new tag (no `latest`), pushed, manifest updated
- [ ] bmad-security-reviewer: no BLOCKERS