# Story AP-P4-02: Choke Point Section

## Status: ready

## Metadata
- **Phase**: P4 — UI
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P4-01 (Attack Paths page must exist — choke point section lives within it), AP-P3-01 (BFF provides choke_points_preview in attack-paths view)
- **Blocks**: nothing (stand-alone feature within the page)
- **RACI**: R=FE-DEV A=DL C=UX I=PO,QA
- **Security Gate**: bmad-security-reviewer must verify choke point cards do not expose sensitive fields (credential_ref, policy details).

## User Story

As a security analyst, I want a "Fix These to Break the Most Paths" section below the path list on the Attack Paths page that shows the top-5 choke point nodes, their type, how many paths they block, and a link to the asset detail, so that I know exactly where to focus remediation effort to eliminate the most attack paths in a single fix.

## Context

Choke point detection is one of the key differentiators vs. Wiz/Orca. After finding the top-10 nodes whose remediation would break the most paths, the UI surfaces the top-5 in a collapsible card section directly on the Attack Paths page.

Each card shows the business-level answer to "what does fixing this one thing buy me?" — N paths blocked, their severity breakdown, and a "View Asset" link to the full inventory asset detail.

Data comes from `fetchView("attack-paths")` response which includes `choke_points_preview[]` (top-3 from BFF). For the full list (top-10), a separate call to the engine's `GET /api/v1/choke-points` is needed — this can be a direct engine call via the gateway, not a BFF view.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [x] RS  [ ] RC
ID.RA-5 (risk prioritized via choke point analysis), RS.MI-3 (remediation recommended)

**CSA CCM v4 Domain(s)**
- GRC-05, IVS-01

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | choke point cards | Card exposes policy_statement or internal ARN details | Cards show only: node_name, node_type, paths_blocked_if_fixed, avg_path_score, severity breakdown — no policy details |
| Elevation | viewer viewing choke points | viewer accesses choke points which are not in summary-only response | Choke point section rendered only if paths[] is present (same viewer check as AP-P4-01) |

## MITRE ATT&CK Techniques Addressed
N/A — UI rendering; no finding logic.

## Acceptance Criteria

### Functional
- [ ] AC-1: Collapsible section added below path list in `frontend/src/app/threats/attack-paths/page.jsx` — title: "Fix These to Break the Most Paths"
- [ ] AC-2: Section header shows total choke point count badge: "5 choke points identified"
- [ ] AC-3: Top-5 choke point cards rendered — each card shows: node_name, node_type badge, `paths_blocked_if_fixed` ("Breaks N paths"), severity breakdown bar (critical/high/medium/low counts), avg_path_score
- [ ] AC-4: Each card has "View Asset" button that navigates to `/inventory/{node_uid}` (the asset detail page)
- [ ] AC-5: Clicking choke point badge in path canvas (AP-P4-01) scrolls to and highlights the matching choke point card — `useRef` + `scrollIntoView`
- [ ] AC-6: Section collapsed by default on first load; "Expand" button shows all top-5 cards
- [ ] AC-7: Section shows top-3 from `choke_points_preview[]` in collapsed state, "Show all 10" loads full list via direct gateway call to `/api/v1/choke-points?limit=10`
- [ ] AC-8: Empty state if `choke_points_preview` is empty: "No choke points identified yet. Run a full pipeline scan."

### Security (must pass bmad-security-reviewer)
- [ ] AC-9: Choke point cards do not render `policy_statement`, `sg_rule`, or `credential_ref` fields
- [ ] AC-10: "View Asset" link uses `node_uid` as the route parameter — verified to be URL-safe (encoded if necessary)
- [ ] AC-11: viewer role: section hidden entirely (consistent with path list restriction in AP-P4-01)

## Technical Notes

**Component file**: Add `<ChokePointSection />` component to `frontend/src/app/threats/attack-paths/page.jsx` or create a separate `ChokePointSection.jsx` in the same directory.

**Data flow**:
- Collapsed state: `choke_points_preview` from `fetchView("attack-paths")` response (top-3)
- Expanded state: call `GET /gateway/api/v1/choke-points?limit=10&tenant_id=...` directly via `getFromEngine()` pattern (or equivalent `fetch` with auth headers)

**Severity breakdown bar**: Simple CSS flex bar with 4 colored segments proportional to critical/high/medium/low counts. No external chart library needed for this.

**scroll-to-choke behavior**: When `AP-P4-01` path canvas detects a node click where `node_uid === choke_node_uid`, it should call a callback that scrolls the choke point section into view and briefly highlights the matching card (yellow background flash for 1.5s).

**No image build needed** if AP-P4-01 ships first and AP-P4-02 is included in the same image build. If separately scheduled, a new image build is required.

## Key Files
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/ChokePointSection.jsx` (create new)
- `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/page.jsx` (modify — add `<ChokePointSection />` import)

## Definition of Done
- [ ] ChokePointSection.jsx committed with top-5 cards
- [ ] Cards render correctly with node_name, type, paths_blocked, severity breakdown, avg_path_score
- [ ] "View Asset" button navigates to /inventory/{node_uid}
- [ ] Section collapsed by default; "Show all 10" expands and fetches full choke list
- [ ] Scroll-to-choke behavior works when choke point badge clicked in canvas
- [ ] viewer role: section not rendered
- [ ] Empty state renders correctly when no choke points
- [ ] bmad-security-reviewer: no BLOCKERS (no sensitive fields in cards)