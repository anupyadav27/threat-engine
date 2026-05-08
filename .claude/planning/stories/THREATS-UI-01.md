# THREATS-UI-01 — Threat Command Room Redesign

**Sprint:** Threats-UI | **Points:** 13 | **Priority:** P1
**Owner:** Frontend dev
**Blocked by:** THREATS-SEC-01 (PATCH permission fix must deploy before Assign/Suppress buttons ship)

---

## Problem Statement

The current 3-zone Command Room has three compounding issues:
1. **Blank Zone C (45% of viewport)** shows a radar SVG "select a scenario" empty state 90% of the time
2. **Hover-triggered preview** — fragile on touch, content lost on mouse-out
3. **Jarring layout shift** — when ScenarioDetailPanel opens, `gridTemplateColumns` animates `'40fr 0fr 60fr'`, collapsing Zone C to 0 and reflowing the card list

**Design decision:** Replace Zone C with a **centered modal dialog** (not a slide-over). The card list stays full-width at all times — zero layout shift. Modal appears over a dark backdrop; click backdrop / ESC / X to close.

---

## New Layout

```
┌─ KPI STRIP (full width) ──────────────────────────────────────────────┐
│  [CRIT 4 ▲2]  [HIGH 12 ▼1]  [Open 31]  [Risk 84]  Last scan: 2h ago │
├─ FILTER BAR ──────────────────────────────────────────────────────────┤
│  [●CRIT][●HIGH][○MED][○LOW]  [Category▾][Status▾][Sort: Risk▾]       │
│  [🔍 Search scenarios...]                                               │
├───────────────────────────────────────────────────────────────────────┤
│  CARD LIST (always full width — never changes)                        │
│  [●CRIT card] ← click                                                 │
│  [●HIGH card]      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
│  [●HIGH card]      ░ ┌─── Scenario Detail Modal ──────────────┐ ░░░ │
│  [●MED  card]      ░ │ s3-bucket-prod-data [CRIT] Risk:92 [X] │ ░░░ │
│  (virtual scroll)  ░ │ ────────────────────────────────────── │ ░░░ │
│                    ░ │ Attack Chain: Internet→EC2→S3           │ ░░░ │
│                    ░ │ MITRE: T1078 · T1190 · T1530            │ ░░░ │
│                    ░ │ ────────────────────────────────────── │ ░░░ │
│                    ░ │ Misconfigs (3): S3_PUBLIC_READ [CRIT]  │ ░░░ │
│                    ░ │ ────────────────────────────────────── │ ░░░ │
│                    ░ │ [Assign▾] [Suppress] (admin+ only)     │ ░░░ │
│                    ░ │ [View Full Details →]                   │ ░░░ │
│                    ░ └────────────────────────────────────────┘ ░░░ │
│                    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
│                         Click backdrop / ESC / [X] to close           │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Files Modified

- `frontend/src/components/domain/threats/CommandRoom.jsx` — layout, state, ESC handler, URL params
- `frontend/src/components/domain/threats/ScenarioCardList.jsx` — virtual scroll
- `frontend/src/components/domain/threats/PreviewPanel.jsx` — delete (replaced by modal)
- `frontend/src/components/domain/threats/ScenarioModal.jsx` (new) — centered modal with backdrop
- `frontend/src/components/domain/threats/FilterBar.jsx` (new)

---

## Implementation

### Layout: Flex column, modal overlay

```jsx
// CommandRoom.jsx — card list always full width, modal floats above via portal

<div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
  <ThreatPulseBar stats={pulseStats} />
  <FilterBar filters={filters} onFilterChange={setFilters} />
  <ScenarioCardList
    scenarios={filteredScenarios}
    selectedId={selectedId}
    onCardClick={handleCardClick}
  />
  {isModalOpen && (
    <ScenarioModal
      scenario={selectedScenario}
      onClose={handleClose}
      userRole={auth.role}
    />
  )}
</div>
```

### ScenarioModal — centered dialog with backdrop

```jsx
// ScenarioModal.jsx — rendered via React portal to document.body
import { createPortal } from 'react-dom';

export function ScenarioModal({ scenario, onClose, userRole }) {
  const canWrite = userRole === 'tenant_admin' || userRole === 'org_admin'
                   || userRole === 'platform_admin';
  return createPortal(
    <>
      {/* Backdrop — click to close */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0,
          backgroundColor: 'rgba(0,0,0,0.5)',
          zIndex: 200,
        }}
      />
      {/* Modal */}
      <div
        role="dialog"
        aria-modal="true"
        style={{
          position: 'fixed',
          top: '50%', left: '50%',
          transform: 'translate(-50%, -50%)',
          width: 800,
          maxHeight: '80vh',
          overflowY: 'auto',
          backgroundColor: '#fff',
          borderRadius: 8,
          boxShadow: '0 24px 48px rgba(0,0,0,0.3)',
          zIndex: 201,
          padding: 24,
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <div>
            <h2>{scenario.title}</h2>
            <SeverityBadge severity={scenario.severity} />
            <span>Risk: <strong>{scenario.risk_score}</strong></span>
          </div>
          <button onClick={onClose} aria-label="Close">✕</button>
        </div>

        {/* Attack chain */}
        <AttackChainSection steps={scenario.attack_chain} />

        {/* Misconfigs */}
        <MisconfigList findings={scenario.top_findings} />

        {/* Role-gated actions */}
        {canWrite && (
          <div className="action-buttons">
            <AssignDropdown scenarioId={scenario.scenario_id} />
            <SuppressButton scenarioId={scenario.scenario_id} />
          </div>
        )}

        {/* Navigate to full detail */}
        <a href={`/threats/${scenario.scenario_id}`}>View Full Details →</a>
      </div>
    </>,
    document.body
  );
}
```

### URL-encoded state (mandatory per ADR-CR-03 + ADR-CR-04)

```jsx
// URL: /threats?selected=<id>&sev=CRIT,HIGH&status=open&sort=risk_score

const searchParams = useSearchParams();
const router = useRouter();

// Selected scenario — from URL
const selectedId = searchParams.get('selected');
const isModalOpen = !!selectedId;

// Filters — from URL
const severities = (searchParams.get('sev') || 'CRIT,HIGH').split(',');
const status = searchParams.get('status') || 'open';
const sort = searchParams.get('sort') || 'risk_score';

// Update URL on card click
function handleCardClick(scenario) {
  const params = new URLSearchParams(searchParams.toString());
  params.set('selected', scenario.scenario_id);
  router.push(`/threats?${params.toString()}`, { scroll: false });
}

// Close slide-over
function handleClose() {
  const params = new URLSearchParams(searchParams.toString());
  params.delete('selected');
  router.push(`/threats?${params.toString()}`, { scroll: false });
}
```

### Virtual scroll (mandatory per ADR-CR-06)

```jsx
// ScenarioCardList.jsx — replace flat map() with @tanstack/virtual
import { useVirtualizer } from '@tanstack/react-virtual';

const CARD_HEIGHT = 88; // px, fixed

const virtualizer = useVirtualizer({
  count: scenarios.length,
  getScrollElement: () => listRef.current,
  estimateSize: () => CARD_HEIGHT,
  overscan: 5,
});
```

### Modal closes when selected card is filtered out

```jsx
// CommandRoom.jsx — useEffect watching filteredScenarios
useEffect(() => {
  if (!selectedId) return;
  const stillVisible = filteredScenarios.some(s => s.scenario_id === selectedId);
  if (!stillVisible) handleClose();
}, [filteredScenarios, selectedId]);
```

### ESC key handler

```jsx
// CommandRoom.jsx
useEffect(() => {
  function onKeyDown(e) {
    if (e.key === 'Escape' && isModalOpen) handleClose();
  }
  document.addEventListener('keydown', onKeyDown);
  return () => document.removeEventListener('keydown', onKeyDown);
}, [isModalOpen]);
```

### Assign/Suppress: role-gated render

```jsx
// ScenarioModal.jsx
{canWrite && (
  <div className="action-buttons">
    <AssignDropdown scenarioId={scenario.scenario_id} />
    <SuppressButton scenarioId={scenario.scenario_id} />
  </div>
)}
// canWrite = auth.permissions.includes('threat:write')
```

### Staleness badge on KPI strip

```jsx
// ThreatPulseBar.jsx — add to last_scan_age display
const staleBadge =
  scanAgeHours > 72 ? 'stale-red' :
  scanAgeHours > 24 ? 'stale-yellow' : null;
```

### Sort options

| Key | Label |
|---|---|
| `risk_score` | Risk Score (default) |
| `newest` | Newest First |
| `severity` | Severity (CRIT first) |
| `resource_name` | Resource Name A→Z |

### Mobile fallback (<768px)

Card click → `router.push('/threats/[threatId]')` directly. No modal rendered on mobile (viewport too narrow).

---

## Acceptance Criteria

1. KPI strip renders within 2s; Critical/High/Open counts match threat engine data for authenticated tenant
2. Severity buttons are multi-select; deselecting all shows all cards (not zero)
3. Clicking a card opens a centered modal with dark backdrop; card list remains full width with no layout shift
4. Clicking backdrop OR pressing ESC OR clicking [X] closes modal; card list unaffected
5. Modal auto-closes when the selected scenario is filtered out by severity/status toggle
6. URL updates to `?selected=<id>&sev=...` on card click; browser back restores previous state
7. `viewer` and `analyst` roles — Assign/Suppress buttons absent from modal
8. `tenant_admin` and above — Assign/Suppress visible and functional
9. On mobile (<768px): tap card → navigate to `/threats/[threatId]`; no modal rendered
10. Loading state: skeleton cards at 88px height; no layout shift on data arrival
11. Empty state (all filtered out): "No threats match your filters" message; filter bar remains visible
12. Error state: non-blocking banner; cached content remains if present
13. List is virtualised; scrolling 2000 cards produces no jank (no full DOM render of all cards)

---

## Scan Staleness Thresholds

- > 24h: yellow badge `⚠ Scan 2d old`
- > 72h: red badge `🔴 Scan 3d old — rescan recommended`
- Threshold is a BFF config value (`pulse_stats.staleness_threshold_hours`), not hardcoded in UI

---

## STRIDE (from security architect review)

- Assign/Suppress conditioned on `threat:write` (role-gated render + endpoint enforced by THREATS-SEC-01)
- `status_changed_by` derived from AuthContext (enforced by THREATS-SEC-01)
- `?selected=<id>` deep-link: BFF ownership validated server-side (existing `resolve_tenant_id`)
- No `dangerouslySetInnerHTML` in card or modal rendering (acceptance criterion)
- Scenario title/description rendered as React text `{value}` only
- Modal rendered via `createPortal` to `document.body` — no z-index stacking issues with nav

---

## Definition of Done

- [ ] Flex layout (not grid) — no rerender of card list on modal open/close
- [ ] URL-encoded `selected` + filter state
- [ ] Virtual scroll (`@tanstack/react-virtual`)
- [ ] ESC key closes modal
- [ ] Modal auto-closes on filter exclusion
- [ ] Role-gated Assign/Suppress buttons
- [ ] Staleness badge on KPI strip
- [ ] Mobile fallback: navigate (not modal)
- [ ] All 13 ACs pass
- [ ] No `dangerouslySetInnerHTML` (grep confirmed)
- [ ] Frontend image rebuilt and deployed