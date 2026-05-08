# STORY-CWPP-02: CWPP Stage 1 Radar Chart + Workload Posture UI Redesign

## Track
CWPP Investigation Journey — Sprint 1

## Priority
P1 — upgrades CWPP landing page from flat cards to investigation-first layout

## Story
As a security analyst on the CWPP overview page, I need a radar/spider chart showing posture scores across all 5 workload types simultaneously, so I can instantly see which workload class is the weakest link and compare relative posture without reading through 5 separate score numbers.

## Current State

`frontend/src/app/cwpp/page.jsx` renders:
- A CWPP score banner (large score, risk band)
- 6 tab layout (Overview, Containers, Images, Hosts/VMs, Serverless, Runtime)
- Each tab has workload cards with `ScoreBar` components
- Images tab has a brief inline CVE note (not a full honest banner)
- No radar chart, no cross-workload posture comparison
- No workload availability warning banner

All data from `useViewFetch('cwpp')` — BFF pattern. Data already provides `posture_score` per workload type in the `workloads` array.

## Files to Modify / Create
- `frontend/src/app/cwpp/page.jsx` — restructure landing view
- `frontend/src/components/cwpp/WorkloadRadarChart.jsx` — **NEW**

## Exact Changes

### 1. `WorkloadRadarChart.jsx` — new pure SVG component

Props:
```typescript
{
  workloads: Array<{
    id: "containers" | "images" | "hosts" | "serverless" | "runtime",
    name: string,
    posture_score: number,   // 0-100
    risk_band: string
  }>,
  size?: number  // default 400
}
```

SVG spec:
- `viewBox="-220 -220 440 440"` (centered at 0,0)
- 5 axes at angles: containers=90°, images=162°, hosts=234°, serverless=306°, runtime=18° (equally spaced, starting top)
- For each axis: draw axis line from center to tip (`stroke="#334155"`, `strokeDasharray="4 4"`)
- Axis label at tip: workload name + score, `fontSize=11`, `fill="#94a3b8"`
- Max polygon (score=100 reference): connect tips with `stroke="#1e293b"` dashed, `fill="none"`
- Current posture polygon: connect (score/100 × tip_distance) per axis. `fill="rgba(99,102,241,0.2)"` (indigo), `stroke="#6366f1"` `strokeWidth=2`
- Center score label: CWPP Score in `fontSize=18 fontWeight=bold fill="#e2e8f0"` at (0,0)
- Clicking an axis label → calls `onWorkloadClick(workload.id)` to navigate to that tab

Data source: `data.workloads` array already returned by BFF — no new endpoint needed.

### 2. `cwpp/page.jsx` — Stage 1 layout restructure

**KPI strip (4 cards) — replace current score banner:**
```jsx
<div className="grid grid-cols-4 gap-4 mb-6">
  <KpiCard label="CWPP Score" value={data.cwppPostureScore} type="score" />
  <KpiCard label="Total Critical" value={data.criticalFindings} severity="critical" />
  <KpiCard
    label="Workloads Below 60"
    value={data.workloads?.filter(w => w.posture_score < 60).length ?? 0}
    className={belowSixty > 0 ? "border-amber-700 bg-amber-950" : ""}
  />
  <KpiCard
    label="Image CVE Scan"
    value="Not Enabled"
    className="border-amber-700 bg-amber-950 text-amber-300"
    tooltip="CVE scanning via Trivy/Grype not yet implemented. Image scores reflect policy posture only."
  />
</div>
```

**Unavailability banner** (show if any workload has `status: 'unavailable'`):
```jsx
{unavailableWorkloads.length > 0 && (
  <div className="bg-amber-950 border border-amber-700 text-amber-200 rounded-lg p-3 flex items-center gap-2 mb-4">
    <AlertTriangleIcon className="w-4 h-4 shrink-0" />
    <span className="text-sm">
      {unavailableWorkloads.map(w => w.name).join(', ')} engine{unavailableWorkloads.length > 1 ? 's' : ''} unreachable — scores may be incomplete
    </span>
  </div>
)}
```

**Radar chart + workload cards row:**
```jsx
<div className="flex flex-col items-center gap-6">
  {/* Radar chart */}
  <WorkloadRadarChart
    workloads={data.workloads}
    onWorkloadClick={(id) => setActiveTab(id)}
    size={360}
  />
  {/* Workload cards below */}
  <div className="grid grid-cols-5 gap-3 w-full">
    {data.workloads.map(workload => (
      <WorkloadCard
        key={workload.id}
        workload={workload}
        onClick={() => setActiveTab(workload.id)}
      />
    ))}
  </div>
</div>
```

**WorkloadCard** (existing component, extend with):
- Trend arrow: if `posture_score > prior_score`: `↑ text-green-400`, if lower: `↓ text-red-400`, if same: `→ text-slate-400`. Show `—` if no prior scan data (do NOT fabricate direction).
- Clickable: `cursor-pointer hover:bg-slate-700 transition-colors`

**Images tab — CVE honest banner (replace inline note with full banner):**
```jsx
<div className="bg-amber-950 border border-amber-700 rounded-lg p-4 flex items-start gap-3 mb-4">
  <AlertTriangleIcon className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
  <div>
    <p className="text-amber-200 font-medium text-sm">CVE Scanning Not Implemented</p>
    <p className="text-amber-400 text-xs mt-1">
      Image posture scores reflect policy checks only (scan-on-push enabled, image age, encryption).
      CVE content scanning via Trivy/Grype is planned — actual vulnerability exposure may be higher than the score suggests.
    </p>
  </div>
</div>
```

## Security Review Fixes (from pre-dev security gate)

**WARN-CWPP-02-1 — Fix falsy prior_score=0 bug in trend arrow logic:**
`if not prior_score` treats score of 0 as "no data". A workload improving from 0 incorrectly shows `—`. Fix:

```jsx
const hasPrior = prior_score !== null && prior_score !== undefined;
const arrow = !hasPrior ? '—' : posture_score > prior_score ? '↑' : posture_score < prior_score ? '↓' : '→';
```

## Acceptance Criteria

- [ ] Radar chart renders with real `posture_score` values per workload type (not placeholder data)
- [ ] Clicking a radar chart axis label scrolls to / activates the corresponding tab
- [ ] Clicking a workload card below the chart activates the corresponding tab
- [ ] Amber banner appears when any workload has `status: 'unavailable'`
- [ ] Image CVE scan KPI card shows "Not Enabled" (amber styling) — never shows a green or neutral state
- [ ] Images tab shows full amber `CVE Scanning Not Implemented` banner above all content
- [ ] Workload cards show `—` for trend arrow when prior scan data is unavailable (not a fake arrow)
- [ ] All data from `fetchView('cwpp')` BFF — no direct engine calls

## Security Checklist
- [ ] No mock/fallback data in any component — empty state components only
- [ ] No hardcoded tenant_id or scan_run_id in frontend
- [ ] Score display: never show a score that implies CVE coverage when image CVE scanning is disabled

## Definition of Done
- [ ] CWPP page renders radar chart alongside workload cards
- [ ] Radar chart axes correctly labeled with workload names and scores
- [ ] Images tab shows full CVE disclaimer banner
- [ ] Unavailability banner triggers when engine is down
- [ ] No console errors on page load