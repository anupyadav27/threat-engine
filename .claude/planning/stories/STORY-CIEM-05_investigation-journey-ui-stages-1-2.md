# STORY-CIEM-05: CIEM Investigation Journey UI — Stage 1 Fleet Overview + Stage 2 Identity Profile

## Track
CIEM Investigation Journey — Sprint 1

## Priority
P1 — main UI deliverable; depends on STORY-CIEM-01 and STORY-CIEM-02

## Story
As a security analyst, I need the CIEM page to guide me through a structured investigation: starting from a fleet-level risk heatmap (Stage 1), then drilling into a specific identity's behavioral profile (Stage 2), so I can move from "which accounts are at risk?" to "what exactly did this role do?" without context-switching.

## Current State

`frontend/src/app/ciem/page.jsx` is a single flat page with 4 tabs:
- Overview: KPI strip + top-critical table + identities table + top-rules table
- Identity Risk: same identities table repeated
- Detection Rules: rules table
- Log Sources: log sources table

No drill-down navigation. No heatmap. No per-identity profile page. L2/L3 findings are indistinguishable from L1 in all tables.

The page uses `useViewFetch('ciem')` — BFF pattern. All data comes from `fetchView('ciem')`.

## Files to Modify / Create
- `frontend/src/app/ciem/page.jsx` — refactor Stage 1 layout
- `frontend/src/app/ciem/identity/[principal]/page.jsx` — **NEW** Stage 2 page
- `frontend/src/components/ciem/IdentityRiskHeatmap.jsx` — **NEW**
- `frontend/src/components/ciem/BehavioralTimeline.jsx` — **NEW**
- `frontend/src/components/ciem/IdentityProfileHeader.jsx` — **NEW**
- `frontend/src/components/ciem/ActivityHeatmap.jsx` — **NEW**

## Stage 1 Changes (`/ciem` page)

### KPI Strip (4 cards, existing pattern)
Replace current KPI strip with:
1. Total Identities at Risk — from `data.kpiGroups[0].identitiesAtRisk` (existing)
2. L2 Correlation Findings — from `data.l2Findings` (existing BFF field)
3. L3 Anomaly Findings — from `data.l3Findings` (existing BFF field)
4. Detection Coverage % — compute `(active log sources / total log sources) × 100` from `data.logSources`

### New Two-Panel Layout (replace current Overview tab content)
```jsx
<div className="grid grid-cols-5 gap-4 mt-4">
  {/* Left: Heatmap */}
  <div className="col-span-2">
    <IdentityRiskHeatmap
      matrix={data.heatmap?.matrix ?? []}
      accounts={data.heatmap?.accounts ?? []}
      principalTypes={data.heatmap?.principal_types ?? []}
      onCellClick={(account, type) => setFilters({account, principalType: type})}
    />
  </div>
  {/* Right: Identity table */}
  <div className="col-span-3">
    <IdentityRiskTable
      identities={data.identitySummary}
      filters={filters}
      onIdentityClick={(principal) => router.push(`/ciem/identity/${encodeURIComponent(principal)}`)}
    />
  </div>
</div>
```

### IdentityRiskTable columns (update from current)
Add columns alongside existing: `actorPrincipalType` (badge), `l2Findings` (count chip, orange if > 0), `l3Findings` (count chip, purple if > 0). Remove duplicate columns.

### IdentityRiskHeatmap component
- SVG grid. For each (account × principalType) cell, render a `<rect>` colored by `max_severity`:
  - critical → `fill="#ef4444"`, high → `fill="#f97316"`, medium → `fill="#eab308"`, low → `fill="#22c55e"`, empty → `fill="#1e293b"`
- X-axis labels: account_id abbreviated to last 6 chars (e.g. `...012`)
- Y-axis labels: principal type (iam_user, iam_role, service_account, root, anonymous)
- Hover tooltip (absolute positioned div): `"{N} critical, {N} high findings in {account} / {type}"`
- Cell click: calls `onCellClick(account_id, principal_type)` to filter the identity table

Data source: separate `fetchView('ciem/heatmap')` call on page load (parallel to main `fetchView('ciem')`).

## Stage 2 Changes (new `/ciem/identity/[principal]` page)

### Page Setup
```
/app/ciem/identity/[principal]/page.jsx
```
- `params.principal` is URL-encoded principal ARN
- Uses `fetchView('ciem_identity', { principal: params.principal })` for identity-specific data
- Falls back gracefully if BFF returns empty (show "No data for this identity")

### IdentityProfileHeader
Props: `principal`, `type`, `riskScore`, `l2Count`, `l3Count`, `accountCount`, `lastSeen`, `sourceIps`

Layout (flex, full width, bg-slate-800 rounded-xl p-6):
- Left 1/3: principal ARN in `font-mono text-sm text-slate-300`, truncated to 48 chars with expand chevron. Type badge below (color by type: role=blue, user=green, service_account=orange, root=red).
- Center 1/3: SVG circular gauge (100px diameter, stroke-width=8). Arc fills based on riskScore. Color: ≥80=red, 60-79=orange, 40-59=yellow, <40=green. Score number centered inside in `text-2xl font-bold`.
- Right 1/3: badge row (`flex flex-wrap gap-2`):
  - `L2 Chains: {N}` — `bg-orange-950 text-orange-300 text-xs px-2 py-1 rounded-full`
  - `Anomalies: {N}` — `bg-purple-950 text-purple-300 text-xs px-2 py-1 rounded-full`
  - `Accounts: {N}` — `bg-blue-950 text-blue-300 text-xs px-2 py-1 rounded-full`
  - Last seen timestamp below in `text-xs text-slate-500`
  - Source IPs: collapsed `{N} IPs` pill, expand to show list

### BehavioralTimeline
Props: `findings[]` (array of finding objects with event_time, severity, rule_source, rule_id, operation, service, resource_name)

- Horizontal scrollable container: `overflow-x-auto`
- SVG inner: `width={max(600, findings.length * 24)}px height=80`
- Horizontal baseline: `<line y1=40 y2=40 stroke="#334155" strokeWidth=2>`
- Each finding = `<circle r=5>` at its x position (proportional to event_time within [first,last] range), colored by severity
- L2 groups (`rule_source='log_correlation'`): bracket above the dots connecting the contributing events, labeled with rule_id short name, `stroke="#f97316"`
- L3 findings (`rule_source='baseline'`): circle with extra `<text>σ</text>` badge above it, `fill="#a855f7"`
- Hover: shows tooltip with event_time, operation, service, resource_name, outcome

### ActivityHeatmap (24×7 grid)
Props: `hourlyData[]` (24 items), `dowData[]` (7 items)

- Grid: `grid-cols-24 gap-px` — each cell `w-3 h-3 rounded-sm`
- Cell color: `bg-slate-700` (0 events) → `bg-blue-900` → `bg-blue-700` → `bg-blue-500` (many events) based on count relative to max
- Row labels: Mon-Sun left side (`text-xs text-slate-500`)
- Col labels: 0, 6, 12, 18 at corresponding cols (`text-xs text-slate-500`)

### Findings Table (Stage 2)
Same `DataTable` component pattern as existing CIEM tables but:
- Pre-filtered to this identity (no cross-identity data)
- Add `Rule Source` column with badges: L1=`bg-slate-800 text-slate-400`, L2=`bg-orange-950 text-orange-400`, L3=`bg-purple-950 text-purple-400`
- L2 rows expandable: click chevron → shows indented list of contributing event titles from `finding_data.contributing_steps`

### Action Buttons (top-right of page)
```jsx
<div className="flex gap-2">
  <button onClick={() => router.push(`/ciem/identity/${encodeURIComponent(principal)}/blast-radius`)}
    className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm px-3 py-1.5 rounded-lg">
    <GraphIcon /> Blast Radius
  </button>
  <button onClick={() => setRemediationOpen(true)}
    className="flex items-center gap-1.5 bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm px-3 py-1.5 rounded-lg">
    <WrenchIcon /> Remediate
  </button>
</div>
```

## Acceptance Criteria

- [ ] Stage 1: heatmap and identity table render on `/ciem` page with `actorPrincipalType`, `l2Findings`, `l3Findings` columns visible
- [ ] Clicking a heatmap cell filters the identity table to that (account × type) combination
- [ ] Clicking an identity row navigates to `/ciem/identity/[encodedPrincipal]`
- [ ] Stage 2: identity profile page loads with header gauge, behavioral timeline, activity heatmap, findings table
- [ ] L2 findings in the findings table are expandable showing contributing steps
- [ ] L3 findings show σ badge on timeline
- [ ] "Blast Radius" button renders and links to `/ciem/identity/[principal]/blast-radius` — **the blast-radius route must render a `<ComingSoon>` placeholder for this sprint**. The full blast-radius page MUST NOT go live without `max_hops=3` enforced server-side in the BFF (BLOCK-CIEM-05-1 from security review). A follow-on story must enforce the hop cap before removing the placeholder.
- [ ] All data is BFF-sourced via `fetchView()` — no direct engine API calls from frontend
- [ ] No mock or fallback data — if BFF returns empty, show empty state component
- [ ] Back breadcrumb on Stage 2 returns to `/ciem`

## Security Review Fixes (from pre-dev security gate)

**BLOCK-CIEM-05-1 — Blast radius page must ship with traversal depth cap:**
The blast-radius route opens a path to unbounded graph traversal. For this sprint, render a placeholder page. The full page requires `max_hops=3` enforced at the BFF layer before it goes live.

**WARN-CIEM-05-2 — New ciem_identity BFF view: use AuthContext for tenant, not principal param:**
When implementing `/api/v1/views/ciem_identity`, the BFF must call `resolve_tenant_id(request)` for tenant scoping. The `principal` parameter is a filter hint only — never a source of tenant identity.

**WARN-CIEM-01-2 — Resolve BFF field name: `identities` vs `identitySummary`:**
`bff/ciem.py:117` exports `"identities"`. This story reads `data.identitySummary`. One must change before dev starts — pick `identitySummary` as the canonical name and update the BFF export.

## Security Checklist
- [ ] `principal` URL-param is only used as a display value and as a BFF query param — never concatenated into SQL
- [ ] BFF enforces `tenant_id` scoping via `resolve_tenant_id(request)` — not from the `principal` param
- [ ] `/views/ciem_identity` BFF view uses AuthContext for tenant_id, not URL parameter
- [ ] No sensitive fields (`credential_ref`, `event_raw`) rendered in UI — stripped by BFF

## Definition of Done
- [ ] Stage 1 and Stage 2 pages render without console errors
- [ ] Navigation flow works: `/ciem` → click identity → `/ciem/identity/X` → click "Blast Radius" → `/ciem/identity/X/blast-radius`
- [ ] Heatmap renders with real data (not all grey) when a `scan_run_id` with findings is active
- [ ] ActivityHeatmap shows density variation (not uniform color) for an identity with varied access times
