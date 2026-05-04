# CIEM + CWPP Investigation Journey — UX Component Specification

> Produced by UX agent from live code analysis of `frontend/src/app/ciem/page.jsx` and `frontend/src/app/cwpp/page.jsx`.
> Covers all new components, routes, data bindings, and interaction patterns.

---

## 1. Existing Shared Components (Reuse)

From `frontend/src/components/`:
| Component | Where Used |
|-----------|-----------|
| `AlertBanner` | Unavailability warnings, CVE scan disclaimer |
| `DataTable` | All findings tables |
| `FilterBar` | Provider/account/severity filters |
| `FindingDetailPanel` | Stage 3 slide-in (extend for attack chain) |
| `KpiCard` / `KpiSparkCard` | Top strip on both pages |
| `MetricStrip` | Summary rows |
| `PageLayout` | Page wrapper with tabs |
| `SeverityBadge` | All severity indicators |
| `CloudProviderBadge` | CSP icons |
| `Sparkline` | Trend lines in KPI cards |

Existing page patterns:
- `useViewFetch(page)` → `fetchView(page)` → BFF. No direct engine calls from frontend.
- Slide-in panels: `state: {open, data}`, rendered as `<div className="fixed right-0 top-0 h-full w-1/2 bg-slate-900 border-l border-slate-700 z-50 overflow-y-auto">` with `×` close button.
- KPI strip: `grid grid-cols-4 gap-4 mb-6`

---

## 2. New Routes

| Route | File | Type | Depends On |
|-------|------|------|-----------|
| `/ciem` | `app/ciem/page.jsx` | Extend (refactor) | STORY-CIEM-01, -02 |
| `/ciem/identity/[principal]` | `app/ciem/identity/[principal]/page.jsx` | New | STORY-CIEM-01, -04 |
| `/ciem/identity/[principal]/blast-radius` | `app/ciem/identity/[principal]/blast-radius/page.jsx` | New | Sprint 2 |
| `/cwpp` | `app/cwpp/page.jsx` | Extend (refactor) | STORY-CWPP-01, -02 |

---

## 3. New Shared Components — Full Specification

### 3.1 `components/ciem/IdentityRiskHeatmap.jsx`

**Purpose:** SVG heatmap grid (account × principal_type) colored by max severity.

**Props:**
```typescript
{
  matrix: Array<{
    account_id: string,
    principal_type: string,
    max_severity: "critical" | "high" | "medium" | "low" | null,
    finding_count: number
  }>,
  accounts: string[],        // X-axis labels (ordered)
  principalTypes: string[],  // Y-axis labels (ordered)
  onCellClick?: (account_id: string, principal_type: string) => void
}
```

**Layout:** `<svg width={accounts.length * 64 + 120} height={principalTypes.length * 48 + 60}>`

**Cell rendering:**
- `fill`: critical=`#ef4444`, high=`#f97316`, medium=`#eab308`, low=`#22c55e`, null=`#1e293b`
- Each cell: `<rect width=52 height=36 rx=4>` + hover `<title>` for native tooltip
- On click: calls `onCellClick(account_id, principal_type)`

**Axis labels:**
- X (accounts): `text-xs fill="#94a3b8"`, rotate -30°, show last 6 chars: `...${id.slice(-6)}`
- Y (types): `text-xs fill="#94a3b8"`, right-aligned

**Empty state:** `<text>No identity data available</text>` centered in grey

**Data source:** `fetchView('ciem/heatmap')` → `data.matrix`, `data.accounts`, `data.principal_types`

---

### 3.2 `components/ciem/IdentityRiskTable.jsx`

**Purpose:** Sortable identity table with L2/L3 columns and principal type badges.

**Props:**
```typescript
{
  identities: Array<{
    actor_principal: string,
    actorPrincipalType: string,
    riskScore: number,
    critical: number,
    high: number,
    l2Findings: number,
    l3Findings: number,
    lastActivity: string,
    account_id: string,
    provider: string
  }>,
  filters?: { account?: string, principalType?: string },
  onIdentityClick: (principal: string) => void
}
```

**Column definitions:**
| Column | Render | Width |
|--------|--------|-------|
| Principal | `font-mono text-xs truncate w-48` + copy icon | 200px |
| Type | Badge: role=`bg-blue-950 text-blue-300`, user=`bg-green-950 text-green-300`, service_account=`bg-orange-950 text-orange-300`, root=`bg-red-950 text-red-300` | 120px |
| Risk Score | Pill: ≥80=`bg-red-950 text-red-300`, 60-79=`bg-orange-950`, 40-59=`bg-yellow-950`, <40=`bg-green-950` | 80px |
| Critical | Red number, bold if > 0 | 60px |
| High | Orange number | 60px |
| L2 Chains | `bg-orange-950 text-orange-300 rounded-full px-2` if > 0, else `text-slate-500` | 80px |
| L3 Anomalies | `bg-purple-950 text-purple-300 rounded-full px-2` if > 0, else `text-slate-500` | 90px |
| Last Activity | Relative time (`2h ago`) | 100px |
| Account | Last 12 chars | 100px |
| CSP | `<CloudProviderBadge>` | 40px |

**Sorting:** Click column header → sort by that column. Default: Risk Score desc.

**Row click:** calls `onIdentityClick(identity.actor_principal)`

---

### 3.3 `components/ciem/CiemFilterBar.jsx`

**Purpose:** Filter bar for CIEM Stage 1 page.

**Props:**
```typescript
{
  providers: string[],
  accounts: string[],
  onChange: (filters: CiemFilters) => void,
  l1Count: number, l2Count: number, l3Count: number
}
```

**Elements (left to right):**
1. Provider pills: `AWS | Azure | GCP | OCI` — toggle buttons, `bg-slate-700 selected:bg-indigo-600`
2. Account dropdown: multi-select, `w-40`
3. Principal type group: `All | Users | Roles | Service Accounts` — segmented control
4. Severity select: `All | Critical | High | Medium | Low`
5. Time range pills: `1h | 24h | 7d | 30d`
6. Level toggles: `L1 ({l1Count}) | L2 ({l2Count}) | L3 ({l3Count})` — independent toggles with count badges. L2=orange, L3=purple when active.

---

### 3.4 `components/ciem/IdentityProfileHeader.jsx`

**Purpose:** Full-width header card for Stage 2 identity profile.

**Props:**
```typescript
{
  principal: string,
  principalType: string,
  riskScore: number,
  l2Count: number,
  l3Count: number,
  accountCount: number,
  lastSeen: string,
  sourceIps: string[]
}
```

**Layout:** `flex items-center gap-6 bg-slate-800 rounded-xl p-6 mb-6`

**Sections:**
- Left (flex-1): ARN in `font-mono text-sm text-slate-300` truncated to 48 chars. Expand chevron `<button>` shows full ARN on click. Type badge below.
- Center (w-36 flex justify-center): SVG gauge.
  - Circle: `r=40, stroke-width=8, strokeLinecap=round`
  - Background arc: `stroke="#1e293b"`
  - Score arc: stroke color by band (≥80=`#ef4444`, 60-79=`#f97316`, 40-59=`#eab308`, <40=`#22c55e`). `stroke-dasharray={`${score * 2.51} 251`}` (circumference=251 for r=40). Rotated -90°.
  - Center text: `{riskScore}` in `text-2xl font-bold fill="#e2e8f0"`
- Right (flex-1): Badge row + metadata
  - `L2 Chains: {l2Count}` — `bg-orange-950 text-orange-300`
  - `Anomalies: {l3Count}` — `bg-purple-950 text-purple-300`
  - `Accounts: {accountCount}` — `bg-blue-950 text-blue-300`
  - Last seen: `text-xs text-slate-500 mt-2`
  - IPs: collapsed `{sourceIps.length} IPs` pill. Expand → `<ul className="text-xs font-mono text-slate-400 mt-1">` with each IP.

---

### 3.5 `components/ciem/BehavioralTimeline.jsx`

**Purpose:** Horizontal scrollable SVG timeline of findings events.

**Props:**
```typescript
{
  findings: Array<{
    finding_id: string,
    event_time: string,
    severity: string,
    rule_source: "log" | "log_correlation" | "baseline",
    rule_id: string,
    operation: string,
    service: string,
    resource_name: string,
    contributing_steps?: Array<{step_idx: number, finding_id: string, event_time: string}>
  }>
}
```

**SVG dimensions:** `height=80`. Width: `Math.max(600, findings.length * 24)` px.

**Baseline:** `<line x1=0 y1=40 x2={width} y2=40 stroke="#334155" strokeWidth=2>`

**Event dots:**
- Position: X = proportional to event_time within [minTime, maxTime] range
- `<circle r=5 cy=40>` colored by severity
- Hover: absolute tooltip showing event_time, operation, service, resource_name

**L2 groups** (`rule_source='log_correlation'`):
- Bracket connecting contributing_steps' dot positions: `<path d="M{x1},30 L{x1},24 L{x2},24 L{x2},30" stroke="#f97316" strokeWidth=1.5 fill="none">`
- Label above bracket: rule_id short form, `font-size=9 fill="#f97316"`

**L3 anomaly dots** (`rule_source='baseline'`):
- Extra σ badge: `<text x={cx} y={cy-14} fontSize=8 fill="#a855f7" textAnchor="middle">σ</text>`

**Container:** `<div className="overflow-x-auto">` wrapping the SVG. Label: `"Behavioral Timeline (last {N} events)"`.

**Max displayed:** 50 most recent findings (sorted by event_time desc, then reversed for display).

---

### 3.6 `components/ciem/ActivityHeatmap.jsx`

**Purpose:** 24×7 grid showing event density by hour × day-of-week.

**Props:**
```typescript
{
  hourlyData: Array<{hour: number, count: number}>,  // 24 items
  dowData: Array<{dow: number, dow_name: string, count: number}>  // 7 items
}
```

**Layout:** `flex gap-6`

**Hourly heatmap (24×1):**
- `grid grid-cols-24 gap-px` (24 equal columns)
- Each cell: `w-6 h-8 rounded-sm` colored by relative count: 0=`bg-slate-700`, max=`bg-blue-500`, intermediate=`bg-blue-900/bg-blue-700` based on `count/maxCount`
- Hour labels: `0`, `6`, `12`, `18`, `23` below grid, `text-xs text-slate-500`
- Title: `"Events by Hour"`

**Day-of-week heatmap (7×1):**
- Same grid pattern, 7 cells
- Labels: Mon Tue Wed Thu Fri Sat Sun
- Title: `"Events by Day"`

**Data source:** Fetched from `GET /api/v1/ciem/identities/{principal}/hourly-activity` via BFF, or included in identity profile BFF view.

---

### 3.7 `components/ciem/AttackChainPanel.jsx`

**Purpose:** Slide-in panel showing L2 correlation finding as ordered step diagram.

**Props:**
```typescript
{
  finding: {
    finding_id: string,
    rule_id: string,
    severity: string,
    title: string,
    mitre_tactics: string[],
    mitre_techniques: string[],
    remediation: string,
    contributing_steps: Array<{
      step_idx: number,
      finding_id: string,
      rule_id: string,
      event_time: string,
      operation: string,
      service: string,
      resource_uid: string,
      resource_name: string,
      outcome: string,
      actor_ip?: string
    }>
  },
  onClose: () => void
}
```

**Layout:** `fixed right-0 top-0 h-full w-1/2 bg-slate-900 border-l border-slate-700 z-50 overflow-y-auto p-6`

**Sections:**
1. **Header:** `flex items-center justify-between`. Rule name + `<SeverityBadge>`. `×` close button.
2. **Step diagram** (`<div className="overflow-x-auto my-6">`):
   - Steps in `flex gap-0 items-start`
   - Each step box: `bg-slate-800 rounded-lg p-3 w-36 shrink-0`
     - Step number badge top-left: `w-5 h-5 bg-slate-600 rounded-full text-xs flex items-center justify-center`
     - Operation: `font-mono text-xs font-medium text-slate-200 mt-1`
     - Service icon + name: `text-xs text-slate-400`
     - Resource: `text-xs text-slate-300 truncate`
     - Outcome: `✓` (green) or `✗` (red), `text-xs`
   - Between boxes: arrow `→` + time delta `text-xs text-slate-500` (`"14 min later"`)
3. **MITRE section:**
   - `"ATT&CK Techniques"` heading
   - Technique badges: `bg-red-950 text-red-300 text-xs px-2 py-1 rounded cursor-help`
   - Hover tooltip on badge: D3FEND countermeasure name (static lookup map by technique ID)
4. **Remediation:** `<p className="text-slate-300 text-sm leading-relaxed">`
5. **Raw events expandable:** `<details><summary>View Raw Events ({N})</summary><ul className="font-mono text-xs text-slate-500">`

**D3FEND static tooltip map (include in component):**
```javascript
const DFEND_MAP = {
  "T1078.004": "D3-MFA Multi-Factor Authentication",
  "T1528": "D3-OAM Object Access Monitoring",
  "T1548.005": "D3-PWAA Privileged Account Access Analysis",
  "T1199": "D3-FNSA Function Network Services Analysis",
  "T1098": "D3-UAA User Account Authentication"
}
```

---

### 3.8 `components/ciem/BlastRadiusGraph.jsx`

**Purpose:** Full-page force-directed graph of identity → resource reachability.

**Props:**
```typescript
{
  principal: string,
  nodes: Array<{
    id: string,          // resource_uid or principal
    type: "identity" | "s3" | "ec2" | "rds" | "iam_role" | "lambda" | "other",
    label: string,
    crossAccount: boolean,
    findingCount: number
  }>,
  edges: Array<{
    source: string,
    target: string,
    operation: string,
    severity: "critical" | "high" | "medium" | "low"
  }>,
  onNodeSelect: (nodeId: string) => void,
  selectedNode?: string
}
```

**Node colors:** identity=`#7c3aed`, s3=`#f97316`, ec2=`#3b82f6`, rds=`#22c55e`, iam_role=`#ef4444`, lambda=`#eab308`, other=`#64748b`

**Cross-account nodes:** dashed `stroke-dasharray="4 2"` on node circle stroke.

**Edge colors:** critical=`#ef4444`, high=`#f97316`, medium=`#eab308`, low=`#22c55e`

**Layout algorithm:** Static dagre-style positioning (no animation required). Central identity node at center. Resources arranged in concentric rings by hop distance.

**Interaction:** Node click → `onNodeSelect(node.id)` → right sidebar updates.

**Controls (top bar):**
- Hop depth: `1-hop | 2-hop | 3-hop` toggle buttons
- Resource type filter: checkboxes per type
- Export JSON: downloads adjacency list as `.json`

**Legend (bottom-left absolute positioned):** Node color key + edge color key. `bg-slate-800 rounded-lg p-3 text-xs`

---

### 3.9 `components/ciem/RemediationPanel.jsx`

**Purpose:** Slide-in Kanban remediation triage panel.

**Props:**
```typescript
{
  findings: Array<{
    finding_id: string,
    title: string,
    severity: string,
    affected_resources: number,
    effort: "low" | "medium" | "high",
    fix_available: boolean,
    rule_id: string,
    compliance_frameworks: string[]
  }>,
  onClose: () => void,
  onGenerateFix: (finding_id: string) => void
}
```

**Layout:** Same slide-in as AttackChainPanel. Inside: 3-column Kanban `grid grid-cols-3 gap-3`.

**Columns:**
- `"Now"` (`bg-red-950`): `severity in ['critical','high'] AND effort='low' AND fix_available=true`
- `"This Sprint"` (`bg-orange-950`): `severity in ['high','medium'] AND effort='medium'`
- `"Backlog"` (`bg-slate-800`): everything else

**Card:** `bg-slate-700 rounded-lg p-3`
- Severity dot + title
- `{N} resources affected` badge
- `<button onClick={() => onGenerateFix(finding.finding_id)} className="bg-emerald-700 hover:bg-emerald-600 text-white text-xs px-2 py-1 rounded">Generate IaC Fix</button>` (only rendered if `fix_available=true`)
- Compliance framework badges row: `text-xs bg-slate-600 rounded px-1.5 py-0.5`

---

### 3.10 `components/cwpp/WorkloadRadarChart.jsx`

**Purpose:** Pure SVG 5-axis radar chart showing posture scores.

**Props:**
```typescript
{
  workloads: Array<{
    id: string,
    name: string,
    posture_score: number
  }>,
  size?: number,  // default 360
  onWorkloadClick?: (id: string) => void
}
```

**SVG spec:**
- `viewBox="-200 -200 400 400"` (centered)
- Axis angles (0° = up): containers=0°, images=72°, hosts=144°, serverless=216°, runtime=288°
- Axis line: `stroke="#1e293b"` to full radius (100px)
- Reference polygon (100 score): `stroke="#334155" strokeDasharray="3 3" fill="none"`
- Posture polygon: `fill="rgba(99,102,241,0.2)" stroke="#6366f1" strokeWidth=2`
  - Each vertex: `x = sin(angle) × (score/100 × 100)`, `y = -cos(angle) × (score/100 × 100)`
- Score label at axis tip+16px: `"{name}\n{score}"`, `fontSize=10 fill="#94a3b8" textAnchor="middle"`
  - Label is `<text>` with `<tspan>` for each line
- Center label: CWPP Score in `fontSize=16 fontWeight=bold fill="#e2e8f0"`
- Click on axis label area: `onWorkloadClick(workload.id)`

**Data source:** `data.workloads` from `fetchView('cwpp')` — no additional endpoint needed.

---

### 3.11 `components/cwpp/CiemRuntimeCard.jsx`

**Purpose:** Shows CIEM behavioral event summary in CWPP Runtime tab.

**Props:**
```typescript
{
  ciemRuntimeEvents: {
    count: number,
    critical: number,
    high: number,
    medium: number,
    low: number,
    link_available: boolean,
    sample_findings: Array<{title: string, severity: string, actor_principal: string, event_time: string}>
  },
  accountId: string
}
```

**Layout:** `bg-slate-800 rounded-xl p-4 mb-4 border border-indigo-800`

**States:**
- `count > 0 AND link_available`: Show severity mini-bars + CTA link
- `count === 0 AND link_available`: Show `"No CIEM runtime events detected for this account"` in `text-slate-500 text-sm`
- `!link_available`: Show `"CIEM engine unavailable"` in `text-slate-500 text-sm italic`

**Severity mini-bar** (when events present):
```jsx
<div className="flex gap-1 my-2">
  {['critical','high','medium'].map(sev => (
    <span key={sev} className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_BG[sev]}`}>
      {ciemRuntimeEvents[sev]}
    </span>
  ))}
</div>
```

**CTA link:**
```jsx
<a href={`/ciem?filter=action_category:runtime&account=${accountId}`}
  className="text-indigo-400 hover:text-indigo-300 text-sm font-medium flex items-center gap-1">
  View Full Behavioral Timeline in CIEM
  <ArrowRightIcon className="w-3 h-3" />
</a>
```

---

### 3.12 `components/cwpp/CveCrosswalkTable.jsx`

**Purpose:** Groups CVEs/rules across workload types to find cross-workload exposure.

**Props:**
```typescript
{
  crosswalkRows: Array<{
    id: string,  // CVE ID or rule_id
    severity: string,
    workload_types: string[],  // which workloads have this
    affected_resources: number,
    mitre_technique: string,
    epss_score: number | null
  }>,
  onRowClick: (id: string) => void
}
```

**Table columns:**
| Column | Render |
|--------|--------|
| CVE/Rule ID | `font-mono text-xs` |
| Severity | `<SeverityBadge>` |
| Workload Types | Icon row: 🐳=containers, 📦=images, 🖥️=hosts, ⚡=serverless, ⚙️=runtime — show colored if present, `opacity-20` if absent |
| Affected Resources | Number |
| MITRE Technique | `bg-red-950 text-red-300 text-xs px-1.5 rounded` badge |
| EPSS Score | `text-xs` — red if > 0.5, amber if 0.1-0.5, slate if < 0.1, `text-slate-500 italic` if null |

**Filter bar above table:**
- `"Cross-workload only"` toggle (default ON) — filters to rows where `workload_types.length >= 2`
- Severity filter
- EPSS threshold: `number input min=0 max=1 step=0.01` (show only rows with EPSS ≥ threshold)

**KPI mini-strip** (4 cards):
- CVEs in Multiple Workloads (count where `workload_types.length >= 2`)
- Critical Cross-Workload (severity=critical + multi-workload)
- Total Affected Resources (sum of `affected_resources`)
- Highest EPSS (max `epss_score`, or "N/A")

---

## 4. Data Binding Table

| Component | BFF View | Key Fields |
|-----------|----------|-----------|
| `IdentityRiskHeatmap` | `fetchView('ciem/heatmap')` | `data.matrix`, `data.accounts`, `data.principal_types` |
| `IdentityRiskTable` | `fetchView('ciem')` | `data.identitySummary[].actorPrincipalType`, `l2Findings`, `l3Findings` |
| `CiemFilterBar` | `fetchView('ciem')` | `data.logSources` (for L1/L2/L3 counts) |
| `IdentityProfileHeader` | `fetchView('ciem_identity', {principal})` | `risk_score`, `l2_count`, `l3_count`, `source_ips` |
| `BehavioralTimeline` | `fetchView('ciem_identity', {principal})` | `findings[]` sorted by `event_time` |
| `ActivityHeatmap` | `fetchView('ciem_identity', {principal})` | `hourly_distribution[]`, `dow_distribution[]` |
| `AttackChainPanel` | `fetchView('ciem_chain', {finding_id})` | `contributing_steps[]`, `mitre_techniques[]` |
| `BlastRadiusGraph` | `fetchView('ciem_blast_radius', {principal})` | `nodes[]`, `edges[]` (Sprint 2) |
| `WorkloadRadarChart` | `fetchView('cwpp')` | `data.workloads[].posture_score` |
| `CiemRuntimeCard` | `fetchView('cwpp')` | `data.workloadData.runtime.ciemRuntimeEvents` |
| `CveCrosswalkTable` | `fetchView('cwpp_cve_crosswalk')` | `data.crosswalkRows[]` |

---

## 5. New BFF View Contracts Needed

| View | Status | Backed By |
|------|--------|-----------|
| `ciem/heatmap` | New (STORY-CIEM-02) | `GET /api/v1/ciem/identities/heatmap` |
| `ciem_identity` | New (Sprint 1) | `GET /api/v1/ciem/findings?actor_principal=X` + hourly activity |
| `ciem_chain` | New (Sprint 1) | `GET /api/v1/ciem/findings/{id}/timeline` |
| `ciem_blast_radius` | New (Sprint 2) | CIEM + IAM + network + datasec cross-engine join |
| `cwpp_cve_crosswalk` | New (Sprint 2) | Computed from existing CWPP `workloads` dict in BFF |
| `cwpp` | Extend (STORY-CWPP-01) | Add `ciemRuntimeEvents` to runtime section |

---

## 6. Interaction Map

| Interaction | Location | Result |
|-------------|----------|--------|
| Click heatmap cell | `IdentityRiskHeatmap` | Filters `IdentityRiskTable` to that (account × type) |
| Click identity row | `IdentityRiskTable` | Navigate to `/ciem/identity/[encodedPrincipal]` |
| Click "Blast Radius" | Stage 2 page | Navigate to `/ciem/identity/[principal]/blast-radius` |
| Click L2 finding row | Stage 2 findings table | Open `AttackChainPanel` slide-in |
| Click "Remediate" | Stage 2 page | Open `RemediationPanel` slide-in |
| Click ATT&CK badge | `AttackChainPanel` | Hover tooltip with D3FEND countermeasure |
| Click workload card | CWPP Stage 1 | Activate corresponding tab |
| Click radar chart axis | `WorkloadRadarChart` | Activate corresponding tab |
| Click "View CIEM →" | `CiemRuntimeCard` | Navigate to `/ciem?filter=action_category:runtime&account=X` |
| Click CVE crosswalk row | `CveCrosswalkTable` | Opens finding detail for highest-severity affected resource |

---

## 7. State Management

Both pages use the existing `useViewFetch` pattern — no global state manager needed.

New local state requirements per page:

**`/ciem` (Stage 1):**
```javascript
const [filters, setFilters] = useState({ account: null, principalType: null, severity: null, level: ['L1','L2','L3'], timeRange: '24h' })
const [heatmapData, setHeatmapData] = useState(null)  // parallel fetch
```

**`/ciem/identity/[principal]` (Stage 2):**
```javascript
const [attackChainPanelOpen, setAttackChainPanelOpen] = useState(false)
const [attackChainFinding, setAttackChainFinding] = useState(null)
const [remediationOpen, setRemediationOpen] = useState(false)
```

**`/cwpp` (Stage 1):**
```javascript
const [activeTab, setActiveTab] = useState('overview')
```