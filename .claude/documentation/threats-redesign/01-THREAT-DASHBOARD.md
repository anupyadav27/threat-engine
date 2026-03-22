# Page 1: Threat Dashboard (`/threats`)

> Enterprise benchmark: Wiz Issues Dashboard, Orca Alert Dashboard, Prisma Cloud Alerts

---

## Page Purpose
Primary entry point for security analysts. Answers: "What threats exist? Which matter most? What's trending?"

NOT a findings page. Shows **contextualized risk scenarios**, not raw rule violations.

---

## Block-Level UI Design

```
┌─────────────────────────────────────────────────────────────────────┐
│ HEADER BAR                                                         │
│ ┌──────────┐  ┌──────────────────────────────────────────────────┐ │
│ │ Threats   │  │ [Provider ▼] [Account ▼] [Region ▼] [Status ▼] │ │
│ │ Overview  │  │ [Severity ▼] [MITRE Tactic ▼] [Search... 🔍]   │ │
│ └──────────┘  └──────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ KPI STRIP (6 cards)                                                │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ ┌────┐│
│ │ Total   │ │Critical │ │ High    │ │ Active  │ │Unassig-│ │Avg ││
│ │ Threats │ │ Threats │ │ Threats │ │ Threats │ │  ned   │ │Risk││
│ │  847    │ │   23    │ │  156    │ │  412    │ │  189   │ │ 67 ││
│ │ ↑12%    │ │ ↑3      │ │ ↓5%     │ │ ↓2%     │ │ ↑15    │ │ ↑4 ││
│ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └────────┘ └────┘│
├─────────────────────────────────────────────────────────────────────┤
│ ROW 2: CHARTS (3-column)                                           │
│ ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────────┐ │
│ │ SEVERITY DONUT   │ │ 30-DAY TREND     │ │ TOP AFFECTED         │ │
│ │                  │ │                  │ │ SERVICES             │ │
│ │   ┌───┐          │ │  ╱\   /\         │ │ ─── EC2 (45)         │ │
│ │   │   │  Crit 23 │ │ /  \_/  \__      │ │ ─── S3  (38)         │ │
│ │   │   │  High156 │ │                  │ │ ─── IAM (29)         │ │
│ │   └───┘  Med 412 │ │  crit|high|med   │ │ ─── RDS (17)         │ │
│ │          Low 256 │ │                  │ │ ─── Lambda (12)      │ │
│ └──────────────────┘ └──────────────────┘ └──────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 3: MITRE ATT&CK MATRIX (full width, collapsible)              │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ MITRE ATT&CK Coverage                            [Expand ▼]   │ │
│ │                                                                 │ │
│ │ Initial     Execution  Persistence  Priv Esc   Defense    ...  │ │
│ │ Access                                          Evasion        │ │
│ │ ┌────────┐  ┌────────┐ ┌──────────┐ ┌────────┐ ┌────────┐     │ │
│ │ │T1078   │  │T1059   │ │T1098     │ │T1548   │ │T1562   │     │ │
│ │ │Valid   │  │Command │ │Account   │ │Abuse   │ │Impair  │     │ │
│ │ │Accounts│  │Script  │ │Manip.    │ │Elev.   │ │Defenses│     │ │
│ │ │■■■ 12  │  │■■ 8    │ │■■■■ 15  │ │■■ 6    │ │■■■ 11  │     │ │
│ │ ├────────┤  ├────────┤ ├──────────┤ │        │ │        │     │ │
│ │ │T1190   │  │        │ │T1136     │ │        │ │T1535   │     │ │
│ │ │Exploit │  │        │ │Create   │ │        │ │Unused  │     │ │
│ │ │Public  │  │        │ │Account  │ │        │ │Regions │     │ │
│ │ │■■ 7    │  │        │ │■ 3      │ │        │ │■ 2     │     │ │
│ │ └────────┘  └────────┘ └──────────┘ └────────┘ └────────┘     │ │
│ └─────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 4: THREATS TABLE (primary content, full width)                 │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ ┌───────────────────────────────────────────────────────────┐   │ │
│ │ │ [Tab: All] [Critical] [High] [Attack Paths] [Unassigned] │   │ │
│ │ └───────────────────────────────────────────────────────────┘   │ │
│ │                                                                 │ │
│ │ Risk│ Title                │MITRE    │Severity│Resource│Provider│ │
│ │ ────┼──────────────────────┼─────────┼────────┼────────┼────────│ │
│ │  95 │ Public S3 bucket     │T1530    │●CRIT   │  3     │  AWS   │ │
│ │     │ with PII exposure    │Collectn │        │        │        │ │
│ │ ────┼──────────────────────┼─────────┼────────┼────────┼────────│ │
│ │  88 │ Overprivileged IAM   │T1078    │●HIGH   │  1     │  AWS   │ │
│ │     │ role with admin path │InitAcces│        │        │        │ │
│ │ ────┼──────────────────────┼─────────┼────────┼────────┼────────│ │
│ │  82 │ Internet-exposed RDS │T1190    │●HIGH   │  1     │  AWS   │ │
│ │     │ with weak auth       │InitAcces│        │        │        │ │
│ └─────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│ ROW 5: SECONDARY PANELS (2-column)                                 │
│ ┌────────────────────────────────┐ ┌──────────────────────────────┐ │
│ │ TOP ATTACK CHAINS              │ │ THREAT INTELLIGENCE          │ │
│ │                                │ │                              │ │
│ │ 1. Public EC2 → IAM Role →    │ │ Source    │Indicator│Matches │ │
│ │    S3 Crown Jewel              │ │ MITRE    │T1078    │  12    │ │
│ │    ●●● Critical  3 hops       │ │ CISA KEV │CVE-2024 │   5    │ │
│ │    [View Path →]               │ │ OTX      │IoC:IP   │   3    │ │
│ │                                │ │                              │ │
│ │ 2. Lambda → DynamoDB →         │ │ [View All Intelligence →]   │ │
│ │    Cross-account trust         │ │                              │ │
│ │    ●● High  4 hops            │ │                              │ │
│ │    [View Path →]               │ │                              │ │
│ └────────────────────────────────┘ └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Inventory

| Component | Type | Library | Props |
|-----------|------|---------|-------|
| HeaderBar | Layout | Custom | title, breadcrumbs |
| GlobalFilterBar | Interactive | Custom | filters: provider, account, region, severity, status, tactic, search |
| KpiStrip | Display | Custom | cards: [{label, value, delta, deltaType, icon}] |
| SeverityDonut | Chart | Recharts PieChart | data: [{name, value, color}] |
| TrendLineChart | Chart | Recharts AreaChart | data: [{date, critical, high, medium, low}] |
| TopServicesBar | Chart | Recharts BarChart | data: [{name, critical, high, medium, low}] |
| MitreMatrixGrid | Display | Custom CSS Grid | matrix: {tactic: [{id, name, count, severity}]} |
| ThreatTable | Data | Custom DataTable | threats: [], columns: [], onRowClick, sortable |
| SeverityBadge | Display | Badge | severity: string |
| RiskScoreBar | Display | Custom | score: 0-100, color-coded |
| AttackChainCard | Display | Card | chain: {name, severity, hops, resources} |
| ThreatIntelTable | Data | DataTable | intel: [{source, indicator, type, relevance, matches}] |
| TabBar | Navigation | Custom | tabs: [], activeTab, onTabChange |

---

## JSON Data Contract (BFF → UI)

```jsonc
// GET /api/v1/views/threats?tenant_id=X&provider=&account=&region=&scan_run_id=latest
{
  // ── KPI Strip ──
  "kpi": {
    "total": 847,
    "critical": 23,
    "high": 156,
    "medium": 412,
    "low": 256,
    "active": 412,
    "unassigned": 189,
    "avgRiskScore": 67,
    // Deltas (compared to previous scan)
    "deltas": {
      "total": { "value": 12, "type": "percent", "direction": "up" },
      "critical": { "value": 3, "type": "absolute", "direction": "up" },
      "high": { "value": -5, "type": "percent", "direction": "down" },
      "active": { "value": -2, "type": "percent", "direction": "down" }
    }
  },

  // ── Severity Distribution (Donut) ──
  "severityChart": [
    { "name": "Critical", "value": 23, "color": "#ef4444" },
    { "name": "High", "value": 156, "color": "#f97316" },
    { "name": "Medium", "value": 412, "color": "#eab308" },
    { "name": "Low", "value": 256, "color": "#3b82f6" }
  ],

  // ── 30-Day Trend (Area Chart) ──
  "trendData": [
    {
      "date": "2026-02-15",
      "critical": 5, "high": 42, "medium": 120, "low": 80,
      "total": 247
    }
    // ... 30 entries
  ],

  // ── Top Affected Services (Bar Chart) ──
  "topServices": [
    { "name": "EC2", "critical": 8, "high": 22, "medium": 15, "total": 45 },
    { "name": "S3", "critical": 5, "high": 18, "medium": 15, "total": 38 },
    { "name": "IAM", "critical": 4, "high": 12, "medium": 13, "total": 29 },
    { "name": "RDS", "critical": 3, "high": 8, "medium": 6, "total": 17 },
    { "name": "Lambda", "critical": 2, "high": 5, "medium": 5, "total": 12 }
  ],

  // ── MITRE ATT&CK Matrix ──
  "mitreMatrix": {
    "Initial Access": [
      { "id": "T1078", "name": "Valid Accounts", "count": 12, "severity": "high" },
      { "id": "T1190", "name": "Exploit Public-Facing App", "count": 7, "severity": "critical" }
    ],
    "Persistence": [
      { "id": "T1098", "name": "Account Manipulation", "count": 15, "severity": "high" }
    ]
    // ... per tactic
  },

  // ── Threats Table ──
  "threats": [
    {
      "id": "tf_abc123",
      "title": "Public S3 bucket with PII data exposure",
      "severity": "critical",
      "riskScore": 95,
      "status": "active",
      "mitreTechnique": "T1530",
      "mitreTactic": "Collection",
      "provider": "AWS",
      "account": "588989875114",
      "region": "ap-south-1",
      "affectedResources": 3,
      "resourceType": "s3.bucket",
      "detected": "2026-03-15T10:30:00Z",
      "assignee": "",
      "environment": "production",
      "hasAttackPath": true,
      "isInternetExposed": true,
      "hasSensitiveData": true,
      "remediationSteps": ["Disable public access", "Enable encryption"]
    }
    // ... paginated
  ],
  "total": 847,

  // ── Attack Chains (Top 5) ──
  "attackChains": [
    {
      "id": "ap_001",
      "name": "Public EC2 → IAM Role → S3 Crown Jewel",
      "severity": "critical",
      "hops": 3,
      "affectedResources": 5,
      "detectionTime": "2026-03-14T08:00:00Z",
      "techniques": ["T1190", "T1078", "T1530"],
      "provider": "AWS",
      "account": "588989875114"
    }
  ],

  // ── Threat Intelligence (Top 10) ──
  "threatIntel": [
    {
      "source": "MITRE ATT&CK",
      "indicator": "T1078",
      "type": "technique",
      "relevance": 95,
      "matchedAssets": 12
    }
  ],

  // ── By Provider (Donut or bar) ──
  "byProvider": {
    "AWS": 680,
    "AZURE": 120,
    "GCP": 47
  }
}
```

---

## Data Flow: What Engine Provides vs What's Needed

### From Threat Engine (`/api/v1/threat/ui-data`)

| Field | Engine Provides | BFF Transform | Status |
|-------|----------------|---------------|--------|
| threats[] | ✅ `threats` array with finding_id, rule_id, severity, etc. | normalize_threat() → camelCase | ✅ READY |
| summary.total/critical/high | ✅ `summary` object | Map to kpi | ✅ READY |
| trendData | ✅ `trend[]` with date, total, critical, high, medium, low | Rename keys | ✅ READY |
| mitreMatrix | ✅ `mitre_matrix[]` with technique_id, tactics[], count | Group by tactic | ✅ READY |
| attackChains | ✅ `attack_paths[]` | normalize_attack_chain() | ✅ READY |
| threatIntel | ✅ `threat_intel[]` | normalize_intel() | ✅ READY |
| **topServices** | ✅ `summary.by_service[]` with service, count, crit/high/med/low | Rename, limit to top 5 | ✅ READY |
| **deltas** | ❌ Not provided | Compute from previous scan | 🔴 NEW — compare 2 scans |
| **hasAttackPath** | ❌ Not on finding | Derive from attack_paths | 🟡 BFF can infer |
| **isInternetExposed** | ❌ Not on finding | Cross-ref internet_exposed | 🟡 BFF can infer |
| **hasSensitiveData** | ❌ Not on finding | Would need datasec cross-ref | 🔴 NEW |
| **assignee** | ❌ Column missing from DB | Add column + PATCH endpoint | 🔴 NEW — DB migration |
| **environment** | ❌ Not in schema | Derive from tags/account mapping | 🟡 BFF can infer |

### What's Missing (Action Required)

1. **DB Migration**: Add `assignee VARCHAR(255)` and `notes TEXT` to `threat_findings`
2. **Delta computation**: BFF should fetch current + previous scan summaries, compute change
3. **Attack path enrichment**: After loading attack_paths, build a Set of resource_uids that have paths
4. **Internet exposure flag**: After loading internet_exposed, build a Set of exposed resource_uids
5. **Sensitive data flag**: Optional — requires cross-engine call to datasec

---

## BFF Module: `bff/threats.py` (Updated)

### Current State
- Already exists, produces correct shape
- Calls `/api/v1/threat/ui-data` + `/api/v1/onboarding/ui-data`
- Returns: kpi, threats, mitreMatrix, attackChains, threatIntel, severityChart, trendData, byProvider

### Required Changes
1. **Add `topServices`** — extract from `summary.by_service`, limit to top 5, sort by total desc
2. **Add `deltas`** — compare current summary with previous scan (fetch 2 scans)
3. **Add `hasAttackPath` flag** — set on each threat by matching resource_uid against attack_paths
4. **Add `isInternetExposed` flag** — set on each threat by matching against internet_exposed resources
5. **Add filter support** — severity, status, mitre_tactic, search text
6. **Pagination** — add limit/offset pass-through

---

## UI Component Specifications

### KpiStrip
```
Props:
  cards: Array<{
    label: string        // "Total Threats"
    value: number        // 847
    icon: LucideIcon     // Shield
    color: string        // "text-red-500"
    delta?: {
      value: number      // 12
      type: "percent" | "absolute"
      direction: "up" | "down"
    }
  }>

Layout: 6-column grid (responsive: 3×2 on tablet, 2×3 on mobile)
Height: 88px per card
```

### MitreMatrixGrid
```
Props:
  matrix: Record<string, Array<{id, name, count, severity}>>

Layout: CSS Grid, columns = number of tactics
Each tactic column:
  - Header: tactic name (bold, uppercase)
  - Techniques stacked vertically
  - Each technique card:
    - ID (monospace, small)
    - Name (truncated to 2 lines)
    - Heat bar (colored by severity, width by count)
    - Count badge

Interaction: Click technique → navigate to threat detail filtered by technique
Responsive: Horizontal scroll on mobile
```

### ThreatTable
```
Columns:
  1. Risk Score    — ColoredBar (0-100, red/orange/yellow/green)
  2. Title         — Text + subtitle (resource_type)
  3. MITRE         — Badge: T-code + tactic name
  4. Severity      — SeverityBadge (pill: Critical/High/Medium/Low)
  5. Resources     — Count badge
  6. Provider      — Cloud icon + text
  7. Status        — StatusBadge (Active/Resolved/Suppressed)
  8. Detected      — Relative time ("2h ago", "3d ago")
  9. Assignee      — Avatar or "Unassigned" (muted)

Row click → navigate to /threats/{id}
Sort: Default by riskScore DESC
Tabs: All | Critical | High | With Attack Path | Unassigned
```
