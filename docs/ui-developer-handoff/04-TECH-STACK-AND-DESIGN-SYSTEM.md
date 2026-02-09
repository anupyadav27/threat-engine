# CSPM Platform — Tech Stack & Design System Recommendations

## Recommended Tech Stack (Figma-compatible component libraries)

### Frontend Framework
- **Next.js 14+** (React) — SSR, file-based routing, API routes
- **TypeScript** — Type safety for API contracts

### UI Component Library (pick one)
| Library | Figma Kit | Best For |
|---------|-----------|----------|
| **Shadcn/UI** (Recommended) | Yes — free Figma kit | Modern, customizable, Tailwind-based |
| Ant Design | Yes — official Figma | Enterprise dashboards, data tables |
| Tremor | Yes — free Figma kit | Dashboard/analytics components |

### Data Visualization
| Library | Use For |
|---------|---------|
| **Recharts** | Line charts, bar charts, area charts (trends, distributions) |
| **React Force Graph** / **D3.js** | Network graph (inventory relationships, attack paths) |
| **Nivo** | Heatmaps (correlation matrix), treemaps (asset distribution) |
| **React Simple Maps** | Geographic threat map |

### Data Table
- **TanStack Table** (React Table v8) — Sorting, filtering, pagination, virtual scroll

### State Management
- **TanStack Query** (React Query) — Server state, caching, polling (scan status)
- **Zustand** — Lightweight client state (tenant selector, filters)

### Authentication (future)
- **NextAuth.js** or **Auth0** — OAuth/SSO integration

---

## Design System Tokens

### Colors (Security Dashboard Palette)
```
Primary:        #1E40AF (blue-700)     — Navigation, primary actions
Secondary:      #7C3AED (violet-600)   — Accent, graphs
Background:     #0F172A (slate-900)    — Dark mode base
Surface:        #1E293B (slate-800)    — Cards, panels
Border:         #334155 (slate-700)    — Dividers

Severity Colors:
  Critical:     #DC2626 (red-600)
  High:         #EA580C (orange-600)
  Medium:       #CA8A04 (yellow-600)
  Low:          #2563EB (blue-600)
  Info:         #64748B (slate-500)

Status Colors:
  Healthy/Pass: #16A34A (green-600)
  Warning:      #CA8A04 (yellow-600)
  Error/Fail:   #DC2626 (red-600)
  Pending:      #64748B (slate-500)
  Running:      #2563EB (blue-600)
```

### Typography
```
Font:           Inter (Google Fonts)
Headings:       600 weight (semibold)
Body:           400 weight (regular)
Code/IDs:       JetBrains Mono (monospace)

Sizes:
  H1:           24px / 1.33 line-height
  H2:           20px / 1.4
  H3:           16px / 1.5
  Body:         14px / 1.5
  Small:        12px / 1.5
  Code:         13px / 1.5 monospace
```

---

## Reusable Component Patterns

### 1. KPI Card
```
┌──────────────┐
│ [Icon]       │
│              │
│    247       │   ← Large number
│ Total Threats│   ← Label
│ ▲ +12 (5%)  │   ← Trend (optional)
└──────────────┘
```
**Used in**: Dashboard, Threat Overview, Compliance Dashboard, SecOps Results

### 2. Data Table (with filters)
```
┌─────────────────────────────────────────────────┐
│ [Filter ▾] [Filter ▾] [Search________] [Export] │
├─────────────────────────────────────────────────┤
│ Col 1 ▾ │ Col 2 ▾ │ Col 3 ▾ │ Col 4 ▾ │ ...   │
│─────────┼─────────┼─────────┼─────────┼────────│
│ row 1   │         │         │         │        │
│ row 2   │         │         │         │        │
├─────────────────────────────────────────────────┤
│ Showing 1-20 of 3,121     [< 1 2 3 ... 157 >] │
└─────────────────────────────────────────────────┘
```
**Used in**: Assets, Threats, Findings, Compliance Controls, Schedules

### 3. Severity Badge
```
[CRITICAL]  [HIGH]  [MEDIUM]  [LOW]  [INFO]
  (red)    (orange) (yellow) (blue)  (gray)
```
**Used in**: Every page with findings/threats

### 4. Status Indicator
```
● Healthy    ● Running    ● Pending    ● Error
 (green)      (blue)       (gray)      (red)
```
**Used in**: Platform Health, Scan Progress, Account Status

### 5. Scan Progress Pipeline
```
Discovery ████████ 100% ✓ → Check ████░░░░ 50% → Threat ░░░░░░░░ 0%
```
**Used in**: Orchestration page, Scan Detail

### 6. Relationship Graph (interactive)
```
Nodes: circles with icon by resource type
Edges: lines with relation labels
Pan/Zoom: mouse wheel + drag
Click node: open detail sidebar
```
**Used in**: Inventory Graph, Attack Paths, Blast Radius

### 7. Framework Gauge
```
     ╭─────╮
    ╱  78%  ╲
   ╱─────────╲
  │  HIPAA    │
   ╲─────────╱
    ╲       ╱
     ╰─────╯
```
**Used in**: Compliance Dashboard

### 8. Tenant/Account Selector (global)
```
[Acme Corp ▾]  [123456789012 (Prod-AWS) ▾]
```
**Persisted in**: URL query params + Zustand store
**Used in**: Every page (top bar)

---

## Page Layout Template

```
┌─────────┬──────────────────────────────────────────────────┐
│         │  [Tenant ▾] [Account ▾]              [User ▾]   │
│         ├──────────────────────────────────────────────────┤
│  Side   │                                                  │
│  Nav    │  Page Content                                    │
│         │                                                  │
│  (240px)│  ┌────────────────────────────────────────────┐  │
│         │  │ Page Header + Filters                      │  │
│         │  ├────────────────────────────────────────────┤  │
│         │  │                                            │  │
│         │  │ Main Content Area                          │  │
│         │  │ (KPI Cards / Charts / Tables)              │  │
│         │  │                                            │  │
│         │  └────────────────────────────────────────────┘  │
│         │                                                  │
└─────────┴──────────────────────────────────────────────────┘

Responsive breakpoints:
  Desktop:  ≥1280px  (sidebar visible, full layout)
  Tablet:   768-1279px (sidebar collapsible)
  Mobile:   <768px (sidebar hidden, hamburger menu)
```

---

## Data Flow Architecture

```
                    ┌──────────────┐
                    │   Next.js    │
                    │   Frontend   │
                    └──────┬───────┘
                           │ HTTP
                           ▼
                    ┌──────────────┐
                    │  NLB (AWS)   │
                    └──────┬───────┘
                           │
                    ┌──────┴───────┐
                    │ Nginx Ingress│
                    └──────┬───────┘
                           │ Path-based routing
              ┌────────────┼────────────┐
              ▼            ▼            ▼
      /gateway/*    /secops/*    /other-engine/*
     ┌─────────┐  ┌──────────┐  ┌──────────┐
     │ API GW  │  │ SecOps   │  │ Engine N │
     │ (proxy) │  │ (direct) │  │ (direct) │
     └────┬────┘  └──────────┘  └──────────┘
          │
    ┌─────┼──────┬────────┬────────┐
    ▼     ▼      ▼        ▼        ▼
 Disc.  Check  Threat  Inventory  ...
```

### Polling Pattern (for async scans)
```typescript
// Use React Query with polling
const { data } = useQuery({
  queryKey: ['scan-status', scanId],
  queryFn: () => fetch(`/gateway/api/v1/discovery/${scanId}/status`),
  refetchInterval: (data) => data?.status === 'completed' ? false : 3000,
});
```

### Global State (tenant/account context)
```typescript
// Zustand store
const useAppStore = create((set) => ({
  tenantId: null,
  accountId: null,
  scanRunId: null, // "latest" or specific ID
  setTenant: (id) => set({ tenantId: id }),
  setAccount: (id) => set({ accountId: id }),
}));
```
