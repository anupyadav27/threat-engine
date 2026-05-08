# Threat Engine UI — Developer Guide

> **Audience:** Frontend engineers contributing to or maintaining the `ui_samples` Next.js application.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites & Setup](#2-prerequisites--setup)
3. [Project Structure](#3-project-structure)
4. [Environment Variables](#4-environment-variables)
5. [Routing & Pages](#5-routing--pages)
6. [Component Library](#6-component-library)
7. [State Management](#7-state-management)
8. [API Integration Layer](#8-api-integration-layer)
9. [Auth System](#9-auth-system)
10. [Styling & Design Tokens](#10-styling--design-tokens)
11. [Adding a New Page](#11-adding-a-new-page)
12. [Adding a New Component](#12-adding-a-new-component)
13. [Mock Data Strategy](#13-mock-data-strategy)
14. [Permissions & RBAC](#14-permissions--rbac)
15. [Theme System](#15-theme-system)
16. [Toast Notifications](#16-toast-notifications)
17. [Global Filter Integration](#17-global-filter-integration)
18. [DataTable Usage](#18-datatable-usage)
19. [Charts Usage](#19-charts-usage)
20. [Code Conventions](#20-code-conventions)
21. [Troubleshooting](#21-troubleshooting)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Next.js 15 App Router                       │
│                    basePath: /ui  (standalone output)           │
├──────────────┬──────────────┬───────────────┬───────────────────┤
│  AppShell    │  Sidebar     │  Header       │  GlobalFilterBar  │
│  (layout)    │  (nav + drag)│  (header)     │  (scope filters)  │
├──────────────┴──────────────┴───────────────┴───────────────────┤
│                      Page Components                            │
│   40+ pages — dashboard, threats, compliance, inventory, ...    │
├──────────────┬──────────────────────────────┬───────────────────┤
│  Shared      │  Chart Components            │  Domain           │
│  Components  │  SeverityDonut, TrendLine,   │  ScanPipeline,    │
│  17 files    │  BarChart, GaugeChart        │  OnboardingWizard │
├──────────────┴──────────────────────────────┴───────────────────┤
│                    Context / State Layer                         │
│  AuthContext · ThemeContext · GlobalFilterContext               │
│  SavedFiltersContext · ToastContext                             │
├──────────────────────────────────────────────────────────────────┤
│                        API Layer (lib/api.js)                    │
│  getFromEngine() · getFromEngineScan() · postToEngine()         │
│  → ELB → Engine Services on EKS                                 │
└──────────────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Framework | Next.js (App Router) | 15.x |
| UI Library | React | 19.x |
| Styling | Tailwind CSS + CSS Custom Properties | 4.x |
| Tables | TanStack React Table | 8.x |
| Charts | Recharts | 2.x |
| Graph viz | react-force-graph-2d | 1.x |
| Icons | Lucide React | 0.460.x |
| Utilities | clsx | 2.x |

---

## 2. Prerequisites & Setup

### Requirements

- **Node.js** 18+ (22 recommended — matches the Docker base image)
- **npm** 9+
- Access to the ELB endpoint OR working with mock data only

### Local Development

```bash
# Clone the repo
git clone <repo-url>
cd threat-engine/ui_samples

# Install dependencies
npm install

# Copy and configure environment variables
cp .env.local.example .env.local
# Edit .env.local — see Section 4

# Start the dev server
npm run dev
# → http://localhost:3001/ui  (port 3001 configured in launch.json)
```

> **Auth note:** With the ELB-backed backend, the login page will call `POST /cspm/api/auth/login/`. In local development, ensure your machine can reach the ELB, or ask an admin to create a local dev user.

### Available Scripts

| Script | Command | Purpose |
|---|---|---|
| Dev server | `npm run dev` | Hot-reload dev server on port 3000 |
| Production build | `npm run build` | Build optimised standalone output |
| Production start | `npm run start` | Serve the production build |
| Lint | `npm run lint` | ESLint with Next.js rules |

---

## 3. Project Structure

```
ui_samples/
├── Dockerfile                   # Multi-stage Docker build
├── next.config.js               # basePath, standalone output
├── jsconfig.json                # @/* path alias
├── tailwind.config.js           # Tailwind config
├── .env.local                   # Local env vars (gitignored)
│
├── docs/                        # Documentation (this file)
│   ├── USER_GUIDE.md
│   ├── DEVELOPER_GUIDE.md
│   └── DEVOPS_GUIDE.md
│
└── src/
    ├── app/                     # Next.js App Router pages
    │   ├── layout.jsx           # Root layout + all providers
    │   ├── globals.css          # CSS custom properties (design tokens)
    │   ├── page.jsx             # Root redirect → /dashboard
    │   │
    │   ├── auth/
    │   │   ├── login/page.jsx
    │   │   └── forgot-password/page.jsx
    │   │
    │   ├── dashboard/page.jsx
    │   ├── threats/             # All threat sub-routes
    │   ├── compliance/          # Compliance + [framework] detail
    │   ├── inventory/           # Inventory + [assetId] + graph + drift
    │   ├── iam/page.jsx
    │   ├── datasec/             # Data security + lineage
    │   ├── misconfig/page.jsx
    │   ├── scans/               # Scans + [scanId] detail
    │   ├── secops/              # IaC scanning
    │   ├── vulnerabilities/page.jsx
    │   ├── risk/page.jsx
    │   ├── reports/page.jsx
    │   ├── notifications/page.jsx
    │   ├── onboarding/
    │   ├── settings/
    │   ├── policies/
    │   ├── rules/page.jsx
    │   └── profile/page.jsx
    │
    ├── components/
    │   ├── charts/              # Recharts wrappers
    │   ├── domain/              # CSPM-specific components
    │   ├── layout/              # AppShell, Sidebar, Header, GlobalFilterBar
    │   └── shared/              # Generic reusable components
    │
    └── lib/
        ├── api.js               # API client
        ├── auth-context.js      # Auth state + login/logout
        ├── constants.js         # App-wide constants + nav config
        ├── global-filter-context.jsx  # Cross-page scope filter
        ├── saved-filters-context.jsx  # Pinned filter presets
        ├── mock-data.js         # Development / fallback data
        ├── permissions.js       # RBAC utilities
        ├── severity-styles.js   # Severity badge/color utilities
        ├── theme-context.js     # Light/dark theme
        └── toast-context.js     # Notification toasts
```

---

## 4. Environment Variables

All `NEXT_PUBLIC_*` variables are **baked into the client bundle at build time**. Never put secrets here.

```bash
# .env.local

# Base URL for engine API calls (via ELB)
NEXT_PUBLIC_API_BASE=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

# cspm-backend URL (for /auth/login/, /auth/me/, etc.)
NEXT_PUBLIC_AUTH_URL=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com/cspm

# Default tenant ID
NEXT_PUBLIC_TENANT_ID=5a8b072b-8867-4476-a52f-f331b1cbacb3
```

### How Variables Flow

```
.env.local
    ↓ (Next.js build)
NEXT_PUBLIC_* embedded in JS bundle
    ↓
lib/constants.js   → API_BASE, TENANT_ID
lib/auth-context.js → AUTH_URL
lib/api.js         → uses API_BASE via constants
```

---

## 5. Routing & Pages

All pages use the Next.js **App Router** (`src/app/` directory). Pages are `'use client'` components.

### Route Convention

| Pattern | Example | Notes |
|---|---|---|
| Static route | `/dashboard` → `src/app/dashboard/page.jsx` | Simple page |
| Dynamic route | `/threats/[threatId]` → `src/app/threats/[threatId]/page.jsx` | Use `params.threatId` |
| Nested | `/threats/analytics` → `src/app/threats/analytics/page.jsx` | Sub-page |

### Page Template

Every page follows this structure:

```jsx
'use client';

import { useState, useEffect } from 'react';
import { getFromEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';
import MetricStrip from '@/components/shared/MetricStrip';
import DataTable from '@/components/shared/DataTable';

export default function MyPage() {
  const [data, setData] = useState(MOCK_DATA);  // Start with mock
  const [loading, setLoading] = useState(true);
  const { provider, account, region } = useGlobalFilter();

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const result = await getFromEngine('engine-name', '/api/v1/engine/endpoint');
        if (result && !result.error && result.items?.length > 0) {
          setData(result.items);  // Replace mock with real data
        }
      } catch (err) {
        // Silently fall back to mock data
        console.warn('API unavailable, using mock data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [provider, account, region]);  // Re-fetch when scope changes

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 style={{ color: 'var(--text-primary)' }}>Page Title</h1>
        <p style={{ color: 'var(--text-tertiary)' }}>Description</p>
      </div>

      {/* Metrics */}
      <MetricStrip groups={[...]} />

      {/* Content */}
      <DataTable data={data} columns={columns} loading={loading} />
    </div>
  );
}
```

---

## 6. Component Library

### Shared Components

#### `<DataTable>`

Full-featured table with sorting, pagination, density controls, and truncation.

```jsx
import DataTable from '@/components/shared/DataTable';

const columns = [
  {
    accessorKey: 'name',
    header: 'Name',
    cell: (info) => <span>{info.getValue()}</span>,
  },
  {
    accessorKey: 'severity',
    header: 'Severity',
    cell: (info) => <SeverityBadge severity={info.getValue()} />,
  },
];

<DataTable
  data={myData}          // Array of row objects
  columns={columns}       // TanStack column definitions
  pageSize={20}           // Rows per page (default: 20)
  loading={isLoading}     // Shows skeleton rows
  emptyMessage="No findings found"
/>
```

#### `<MetricStrip>`

Displays a horizontal strip of KPI groups with labels, values, and trend deltas.

```jsx
import MetricStrip from '@/components/shared/MetricStrip';

<MetricStrip groups={[
  {
    label: '🔴 CRITICAL',
    color: 'var(--accent-danger)',
    cells: [
      {
        label: 'OPEN FINDINGS',
        value: 42,
        valueColor: 'var(--severity-critical)',
        delta: +3,           // Positive = increase
        deltaGoodDown: true, // For metrics where lower is better
        context: 'vs last 7d',
      },
      {
        label: 'ASSETS AT RISK',
        value: 18,
        noTrend: true,       // Hide delta arrow
      },
    ],
  },
]} />
```

#### `<SeverityBadge>`

```jsx
import SeverityBadge from '@/components/shared/SeverityBadge';

<SeverityBadge severity="critical" />  // critical | high | medium | low | info
```

#### `<FilterBar>`

```jsx
import FilterBar from '@/components/shared/FilterBar';

const filterDefs = [
  {
    key: 'severity',
    label: 'Severity',
    options: ['critical', 'high', 'medium', 'low'],
  },
  {
    key: 'provider',
    label: 'Provider',
    options: ['aws', 'azure', 'gcp'],
  },
];

<FilterBar
  filters={filterDefs}
  activeFilters={activeFilters}      // { severity: '', provider: '' }
  onFilterChange={(key, value) => {  // Called when user changes a filter
    setActiveFilters(prev => ({ ...prev, [key]: value }));
  }}
/>
```

#### `<SearchBar>`

```jsx
import SearchBar from '@/components/shared/SearchBar';

<SearchBar
  value={searchText}
  onChange={setSearchText}
  placeholder="Search by name or ID..."
/>
```

#### `<KpiCard>`

```jsx
import KpiCard from '@/components/shared/KpiCard';

<KpiCard
  title="Total Findings"
  value={247}
  delta={+12}
  deltaGoodDown={true}
  icon={<AlertTriangle size={20} />}
  color="var(--accent-danger)"
/>
```

#### `<EmptyState>`

```jsx
import EmptyState from '@/components/shared/EmptyState';

<EmptyState
  icon={<Shield size={40} />}
  title="No threats detected"
  description="All clear — no active threats for the selected scope."
/>
```

#### `<Can>` — Permission Gate

```jsx
import Can from '@/components/shared/Can';

<Can capability="create_scans">
  <button>Start Scan</button>
</Can>
```

Renders children only if the current user has the required capability.

---

### Chart Components

#### `<SeverityDonut>`

```jsx
import SeverityDonut from '@/components/charts/SeverityDonut';

<SeverityDonut
  data={[
    { name: 'Critical', value: 12, color: '#ef4444' },
    { name: 'High', value: 34, color: '#f97316' },
    { name: 'Medium', value: 78, color: '#eab308' },
    { name: 'Low', value: 123, color: '#3b82f6' },
  ]}
  title="Findings"   // Center label
/>
```

#### `<TrendLine>`

```jsx
import TrendLine from '@/components/charts/TrendLine';

<TrendLine
  data={[
    { date: '2026-03-01', critical: 10, high: 23 },
    { date: '2026-03-02', critical: 12, high: 20 },
    // ...
  ]}
  series={[
    { key: 'critical', color: '#ef4444', label: 'Critical' },
    { key: 'high',     color: '#f97316', label: 'High' },
  ]}
/>
```

#### `<GaugeChart>`

```jsx
import GaugeChart from '@/components/charts/GaugeChart';

<GaugeChart value={72} size={180} />  // value: 0-100
```

Color thresholds: red (<40), orange (40–60), yellow (60–80), green (80+).

---

## 7. State Management

All global state uses **React Context**. There is no Redux or Zustand.

### Context Hierarchy (in `layout.jsx`)

```jsx
<ThemeProvider>
  <AuthProvider>
    <ToastProvider>
      <GlobalFilterProvider>
        <SavedFiltersProvider>
          <AppShell>
            {children}
          </AppShell>
        </SavedFiltersProvider>
      </GlobalFilterProvider>
    </ToastProvider>
  </AuthProvider>
</ThemeProvider>
```

### Accessing Context in Components

```jsx
import { useAuth } from '@/lib/auth-context';
import { useTheme } from '@/lib/theme-context';
import { useGlobalFilter } from '@/lib/global-filter-context';
import { useToast } from '@/lib/toast-context';
import { useSavedFilters } from '@/lib/saved-filters-context';

// In any component:
const { user, isAuthenticated, logout } = useAuth();
const { theme, toggleTheme } = useTheme();
const { provider, account, region, setFilter } = useGlobalFilter();
const { success, error } = useToast();
const { savedFilters, saveFilter, deleteFilter } = useSavedFilters();
```

---

## 8. API Integration Layer

All API calls go through `src/lib/api.js`.

### Engine Mapping

Each engine service has a path prefix on the ELB:

```js
// From lib/constants.js → ENGINE_ENDPOINTS
const ENGINE_ENDPOINTS = {
  onboarding:  '/onboarding',
  discoveries: '/discoveries',
  check:       '/check',
  inventory:   '/inventory',
  threat:      '/threat',
  compliance:  '/compliance',
  iam:         '/iam',
  datasec:     '/datasec',
  secops:      '/secops',
  rule:        '/rule',
  risk:        '/risk',
  gateway:     '/gateway',
};
```

### Usage Examples

```js
import { getFromEngine, getFromEngineScan, postToEngine } from '@/lib/api';

// Basic GET — tenant_id auto-injected
const findings = await getFromEngine(
  'threat',                              // engine name
  '/api/v1/threat/findings',             // path
  { scan_run_id: 'latest', limit: 100 }  // optional query params
);

// GET with default scan_id and CSP (for IAM, DataSec)
const iamFindings = await getFromEngineScan(
  'iam',
  '/api/v1/iam-security/findings'
);

// POST
const result = await postToEngine(
  'onboarding',
  '/api/v1/onboarding/accounts',
  { account_id: '123456', provider: 'aws', role_arn: 'arn:aws:...' }
);
```

### Error Handling Pattern

```js
try {
  const result = await getFromEngine('threat', '/api/v1/threat/findings');
  if (result && !result.error && result.findings?.length > 0) {
    setFindings(result.findings);  // Use real data
  }
  // If empty/null → silently keep mock data
} catch (err) {
  console.warn('[API] threat/findings unavailable, using mock data');
  // Mock data remains in state
}
```

---

## 9. Auth System

Authentication is handled by `src/lib/auth-context.js`.

### Flow

```
App loads
  → AuthProvider mounts
  → Checks sessionStorage for cached session
  → If none: calls GET /cspm/api/auth/me/ (cookie-based)
  → If cookie valid: restores session
  → If no cookie: isInitialized=true, isAuthenticated=false
  → AppShell redirects to /auth/login
```

### Login

```js
const { login } = useAuth();

const result = await login(email, password, rememberMe);
if (result.success) {
  router.push('/dashboard');
} else {
  setError(result.error); // Display error message
}
```

### Logout

```js
const { logout } = useAuth();
await logout(); // Clears cookies via API, clears sessionStorage
// AppShell will redirect to /auth/login
```

### Auth Guard

`AppShell` automatically redirects unauthenticated users to `/auth/login`. Auth pages (`/auth/*`) are exempt from this guard.

---

## 10. Styling & Design Tokens

The app uses **CSS custom properties** defined in `src/app/globals.css`. Never use hardcoded hex values — always use the tokens.

### Core Tokens

```css
/* Backgrounds */
--bg-primary          /* Main page background */
--bg-secondary        /* Slightly lighter background */
--bg-card             /* Card / panel background */
--bg-tertiary         /* Hover / subtle background */

/* Text */
--text-primary        /* Main text */
--text-secondary      /* Secondary/dimmer text */
--text-tertiary       /* Hint/placeholder text */
--text-muted          /* Disabled/very dim text */

/* Borders */
--border-primary      /* Main border colour */
--border-secondary    /* Subtle border */

/* Sidebar */
--sidebar-bg          /* Sidebar background */
--sidebar-hover       /* Nav item hover */
--sidebar-active      /* Active nav item background */
--sidebar-active-text /* Active nav item text */

/* Accents */
--accent-primary      /* Blue  (#3b82f6) */
--accent-success      /* Green (#22c55e) */
--accent-warning      /* Amber (#f59e0b) */
--accent-danger       /* Red   (#ef4444) */

/* Severity */
--severity-critical   /* #ef4444 */
--severity-high       /* #f97316 */
--severity-medium     /* #eab308 */
--severity-low        /* #3b82f6 */
--severity-info       /* #6b7280 */
```

### Usage

```jsx
// ✅ Correct — uses design token
<div style={{ color: 'var(--text-primary)', backgroundColor: 'var(--bg-card)' }}>

// ❌ Wrong — hardcoded hex (breaks dark mode)
<div style={{ color: '#f1f5f9', backgroundColor: '#1e293b' }}>
```

### Tailwind Classes

Tailwind is used for layout utilities (`flex`, `grid`, `space-y-6`, `gap-4`, `rounded-xl`, `truncate`, etc.). Colours should always come from CSS custom properties, not Tailwind colour classes.

---

## 11. Adding a New Page

1. **Create the file:**
   ```
   src/app/my-feature/page.jsx
   ```

2. **Add to navigation** in `src/lib/constants.js`:
   ```js
   // In NAV_ITEMS array:
   {
     label: 'My Feature',
     href: '/my-feature',
     icon: 'Radar',   // Must exist in ICON_MAP in Sidebar.jsx
   },
   ```

3. **Add icon to Sidebar.jsx** if it's new:
   ```js
   // In Sidebar.jsx ICON_MAP:
   import { Radar } from 'lucide-react';
   const ICON_MAP = { ..., Radar };
   ```

4. **Add route permissions** in `src/lib/permissions.js`:
   ```js
   export const ROUTE_CAPABILITIES = {
     ...
     '/my-feature': 'view_threats',  // Required capability
   };
   ```

5. **Use the page template** from [Section 5](#5-routing--pages).

---

## 12. Adding a New Component

1. Decide the category: `charts/`, `domain/`, `layout/`, or `shared/`
2. Create the file: `src/components/[category]/MyComponent.jsx`
3. Add `'use client';` at the top (all components are client-side)
4. Use CSS custom properties for all colours
5. Accept `className` and `style` props for composability
6. Export as default

```jsx
'use client';

export default function MyComponent({ title, value, style, className }) {
  return (
    <div
      className={`rounded-xl border p-4 ${className ?? ''}`}
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-primary)', ...style }}
    >
      <p style={{ color: 'var(--text-tertiary)' }}>{title}</p>
      <p style={{ color: 'var(--text-primary)', fontSize: 24, fontWeight: 700 }}>{value}</p>
    </div>
  );
}
```

---

## 13. Mock Data Strategy

All pages ship with built-in mock data that activates when the API is unavailable. This ensures the UI always renders meaningfully, even in offline mode or when an engine is down.

### Pattern

```js
// 1. Define mock data at the top of the page
const MOCK_FINDINGS = [
  { id: 'f-001', title: 'Example finding', severity: 'high', ... },
  // ...
];

// 2. Initialise state with mock
const [findings, setFindings] = useState(MOCK_FINDINGS);

// 3. Try real API — if it works, replace mock; if not, keep mock
useEffect(() => {
  getFromEngine('threat', '/api/v1/threat/findings')
    .then(data => {
      if (data?.findings?.length > 0) setFindings(data.findings);
    })
    .catch(() => {}); // Silently fail → mock stays
}, []);
```

### Adding Mock Data for New Pages

Add your mock data to `src/lib/mock-data.js` as a named export, then import it in your page.

---

## 14. Permissions & RBAC

Use the `<Can>` component or `usePermissions()` hook to gate UI elements.

```jsx
import Can from '@/components/shared/Can';
import { usePermissions } from '@/lib/permissions';

// Component gate
<Can capability="create_scans">
  <button>Start New Scan</button>
</Can>

// Programmatic check
const { hasCapability } = usePermissions();
if (hasCapability('manage_users')) {
  // Show admin options
}
```

### Capability Reference

See [User Guide → Section 20.2](#202-capability-reference) for the full list.

---

## 15. Theme System

The theme system switches between light and dark CSS variable sets.

```jsx
import { useTheme } from '@/lib/theme-context';

const { theme, toggleTheme } = useTheme();
// theme: 'dark' | 'light'
// toggleTheme: () => void
```

**Implementation:** The `ThemeProvider` applies a `data-theme="dark"` attribute to a root `<div>`. CSS rules in `globals.css` under `[data-theme="dark"]` override the `:root` light-mode values.

---

## 16. Toast Notifications

```jsx
import { useToast } from '@/lib/toast-context';

const { success, error, warning, info } = useToast();

// Usage
success('Scan started successfully');
error('Failed to connect to AWS — check credentials');
warning('MFA not enabled for 3 users', { duration: 6000 });
info('Compliance report is ready for download');
```

Toasts auto-dismiss after 4 seconds (configurable via `duration` option).

---

## 17. Global Filter Integration

Every page that needs to respond to the global scope selector should:

```jsx
import { useGlobalFilter } from '@/lib/global-filter-context';

const { provider, account, region, timeRange, filterSummary } = useGlobalFilter();

// Show filter context to user
{filterSummary && (
  <p style={{ color: 'var(--text-tertiary)' }}>
    <span style={{ color: 'var(--accent-primary)' }}>Filtered to:</span>{' '}
    {filterSummary}
  </p>
)}

// Re-fetch data when filters change
useEffect(() => {
  fetchData({ provider, account, region });
}, [provider, account, region]);
```

---

## 18. DataTable Usage

`DataTable` wraps TanStack React Table v8. Column definitions follow the TanStack API:

```jsx
const columns = [
  // Text column
  {
    accessorKey: 'resource_name',
    header: 'Resource',
    cell: (info) => (
      <span className="truncate" style={{ color: 'var(--text-primary)' }}>
        {info.getValue()}
      </span>
    ),
  },

  // Badge column
  {
    accessorKey: 'severity',
    header: 'Severity',
    cell: (info) => <SeverityBadge severity={info.getValue()} />,
  },

  // Computed column (no accessorKey)
  {
    id: 'actions',
    header: '',
    cell: ({ row }) => (
      <button onClick={() => handleAction(row.original.id)}>
        View
      </button>
    ),
  },
];
```

---

## 19. Charts Usage

All charts use `Recharts` and are responsive by default (wrapped in `ResponsiveContainer`).

### Quick Reference

| Component | Use Case |
|---|---|
| `<SeverityDonut>` | Distribution of severity levels |
| `<TrendLine>` | Time-series trend data |
| `<BarChartComponent>` | Categorical comparisons |
| `<GaugeChart>` | Single score/percentage display |

---

## 20. Code Conventions

### File Naming
- Pages: `page.jsx`
- Components: `PascalCase.jsx` (e.g., `DataTable.jsx`)
- Utilities: `kebab-case.js` (e.g., `auth-context.js`)

### Import Order
```js
// 1. React hooks
import { useState, useEffect } from 'react';

// 2. Next.js
import { useRouter } from 'next/navigation';
import Link from 'next/link';

// 3. Third-party
import { Shield } from 'lucide-react';

// 4. Internal lib
import { getFromEngine } from '@/lib/api';
import { useGlobalFilter } from '@/lib/global-filter-context';

// 5. Internal components
import DataTable from '@/components/shared/DataTable';
import MetricStrip from '@/components/shared/MetricStrip';
```

### Dos and Don'ts

| ✅ Do | ❌ Don't |
|---|---|
| Use `var(--token-name)` for all colours | Use hardcoded hex values |
| Use `'use client';` at top of every file | Use Server Components (not compatible) |
| Start state with mock data | Leave state as `[]` and show empty until API |
| Wrap API calls in try/catch | Let unhandled API errors break the page |
| Use `space-y-6` for consistent vertical spacing | Use arbitrary `margin-top` values |
| Add `loading` prop to DataTable during fetch | Show empty table while loading |

---

## 21. Troubleshooting

### Login redirects to `/auth/login` in a loop
**Cause:** Auth context can't reach `/cspm/api/auth/me/` to verify the session.
**Fix:** Check that `NEXT_PUBLIC_AUTH_URL` in `.env.local` points to the running cspm-backend.

### Sidebar width jumps on resize
**Cause:** CSS transition is not disabled during drag.
**Fix:** The `Sidebar.jsx` sets `transition: dragging ? 'none' : 'width 200ms ease'` — this is already handled. If you see jumps, ensure `dragging` state is updating correctly.

### Charts don't render (blank white box)
**Cause:** `ResponsiveContainer` needs a parent with explicit height.
**Fix:** Wrap the chart in a div with `style={{ height: 300 }}`.

### Content area doesn't shift when sidebar resizes
**Cause:** `AppShell.jsx` uses `var(--sidebar-width)` CSS variable for `marginLeft`. The variable is set on `document.documentElement` by `Sidebar.jsx`.
**Fix:** Ensure the `useEffect` in `Sidebar.jsx` is running (it requires `collapsed` and `sidebarWidth` state to be present).

### API calls returning 404
**Cause:** Engine service may be down, or the endpoint path is wrong.
**Fix:** Check `ENGINE_ENDPOINTS` in `constants.js` and verify the engine is healthy at `GET /[engine]/api/v1/health`.

### `var(--accent-primary)` not resolving
**Cause:** Custom property not defined in `globals.css`.
**Fix:** Add missing token to both `:root` (light) and `[data-theme="dark"]` blocks.

---

*For questions or contributions, open a PR and tag a frontend reviewer.*
