---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
inputDocuments: ["_bmad-output/planning-artifacts/prd.md", "_bmad-output/planning-artifacts/architecture.md"]
---

# UX Design Specification — threat-engine

**Author:** Anup
**Date:** 2026-05-02

---

## Executive Summary

### Project Vision

Two specialist pages for the Threat Engine CSPM portal (Next.js 15 + React 19, dark theme) — a Billing & Subscription portal (`/ui/billing`) and a Platform Admin Dashboard (`/ui/admin/dashboard`). Both pages are already implemented; this specification captures the assessed current state, improvement rationale, and the agreed target layout to rebuild toward.

### Target Users

| Page | Primary User | Secondary User |
|------|-------------|----------------|
| `/ui/billing` | **org_admin** — owns subscription, pays the bill, upgrades tiers | **tenant_admin** — read-only usage viewer |
| `/ui/admin/dashboard` | **platform_admin** — SaaS ops monitoring all customer orgs | None (gated) |

### Key Design Challenges

1. **Billing page** — mixing commercial urgency (upgrade CTAs) with operational data (usage bars) risks cognitive overload; trial/past-due states need prominent visual treatment.
2. **Plan grid** — 4 PlanCards collapsed behind a disclosure hides the upgrade path at the exact moment a user wants to act.
3. **Admin dashboard** — 20+ engine tiles in alphabetical order loses scanability; operators need to spot red/yellow fast without scrolling.
4. **Admin table** — 10-row pagination creates too many clicks when managing 50+ orgs.

### Design Opportunities

- Surface trial countdown prominently on billing page — drives conversion.
- Separate "current state" (plan + usage) from "change state" (upgrade flow) into a cleaner two-zone layout.
- Group engines by pipeline stage (Discovery → Check → Threat → Compliance) so operators read health in data-flow order.

---

## Block-Level Wireframes

### Page 1: `/ui/billing` — Current Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  💳 Billing & Subscription                                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  [BANNER] ⚠ Payment failed — update card  [✕]          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  CURRENT PLAN CARD                                        │   │
│  │  [PRO badge]  [active badge]    $149/mo   Renews Jun 1   │   │
│  │                                 [Manage Billing →]        │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  USAGE METERS                                             │   │
│  │  Cloud Accounts  ████████░░░░  8 / 15                    │   │
│  │  Scans Today     ██████████░░  48 / 50                   │   │
│  │  Scans/Month     ████░░░░░░░░  320 / 1000                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ▶  View / change plan   (collapsible — CLOSED by default)       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  [FREE]   [STARTER $49]   [PRO $149 ★]   [ENT $499]      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  INVOICE HISTORY                                          │   │
│  │  Date       Amount    Status    Link                      │   │
│  │  2026-04-01  $149.00  ✓ Paid    [Download]               │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  Downgrade or cancel subscription                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Page 1: `/ui/billing` — Proposed Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  💳 Billing & Subscription                                       │
├─────────────────────────────────────────────────────────────────┤
│  [BANNER — trial/warning/error, sticky]                          │
│  ⏳ Trial ends in 6 days — upgrade to keep access  [Upgrade Now] │
├──────────────────────┬──────────────────────────────────────────┤
│  LEFT PANEL (40%)    │  RIGHT PANEL (60%)                        │
│                      │                                           │
│  ┌──────────────────┐│  ┌──────────────────────────────────────┐│
│  │ CURRENT PLAN     ││  │ USAGE vs LIMITS                       ││
│  │ [PRO]  [active]  ││  │ Cloud Accounts  ████████░░  8/15      ││
│  │ $149/mo          ││  │ Scans Today     ██████████  48/50 ⚠  ││
│  │ Renews Jun 1     ││  │ Scans/Month     ████░░░░░░  320/1k    ││
│  │ [Manage Billing] ││  │ ── Upgrading to ENT gives ──          ││
│  └──────────────────┘│  │    30 accounts · 5000 scans/month     ││
│                      │  └──────────────────────────────────────┘│
│  ┌──────────────────┐│                                           │
│  │ PLAN OPTIONS     ││  ┌──────────────────────────────────────┐│
│  │ ○ FREE    —      ││  │ INVOICE HISTORY            [All →]    ││
│  │ ○ STARTER $49    ││  │ Apr 2026  $149.00  ✓ Paid  [↓]       ││
│  │ ● PRO    $149 ★  ││  │ Mar 2026  $149.00  ✓ Paid  [↓]       ││
│  │ ○ ENT    $499    ││  │ Feb 2026  $149.00  ✓ Paid  [↓]       ││
│  │ [Upgrade to ENT] ││  │ Downgrade or cancel  (subtle link)   ││
│  └──────────────────┘│  └──────────────────────────────────────┘│
└──────────────────────┴──────────────────────────────────────────┘
```

---

### Page 2: `/ui/admin/dashboard` — Current Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  ⊞ Platform Admin Dashboard                    [↻ Refresh]      │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │Total Orgs│  │Trials    │  │Past Due  │  │Engines Healthy   ││
│  │    12    │  │Expiring  │  │  2       │  │   18 / 21        ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Orgs by Tier  [FREE 25%][STARTER 17%][PRO 41%][ENT 17%]        │
├─────────────────────────────────────────────────────────────────┤
│  Engine Health (alphabetical flat grid, 2-6 cols)                │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
│  │● disc│ │● chk │ │● thr │ │● inv │ │● com │ │● iam │        │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘        │
│  ... 21 total tiles                                              │
├─────────────────────────────────────────────────────────────────┤
│  Org Name    Tier    Status    Accounts  Trial End  Created      │
│  [< 1 2 3 >]                                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Page 2: `/ui/admin/dashboard` — Proposed Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  ⊞ Platform Admin Dashboard         [↻ Refresh]  [⚙ Settings]  │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │ 12 Orgs  │  │ 3 Trials │  │ ⚠ 2 Past │  │ ● 18/21 Engines ││
│  │ [filter▾]│  │ [filter▾]│  │   Due    │  │   Healthy        ││
│  │          │  │          │  │ [filter▾]│  │ [filter▾]        ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘│
│            (clicking any card filters org table below)           │
├─────────────────────────────────────────────────────────────────┤
│  ENGINE HEALTH — grouped by pipeline stage                       │
│                                                                   │
│  INGEST           CHECK          ANALYSIS          REPORTING     │
│  ┌─────────────┐  ┌───────────┐  ┌─────────────┐  ┌──────────┐ │
│  │● discovery  │  │● check    │  │● threat     │  │● comply  │ │
│  │● inventory  │  │● rule     │  │● iam        │  │● risk    │ │
│  │● onboarding │  │           │  │● ciem       │  │          │ │
│  └─────────────┘  └───────────┘  │● network    │  └──────────┘ │
│                                  │● datasec    │                │
│  ENTERPRISE ENGINES              │● secops     │                │
│  ┌──────────────────────────┐    │● vuln       │                │
│  │● ai-sec  ● encryption    │    │● container  │                │
│  │● dbsec   ● fix-engines   │    └─────────────┘                │
│  └──────────────────────────┘                                   │
│  Each tile: status-dot  name  Xms  N pods                        │
├─────────────────────────────────────────────────────────────────┤
│  ORGANISATIONS              Filter: [All ▾]  [🔍 Search…]       │
│                                                                   │
│  Org Name    Tier    Status     Accts   Trial End  Actions       │
│  ─────────   ──────  ─────────  ──────  ─────────  ──────────── │
│  Acme Corp   PRO     ● active   8/15    —          [Grant trial] │
│  Beta Ltd    TRIAL   ⏳ 6d left  2/15    2026-05-08 [Extend][↑]  │
│  Gamma Inc   ENT     ● active   22/25   —          [View usage]  │
│  Delta Co    FREE    ⚠ past due 0/3     —          [Contact]    │
│                                                                   │
│  Show: [10 ▾]   Showing 1-10 of 42      [< 1 2 3 4 5 >]        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Proposed Changes Summary

| # | Page | Change | Priority |
|---|------|--------|----------|
| 1 | Billing | Two-column layout (plan+selector left, usage+invoices right) | High |
| 2 | Billing | Plan selector always visible (remove collapsible) | High |
| 3 | Billing | Inline ⚠ on near-limit usage meters | Medium |
| 4 | Billing | Trial banner sticky + action CTA | High |
| 5 | Billing | Contextual upgrade hint inside usage panel | Medium |
| 6 | Admin | Group engine tiles by pipeline stage | High |
| 7 | Admin | MetricCards clickable → filter org table | High |
| 8 | Admin | Actions column (Extend/Grant/View/Contact) | High |
| 9 | Admin | Per-row countdown ("6d left") instead of raw date | Medium |
| 10 | Admin | Remove tier breakdown bar (redundant with table) | Low |
| 11 | Admin | Configurable row-count selector (10/25/50) | Low |

---

## Core User Experience

### Defining Experience

**Billing page — core action:** See you're near a limit and upgrade in one motion. The org_admin opens billing, sees a usage bar at 96%, and the upgrade path is visible on the same screen without navigation or expanding a collapsible. That loop must be < 3 clicks: see problem → select tier → confirm on Stripe → return with success banner.

**Admin dashboard — core action:** Spot a degraded engine or at-risk org within 5 seconds of page load. The platform_admin scans health in pipeline order (not alphabetical), jumps from a red tile to the relevant log link, and filters the org table by a single metric card click.

### Platform Strategy

- **Desktop-first** — dark theme, wide viewport; these are power-user ops pages, not mobile
- **Keyboard-friendly** — Tab through org table, Enter to expand actions, Escape to dismiss
- **Auto-refresh on admin dashboard** — 30s polling so the page stays live without manual refresh

### Effortless Interactions

- **Billing:** Plan selection is a radio-button list — pick one, CTA label updates instantly to "Upgrade to [tier]"
- **Billing:** Invoice download is one click, no modal
- **Admin:** Clicking a MetricCard instantly filters the org table — zero loading state or page navigation
- **Admin:** Trial extension is a popover (2 clicks), not a full page

### Critical Success Moments

- **Billing:** User sees `⚠ 48/50 scans today` → reads contextual hint "ENT gives 5000/mo" → clicks Upgrade — all before friction builds
- **Admin:** Operator reads `3/21 engines degraded` on MetricCard → affected tiles highlight in grid → one click to logs

### Experience Principles

1. **Proximity of signal and action** — show the problem and the fix on the same screen, same view
2. **Data-flow navigation** — group information the way operators think (pipeline stages, not alpha)
3. **Progressive urgency** — yellow warning before red alert; inline contextual nudge before hard block
4. **Zero-confirmation for reads, one-confirmation for writes** — table filters are instant; upgrades confirm once on Stripe

---

## Desired Emotional Response

### Primary Emotional Goals

- **Billing page → Confident control:** org_admin feels *in charge*, not pressured. Usage is transparent, upgrade is an informed choice (not a paywall), and anxiety ("am I about to be cut off?") resolves into clarity ("6 days left, here's what I get").
- **Admin dashboard → Calm competence:** platform_admin feels they have the best view in the room. Green dots are boring — that's the goal. When red appears, the layout makes the problem and the diagnosis path immediately obvious.

### Emotional Journey Mapping

| Stage | Billing | Admin |
|-------|---------|-------|
| Arrive | Quick orientation — "here's where I stand" | < 10s scan — "all green, moving on" |
| See a problem | Yellow bar + inline hint → mild urgency, not alarm | Red tile in grouped grid → controlled alert |
| Take action | Tier select → deliberate; Stripe → trusted handoff | Click Extend/Grant → powerful; popover confirms → done |
| After action | Success banner → relief + accomplishment | Green dot restored → satisfaction of resolution |
| Return visit | Familiar layout → zero re-learning | Muscle memory — same grid order every time |

### Micro-Emotions

- **Trust over skepticism** — real numbers (used/limit), no marketing language, downgrade link always visible
- **Accomplishment over frustration** — upgrade completes in < 30s; admin action in 2 clicks
- **Calm over anxiety** — yellow before red; grace periods shown explicitly; no surprise suspensions

### Design Implications

- Confidence → progress bars show exact numbers AND percentage, not just color
- Trust → "Downgrade or cancel" link is reachable, never buried
- Calm → engine unhealthy badge is amber at 1-2 degraded, red at 3+ (not red at first sign)
- Accomplishment → success banner after Stripe return names the change ("You're now on PRO")

### Emotional Design Principles

1. Urgency is earned — yellow precedes red; inline nudge precedes hard block
2. Transparency builds trust — show real limits, real trial countdowns, real latency numbers
3. Familiar structure reduces cognitive load — same layout on every visit, no surprise rearrangements
4. Completion feels rewarding — every write action (upgrade, extend, grant) ends with a visible confirmation

---

## UX Pattern Analysis & Inspiration

### Inspiring Products Analysis

| Product | Key pattern | Apply to |
|---------|------------|----------|
| **Datadog** | Health tiles grouped by service domain, not alphabetical; status = color + text + count | Engine health grid grouping |
| **Stripe Dashboard** | Plan always top-left, never hidden; usage beside plan card; compact 5-row invoice list | Two-column billing layout |
| **Linear** | 8px grid, subtle borders, muted text hierarchy; toasts for write confirmations | Visual language, admin action toasts |
| **Grafana** | Click-to-filter MetricCard pattern affecting all panels simultaneously | MetricCard → org table filter |

### Transferable UX Patterns

| Pattern | Source | Application |
|---------|--------|-------------|
| Grouped health tiles | Datadog | Engine health by pipeline stage |
| Adjacent plan + usage | Stripe | Two-column billing layout |
| Persistent plan selector | Stripe | Replace collapsible with radio list |
| Click-to-filter metrics | Grafana | MetricCard → org table filter |
| Toast for write actions | Linear | Admin action confirmations |
| Compact invoice + "View all" | Stripe | 5 invoices + link |

### Anti-Patterns to Avoid

- Hidden upgrade path behind collapsible — Stripe never hides the plan selector
- Alphabetical engine grid — meaningless to ops engineers; Datadog never does this
- Full-page navigation for drill-down — filter must happen in place
- Generic error banners — every message must name the issue and next action
- Dark-pattern cancel flows — downgrade link must be direct, not a retention wizard

### Design Inspiration Strategy

**Adopt:** Stripe two-column layout · Datadog pipeline-grouped tiles · Grafana click-to-filter

**Adapt:** Linear toast system → admin write confirmations · Stripe compact invoice list (5 rows)

**Avoid:** Grafana query language (overkill) · Datadog sparklines (phase 2) · Modal plan comparison

---

## Design System Foundation

### Design System Choice

**Tailwind CSS v4 with custom CSS variable theming** — already established across the portal. Dark theme is the default (`--bg-primary: #020617`). No new library needed.

### Token Reference

| Role | CSS Variable | Dark value |
|------|-------------|------------|
| Page background | `--bg-primary` | `#020617` |
| Card background | `--bg-card` | `#0f172a` |
| Input / hover | `--bg-tertiary` | `#1e293b` |
| Card border | `--border-primary` | `#1e293b` |
| Divider | `--border-secondary` | `#334155` |
| Body text | `--text-primary` | `#f8fafc` |
| Secondary text | `--text-secondary` | `#cbd5e1` |
| Muted / cancel | `--text-muted` | `#64748b` |
| CTA / active | `--accent-primary` | `#60a5fa` |
| Success / healthy | `--accent-success` | `#4ade80` |
| Warning / near-limit | `--accent-warning` | `#fbbf24` |
| Danger / error | `--accent-danger` | `#f87171` |

### Usage Bar Fill Color Logic

- < 75% used → `--accent-primary` (blue)
- 75–90% used → `--accent-warning` (amber) + ⚠ icon
- > 90% used → `--accent-danger` (red) + ⚠ icon

### Engine Dot Color Logic

- healthy → `--accent-success`
- degraded (latency > 500ms) → `--accent-warning`
- unhealthy (pods = 0) → `--accent-danger`

### New Primitives Required

1. **RadioTierCard** — bordered card with radio dot, plan name, price, feature list, upgrade CTA (billing page, inline JSX)
2. **EngineGroupPanel** — labeled group container wrapping engine tiles by pipeline stage (admin page, inline JSX)

---

## Design Direction Decision

### Design Directions Explored

Six layout directions were considered: (1) current single-column scroll, (2) two-column split, (3) tab-segmented plan vs usage, (4) modal upgrade flow, (5) sidebar plan selector, (6) full-page plan comparison. For admin: (A) current flat grid, (B) pipeline-grouped panels, (C) collapsible stage accordions, (D) map/topology view.

### Chosen Direction

- **Billing:** Direction 2 — two-column split (plan identity + radio selector left, usage meters + invoice history right). Plan selector always visible, no collapsible.
- **Admin:** Direction B — pipeline-grouped engine health panels (Ingest → Check → Analysis → Reporting + Enterprise block), MetricCards as interactive filters, Actions column in org table.

### Design Rationale

- Two-column billing layout spatially links plan choice to usage data — the decision and the evidence are side by side
- Pipeline-grouped engine grid matches how operators mentally model the system — degradation is localised to a stage, not scattered alphabetically
- Interactive MetricCards reduce navigation — drill-down is a single click, not a page change
- Actions column transforms the read-only table into an operations tool without adding new pages

### Implementation Approach

Interactive HTML mockup created at `_bmad-output/planning-artifacts/ux-design-directions.html` — open in browser to verify layouts before code implementation. All 11 proposed changes captured. Proceed to implement in `frontend/src/app/billing/page.jsx` and `frontend/src/app/admin/dashboard/page.jsx`.

---

## Defining Experience Mechanics

### Billing Page — "See limit → upgrade in one motion"

**Flow:**
1. User arrives → left panel shows current tier (● PRO) + radio list · right panel shows usage bars
2. Usage bar > 90% renders red with ⚠ + inline hint: "Upgrading to ENT gives 5000 scans/mo"
3. User clicks ○ ENTERPRISE radio → CTA label updates to "Upgrade to Enterprise — $499/mo"
4. User clicks CTA → POST checkout → Stripe Checkout redirect
5. Payment complete → redirect to `/ui/billing?session=success` → success banner + refreshed usage bars

**Feedback signals:** radio selection highlights instantly (no network call) · CTA label reactive to radio · spinner on CTA click · success banner names the specific change · usage bars re-render post-upgrade

**Error states:** expired Stripe session → warning banner with retry CTA · billing engine down → CTA disabled with "Billing temporarily unavailable"

---

### Admin Dashboard — "Spot degraded → filter → act in < 5s"

**Flow:**
1. User scans MetricCards → sees "⚠ 2 Past Due" (amber border)
2. Click → org table filters to past_due orgs · active filter chip appears: [× past_due]
3. User finds offending row → clicks [Contact] → opens mailto/Slack in new tab
4. User sees "18/21 Healthy" MetricCard → click → 3 non-green engine tiles get warning/danger ring
5. User clicks degraded tile → logs link opens in new tab

**Feedback signals:** filter applied instantly (client-side, no loading) · filter chip with × to clear · engine tiles ring on health filter · row actions open 2-field popover (not navigation) · popover auto-dismisses after 3s with confirmation

**Error states:** platform-admin engine unreachable → MetricCards show "—" with "Data stale" label · extend trial fails → popover shows inline error

---

## Visual Design Foundation

### Color System

Existing CSS variable system — dark theme default. No changes to palette needed. Semantic usage:

| Signal | Token | Hex | When |
|--------|-------|-----|------|
| Healthy / active | `--accent-success` | `#4ade80` | Engine green dot, active badge |
| Warning / near-limit | `--accent-warning` | `#fbbf24` | Usage bar 75-90%, amber dot, trial banner |
| Danger / error | `--accent-danger` | `#f87171` | Usage bar >90%, red dot, past-due badge |
| CTA / selected | `--accent-primary` | `#60a5fa` | Upgrade button, radio selected ring |
| Card surface | `--bg-card` | `#0f172a` | All panel backgrounds |
| Hover / input | `--bg-tertiary` | `#1e293b` | Radio hover, table row hover |

### Typography System

Portal already uses system-default sans via Tailwind. For these two pages:

| Element | Class | Notes |
|---------|-------|-------|
| Page heading | `text-2xl font-bold text-[--text-primary]` | With icon, left-aligned |
| Section label | `text-xs font-semibold uppercase tracking-wider text-[--text-muted]` | Group headers (INGEST, CHECK…) |
| Plan name | `text-lg font-semibold text-[--text-primary]` | In RadioTierCard |
| Plan price | `text-3xl font-bold text-[--text-primary]` | "$149" with `/mo` in text-sm |
| Meter label | `text-sm text-[--text-secondary]` | "Cloud Accounts" |
| Meter count | `text-xs text-[--text-muted]` | "8 / 15" right-aligned |

### Spacing & Layout Foundation

- **Base unit:** 4px (Tailwind default) — gap-4 (16px) between cards, gap-2 (8px) within cards
- **Card padding:** `p-6` (24px) for main panels, `p-4` (16px) for engine tiles
- **Two-column split (billing):** `grid grid-cols-5` → left col `col-span-2`, right col `col-span-3`
- **Engine grid:** `grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4` within each group panel
- **Org table row height:** `py-3` — dense enough for 10 rows without scroll on 1080p

### Accessibility Considerations

- All interactive elements (RadioTierCard, MetricCard, engine tiles) have `focus:ring-2 focus:ring-[--accent-primary]`
- Color is never the sole signal — ⚠ icon accompanies amber/red states
- Engine status: dot + latency text (not dot alone)
- Contrast: `--text-primary` on `--bg-card` = #f8fafc on #0f172a ≈ 16:1 (AAA)
- `aria-label` on MetricCard buttons: "Filter organisations by past due status"

---

## User Journey Flows

### Journey 1: org_admin upgrades plan after hitting scan limit

```
[Open /ui/billing]
     ↓
[Usage bars render — Scans Today 96% RED + ⚠]
     ↓
[Inline hint: "ENT gives 5000 scans/mo"]
     ↓
[User clicks ○ ENTERPRISE radio]  ← radio highlights, CTA label updates
     ↓
[Click "Upgrade to Enterprise — $499/mo"]  ← spinner
     ↓
[POST checkout → Stripe Checkout]
     ↓
[Payment complete → /ui/billing?session=success]
     ↓
[Success banner: "You're now on Enterprise" + bars refresh]
```
**Steps to complete:** 3 user actions. Time: < 45s.

---

### Journey 2: platform_admin investigates past-due orgs

```
[Open /ui/admin/dashboard]
     ↓
[Scan MetricCards — "⚠ 2 Past Due" (amber border)]
     ↓
[Click MetricCard]  ← org table filters instantly, chip appears
     ↓
[Find Delta Co — ⚠ past due — 0/3 accounts]
     ↓
[Click Contact]  ← mailto/Slack opens in new tab
     ↓
[Also: click "3 Trials Expiring"]  ← table re-filters
     ↓
[Find Beta Ltd — 6d left — Click Extend]
     ↓
[Popover: "Extend trial for Beta Ltd" — Confirm]  ← spinner
     ↓
[Popover: "Trial extended to 2026-05-16" — auto-dismiss 3s]
     ↓
[Row updates: "14d left"]
```
**Steps to complete:** 3–4 user actions. Time: < 20s per org.

---

### Journey Patterns

| Pattern | Billing | Admin |
|---------|---------|-------|
| Immediate feedback | Radio highlights (no API) | MetricCard filter (client-side) |
| Progressive commitment | Select tier → click CTA → Stripe confirm | Click filter → click action → popover confirm |
| Graceful degradation | CTA disabled if billing engine down | MetricCards show "—" if platform-admin unreachable |
| Write confirmation | Success banner naming the change | Popover auto-dismiss with result |
| Escape hatch | Stripe cancel returns clean | Popover Cancel = no change |

### Flow Optimization Principles

1. Reads are instant — no confirmation for filter/select
2. Errors are inline — at the point of failure, never a separate page
3. Success is proven — usage bars re-render; row countdown updates
4. Abandon is graceful — navigating away leaves the page in a clean state

---

## Component Strategy

### Design System Components (reuse as-is)

Tailwind CSS v4 + existing portal patterns: grid, progress bars, badges, tables, buttons, inputs, selects — all established patterns in the codebase.

### Custom Components

#### RadioTierCard
- **Props:** `tier`, `price`, `isSelected`, `isCurrent`, `features[]`, `onSelect(tier)`
- **States:** default → hover → selected (accent border) → current-selected (★ suffix)
- **ARIA:** `role="radio"` + `aria-checked` + `aria-label="Select {tier} plan at ${price}/month"`

#### UsageMeter
- **Props:** `label`, `used`, `limit`, `upgradeHint?`
- **Color logic:** < 75% blue · 75–90% amber + ⚠ · > 90% red + ⚠
- **Hint:** renders only when `upgradeHint` provided AND pct > 75%

#### EngineGroupPanel
- **Props:** `label` (INGEST/CHECK/ANALYSIS/REPORTING), `engines[]`, `variant` (default|enterprise)
- Enterprise variant: amber-tinted border

#### MetricCard (upgrade)
- Add: `onClick`, `filterActive`, `severity` props
- Add: `role="button"` + `tabIndex={0}` + `aria-label`

#### ActionPopover
- **Props:** `title`, `confirmLabel`, `body`, `onConfirm()`, `onCancel()`
- **States:** idle → loading → success (auto-dismiss 3s) → error (inline)
- **ARIA:** `role="dialog"` + `aria-modal` + focus trap + Escape closes

### Implementation Roadmap

**Phase 1 (now):** RadioTierCard · UsageMeter · MetricCard click upgrade  
**Phase 2 (complete pages):** EngineGroupPanel · ActionPopover  
**Phase 3 (polish):** rows-per-page selector · filter chip · engine tile log links

---

## UX Consistency Patterns

### Button Hierarchy

| Level | Style | Use |
|-------|-------|-----|
| Primary | `bg-[--accent-primary] text-[#020617] font-semibold` | One per view: Upgrade CTA, Confirm in popover |
| Secondary | `bg-[--bg-tertiary] border-[--border-secondary]` | Manage Billing, Refresh, row actions |
| Ghost | `border-[--border-primary] text-[--text-muted]` | Cancel in popover, Downgrade link |
| Disabled | `bg-[--bg-tertiary] text-[--text-muted] cursor-not-allowed` | Upgrade CTA when current plan selected |

### Feedback Patterns

| Trigger | Pattern | Duration |
|---------|---------|----------|
| Stripe success redirect | Full-width success banner (dismissible) | Persistent until dismissed |
| Admin write action success | Popover inline confirmation → auto-dismiss | 3s |
| Admin write action error | Popover inline error message | Until dismissed or retry |
| Near-limit usage | Inline ⚠ on meter + contextual hint below | Persistent while condition true |
| Billing engine down | CTA disabled + "temporarily unavailable" text | Persistent while down |
| Data stale (admin) | MetricCard "—" + amber "Data stale" sub-label | Persistent while stale |

### Loading States

- CTA click → spinner replaces icon inside button, text unchanged
- Popover confirm → spinner inside confirm button, dims overlay
- Page data load → skeleton cards (same dimensions as real cards)
- MetricCard filter → no loading state (client-side instant)

### Empty States

- Invoice history empty → "No invoices yet — your first invoice will appear here after payment"
- Org table filtered with no matches → "No organisations match this filter" + [Clear filter] link
- Engine grid unreachable → "Engine health data unavailable" + retry button

### Navigation Patterns

- Sidebar active item: `bg-[--accent-primary]/12 text-[--accent-primary]`
- No breadcrumbs needed (both pages are flat, not nested)
- Page heading always visible at top — no sticky toolbar needed

---

## Responsive Design & Accessibility

### Responsive Strategy

**Desktop (≥ 1280px) — primary target:**
- Billing: full two-column split (2fr + 3fr)
- Admin: 4-column MetricCards + 4-column engine stages

**Tablet (768px – 1279px):**
- Billing: collapse to single column (plan card → usage → plan selector → invoices)
- Admin: 2-column MetricCards + 2-column engine stages + horizontal-scroll table

**Mobile (< 768px):**
- Not a supported use case for these pages (ops tooling) — graceful degradation only:
  - Single column, all cards stacked
  - Table becomes scroll-x
  - No layout breaking

### Breakpoints

```css
/* Tailwind defaults — no custom breakpoints needed */
sm:  640px   /* not used for these pages */
md:  768px   /* tablet collapse */
lg: 1024px   /* engine grid goes 3-col */
xl: 1280px   /* full two-column billing layout */
```

### Accessibility Requirements — WCAG AA

| Requirement | Implementation |
|------------|----------------|
| Colour contrast | All text ≥ 4.5:1 (already AAA at 16:1) |
| Colour not sole signal | ⚠ icon accompanies all amber/red states |
| Keyboard navigation | Tab → Enter/Space to activate; Escape closes popovers |
| Focus rings | `focus:ring-2 focus:ring-[--accent-primary]` on all interactive elements |
| Screen reader | `aria-label` on MetricCards, RadioTierCards, UsageMeters |
| Focus management | Popover traps focus; restores to trigger on close |
| Touch targets | All buttons ≥ 36×36px (most are 40px+) |

### Implementation Checklist (for dev)

- [ ] `role="radio"` + `aria-checked` on RadioTierCard items
- [ ] `role="button"` + `tabIndex={0}` + `aria-label` on MetricCards
- [ ] `role="dialog"` + `aria-modal="true"` + focus trap in ActionPopover
- [ ] `aria-live="polite"` on success/error banner zones
- [ ] `aria-label` describing meter fill on UsageMeter (`aria-valuenow`, `aria-valuemin`, `aria-valuemax`)
- [ ] Engine health grid: `aria-label="Engine health: {name} — {status} — {latency}ms — {pods} pods"`

---

## Workflow Complete

All 14 steps completed. The UX design specification is final and implementation-ready.

**Deliverables:**
- Spec: `_bmad-output/planning-artifacts/ux-design-specification.md`  
- Interactive mockup: `_bmad-output/planning-artifacts/ux-design-directions.html`

**11 changes approved for implementation — ready to build.**
