# User Stories — Threats Module Redesign

---

## Epic 1: Foundation (Phase 1)

### US-1.1: Database Migration — Workflow Columns
**As a** security analyst
**I want to** assign threats and add notes
**So that** my team can track ownership and context

**Acceptance Criteria:**
- [ ] `assignee` VARCHAR(255) column added to `threat_findings`
- [ ] `notes` TEXT column added to `threat_findings`
- [ ] `status_changed_at` and `status_changed_by` columns added
- [ ] Index on `assignee` created
- [ ] Alembic migration file committed
- [ ] Migration tested on local DB
- [ ] PATCH `/api/v1/threat/{id}` updated to accept `assignee` and `notes`

**Dependencies:** None
**Agent:** `db-migration-agent`

---

### US-1.2: BFF Gateway Wiring
**As a** frontend developer
**I want** the threats BFF route accessible at `/gateway/api/v1/views/threats`
**So that** `fetchView('threats')` works from the UI

**Acceptance Criteria:**
- [ ] `views.py` gateway prefix includes threats BFF router
- [ ] `GET /gateway/api/v1/views/threats?tenant_id=X` returns 200
- [ ] Response matches the JSON contract in `01-THREAT-DASHBOARD.md`

**Dependencies:** None
**Agent:** `bff-integration-agent`

---

### US-1.3: BFF Threat Detail Module
**As a** security analyst
**I want** a dedicated detail endpoint instead of client-side filtering
**So that** the detail page loads fast with full context

**Acceptance Criteria:**
- [ ] `bff/threat_detail.py` created
- [ ] `GET /api/v1/views/threats/{threatId}?tenant_id=X` works
- [ ] Response includes: threat header, exposure context, affected resources, supporting findings, MITRE context, attack path, blast radius, remediation, timeline
- [ ] Fan-out calls made in parallel
- [ ] Response matches `02-THREAT-DETAIL.md` JSON contract

**Dependencies:** US-1.1 (for assignee field)
**Agent:** `bff-integration-agent`

---

### US-1.4: MITRE Data Shape Fix
**As a** frontend developer
**I want** MITRE techniques as `[{id, name}]` objects (not plain strings)
**So that** I can render technique names in the UI without a lookup table

**Acceptance Criteria:**
- [ ] `normalize_threat()` in `_transforms.py` maps `mitre_techniques` JSONB to `[{id, name}]`
- [ ] If engine returns `["T1078", "T1190"]`, BFF enriches from `mitre_technique_reference`
- [ ] If engine returns `[{id: "T1078", name: "Valid Accounts"}]`, BFF passes through

**Dependencies:** None
**Agent:** `bff-integration-agent`

---

## Epic 2: Core Pages (Phase 2)

### US-2.1: Threat Dashboard UI Redesign
**As a** security analyst
**I want** an enterprise-grade threat overview dashboard
**So that** I can quickly assess my organization's threat landscape

**Acceptance Criteria:**
- [ ] KPI strip with 6 metrics + deltas
- [ ] 3-column chart row: severity donut, 30-day trend, top services
- [ ] MITRE ATT&CK matrix grid (collapsible)
- [ ] Threat table with tabs (All, Critical, High, Attack Path, Unassigned)
- [ ] Filter bar: provider, account, region, severity, status, tactic, search
- [ ] Row click navigates to `/threats/{id}`
- [ ] Responsive layout (desktop/tablet)
- [ ] Loading skeletons
- [ ] Empty state handling

**Dependencies:** US-1.2 (BFF wiring)
**Agent:** `ui-threat-dashboard-agent`

---

### US-2.2: Threat Detail UI Redesign
**As a** security analyst
**I want** full threat context in a single page
**So that** I can understand the risk, see the attack path, and know what to fix

**Acceptance Criteria:**
- [ ] Header with severity, MITRE code, risk score, status, actions
- [ ] Tab bar: Overview, Attack Path, Blast Radius, Evidence, Remediation, Timeline
- [ ] Overview tab: exposure context (4 cards), affected resources, supporting findings, MITRE context
- [ ] Attack path tab: horizontal step-by-step visualization
- [ ] Blast radius tab: mini force-directed graph + depth chart
- [ ] Remediation tab: numbered steps with effort/impact + SLA status
- [ ] Timeline tab: vertical timeline with events
- [ ] Action buttons: Assign, Change Status, Suppress, Export

**Dependencies:** US-1.3 (BFF detail endpoint)
**Agent:** `ui-threat-detail-agent`

---

### US-2.3: Analytics UI
**As a** security leader
**I want** trend analysis and pattern recognition
**So that** I can report on security posture improvement

**Acceptance Criteria:**
- [ ] KPI strip: total, crit+high, new 7d, resolved/week, MTTD
- [ ] Severity donut + category bar + provider bar (3-column)
- [ ] 30-day stacked area trend (with 7d/14d/30d toggle)
- [ ] Top services + top MITRE techniques (2-column)
- [ ] Account heatmap
- [ ] Pattern analysis table

**Dependencies:** US-2.4 (BFF analytics)
**Agent:** `ui-threat-analytics-agent`

---

### US-2.4: BFF Analytics Module
**As a** frontend developer
**I want** aggregated analytics data in one call
**So that** the analytics page loads with a single fetch

**Acceptance Criteria:**
- [ ] `bff/threat_analytics.py` created
- [ ] `GET /api/v1/views/threats/analytics?tenant_id=X&days=30` works
- [ ] Fan-out to: ui-data, analytics/distribution, analytics/trend, analytics/patterns
- [ ] Response matches `03-ANALYTICS.md` JSON contract

**Dependencies:** None
**Agent:** `bff-integration-agent`

---

## Epic 3: Graph & Paths (Phase 3)

### US-3.1: Attack Paths UI
**As a** security analyst
**I want** to see multi-step attack chains visualized
**So that** I can understand how an attacker could move from entry to crown jewels

**Acceptance Criteria:**
- [ ] KPI cards: total paths, critical, high, active
- [ ] Filter bar: severity, min hops, target type
- [ ] Expandable attack path cards with horizontal chain visualization
- [ ] Each step shows: resource icon, name, MITRE technique, risk score
- [ ] Expanded view shows step-by-step details
- [ ] MITRE tactic pills on each card
- [ ] Links to blast radius and misconfig pages

**Dependencies:** US-3.4 (BFF attack paths)
**Agent:** `ui-threat-graph-agent`

---

### US-3.2: Blast Radius UI
**As a** security analyst
**I want** to see the downstream impact if a resource is compromised
**So that** I can prioritize remediation by impact

**Acceptance Criteria:**
- [ ] KPI cards + search bar for resource ARN/UID
- [ ] Force-directed SVG graph with zoom/pan
- [ ] Node colors: red=threats, orange=findings, green=clean, blue=source
- [ ] Right panel detail on node click
- [ ] Depth distribution bar chart
- [ ] Internet-exposed resources table

**Dependencies:** US-3.5 (BFF blast radius)
**Agent:** `ui-threat-graph-agent`

---

### US-3.3: Internet Exposed UI
**As a** security analyst
**I want** to see all publicly accessible resources
**So that** I can reduce attack surface

**Acceptance Criteria:**
- [ ] KPI cards: total, critical, high, medium
- [ ] Grouped by exposure category (Direct, Database, Storage, LB)
- [ ] Each resource shows exposure path diagram (Internet → Resource)
- [ ] Open ports as badges
- [ ] Expandable remediation (resource-type specific templates)
- [ ] Links to misconfig and threat detail pages

**Dependencies:** US-3.6 (BFF internet exposed)
**Agent:** `ui-threat-graph-agent`

---

### US-3.4–3.8: BFF Modules for Graph Pages
**As a** frontend developer
**I want** dedicated BFF modules for each graph page

| Story | BFF File | Engine Calls |
|-------|----------|-------------|
| US-3.4 | `threat_attack_paths.py` | `/graph/attack-paths` |
| US-3.5 | `threat_blast_radius.py` | `/graph/blast-radius/{uid}`, `/graph/summary`, `/graph/internet-exposed` |
| US-3.6 | `threat_internet_exposed.py` | `/graph/internet-exposed` |
| US-3.7 | `threat_toxic_combos.py` | `/graph/toxic-combinations`, `/graph/toxic-combinations/matrix` |
| US-3.8 | `threat_graph.py` | `/inventory/runs/latest/graph` |

**Agent:** `bff-integration-agent`

---

## Epic 4: Advanced (Phase 4)

### US-4.1: Toxic Combinations UI
**As a** security analyst
**I want** to see compound risk scenarios
**So that** I can fix the highest-impact multi-factor risks first

**Agent:** `ui-threat-graph-agent`

### US-4.2: Graph Explorer UI
**As a** security investigator
**I want** to explore the full security graph
**So that** I can discover hidden relationships and attack vectors

**Agent:** `ui-threat-graph-agent`

### US-4.3: Hunting UI
**As a** threat hunter
**I want** to run predefined queries and check IOC intelligence
**So that** I can proactively find threats before they're exploited

**Agent:** `ui-threat-hunting-agent`

---

## Epic 5: Polish (Phase 5)

### US-5.1: Cross-Page Navigation
- Finding page → "View as Threat" link
- Threat page → "View in Inventory" link
- Asset page → "Threats for this resource" tab
- Graph → click node → threat detail sidebar

### US-5.2: Loading & Error States
- Skeleton loaders for each page section
- Error boundaries per section (partial render)
- Empty states with actionable guidance

### US-5.3: Performance
- Virtual scrolling for threat table (>1000 items)
- Lazy tab loading (attack path, blast radius tabs load on click)
- Debounced search (300ms)
- Memoized chart data

---

## Story Dependency Graph

```
US-1.1 (DB migration)
  │
  ├── US-1.3 (BFF detail) ──→ US-2.2 (Detail UI)
  │
  └── US-1.2 (BFF wiring) ──→ US-2.1 (Dashboard UI)

US-1.4 (MITRE fix) ──→ US-2.1, US-2.2

US-2.4 (BFF analytics) ──→ US-2.3 (Analytics UI)

US-3.4-3.8 (BFF graph modules) ──→ US-3.1, 3.2, 3.3 (Graph UIs)

US-4.1, 4.2, 4.3 depend on US-3.4-3.8

US-5.* depends on all of the above
```
