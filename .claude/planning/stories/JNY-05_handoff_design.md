# JNY-05 Design — Universal Finding Route

## 1. URL contract

**Pattern:** `/finding/[engine]/[id]` (Next.js App Router, server-rendered for direct paste / middle-click per AC).

**Engine slug whitelist** (validated in `layout.jsx`; mismatch → 404):
```
['iam','network-security','datasec','encryption','container-security',
 'dbsec','ai-security','ciem','check','threat','secops']
```
Note: story §AC-2 uses short slugs (`network`, `container`, `ai`) — design **rejects** that and aligns with the existing `EngineCard` route map plus engine namespace conventions; we will request a story amendment in §10.

**ID format per engine** (regex, used for client-side validation before fetch):
| Engine | ID source | Regex |
|---|---|---|
| iam, datasec, encryption, container-security, dbsec, ai-security, network-security, ciem, secops | `<engine>_findings.finding_id` (sha-prefixed) | `^[A-Za-z0-9_-]{8,128}$` |
| check | `check_findings.finding_id` (sha256[:16] generated) | `^[a-f0-9]{16}$` |
| threat | `threat_findings.finding_id` (sha256[:16]) | `^[a-f0-9]{16}$` |

Invalid id → render 404 component, do not call BFF.

## 2. Page layout (header card + 5 tabs)

**Header card** (sticky top, always rendered, fed by `finding.header`):
- Row 1: `<SeverityBadge severity>` · status pill · engine badge · rule_id chip · risk_score (0–100) gauge.
- Row 2: `title` (h1) · `description` (truncate 2 lines, expandable).
- Row 3 (metadata grid): provider · account_id · region · `resource_uid` rendered as `<PivotLink to="asset" id={resource_uid} />` · first_seen_at · last_seen_at · `<SlaStatusBadge>`.
- Row 4 (action bar, right-aligned): `Assign` · `Change Status` · `Suppress` · `Export JSON`. Status PATCH posts to **`PATCH /api/v1/views/finding/{engine}/{id}/status`** (BFF write endpoint added by CP-2 B2 amendment — UI never calls engines directly). BFF audit-logs every status change centrally.

**Tabs** (deep-linkable via `?tab=` query, default `overview`):

| # | tabId | Component | Data source |
|---|---|---|---|
| 1 | `overview` | `OverviewTab` | `finding.header` + `finding.evidence[]` + `finding.supporting[]` from BFF |
| 2 | `resource` | `ResourceContextTab` | wraps existing `<AssetContextCard resource_uid={...} provider={...} accountId={...} />` unchanged |
| 3 | `related` | `RelatedFindingsTab` | `related_findings[]` (cross-engine, same resource_uid) — `<DataTable>` with PivotLink rows |
| 4 | `compliance` | `ComplianceTab` | `compliance_mappings[]` from rule_control_mapping; tab hidden if BFF returns 403 or `mappings_visible:false` |
| 5 | `remediation` | `RemediationTab` | `remediation.guidance` (markdown) + `remediation.runbook_url` from rule_metadata |

## 3. Engine-specific tab plugin registry

**File:** `frontend/src/lib/engine-finding-tabs.js`

```
export const ENGINE_FINDING_TABS = {
  // ciem: [{ tabId:'activity', label:'Activity Heatmap',
  //         component: () => import('@/components/ciem/ActivityHeatmapTab'),
  //         fetchPath: (id) => `ciem/findings/${id}/activity` }],
};
```

**Contract per entry:** `{ tabId: string, label: string, component: () => Promise<{default: ReactComponent}>, fetchPath?: (id)=>string, visible?: (finding)=>boolean }`.

**Renderer rules:**
- Universal tabs render first (1–5), then registry tabs appended in array order.
- Phase B ships with **empty registry** except CIEM `Activity Heatmap` to satisfy AC-8.
- Registry components receive `{ finding, engine, id }` props; lazy-loaded via `next/dynamic`.
- Floor = 5 universal tabs (ADR §3.1).

## 4. Loading / 404 / 403 / 500 handling

- **Loading:** `<LoadingSkeleton variant="finding-detail" />` — matches Inventory journey skeleton (3-row header bar + tab strip + 6-row table).
- **404:** dedicated `not-found.jsx` under route — renders `EmptyState` with copy "Finding not found" + `<Link href="/<engine-list-route>">Back to {engineLabel}</Link>` derived from `EngineCard` ENGINE_META map.
- **403:** inline amber banner `"You don't have access to this finding."` plus tab visibility flag — `compliance` tab also auto-hides on per-tab 403 (BFF returns `tab_permissions: {compliance:false}`).
- **500:** existing `SectionErrorBoundary` from threats page promoted to `frontend/src/components/shared/SectionErrorBoundary.jsx`; surfaces `correlation_id` from BFF error envelope `{error, correlation_id, trace_id}` for support copy-paste.

## 5. Cross-engine pivots (PivotLink usage)

Component: `frontend/src/components/shared/PivotLink.jsx` (already planned in JNY-04; this story consumes only).

| Use site | Invocation |
|---|---|
| Header `resource_uid`, Resource Context tab | `<PivotLink to="asset" id={resource_uid} provider={provider} accountId={accountId} />` |
| MITRE technique chips (Overview tab, threat engine) | `<PivotLink to="technique" id={tid} />` |
| Compliance control rows | `<PivotLink to="control" id={cid} framework={fw} />` |
| Related Findings rows | `<PivotLink to="finding" engine={row.engine} id={row.finding_id} />` |
| Rule chip in header | `<PivotLink to="rule" id={rule_id} />` |

PivotLink renders `next/link` under the hood; middle-click + open-in-new-tab work natively (AC-5).

## 6. Telemetry

Emit via `lib/telemetry.js` (existing):
- `finding.page_view` — `{engine, finding_id, severity, status, has_compliance_tab}` on mount.
- `finding.tab_switch` — `{engine, finding_id, from, to}` on tab change.
- `finding.pivot_click` — `{engine, finding_id, pivot_type, target_id}` from `PivotLink` callback.
- `finding.action` — `{engine, finding_id, action: 'assign'|'status'|'suppress'|'export', outcome}`.

## 7. Security boundaries

- `tenant_id` resolved server-side from auth context (NextAuth/JWT in `headers()`); URL never carries tenant.
- Engine slug + id regex validated in `layout.jsx` before any fetch — invalid → notFound().
- BFF response (per ADR §3.1.c) MUST strip `raw_event`, `credential_ref`, `actor_credentials`, `secret_ref`, `cred_payload`. UI defensively asserts: in dev mode, log+drop unknown fields matching `/credential|secret|raw_event/i`.
- Resource Context tab: when CIEM data is included (assets with identity bindings), BFF emits audit-log entry `ciem.asset_view` keyed on `(tenant_id, user_id, resource_uid)`.
- Cross-tenant: middleware compares JWT `tenant_id` to BFF-resolved finding `tenant_id`; mismatch → 403.

## 8. File plan

```
frontend/src/app/finding/[engine]/[id]/
  layout.jsx                  # validates engine+id; auth check; sets <html lang>
  page.jsx                    # server component: fetchView, hand off to client tabs shell
  not-found.jsx               # 404 component
  error.jsx                   # 500 boundary

frontend/src/components/finding/
  FindingHeaderCard.jsx
  FindingTabsShell.jsx        # 'use client', tab state via ?tab= query
  OverviewTab.jsx
  ResourceContextTab.jsx      # thin wrapper around AssetContextCard
  RelatedFindingsTab.jsx
  ComplianceTab.jsx
  RemediationTab.jsx

frontend/src/lib/engine-finding-tabs.js
```

No new BFF code in this story — owned by JNY-06.

## 9. State / data-flow

```
Browser GET /finding/iam/abc123
  ↓
layout.jsx (server)  →  validate slug + id regex; resolve tenant from cookie/JWT
  ↓
page.jsx (server)    →  fetchView(`finding/${engine}/${id}`)   [single fetch, AC-6]
  ↓
Gateway (auth, tenant scope)  →  BFF /api/v1/views/finding/{engine}/{id}
  ↓
BFF (JNY-06)   →  parallel: engine /findings/{id}, inventory /assets/{uid},
                  rule /rules/{rule_id}, compliance /mappings?rule_id=...,
                  related: each engine /findings?resource_uid=...
  ↓
BFF normalizes → camelCase response → page.jsx props
  ↓
<FindingTabsShell finding={finding} engine={engine} id={id} />
  - tab change: pushState(?tab=...) only, NO refetch (AC-6)
  - status PATCH: postToEngine(`/api/v1/${engine}/findings/${id}/status`)
  - on success: optimistic header update + revalidatePath
```

## 10. Open questions for `bmad-security-architect` (CP-2)

1. **Cross-tenant guard placement** — should the slug-mismatch / tenant-mismatch 403 be enforced in (a) Next.js middleware before BFF call, (b) BFF only, or (c) both with defense-in-depth? Current design is (c); confirm acceptable cost.
2. **CIEM audit-log granularity on Resource Context tab** — emit per page-view, or only when user expands an identity binding row? Per-view is cheaper but noisier; per-expand needs a client→BFF audit hook.
3. **Compliance tab inheritance** — if a user has access to the finding but not to the framework (e.g. PCI-restricted role viewing a SOC2 mapping), do we hide the entire tab, or render the tab with framework-level row redaction? Current design: hide tab on 403; needs sign-off.
4. **Engine slug mismatch with story** — story AC-2 lists short slugs (`network`, `container`, `ai`); design uses long slugs (`network-security`, `container-security`, `ai-security`) to align with K8s service names and existing routes. Sign-off needed.

## 11. Open questions for `cspm-bff-dev` (JNY-06)

1. **Response shape** — confirm camelCase top-level with snake_case preserved inside `evidence`/`raw_*` payloads (Phase A precedent), single root: `{ header, evidence, supporting, related, compliance, remediation, tabPermissions, correlationId }`.
2. **Related-findings fan-out** — recommended timeout per engine? Proposal: 800 ms per engine, `Promise.allSettled`, surface `partial: true` flag plus `degraded_engines: [...]`. Acceptable, or move related-findings to a deferred 2nd-call?
3. **rule_metadata cache TTL** — remediation + compliance mappings are slow-changing; propose 5 min in-process LRU keyed on `rule_id`. Confirm or specify Redis instead.
4. **Status PATCH path** — story AC-7 requires UI to write directly to the engine, bypassing BFF. Confirm gateway routes `/api/v1/<engine>/findings/{id}/status` are RBAC-enforced and audit-logged at the gateway layer for all 11 engines (notably `secops` and `ciem` which historically diverged).
