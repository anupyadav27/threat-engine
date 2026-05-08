# Story DI-10: CIEM Tab in `/inventory/[assetId]/page.jsx`

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 4
**Depends On:** DI-01 (ciem:sensitive permission), DI-05 (inventory CIEM BFF endpoint)
**Blocks:** None

## Context

The Asset Investigation Journey at `/inventory/[assetId]` shows 7 tabs (Overview, Misconfigurations, Threats, Blast Radius, Compliance, Configuration, Drift). This story adds a CIEM tab between Threats and Blast Radius, visible to all roles but gated by `ciem:sensitive` permission for its data. Viewer roles see the tab but get an access-denied message. Analyst and above roles see the full identity risk table aggregated from the CIEM engine (via BFF DI-05).

## Scope

Modify `frontend/src/app/inventory/[assetId]/page.jsx` to add the CIEM tab. The CIEM data is loaded lazily (only when the tab is active) via `fetchView`.

**Out of scope:** BFF endpoint (DI-05), Django migration (DI-01), any backend changes.

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/frontend/src/app/inventory/[assetId]/page.jsx` — add CIEM tab

## Implementation Notes

### Step 1: Determine existing tab structure

Read the inventory asset page. The page does NOT currently have an explicit TABS array (unlike the threat detail page). Tab navigation is inline. Search for the tab bar markup around the `activeTab` state variable and the section that renders tab content. The existing tabs are defined inline as buttons. You must add a new "CIEM" tab button and a new conditional content block.

**Find the tab bar** by searching for `activeTab === 'overview'` or `setActiveTab('overview')` in the file. The tab bar is likely a `<div className="flex ...">` with multiple `<button>` elements that call `setActiveTab(...)`.

**Existing tab order (as of this sprint):**
Overview → Misconfigurations → Threats → Blast Radius → Compliance → Configuration → Drift

**Insert CIEM between Threats and Blast Radius.**

### Step 2: Add CIEM tab button

In the tab bar, after the Threats tab button and before the Blast Radius tab button, insert:

```jsx
<button
  onClick={() => setActiveTab('ciem')}
  className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
    activeTab === 'ciem' ? 'text-white' : ''
  }`}
  style={{
    backgroundColor: activeTab === 'ciem' ? 'var(--accent-primary)' : 'transparent',
    color: activeTab === 'ciem' ? '#fff' : 'var(--text-muted)',
  }}
>
  CIEM
</button>
```

Match the style of existing tab buttons in the file exactly. Read the existing tab buttons first to confirm the CSS pattern.

### Step 3: Add CIEM tab state and lazy fetch

Add state variables near the top of the component (alongside existing state vars):

```js
const [ciemData, setCiemData] = useState(null);
const [ciemLoading, setCiemLoading] = useState(false);
const [ciemError, setCiemError] = useState(null);  // null | 403 | 'error'
```

Add a `useEffect` to load CIEM data when the tab becomes active:

```js
useEffect(() => {
  if (activeTab !== 'ciem') return;
  if (ciemData !== null || ciemLoading) return;  // already loaded or loading

  setCiemLoading(true);
  setCiemError(null);

  const encoded = encodeURIComponent(assetId);
  fetchView(`inventory/${encoded}/ciem`)
    .then((data) => {
      setCiemData(data);
      setCiemLoading(false);
    })
    .catch((err) => {
      // Check for 403 (permission denied)
      if (err?.status === 403 || err?.message?.includes('403')) {
        setCiemError('403');
      } else {
        setCiemError('error');
      }
      setCiemLoading(false);
    });
}, [activeTab, assetId, ciemData, ciemLoading]);
```

**Note:** `fetchView` is already imported (`import { getFromEngine, fetchView } from '@/lib/api'`). The BFF endpoint is `GET /api/v1/views/inventory/{asset_id}/ciem` which maps to `fetchView('inventory/{encoded}/ciem')`.

### Step 4: Add CIEM tab content block

Find the section that renders tab content (the if/else block or switch for `activeTab`). Add a CIEM case:

```jsx
{activeTab === 'ciem' && (
  <div className="space-y-4">
    <div className="flex items-center justify-between">
      <h2 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>
        CIEM / Identity Risk
      </h2>
    </div>

    {/* Loading skeleton */}
    {ciemLoading && <CiemSkeletonTable />}

    {/* 403 — access denied (viewer role or missing permission) */}
    {!ciemLoading && ciemError === '403' && (
      <div className="p-6 rounded-xl text-center" style={{ backgroundColor: 'var(--bg-secondary)' }}>
        <p className="text-sm mb-2" style={{ color: 'var(--text-secondary)' }}>
          You need Analyst access to view identity entitlements.
        </p>
        <a
          href="/settings/access"
          className="text-sm font-medium underline"
          style={{ color: 'var(--accent-primary)' }}
        >
          Request Access →
        </a>
      </div>
    )}

    {/* Generic error */}
    {!ciemLoading && ciemError && ciemError !== '403' && (
      <p className="text-sm py-4 text-center" style={{ color: 'var(--text-muted)' }}>
        Could not load identity data for this resource.
      </p>
    )}

    {/* Data */}
    {!ciemLoading && !ciemError && ciemData && (
      <>
        {/* KPI strip */}
        <div className="grid grid-cols-2 gap-4">
          <div className="p-4 rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Total Identities</p>
            <p className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>
              {ciemData.totalIdentities ?? 0}
            </p>
          </div>
          <div className="p-4 rounded-xl" style={{ backgroundColor: 'var(--bg-secondary)' }}>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Over-Privileged</p>
            <p className="text-2xl font-bold mt-1" style={{ color: ciemData.overPrivilegedCount > 0 ? 'var(--color-critical)' : 'var(--text-primary)' }}>
              {ciemData.overPrivilegedCount ?? 0}
            </p>
          </div>
        </div>

        {/* Identity table */}
        {ciemData.identities?.length === 0 ? (
          <p className="text-sm py-6 text-center" style={{ color: 'var(--text-muted)' }}>
            No identity activity found for this resource.
          </p>
        ) : (
          <div className="rounded-xl overflow-hidden border" style={{ borderColor: 'var(--border-primary)' }}>
            <table className="w-full text-sm">
              <thead>
                <tr style={{ backgroundColor: 'var(--bg-secondary)' }}>
                  <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Identity ARN</th>
                  <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Type</th>
                  <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Privilege</th>
                  <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Last Used</th>
                  <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: 'var(--text-muted)' }}>Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {ciemData.identities.map((identity, idx) => (
                  <tr
                    key={idx}
                    className="border-t"
                    style={{ borderColor: 'var(--border-primary)' }}
                  >
                    <td className="px-4 py-3">
                      <code className="text-xs" style={{ color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                        {identity.identity_arn}
                      </code>
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                      {identity.identity_type}
                    </td>
                    <td className="px-4 py-3">
                      <PrivilegeBadge level={identity.privilege_level} />
                    </td>
                    <td className="px-4 py-3 text-xs" style={{ color: 'var(--text-secondary)' }}>
                      {identity.last_used_days !== null && identity.last_used_days !== undefined
                        ? `${identity.last_used_days}d ago`
                        : 'Never'}
                    </td>
                    <td className="px-4 py-3 text-xs font-bold" style={{ color: identity.risk_score >= 75 ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                      {identity.risk_score}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* "See all in CIEM" link — shown only when truncated */}
        {ciemData.truncated && (
          <div className="text-right">
            <a
              href={`/ciem?resource_uid=${encodeURIComponent(assetId)}`}
              className="text-sm font-medium underline"
              style={{ color: 'var(--accent-primary)' }}
            >
              See all in CIEM →
            </a>
          </div>
        )}
      </>
    )}
  </div>
)}
```

### PrivilegeBadge component (inline in page.jsx or extracted)

```jsx
function PrivilegeBadge({ level }) {
  const colorMap = {
    admin: { bg: '#fee2e2', text: '#dc2626' },
    power: { bg: '#ffedd5', text: '#ea580c' },
    readonly: { bg: '#f3f4f6', text: '#6b7280' },
  };
  const colors = colorMap[level] || colorMap.readonly;
  return (
    <span
      className="text-xs font-medium px-2 py-0.5 rounded capitalize"
      style={{ backgroundColor: colors.bg, color: colors.text }}
    >
      {level}
    </span>
  );
}
```

### CiemSkeletonTable component (inline)

```jsx
function CiemSkeletonTable() {
  return (
    <div className="space-y-2 animate-pulse">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-12 rounded" style={{ backgroundColor: 'var(--bg-secondary)' }} />
      ))}
    </div>
  );
}
```

### CSS variable for critical color

Use `var(--color-critical)` if it exists in the project CSS. If not, fall back to `#ef4444` (Tailwind red-500). Check `frontend/src/app/globals.css` or the theme config to confirm the variable name.

### URL encoding for "See all in CIEM" link

```jsx
href={`/ciem?resource_uid=${encodeURIComponent(assetId)}`}
```

`assetId` is already decoded at the top of the component (`const assetId = decodeURIComponent(params.assetId)`), so `encodeURIComponent(assetId)` correctly re-encodes the full ARN for the query param.

### Important: CIEM tab is VISIBLE but shows access denied for viewer

The tab button is rendered for all roles. Only the content differs:
- Analyst+: full identity table
- Viewer (403): "You need Analyst access" message + "Request Access →" link

This is different from hiding the tab entirely. The tab must always appear in the tab bar.

## Acceptance Criteria

- [ ] CIEM tab appears in the tab bar at position 4 (between Threats and Blast Radius) for all authenticated users
- [ ] Clicking CIEM tab activates it and triggers the `fetchView` call to `inventory/{encoded}/ciem`
- [ ] CIEM data is loaded LAZILY — only when the CIEM tab is first activated, not on initial page load
- [ ] For analyst+ session: KPI strip shows `totalIdentities` and `overPrivilegedCount`
- [ ] For analyst+ session: identity table shows ARN, type, privilege badge, last used, risk score
- [ ] `admin` privilege badge: red background
- [ ] `power` privilege badge: orange background
- [ ] `readonly` privilege badge: gray background
- [ ] "See all in CIEM →" link appears ONLY when `ciemData.truncated === true`
- [ ] "See all in CIEM →" navigates to `/ciem?resource_uid={encodeURIComponent(assetId)}`
- [ ] For viewer session (403 from BFF): tab is visible, content shows "You need Analyst access to view identity entitlements"
- [ ] 403 message has "Request Access →" link pointing to `/settings/access`
- [ ] Empty state (`identities: []`): shows "No identity activity found for this resource."
- [ ] Loading state: skeleton rows shown while fetching
- [ ] Generic error state (non-403): "Could not load identity data for this resource."
- [ ] All ARN values in table cells rendered as `<code>` text content — no `dangerouslySetInnerHTML`
- [ ] `assetId` URL-encoded in all outgoing links (full ARN has colons and slashes)

## Security Gates

- **B-1 (AuthContext-only):** `fetchView()` sends session cookie; BFF resolves `tenant_id` from `X-Auth-Context` — no `tenant_id` in the URL
- **B-4 (permission visible but gated):** Tab button visible to viewer, but 403 response from BFF controls what content is shown — frontend does NOT make a permission decision independently
- **B-10 (URL encoding):** `encodeURIComponent(assetId)` used in all navigation hrefs
- **No dangerouslySetInnerHTML:** ARNs and identity data rendered as React text content

## Definition of Done

- [ ] Code written and passes ESLint
- [ ] CIEM tab renders for all roles (tab button always visible)
- [ ] Analyst+ sees identity table with correct data
- [ ] Viewer sees 403 message with request access link
- [ ] `fetchView` called only when tab is activated (lazy load confirmed via browser network tab)
- [ ] "See all in CIEM" only shown when `truncated: true`
- [ ] No `dangerouslySetInnerHTML` anywhere in CIEM tab
- [ ] bmad-qa acceptance test run (switch to CIEM tab as analyst, verify data; switch as viewer, verify 403 message)