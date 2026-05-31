# Story AP-REDESIGN-05: Frontend — Inventory Page Inline Expand

**Epic:** Attack Path UI Redesign  
**Phase:** REDESIGN  
**Priority:** P1  
**Story Points:** 3  
**Status:** ready  
**Depends on:** AP-REDESIGN-04 (AssetDetailMini must be merged)  

---

## Context

Currently, clicking an asset row in the inventory page navigates to a full-page asset detail view (`/inventory/[assetId]`). This interrupts the investigation flow — the analyst loses their filtered list context when they click into a row.

This story changes row click to **inline expand** (same accordion pattern as attack paths), showing `AssetDetailMini` below the clicked row. The full-page asset detail (`/inventory/[assetId]`) remains available via a "View Full Details" button inside the expanded section.

---

## Files to Change

| File | Change |
|------|--------|
| `frontend/src/app/inventory/page.jsx` | Change row click from `router.push` to inline expand toggle |

## No BFF Changes

Both `asset_findings.py` and `asset_posture.py` already exist and are sufficient. No new endpoints.

---

## Layout Change

**Before:**
```
Row click → router.push('/inventory/{uid}') → full page navigation
```

**After:**
```
Row click → toggle expand → AssetDetailMini mounts inline below row
            Click same row again → collapse
            Click "View Full Details →" → router.push('/inventory/{uid}')
```

---

## Acceptance Criteria

### Row Expand Behavior (AC-1 to AC-8)
- AC-1: Clicking anywhere on an asset row toggles an inline expand section below it
- AC-2: Only ONE row can be expanded at a time — clicking a new row collapses the previous
- AC-3: Expanded row has a subtle left border accent
- AC-4: Expanded section renders `<AssetDetailMini uid={asset.resource_uid} displayName={asset.resource_name} resourceType={asset.resource_type} />`
- AC-5: "View Full Details →" button in the expanded section navigates to `/inventory/${encodeURIComponent(asset.resource_uid)}` (existing full-page view unchanged)
- AC-6: Clicking the same expanded row again → collapses it
- AC-7: ESC key while a row is expanded → collapses it
- AC-8: Expanded state resets on page filter/search change (no stale open row)

### AssetDetailMini Integration (AC-9 to AC-13)
- AC-9: No `prefetched*` props passed (inventory page doesn't have pre-loaded findings) — AssetDetailMini lazy-fetches all tabs
- AC-10: Misconfigs tab count badge shown in tab label from `by_engine.check` in findings response
- AC-11: CVEs tab count badge from count of findings where `finding_type = 'cve'`
- AC-12: CDR tab hidden for viewer role (AssetDetailMini handles this internally)
- AC-13: Posture tab loads on first tab click (lazy) — not on row expand

### Preserved Behavior (AC-14 to AC-17)
- AC-14: Direct URL `/inventory/{uid}` still navigates to full-page asset detail (no change to `[assetId]/page.jsx`)
- AC-15: "View Full Details →" inside expanded row = same destination as the old row click
- AC-16: All existing filters (provider, account, region, severity, resource_type) continue to work unchanged
- AC-17: Pagination, sort, and KPI bar behavior unchanged

### Performance (AC-18 to AC-20)
- AC-18: AssetDetailMini only mounts on first expand — no pre-fetching of findings for all rows
- AC-19: Asset findings cached in component state (useRef Map) keyed by `resource_uid` — reopening same row doesn't re-fetch
- AC-20: Inventory list fetch (`fetchView('inventory')`) unchanged — no additional calls on page load

---

## Technical Notes

**State management in page.jsx:**
```javascript
const [expandedUid, setExpandedUid] = useState(null);
const detailCache = useRef(new Map());

function handleRowClick(asset) {
  const uid = asset.resource_uid;
  setExpandedUid(prev => prev === uid ? null : uid);
}
```

**Row render pattern:**
```jsx
<>
  <tr
    onClick={() => handleRowClick(asset)}
    className={expandedUid === asset.resource_uid ? styles.rowExpanded : styles.row}
  >
    {/* existing row cells unchanged */}
  </tr>
  {expandedUid === asset.resource_uid && (
    <tr>
      <td colSpan={ALL_COLUMNS}>
        <AssetDetailMini
          uid={asset.resource_uid}
          displayName={asset.resource_name || asset.resource_id}
          resourceType={asset.resource_type}
          onViewFull={() => router.push(`/inventory/${encodeURIComponent(asset.resource_uid)}`)}
        />
      </td>
    </tr>
  )}
</>
```

**Remove:** `onRowClick={(asset) => router.push(...)}` from the existing table config.

---

## Definition of Done
- [ ] Row click toggles inline expand (no full-page navigation)
- [ ] `AssetDetailMini` renders all 4 tabs with real data
- [ ] "View Full Details →" navigates to existing full-page view
- [ ] One row expanded at a time
- [ ] ESC key collapses
- [ ] Expand resets on filter/search change
- [ ] Detail cache in useRef prevents re-fetch on same row
- [ ] All 5 roles tested locally (viewer: CDR tab hidden, EPSS = "—")
- [ ] All existing inventory filters and pagination still work
- [ ] No console errors or React key warnings
- [ ] Local dev server golden path: click row → Misconfigs tab → CVEs tab → "View Full Details" → full page opens