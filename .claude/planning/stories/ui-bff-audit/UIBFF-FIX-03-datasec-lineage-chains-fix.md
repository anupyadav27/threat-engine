# Story UIBFF-FIX-03: DataSec Lineage — Verify and Fix lineage_chains Structure

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P2 (page may silently render empty — no crash but no data)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want the DataSec Lineage page to show real data lineage chains when the engine has mapped data flows, rather than rendering blank.

## Context

Audit finding: `datasec/lineage/page.jsx` reads `data.lineage.lineage_chains` (line 118) and renders chain objects with fields `chain_id`, `risk`, `source`, `transforms`, `sink`, `records_per_day`, `encryption_at_rest`, `encryption_in_transit`, `cross_region`, `data_types`.

`shared/api_gateway/bff/datasec.py` line 314 returns a `lineage` object from the datasec engine, but the exact structure is unverified. If the engine returns a different shape, the page silently shows empty.

## What to Build

### 1. Read actual datasec engine response for lineage

Connect to the datasec engine and check what it actually returns for `lineage`:
```bash
kubectl port-forward svc/engine-datasec 8003:80 -n threat-engine-engines &
python3 -c "
import urllib.request, json
req = urllib.request.Request('http://localhost:8003/api/v1/datasec/ui-data?tenant_id=default')
with urllib.request.urlopen(req) as r:
    data = json.loads(r.read())
    print(json.dumps(data.get('lineage', {}), indent=2, default=str))
"
```

### 2. Fix `datasec.py` to return correct lineage_chains shape

The BFF at `datasec.py` line 314 returns:
```python
"lineage": safe_get(data, "lineage", {}),
```

If the engine returns `{"chains": [...]}` but the page expects `{"lineage_chains": [...]}`, add normalization:

```python
lineage_raw = safe_get(data, "lineage", {})
# Normalize field name: engine may return "chains" or "data_flows"
lineage_chains = (
    lineage_raw.get("lineage_chains")
    or lineage_raw.get("chains")
    or lineage_raw.get("data_flows")
    or []
)

return {
    ...existing fields...,
    "lineage": {
        "lineage_chains": [
            _normalize_chain(c) for c in lineage_chains
        ]
    },
}
```

### 3. Add `_normalize_chain()` helper in `datasec.py`

Map engine fields to the shape the page expects:
```python
def _normalize_chain(c: dict) -> dict:
    return {
        "chain_id":            c.get("chain_id") or c.get("id", ""),
        "risk":                c.get("risk") or c.get("risk_level", "low"),
        "source":              c.get("source") or c.get("source_resource", {}),
        "transforms":          c.get("transforms") or c.get("processing_steps", []),
        "sink":                c.get("sink") or c.get("destination", {}),
        "records_per_day":     c.get("records_per_day") or c.get("volume_per_day", 0),
        "encryption_at_rest":  c.get("encryption_at_rest", False),
        "encryption_in_transit": c.get("encryption_in_transit", False),
        "cross_region":        c.get("cross_region", False),
        "data_types":          c.get("data_types") or c.get("classifications", []),
    }
```

### 4. Add empty-state check in `datasec/lineage/page.jsx`

After the fix, if the engine genuinely has no lineage data, the page should show an empty state:
```javascript
// line 118 in datasec/lineage/page.jsx:
const chains = data?.lineage?.lineage_chains || [];

// Later in render, where chains.length check happens:
{chains.length === 0 && (
  <p className="text-muted-foreground text-sm text-center py-12">
    No data lineage chains detected. Run a DataSec scan to map data flows.
  </p>
)}
```

## Acceptance Criteria

### AC-01 — Lineage chains render when engine has data
After a DataSec scan that discovers data flows, `datasec/lineage` page shows chain cards with source → transforms → sink.

### AC-02 — Empty state renders without crash
When engine returns no lineage data, page shows the empty-state message instead of blank screen.

### AC-03 — Normalized fields present
Each chain object in BFF response has: `chain_id`, `risk`, `source`, `transforms`, `sink`, `records_per_day`, `encryption_at_rest`, `encryption_in_transit`, `cross_region`, `data_types`.

### AC-04 — Multi-tenant isolation
Lineage chains always scoped by `tenant_id` from `AuthContext`.

## Technical Notes

- The engine field names are unverified until you inspect live response — do the `kubectl port-forward` check first
- If the datasec engine has no lineage capability at all (returns `{}`), that is acceptable — the empty state should display and the story is still done
- `safe_get()` is already imported in `datasec.py`

## Definition of Done

- [ ] Actual engine response shape verified via port-forward
- [ ] `_normalize_chain()` helper added with field mappings
- [ ] `datasec.py` returns `lineage.lineage_chains[]` with normalized shape
- [ ] Empty-state added to `datasec/lineage/page.jsx`
- [ ] AC-01 through AC-04 verified
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-datasec1`
