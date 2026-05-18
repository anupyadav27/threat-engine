# Story UIBFF-FIX-02: Risk BFF — Remove Synthetic Mitigation Roadmap Fallback

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P1 (CSPM Constitution violation — BFF fabricates data)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want the Risk Mitigation Roadmap to show real mitigation plans or an empty state — never synthetic items fabricated by the BFF from scenario names.

## Context

Audit finding: `shared/api_gateway/bff/risk.py` lines 144–162 fabricate a mitigation roadmap when the risk engine returns none:

```python
if not mitigation_roadmap:
    for i, s in enumerate(scenarios[:10]):
        mitigation_roadmap.append({
            "id": f"MIT-{i+1:03d}",
            "action": f"Mitigate: {s.get('scenario_name', '')}",
            "status": "planned",
            ...
        })
```

Also: `risk.py` lines 34–43 define `RISK_SCAN_TREND` — a hardcoded static fallback array used when the engine returns no trend.

Both violate: **"BFF for charts/aggregates — never add fallback/mock data in BFF"**.

## What to Build

### 1. Remove synthetic mitigation roadmap from `risk.py`

```python
# BEFORE (lines 144-162):
if not mitigation_roadmap:
    for i, s in enumerate(scenarios[:10]):
        mitigation_roadmap.append({...})  # DELETE THIS BLOCK

# AFTER:
# mitigation_roadmap stays as-is (empty list or whatever engine returned)
```

The UI already handles empty `mitigationRoadmap` — it renders "No mitigation plans yet" when the array is empty (verify line in `risk/page.jsx` that checks length before rendering).

### 2. Remove `RISK_SCAN_TREND` static fallback from `risk.py`

```python
# DELETE lines 34-43:
RISK_SCAN_TREND = [
    {"date": "...", "score": ...},
    ...
]

# BEFORE (in view_risk):
trend_data = risk_data.get("trend_data") or RISK_SCAN_TREND

# AFTER:
trend_data = risk_data.get("trend_data") or []
```

### 3. Add empty-state check in `risk/page.jsx`

Find the Mitigation Roadmap table rendering block and ensure it handles empty array:
```javascript
// Find in risk/page.jsx — the mitigationRoadmap render:
{mitigationRoadmap.length === 0 ? (
  <p className="text-muted-foreground text-sm py-8 text-center">
    No mitigation plans yet — they will appear after risk scenarios are analyzed
  </p>
) : (
  <table>...</table>
)}
```

Also for `trendData`:
```javascript
// Ensure trendData empty state is handled:
const trendData = data.trendData || [];
// TrendChart should already handle empty array — verify it renders a flat line or message
```

### 4. Add empty-state for Risk Scenario mitigations in `risk/scenario/[id]/RiskScenarioPageClient.jsx`

The mitigations in scenario detail are boilerplate. Label them clearly (do not remove — they have value as guidance):
```javascript
// In Mitigations tab header, add a note when mitigations are engine-suggested:
<div className="flex items-center gap-2 mb-3">
  <h3>Recommended Actions</h3>
  <span className="text-xs text-muted-foreground">(engine-level guidance)</span>
</div>
```

This does not remove the data — it accurately labels it as guidance, not tracked mitigations.

## Acceptance Criteria

### AC-01 — No fabricated mitigation rows
`grep "MIT-[0-9]" shared/api_gateway/bff/risk.py` returns 0 hits after this change.

### AC-02 — Empty mitigation state renders correctly
When risk engine returns `mitigation_roadmap: []`, the Risk page shows the empty-state message instead of fabricated rows.

### AC-03 — No RISK_SCAN_TREND constant
`grep "RISK_SCAN_TREND" shared/api_gateway/bff/risk.py` returns 0 hits.

### AC-04 — Real trend data or empty
`trendData` in risk BFF response is either real data from the engine or `[]`. Never a static array.

### AC-05 — Scenario mitigations labeled as guidance
`/risk/scenario/[id]` Mitigations tab header includes `(engine-level guidance)` label to distinguish from tracked plans.

## Technical Notes

- Verify the UI's empty-state path for `mitigationRoadmap` before removing the BFF fallback — if UI crashes on empty, fix UI first
- The `RISK_SCAN_TREND` static array at lines 34–43 — verify exact line numbers before deleting (may have shifted)
- Do NOT remove the scenario-level `_ENGINE_MITIGATIONS` dict from `risk_scenario_detail.py` — the label change is sufficient for accuracy; removing it would show no guidance at all

## Definition of Done

- [ ] `if not mitigation_roadmap:` fabrication block removed from `risk.py`
- [ ] `RISK_SCAN_TREND` constant and usage removed from `risk.py`
- [ ] Empty-state message added to mitigation roadmap in `risk/page.jsx`
- [ ] Scenario mitigations labeled as guidance in `RiskScenarioPageClient.jsx`
- [ ] AC-01 through AC-05 verified
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-risk1`