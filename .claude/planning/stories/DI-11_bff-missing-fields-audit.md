# DI-11: BFF — Missing Fields Audit: What Components Need vs What BFF Returns

## Track
Track 2 — BFF Contract Audit

## Priority
P1 — parallel with DI-10

## Story
As a frontend engineer, I need every BFF view to return all fields that the React component actually reads (including optional nested fields), so that components don't render with `undefined` data causing chart breaks or conditional rendering failures.

## Background

Beyond field name mismatches (DI-10), some fields are simply absent from the BFF response. The component tries to read `data.threatIntel`, finds `undefined`, and the Threat Intel section stays blank — not because there's no data, but because the field was never included in the BFF response shape.

## Research Method

For each major page below:
1. Open the page component JSX
2. Read every `data.X`, `data?.X?.Y`, `data[key]` access
3. Compare against BFF handler return object
4. Flag any field that the component reads but the BFF doesn't return

## Pages and Expected Fields to Audit

### /threats page
File: find `page.jsx` under `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/`

Expected fields from component (verify these exist in BFF response):
- `threats` — array of threat items
- `threatFindings` — array of finding items  
- `mitreMatrix` — dict of tactic → techniques
- `attackChains` — array of attack paths
- `threatIntel` — array of intel items
- `trendData` — array of {date, critical, high, medium, low}
- `accountHeatmap` — array of {account, critical, high, medium, low, total}
- `kpiGroups` — KPI strip
- `scanMeta` — scan metadata

### /threats/[threatId] (detail)
File: `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/[threatId]/page.jsx`

Expected: `threat`, `relatedThreats`, `timeline`, `remediation`, `evidence`

### /compliance page
File: find under `/Users/apple/Desktop/threat-engine/frontend/src/app/compliance/`

Expected: `frameworks`, `overallScore`, `controlBreakdown`, `trendData`

### /inventory page
File: find under `/Users/apple/Desktop/threat-engine/frontend/src/app/inventory/`

Expected: `resources` or `assets`, `total`, `byProvider`, `byRegion`, `driftCount`

### /dashboard page
File: find under `/Users/apple/Desktop/threat-engine/frontend/src/app/dashboard/`

Expected: `kpiGroups`, `postureHero`, `cloudHealth`, `trendData`, `complianceFrameworks`, `criticalActions`, `topRiskyResources`

## Deliverable

A markdown table committed to the story or to a companion doc:

| Page | Field | BFF Returns It | Notes |
|------|-------|----------------|-------|
| /threats | threatIntel | YES | max 50 items |
| /threats | attackChains | YES | from threat engine |
| /threats | mitreTactics (field name) | NO — returns mitre_matrix | see DI-10 |
| /dashboard | cloudHealth | ? | needs audit |
| ... | ... | ... | ... |

## Files to Check (BFF side)

For each page, check the corresponding BFF handler:
- `/threats` → `shared/api_gateway/bff/threats.py`, look at the `result` dict returned
- `/compliance` → `shared/api_gateway/bff/compliance.py`
- `/inventory` → `shared/api_gateway/bff/inventory.py`
- `/dashboard` → `shared/api_gateway/bff/dashboard.py`
- `/threats/[id]` → `shared/api_gateway/bff/threat_detail.py`

## Fix Implementation

After audit, for each missing field:

**Option A: BFF never fetched this data** — add engine call to BFF, shape the response.

**Option B: BFF fetches it but doesn't include it in return dict** — add field to the return dict.

**Option C: Engine never returns it** — document as "engine gap", file a separate story in Track 3.

## Acceptance Criteria

- [ ] Audit completed for all 5 major pages listed above
- [ ] Markdown gap table produced (can be committed as a comment in the story file)
- [ ] All "BFF fetches but doesn't return" gaps fixed (Option B)
- [ ] All "BFF never fetched" gaps either fixed (Option A) or filed as Track 3 engine gaps
- [ ] After fixes: /threats Threat Intel section shows items (was empty because field missing)
- [ ] After fixes: /dashboard Cloud Health grid renders provider cards

## Time Estimate
1 day for audit, 1 day for Option A/B fixes (total 2 days for this story)

## Definition of Done
- Gap table committed
- All Option B gaps fixed in BFF handlers
- New BFF contract tests added for each fixed field
