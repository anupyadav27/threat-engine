# DI-10: BFF — Fix Field Name Mismatches (snake_case → camelCase Normalization)

## Track
Track 2 — BFF Contract Audit

## Priority
P1 — depends on DI-09 (mismatch audit)

## Story
As a frontend engineer, I need all BFF view responses to use the exact camelCase field names that React components read, so that charts and tables receive the correct data instead of silently rendering zero/empty.

## Background

Engines return snake_case field names (Python convention). React reads camelCase (JS convention). The BFF is the translation layer. Today, some BFF views forward engine fields unchanged (`risk_score`, `mitre_tactics`, `resource_uid`) instead of normalizing to camelCase. The frontend component reads the camelCase version and gets `undefined`.

## The `_transforms.py` Approach

The file `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_transforms.py` already exists and contains normalization helpers like `normalize_threat()`. The fix is to ensure these normalizations are complete.

## Files to Modify

Primary: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_transforms.py`

Secondary (individual BFF views that bypass transforms): individual BFF view files as identified in DI-09.

## Change 1: normalize_threat() audit

Read current `normalize_threat()` in `_transforms.py`. Verify it outputs:
- `riskScore` (not `risk_score`)
- `mitreTactics` (not `mitre_tactics`)
- `mitreTechiqueIds` (not `mitre_technique_ids`)
- `resourceType` (not `resource_type`)
- `resourceUid` (not `resource_uid`)
- `accountId` (not `account_id`)
- `detectedAt` (not `detected_at` or `first_seen_at`)
- `hasAttackPath` — boolean
- `isInternetExposed` — boolean

Add any missing normalizations.

## Change 2: Threat findings normalization

In `threats.py`, the `threat_findings` list (lines 101-123) builds dicts with:
```python
"resource_type":   f.get("resource_type", ""),
"resource_uid":    f.get("resource_uid", ""),
"account_id":      f.get("account_id", ""),
"mitre_tactics":   f.get("mitre_tactics", []),
"mitre_techniques": f.get("mitre_techniques", []),
```

These must be camelCase because the frontend reads `contributingFindings[n].resourceType`:
```python
"resourceType":    f.get("resource_type", ""),
"resourceUid":     f.get("resource_uid", ""),
"accountId":       f.get("account_id", ""),
"mitreTactics":    f.get("mitre_tactics", []),
"mitreTechniqueIds": f.get("mitre_techniques", []),
```

## Change 3: Risk view normalization

Read `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/risk.py`.

In the scenarios/summary output, ensure:
- `riskScore` not `risk_score`
- `blastRadius` not `blast_radius`
- `scenarioId` not `scenario_id`

## Change 4: Compliance view normalization

Read `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/compliance.py`.

Ensure framework entries use:
- `frameworkId` not `framework_id`
- `frameworkName` not `framework_name`
- `passCount` not `pass_count`
- `failCount` not `fail_count`
- `totalControls` not `total_controls`

## Change 5: Inventory normalization

Read `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/inventory.py`.

Ensure resources use:
- `resourceUid` not `resource_uid`
- `resourceType` not `resource_type`
- `accountId` not `account_id`
- `firstSeen` not `first_seen_at`
- `lastSeen` not `last_seen_at`

## Research Required Before Implementation

Before making changes, run this script to find all fields the frontend actually reads:
```bash
# Find all data.X reads in threat page
grep -h "data\.\|result\.\|item\.\|threat\." \
  /Users/apple/Desktop/threat-engine/frontend/src/app/threats/**/*.jsx \
  | grep -oP '(?<=\.)[a-zA-Z_]+' | sort -u
```

Run for each major page (threats, compliance, inventory, risk, dashboard) and reconcile against BFF output.

## Acceptance Criteria

- [ ] `normalize_threat()` outputs all required camelCase fields listed above
- [ ] `threat_findings` list in `threats.py` uses camelCase keys
- [ ] Risk scenarios use `riskScore`, `blastRadius`, `scenarioId`
- [ ] Compliance framework entries use `frameworkId`, `frameworkName`, `passCount`, `failCount`
- [ ] Inventory resources use `resourceUid`, `resourceType`, `accountId`
- [ ] After deployment: Threats page shows non-zero MITRE tactic counts
- [ ] After deployment: Risk page shows risk score values in the score cards
- [ ] After deployment: Compliance frameworks table shows framework names

## Testing

For each fixed view, add an assertion to the contract test (DI-08):
```python
def test_threats_risk_score_is_camel_case(self):
    data = get_view("threats")
    if data.get("threats"):
        first = data["threats"][0]
        assert "riskScore" in first, f"threats[0] missing 'riskScore'. Keys: {list(first.keys())}"
        assert "risk_score" not in first, "threats[0] has snake_case 'risk_score' — should be 'riskScore'"
```

## Definition of Done
- All BFF-to-frontend field name mismatches from DI-09 mismatch table fixed
- Contract tests updated to assert camelCase field names
- MITRE tactics tab shows data after deploy (was always empty due to `mitre_tactics` vs `mitreTactics`)
