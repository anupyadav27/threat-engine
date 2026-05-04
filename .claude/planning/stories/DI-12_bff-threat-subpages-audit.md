# DI-12: BFF — Threat Sub-Pages Contract Audit (9 Threat Sub-Views)

## Track
Track 2 — BFF Contract Audit

## Priority
P1

## Story
As a frontend engineer, I need each of the 9 threat sub-pages to return correctly shaped data from their dedicated BFF views, so that the Threat page tabs (Overview, MITRE, Attack Paths, Findings, Timeline, Command Room, Toxic Combos, Blast Radius, Posture Delta) all render data.

## The 9 Threat Sub-Views

| URL path | BFF view file | View name |
|----------|---------------|-----------|
| /threats (overview) | `threats.py` | `threats` |
| /threats/attack-paths | `threat_attack_paths.py` | `threats/attack-paths` |
| /threats/blast-radius | `threat_blast_radius.py` | `threats/blast-radius` |
| /threats/command-room | `threat_command_room.py` | `threats/command-room` |
| /threats/graph | `threat_graph.py` | `threats/graph` |
| /threats/posture-delta | `threat_posture_delta.py` | `threats/posture-delta` |
| /threats/scenario/{id} | `threat_scenario_detail.py` | `threats/scenario/{id}` |
| /threats/timeline | `threat_timeline.py` | `threats/timeline` |
| /threats/toxic-combinations | `threat_toxic_combos.py` | `threats/toxic-combinations` |

## Audit Tasks Per View

For each view, do:

1. **Read the frontend page component** — find the JSX file, list every field it reads from `data`
2. **Read the BFF view handler** — list every key in the `result` dict returned
3. **Compare** — find gaps (missing fields) and mismatches (wrong names)
4. **Fix** — apply fixes directly in this story

## Known Issue: threat_command_room.py

The Command Room view aggregates data from the threat engine's "active threats" summary plus the compliance engine's recent failures. Verify:
- The BFF handler exists and is registered in `shared/api_gateway/bff/__init__.py`
- The corresponding frontend page imports `useViewFetch('threats/command-room')` or equivalent
- The engine endpoint it calls returns current data

## Known Issue: threat_posture_delta.py

This view has two endpoints (lines 304 and 525 based on grep output). Verify both are converted in DI-05/DI-06. Verify the frontend page uses the correct view name.

## Fix Pattern

For each gap or mismatch found:

```python
# In the BFF view handler's result dict, add or rename the field:
result = {
    # ... existing fields ...
    "newField": computed_value,           # add missing field
    "riskScore": item.get("risk_score"),  # rename mismatch
}
```

## Acceptance Criteria

- [ ] All 9 view BFF handlers read and audited
- [ ] All 9 frontend page components read and audited
- [ ] Gap table created (can be inline in this story) for all 9 views
- [ ] All identified field mismatches fixed
- [ ] All identified missing fields either added to BFF or filed as engine gaps
- [ ] Attack Paths tab shows attack path data (not empty)
- [ ] Timeline tab shows trend data
- [ ] Toxic Combos tab shows combinations

## Research Commands

```bash
# Find frontend files for each threat sub-page
find /Users/apple/Desktop/threat-engine/frontend/src/app/threats -name "*.jsx" | sort

# Find what fields each component reads
grep -h "data\." /Users/apple/Desktop/threat-engine/frontend/src/app/threats/attack-paths/page.jsx \
  | grep -oP '(?<=data\.)[a-zA-Z]+' | sort -u
```

## Definition of Done
- All 9 sub-view handlers audited
- All gaps documented
- All BFF-fixable gaps fixed
- Contract tests added for each sub-view (at minimum: response is 200, has expected top-level key)
