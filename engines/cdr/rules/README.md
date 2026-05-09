# CIEM Detection Rules

## Three Levels

### Level 1: Detection Rules (single event)
- Evaluate each log event independently
- "IF this event matches condition → finding"
- Files: `l1_threat_rules.yaml`, `l1_ciem_rules.yaml`, `l1_datasec_rules.yaml`

### Level 2: Correlation Scenarios (multi-event)
- Match patterns across multiple events within a time window
- "IF event A followed by event B within 10 min → alert"
- Files: `l2_threat_scenarios.yaml`, `l2_ciem_scenarios.yaml`

### Level 3: Behavior Baselines (statistical)
- Learn normal patterns, detect deviations
- "IF this role's API call count exceeds 3 stddev from baseline → anomaly"
- Files: `l3_baselines.yaml`

## Mapping
Each L1 rule references which L2 scenarios it feeds into.
Each L2 scenario references which L3 baselines it relates to.

## Source
CSPM posture rules (check_rules) verify logging IS configured.
These rules analyze what the logs CONTAIN.
