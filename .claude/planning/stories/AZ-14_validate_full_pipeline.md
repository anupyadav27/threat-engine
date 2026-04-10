---
story_id: AZ-14
title: Validate Full Azure Pipeline (Check → Threat → Compliance → IAM → Neo4j)
status: ready
sprint: azure-track-wave-7
depends_on: [AZ-13]
blocks: [AZ-18]
sme: QA + Backend
estimate: 1 day
---

# Story: Validate Full Azure Pipeline

## Context
AZ-13 validates the discovery scan only. This story validates that all downstream engines
(check, inventory, threat, compliance, IAM) correctly process Azure data from a completed
discovery scan. Also verifies Neo4j has correct Azure node labels and provider properties.

## Files to Create

- `scripts/validate_azure_pipeline.py`

## Validation Checks

### Check Engine
- `check_findings WHERE provider='azure' AND scan_run_id=<id>` COUNT > 0
- At least 3 distinct rule_ids matched
- No check_findings with NULL severity

### Inventory Engine
- `inventory_findings WHERE provider='azure' AND scan_run_id=<id>` COUNT > 0
- `service_classification WHERE csp='azure'` joined successfully (no "unknown" categories)

### Threat Engine
- `threat_findings WHERE provider='azure' AND scan_run_id=<id>` COUNT > 0 (or 0 is acceptable if no misconfigs)
- Neo4j: `MATCH (r:Resource {provider:'azure'}) RETURN count(r)` > 0
- Neo4j: `MATCH (r:VirtualMachine) RETURN count(r)` > 0 (correct label — not "CloudResource")
- Neo4j: No `(r:CloudResource {provider:'azure'})` nodes (regression check on _neo4j_label fix)

### Compliance Engine
- `compliance_report WHERE provider='azure' AND framework_id='cis_azure_1_5'` row exists after scoring run
- CIS Azure 1.5 score > 0 (even if low — just must be computed)

### IAM Engine
- `iam_findings WHERE provider='azure' AND scan_run_id=<id>` COUNT > 0

## How to Run

```bash
# After AZ-13 scan completes:
SCAN_RUN_ID=<id from AZ-13>
TENANT_ID=<your tenant>

# Port-forward all DBs or use RDS host directly
DISCOVERIES_DB_HOST=localhost \
CHECK_DB_HOST=localhost \
THREAT_DB_HOST=localhost \
COMPLIANCE_DB_HOST=localhost \
IAM_DB_HOST=localhost \
NEO4J_PASSWORD=xxx \
python scripts/validate_azure_pipeline.py $SCAN_RUN_ID $TENANT_ID
```

## Acceptance Criteria
- [ ] All 5 engines have Azure findings for the scan_run_id
- [ ] Neo4j has VirtualMachine/StorageAccount labels (not CloudResource)
- [ ] CIS Azure 1.5 compliance score computed
- [ ] No "CloudResource" nodes with provider=azure in Neo4j

## Definition of Done
- [ ] Validation script committed
- [ ] All checks pass on live data
- [ ] Actual counts recorded in this story file