---
story_id: AZ-13
title: E2E Azure Discovery Scan Validation
status: ready
sprint: azure-track-wave-7
depends_on: [AZ-12, AZ-06, AZ-07, AZ-08, AZ-08b, AZ-09, AZ-10, AZ-11]
blocks: [AZ-14, AZ-16, AZ-17, AZ-17b, AZ-13b]
sme: QA + Backend
estimate: 1 day
---

# Story: E2E Azure Discovery Scan Validation

## Context
First live Azure scan against subscription `f6d24b5d-51ed-47b7-9f6a-0ad194156b5e`. This validates the scanner, credential resolution, DB writes, and scan orchestration end-to-end.

## How to Trigger

```bash
export SCAN_RUN_ID=$(python -c "import uuid; print(uuid.uuid4())")
export TENANT_ID="<your-tenant-id>"
export ACCOUNT_ID="f6d24b5d-51ed-47b7-9f6a-0ad194156b5e"

bash deployment/aws/eks/argo/trigger-scan.sh \
  $SCAN_RUN_ID $TENANT_ID $ACCOUNT_ID azure
```

## Validation Script

Create `scripts/validate_azure_scan.py`:

```python
"""Validates Azure E2E scan results."""
import sys
import re
import psycopg2

SCAN_RUN_ID = sys.argv[1]

# Connect to RDS
conn = psycopg2.connect(...)
cur = conn.cursor()

# Check 1: >= 100 Azure resources discovered
cur.execute("SELECT COUNT(*) FROM discovery_findings WHERE scan_run_id=%s AND provider='azure'", (SCAN_RUN_ID,))
count = cur.fetchone()[0]
assert count >= 100, f"FAIL: Only {count} Azure resources discovered (need >= 100)"
print(f"PASS: {count} Azure resources discovered")

# Check 2: All resource_uids match Azure format
cur.execute("""
    SELECT COUNT(*) FROM discovery_findings
    WHERE scan_run_id=%s AND provider='azure'
    AND resource_uid NOT LIKE '/subscriptions/%%'
""", (SCAN_RUN_ID,))
bad_uids = cur.fetchone()[0]
assert bad_uids == 0, f"FAIL: {bad_uids} resources have invalid resource_uid format"
print("PASS: All resource_uids match Azure format")

# Check 3: scan_runs.overall_status = 'completed'
cur.execute("SELECT overall_status FROM scan_runs WHERE scan_run_id=%s", (SCAN_RUN_ID,))
status = cur.fetchone()[0]
assert status == 'completed', f"FAIL: scan_runs.overall_status = '{status}' (expected 'completed')"
print(f"PASS: Scan status = {status}")

print("ALL CHECKS PASSED")
```

## Pass Criteria (ALL must be met)

- [ ] `discovery_findings WHERE provider='azure' AND scan_run_id=<id>` COUNT >= 100
- [ ] All `resource_uid` values match `/subscriptions/f6d24b5d.+` regex
- [ ] Error rate in Argo scan logs < 5% (count `ERROR` log lines / total API calls)
- [ ] Scan duration < 60 minutes (`scan_runs.finished_at - started_at`)
- [ ] `scan_runs.overall_status = 'completed'`

## Failure Triage Guide

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| 0 resources, status=failed | Credential resolution broken | Check AZ-17b — Secrets Manager path |
| status=credential_expiry_warning | Azure SP expired | Rotate SP secret |
| status=completed but < 10 resources | Noise removal too aggressive | Check rule_discoveries is_enabled |
| resource_uid missing /subscriptions/ | Normalization bug in AZ-04 | Fix _RESOURCE_TYPE_MAP |
| Scan > 60 minutes | Timeout not working | Check AZ-02b implementation |

## Definition of Done
- [ ] All 5 pass criteria verified by validation script
- [ ] Validation script committed to `scripts/validate_azure_scan.py`
- [ ] Scan run ID + results logged in this story file (update with actual counts)