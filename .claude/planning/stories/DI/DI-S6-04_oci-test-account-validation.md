# DI-S6-04 — OCI Test Account Validation
**Sprint**: DI-S6 | **Type**: Validation | **Status**: Planned
**Points**: 2 | **Priority**: Low (OCI pipeline likely works, account is empty)

---

## Context

OCI scan (scan_run_id `e8f4eac4-d982-43d0-9137-bb7a745d80d3`) completed with:
- 0 rows written
- 0 errors
- 1129 identifiers loaded from DB
- No AuthError logged

This is consistent with an **empty test account** — the API calls succeeded but returned no
resources for the 5 services scanned (compute, objectstorage, identity, database, core).

OCI has 1705 active check rules and 293 active rule_discoveries. The pipeline code is correct.

---

## Validation Steps

### Option A — Provision minimal free resources ($0 cost)
OCI Always Free tier includes:
- 2 AMD VM instances (compute)
- 2 Object Storage buckets (objectstorage)
- 1 Autonomous Database (database)

Provision one of each, re-run scan, confirm rows appear.

### Option B — Check existing account resources
```bash
# Run full OCI scan (no --services filter) and check di_scan_errors for AuthErrors
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id e8f4eac4-d982-43d0-9137-bb7a745d80d3 \
   > /tmp/di_scan_oci_full.log 2>&1 & disown && echo started"

# If AuthError → credential issue
# If 0 rows + 0 errors again → account is genuinely empty
```

### Acceptance Criteria
- [ ] OCI scan with a provisioned resource writes ≥ 1 row to asset_inventory with `resource_uid` starting with `ocid1.`
- [ ] OR confirm via OCI Console that test account has zero resources (closes as expected behavior)