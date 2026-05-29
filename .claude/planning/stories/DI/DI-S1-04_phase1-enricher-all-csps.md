# DI-S1-04 — Phase 1 Enricher (All CSPs — rule_discoveries Driven)
**Sprint**: DI-S1 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Build Phase 1 (Enrich). For each service×region pair where Phase 0 found resources, call the
`enrich_ops` from `resource_inventory_identifier` (these are the detailed describe/get API calls).
Reuse the existing CSP scanner classes for all API calls. Only services where Phase 0 produced
resources are enriched — no calls for empty regions/services.

## Context
Phase 0 yields minimal resource rows (phase=0) with just the canonical UID and basic fields.
Phase 1 enriches those rows with full API response data (phase=1) by calling `enrich_ops`.
The enrichment driver is the `rule_discoveries` table in the check DB, which maps rule_id →
discovery_id → the operations that provide rule-evaluation data. engine-di runs enrich_ops only
for service×region pairs where Phase 0 found ≥ 1 resource.

## Files to Create / Modify
- `engines/di/di_engine/phase1/enricher.py` — Phase 1 core logic
- `engines/di/di_engine/phase1/__init__.py` — empty
- `engines/di/di_engine/phase1/enrich_plan.py` — builds (service, region) plan from Phase 0 output

## Architecture

```
Phase 1 flow:
  1. From Phase 0 output: collect {provider, service, region} pairs that produced ≥ 1 resource
  2. Load enrich_ops from resource_inventory_identifier for those service×CSP pairs
  3. Also load rule_discoveries from check DB: these are additional enrichment calls per rule
  4. For each service×region: call enrich_ops via existing scanner class
  5. Match enrichment response to Phase 0 row via resource_uid join
  6. Update row: set phase=1, emitted_fields=merged, raw_response=full API response
```

## Implementation

### enrich_plan.py
```python
"""Build an enrichment plan from Phase 0 output."""
from collections import defaultdict
from typing import Dict, List, Set, Tuple

def build_enrich_plan(
    phase0_rows: List[Dict],
    identifiers: List[Dict],
) -> Dict[Tuple[str, str], List[Dict]]:
    """Return {(service, region): [enrich_op_dicts]} for services that produced resources.

    Only services with ≥ 1 Phase 0 resource get enrich ops scheduled.
    This is the key efficiency gain: if EC2 found 0 VMs in eu-west-3, no describe_instances
    call is made for eu-west-3.
    """
    # Collect (service, region) pairs from Phase 0
    active_pairs: Set[Tuple[str, str]] = set()
    for row in phase0_rows:
        active_pairs.add((row['service'], row['region']))

    # Build plan: for each active pair, collect enrich_ops
    plan: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
    identifier_map = {(id_['service'],): id_ for id_ in identifiers}

    for identifier in identifiers:
        service = identifier['service']
        enrich_ops = identifier.get('enrich_ops') or []
        if not enrich_ops:
            continue
        for region in [r for (s, r) in active_pairs if s == service]:
            plan[(service, region)].extend(enrich_ops)

    return dict(plan)
```

### enricher.py
```python
"""Phase 1: Enrich Phase 0 resources with detailed API call data."""
import logging
from typing import Any, Dict, Generator, List

logger = logging.getLogger('di.phase1')


def run_phase1(
    phase0_rows: List[Dict[str, Any]],
    identifiers: List[Dict],
    scanner,  # existing CSP scanner (already authenticated in Phase 0)
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    di_conn,  # for di_scan_errors writes
) -> Generator[Dict[str, Any], None, None]:
    """Enrich Phase 0 resources via enrich_ops. Yields updated rows (phase=1).

    Uses the same scanner instance from Phase 0 — no re-authentication needed.
    Scanner handles all pagination, retries, and error handling.

    For services with no enrich_ops, yields Phase 0 rows unchanged (phase stays 0).
    """
    from .enrich_plan import build_enrich_plan
    plan = build_enrich_plan(phase0_rows, identifiers)

    # Index Phase 0 rows by (service, region, resource_uid) for lookup
    p0_index: Dict[str, Dict] = {row['resource_uid']: row for row in phase0_rows}

    enriched_uids = set()

    for (service, region), enrich_ops in plan.items():
        for op in enrich_ops:
            op_name = op if isinstance(op, str) else op.get('operation', '')
            try:
                raw_items = _call_enrich_op(scanner, provider, service, region,
                                            op_name, account_id)
            except Exception as api_err:
                logger.warning("Phase1 enrich_op=%s service=%s region=%s failed: %s",
                               op_name, service, region, api_err)
                _write_error(di_conn, scan_run_id, tenant_id, account_id, provider,
                             region, service, None, 'APICallError', str(api_err))
                continue

            for item in raw_items:
                # Match to Phase 0 row by primary_param value → resource_uid
                matched_uid = _match_phase0_row(item, service, region, account_id, identifiers)
                if not matched_uid or matched_uid not in p0_index:
                    continue

                p0_row = p0_index[matched_uid]
                merged_emitted = {**p0_row['emitted_fields'], **_safe_emitted_fields(item)}
                enriched_row = {
                    **p0_row,
                    'phase': 1,
                    'emitted_fields': merged_emitted,
                    'raw_response': item,  # full enrichment response
                }
                p0_index[matched_uid] = enriched_row
                enriched_uids.add(matched_uid)

    # Yield all rows (phase=1 if enriched, phase=0 if no enrich_ops for this service)
    for uid, row in p0_index.items():
        yield row

    logger.info("Phase 1 complete: %d/%d rows enriched", len(enriched_uids), len(p0_index))


def _call_enrich_op(scanner, provider: str, service: str, region: str,
                    op_name: str, account_id: str) -> List[Dict]:
    """Call a single enrich_op via the existing scanner's API client.

    Reuses the scanner's authenticated session for all API calls.
    AWS: uses scanner.session to get boto3 client
    Non-AWS: uses scanner's equivalent client factory
    """
    if provider == 'aws':
        from providers.aws.scanner.service_scanner import run_regional_service, run_global_service
        # Call via the existing function — same retry/pagination logic
        results = run_regional_service(
            service_name=f"{service}.{op_name}",
            region=region,
            session_override=scanner.session,
            skip_checks=True,  # skip DB writes — Phase 0/2 writer handles writes
        )
        return results or []
    # Azure, GCP, OCI, IBM, AliCloud, K8s — call scanner.scan_service() equivalent
    # Each CSP scanner exposes scan_service(service, region) → List[Dict]
    return scanner.scan_service(service, region, op_name) or []
```

## Acceptance Criteria

### Functional
- [ ] Phase 1 only runs enrich_ops for (service, region) pairs where Phase 0 found ≥ 1 resource
- [ ] Phase 1 does NOT re-authenticate — uses the same scanner session from Phase 0
- [ ] EC2 instances enriched: `emitted_fields` contains SecurityGroups, VpcId, SubnetId, Tags.Name
- [ ] S3 buckets enriched: `emitted_fields` contains ServerSideEncryptionConfiguration, BucketPolicy, Versioning
- [ ] RDS instances enriched: `emitted_fields` contains VpcSecurityGroups, MasterUsername (masked), MultiAZ
- [ ] Azure VMs enriched: `emitted_fields` contains networkProfile.networkInterfaces, storageProfile.osDisk
- [ ] GCP Compute instances enriched: `emitted_fields` contains networkInterfaces, metadata.items
- [ ] Phase 0 rows with no enrich_ops yield with `phase=0` (not phase=1) — unchanged
- [ ] `rule_discoveries` ops also covered: check engine's enrichment discovery_ids included in plan

### Security
- [ ] `raw_response` does NOT contain credentials/access_keys/password fields before Phase 2 scrubs them
  (Phase 2 is responsible for scrubbing — this story adds a `_safe_emitted_fields()` helper that
  removes known sensitive keys: `MasterUserPassword`, `AccessKeyId`, `SecretAccessKey`,
  `AuthToken`, `ConnectionString`, `Password`)
- [ ] Scanner session not logged; credential values not in any log line
- [ ] `skip_checks=True` passed to `run_regional_service` to prevent Phase 1 writing to `discovery_findings`

### Error Handling
- [ ] `APICallError` during enrich_op → log at WARNING + `di_scan_errors` row + continue (not a fatal error)
- [ ] Phase 0 rows without matched enrich data yield unchanged (no missing-enrichment crash)

## Testing Requirements

**Unit** (`tests/engines/di/test_phase1_enricher.py`):
- `build_enrich_plan()`: service with Phase 0 resources → ops scheduled; service without → not scheduled
- `run_phase1()`: enriched row has `phase=1`, merged `emitted_fields`; unenriched row has `phase=0`
- `_safe_emitted_fields()`: removes `MasterUserPassword`, `AccessKeyId`, `SecretAccessKey` keys
- `run_regional_service` called with `skip_checks=True` on AWS path
- Coverage ≥ 80% on `enricher.py` and `enrich_plan.py`

**Integration**:
1. Run Phase 0 + Phase 1 for AWS test account
2. Assert ≥ 80% of Phase 0 rows have `phase=1` after Phase 1 (most services have enrich_ops)
3. Assert EC2 instance rows have `emitted_fields.SecurityGroups` populated
4. Assert no `MasterUserPassword` in any `raw_response` JSONB

**Post-deploy smoke** (combined with DI-S1-06):
```sql
SELECT phase, count(*) FROM asset_inventory GROUP BY phase;
-- Expected: phase=0: small number (no enrich_ops), phase=1: majority
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (sensitive field scrubbing must be verified) |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `engines/di/di_engine/phase1/` created with `enricher.py` + `enrich_plan.py`
- [ ] `_safe_emitted_fields()` strips known sensitive keys before any write
- [ ] Phase 1 only calls enrich_ops for services with Phase 0 resources (verified by unit test)
- [ ] `run_regional_service` called with `skip_checks=True` — no writes to `discovery_findings`
- [ ] ≥ 80% of Phase 0 rows enriched to `phase=1` in integration test
- [ ] Unit tests ≥ 80% coverage; sensitive field scrubbing tested
- [ ] bmad-security-reviewer gate passed

## Dependencies
- DI-S1-03 (Phase 0 enumerator — Phase 1 uses its scanner instance and row output)
- DI-S1-02 (`enrich_ops` column in identifier table)
- check DB accessible for `rule_discoveries` lookup (optional in this story — can skip rule_discoveries enrichment and add in DI-S1-05)

## Rollback
Phase 1 enriches in-memory generator — no direct DB writes. If Phase 1 has bugs, it fails
before Phase 2 writes any rows. Revert to Phase 0-only by setting an env var:
`DI_PHASE1_ENABLED=false` (skips enrichment plan, all rows yield as phase=0).