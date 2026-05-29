# DI-S1-03 — Phase 0 Enumerator (All CSPs — Reuse Existing Scanner Classes)
**Sprint**: DI-S1 | **Points**: 13 | **Status**: Ready for Dev

## Goal
Build the Phase 0 (Enumerate) component of engine-di. This calls root_ops from
`resource_inventory_identifier` for every service registered for a given provider, extracts the
canonical resource UID using `identifier_pattern`, and passes rows to the Phase 2 writer.

**CRITICAL**: Reuse the existing CSP scanner classes from `engines/discoveries/providers/` for ALL
API calls, authentication, pagination, and retry logic. Do NOT rewrite anything already working.

## Context — Reuse Principle
The discoveries engine has battle-tested scanners for all 7 CSPs:
- `providers/aws/scanner/service_scanner.py` → `AWSDiscoveryScanner`, `run_service()`, `run_global_service()`
- `providers/azure/scanner/service_scanner.py` → `AzureDiscoveryScanner`
- `providers/gcp/scanner/service_scanner.py` → `GCPDiscoveryScanner`
- `providers/oci/scanner/service_scanner.py` → `OCIDiscoveryScanner`
- `providers/ibm/scanner/service_scanner.py` → `IBMDiscoveryScanner`
- `providers/alicloud/scanner/service_scanner.py` → `AliCloudDiscoveryScanner`
- `providers/kubernetes/scanner/service_scanner.py` → `K8sDiscoveryScanner`

engine-di's Dockerfile copies `engines/discoveries/providers/` so it can `import` these classes
directly. The authentication, adaptive retry, pagination, and error handling are already correct —
they should be used as-is.

**What engine-di adds**: After the scanner returns raw API response data, engine-di applies
Phase 0 UID construction using `identifier_pattern` from `resource_inventory_identifier` BEFORE
writing any row. No synthetic UIDs are written under any circumstance.

## Files to Create / Modify
- `engines/di/di_engine/phase0/enumerator.py` — Phase 0 core logic
- `engines/di/di_engine/phase0/__init__.py` — empty
- `engines/di/di_engine/phase0/uid_builder.py` — canonical UID construction from identifier_pattern
- `engines/di/di_engine/phase0/identifier_loader.py` — loads `resource_inventory_identifier` for current scan's provider
- `engines/di/Dockerfile` — copies `engines/discoveries/providers/` so scanner imports work

## Architecture

```
Phase 0 flow (per provider per account):
  1. Load identifiers: SELECT * FROM resource_inventory_identifier WHERE csp=provider AND should_inventory=TRUE
  2. For each identifier: call root_op (API call via existing scanner class)
  3. For each item in response: build_canonical_uid(item, identifier)
     - If has_arn=True: use the ARN field value directly
     - If has_arn=False: substitute primary_param value into identifier_pattern
  4. If UID cannot be built: raise ResourceIdMissingError → log to di_scan_errors, skip row
  5. Pass {resource_uid, emitted_fields, raw_response, ...} to Phase 2 writer
```

## Implementation

### uid_builder.py
```python
"""Canonical UID construction from resource_inventory_identifier patterns."""
import re
from typing import Any, Dict, Optional
from engines.discoveries.providers.aws.aws_utils.extraction import (
    ResourceIdMissingError, auto_emit_arn_and_name
)


def build_canonical_uid(
    item: Dict[str, Any],
    identifier: Dict[str, Any],
    region: str,
    account_id: str,
) -> str:
    """Build canonical resource UID (ARN/OCID/ARM ID/CRN) from API response item.

    Args:
        item: Raw API response dict for a single resource
        identifier: Row from resource_inventory_identifier
        region: Cloud region
        account_id: Cloud account/subscription/project identifier

    Returns:
        Canonical resource UID string

    Raises:
        ResourceIdMissingError: If UID cannot be constructed — caller logs and skips
    """
    if identifier.get('has_arn'):
        # ARN already in the response — extract it
        auto_fields = auto_emit_arn_and_name(item)
        arn = auto_fields.get('resource_arn')
        if arn and arn.startswith('arn:'):
            return arn
        raise ResourceIdMissingError(
            f"has_arn=True but no ARN found in item. "
            f"service={identifier['service']!r} resource_type={identifier['resource_type']!r} "
            f"item_keys={list(item.keys())[:15]}"
        )

    # Build UID from identifier_pattern
    pattern: Optional[str] = identifier.get('identifier_pattern')
    primary_param: Optional[str] = identifier.get('primary_param')
    if not pattern or not primary_param:
        raise ResourceIdMissingError(
            f"No identifier_pattern or primary_param for service={identifier['service']!r} "
            f"resource_type={identifier['resource_type']!r}"
        )

    # Extract the primary_param value from nested path (supports dot notation)
    value = _extract_nested(item, primary_param)
    if not value:
        raise ResourceIdMissingError(
            f"primary_param={primary_param!r} not found in item. "
            f"service={identifier['service']!r} item_keys={list(item.keys())[:15]}"
        )

    # Substitute placeholders: {account_id}, {region}, {value}
    uid = pattern.format(
        account_id=account_id,
        region=region,
        value=str(value),
    )
    return uid


def _extract_nested(obj: Any, path: str) -> Any:
    """Extract value from nested dict using dot notation."""
    parts = path.split('.')
    current = obj
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current
```

### enumerator.py
```python
"""Phase 0: Enumerate resources via root_ops for all services."""
import logging
import os
from typing import Any, Dict, Generator, List, Optional
import psycopg2
from psycopg2.extras import RealDictCursor

from .uid_builder import build_canonical_uid
from engines.discoveries.providers.aws.aws_utils.extraction import ResourceIdMissingError

logger = logging.getLogger('di.phase0')

# Map provider → scanner class (reuse existing discoveries scanner classes)
def _get_scanner_class(provider: str):
    if provider == 'aws':
        from providers.aws.scanner.service_scanner import AWSDiscoveryScanner
        return AWSDiscoveryScanner
    elif provider == 'azure':
        from providers.azure.scanner.service_scanner import AzureDiscoveryScanner
        return AzureDiscoveryScanner
    elif provider == 'gcp':
        from providers.gcp.scanner.service_scanner import GCPDiscoveryScanner
        return GCPDiscoveryScanner
    elif provider == 'oci':
        from providers.oci.scanner.service_scanner import OCIDiscoveryScanner
        return OCIDiscoveryScanner
    elif provider == 'ibm':
        from providers.ibm.scanner.service_scanner import IBMDiscoveryScanner
        return IBMDiscoveryScanner
    elif provider == 'alicloud':
        from providers.alicloud.scanner.service_scanner import AliCloudDiscoveryScanner
        return AliCloudDiscoveryScanner
    elif provider == 'k8s':
        from providers.kubernetes.scanner.service_scanner import K8sDiscoveryScanner
        return K8sDiscoveryScanner
    raise ValueError(f"Unknown provider: {provider!r}")


def run_phase0(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
    regions: List[str],
    credentials: Dict[str, Any],
    inv_conn,  # psycopg2 connection to threat_engine_inventory (has identifier table)
    di_conn,   # psycopg2 connection to threat_engine_di (for di_scan_errors)
) -> Generator[Dict[str, Any], None, None]:
    """Enumerate all resources for a provider account, yield Phase 2-ready rows.

    Yields one dict per successfully identified resource:
    {scan_run_id, tenant_id, account_id, provider, region, resource_uid,
     resource_type, resource_name, service, discovery_id, phase=0,
     emitted_fields, raw_response}

    ResourceIdMissingError rows are logged to di_scan_errors and skipped.
    """
    # Load identifiers for this provider
    identifiers = _load_identifiers(inv_conn, provider)
    logger.info("Phase 0: loaded %d identifiers for provider=%s", len(identifiers), provider)

    # Initialize scanner (reuse existing class for auth + session management)
    ScannerClass = _get_scanner_class(provider)
    scanner = ScannerClass(credentials=credentials)
    scanner.authenticate()
    logger.info("Phase 0: authenticated to %s account %s", provider, account_id)

    for identifier in identifiers:
        service = identifier['service']
        resource_type = identifier['resource_type']
        root_ops = identifier.get('root_ops') or []
        is_global = identifier.get('is_global', False)
        scan_regions = ['global'] if is_global else regions

        for region in scan_regions:
            for op in root_ops:
                op_name = op if isinstance(op, str) else op.get('operation', '')
                try:
                    raw_items = _call_root_op(scanner, provider, service, region, op_name, credentials)
                except Exception as api_err:
                    _write_error(di_conn, scan_run_id, tenant_id, account_id, provider,
                                 region, service, identifier.get('discovery_id'),
                                 'APICallError', str(api_err))
                    continue

                for item in raw_items:
                    try:
                        resource_uid = build_canonical_uid(item, identifier, region, account_id)
                    except ResourceIdMissingError as rid_err:
                        logger.error("RESOURCE_ID_MISSING: %s", rid_err)
                        _write_error(di_conn, scan_run_id, tenant_id, account_id, provider,
                                     region, service, identifier.get('discovery_id'),
                                     'ResourceIdMissingError', str(rid_err),
                                     item_keys=list(item.keys())[:15])
                        continue  # no synthetic UID — row is skipped

                    yield {
                        'scan_run_id': scan_run_id,
                        'tenant_id': tenant_id,
                        'account_id': account_id,
                        'provider': provider,
                        'region': region,
                        'resource_uid': resource_uid,
                        'resource_type': resource_type,
                        'resource_name': _extract_name(item),
                        'service': service,
                        'discovery_id': identifier.get('discovery_id'),
                        'phase': 0,
                        'emitted_fields': _safe_emitted_fields(item),
                        'raw_response': {},  # Phase 0: no enrichment yet
                    }
```

### identifier_loader.py
```python
def _load_identifiers(inv_conn, provider: str) -> List[Dict]:
    """Load all should_inventory=True identifiers for a provider from resource_inventory_identifier."""
    with inv_conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT service, resource_type, root_ops, enrich_ops, primary_param,
                   identifier_pattern, has_arn, is_global, used_by_engines,
                   csp || '.' || service || '.' || (root_ops->0->>'operation') AS discovery_id
            FROM resource_inventory_identifier
            WHERE csp = %s AND should_inventory = TRUE
            ORDER BY service, resource_type
        """, (provider,))
        return [dict(row) for row in cur.fetchall()]
```

### _call_root_op
The scanner already handles pagination and retries. For AWS, use the existing `run_service()` and
`run_global_service()` functions with `session_override=scanner.session`. These return items as
they would normally — Phase 0 processes them before any write.

For non-AWS CSPs: call the scanner's equivalent method (each has a `scan_service()` or
`discover_service()` method — check each service_scanner.py and match the call pattern).

### Dockerfile (engine-di)
```dockerfile
FROM python:3.11-slim
WORKDIR /app

# Copy shared common (same as all other engines)
COPY shared/common /app/engine_common

# Copy engine-di application
COPY engines/di /app

# REUSE: copy discoveries providers (scanner classes for all CSPs)
# This avoids rewriting auth, pagination, and retry logic for all 7 CSPs
COPY engines/discoveries/providers /app/providers
COPY engines/discoveries/common /app/common

# Copy catalog YAML files (used by discovery engine for service definitions)
COPY catalog/discovery_generator_data /app/catalog

RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONPATH=/app
CMD ["python", "-m", "uvicorn", "di_engine.api.api_server:app", "--host", "0.0.0.0", "--port", "8025"]
```

## Acceptance Criteria

### Functional
- [ ] Phase 0 runs for all 7 providers (aws, azure, gcp, oci, ibm, alicloud, k8s) via the same code path
- [ ] AWS Phase 0: all EC2 instances in test account have canonical ARN (`arn:aws:ec2:...:instance/i-*`)
- [ ] Azure Phase 0: all VMs have ARM ID (`/subscriptions/*/resourceGroups/*/providers/Microsoft.Compute/virtualMachines/*`)
- [ ] GCP Phase 0: all Compute instances have projects URI
- [ ] OCI Phase 0: all Compute instances have OCID (`ocid1.instance.*`)
- [ ] K8s Phase 0: all pods have `k8s://{cluster}/{namespace}/{name}` UID
- [ ] No row written with synthetic UID (`region:name` format) — grep `di_scan_errors` for errors instead
- [ ] `di_scan_errors` receives a row for every `ResourceIdMissingError` and every `APICallError`
- [ ] Generator yields for each successfully identified resource (no buffering entire result set in memory)

### Security
- [ ] `credentials` dict not logged at any log level (no f-strings with credential values)
- [ ] Scanner classes authenticate per scan; sessions are not shared across scans
- [ ] No hardcoded AWS/Azure/GCP credentials in Dockerfile or code

### Error Handling
- [ ] `ResourceIdMissingError` → `di_scan_errors` row + `continue` — scan does not stop
- [ ] `APICallError` (boto3 ClientError, Azure SDK exception, etc.) → `di_scan_errors` row + `continue`
- [ ] Authentication failure → `AuthenticationError` raised — scan aborted with clear ERROR log
- [ ] `inv_conn` and `di_conn` closed in `finally` block in the caller (Phase 2 writer manages connections)

### RBAC Matrix (Phase 0 has no direct HTTP endpoint — tested via full scan)
- Scan trigger via POST `/api/v1/di/scan` requires `scans:create` permission
- All 5 roles × scan trigger endpoint tested in DI-S1-06

## Testing Requirements

**Unit** (`tests/engines/di/test_phase0_enumerator.py`):
- `build_canonical_uid(item, identifier, region, account_id)` with `has_arn=True` → extracts ARN
- `build_canonical_uid(item, identifier, region, account_id)` with `has_arn=False` → substitutes pattern
- `build_canonical_uid(item_without_primary_param, identifier, ...)` → raises `ResourceIdMissingError`
- `_load_identifiers()` query uses `csp = %s AND should_inventory = TRUE`
- Provider dispatch: `_get_scanner_class('aws')` → `AWSDiscoveryScanner`; `_get_scanner_class('gcp')` → `GCPDiscoveryScanner`
- Coverage ≥ 80% on `uid_builder.py`, `identifier_loader.py`, `enumerator.py`

**Integration** (runs against test account via port-forward):
1. Trigger Phase 0 for `provider='aws'`, record yielded resource_uid count
2. Assert all resource_uids start with `arn:aws:` (100%)
3. Assert `di_scan_errors` count = 0 for a known-good identifier set

**CSP coverage test** (can be mocked):
- `_get_scanner_class(provider)` successfully imports and instantiates for all 7 providers

**Post-deploy smoke** (via DI-S1-06 scan trigger):
```bash
POST /api/v1/di/scan → 202
GET /api/v1/di/scan/{scan_run_id}/status → "running"
# After completion:
SELECT count(*) FROM asset_inventory WHERE provider='aws' AND phase=0;
-- Expected: > 0
SELECT count(*) FROM di_scan_errors WHERE error_type='ResourceIdMissingError';
-- Expected: 0 for services with correct identifier_pattern
```

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev design review | bmad-security-architect | dev start (mandatory — new engine, credential handling) |
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge (credential handling in scanner auth) |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `engines/di/di_engine/phase0/` created with all 3 modules
- [ ] Dockerfile copies `engines/discoveries/providers/` — scanner imports verified
- [ ] All 7 CSP scanner classes import successfully from within engine-di container
- [ ] `build_canonical_uid()` handles `has_arn=True` and `has_arn=False` paths
- [ ] Phase 0 scan on test account: all yielded UIDs are canonical (no synthetic format)
- [ ] Unit tests ≥ 80% coverage; integration test passing
- [ ] bmad-security-architect design review signed off
- [ ] bmad-security-reviewer gate passed
- [ ] MEMORY.md updated: engine-di Phase 0 reuses discoveries scanner classes

## Dependencies
- DI-S1-01 (threat_engine_di DB exists)
- DI-S1-02 (identifier table has `used_by_engines` column + `discovery_id` computed column)

## Rollback
No data written by Phase 0 alone — it only yields. If Phase 0 misbehaves, stop the DI scan:
`kubectl delete pods -l app=engine-di -n threat-engine-engines`