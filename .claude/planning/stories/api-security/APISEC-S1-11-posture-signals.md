# Story APISEC-S1-11: Posture Signals — write_api_posture_signals()

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 3
- **Depends on**: APISEC-S1-01 (apisec_002_posture_columns migration), APISEC-S1-03
- **Blocks**: APISEC-S1-05 (run_scan calls this after writer)
- **Security Gate**: bmad-security-reviewer (UPSERT scoped by resource_uid + scan_run_id + tenant_id)

## Implementation

**File**: `engines/api-security/api_security_engine/storage/posture_signals.py`

```python
import logging
from typing import List, Dict, Any

import psycopg2.extras

logger = logging.getLogger("api_security.posture_signals")

_UPSERT_SQL = """
    INSERT INTO resource_security_posture (
        resource_uid, scan_run_id, tenant_id,
        api_auth_type,
        api_has_waf,
        api_has_rate_limit,
        api_publicly_accessible,
        api_deprecated_version_active,
        api_security_score,
        api_detail
    ) VALUES (
        %(resource_uid)s, %(scan_run_id)s, %(tenant_id)s,
        %(api_auth_type)s,
        %(api_has_waf)s,
        %(api_has_rate_limit)s,
        %(api_publicly_accessible)s,
        %(api_deprecated_version_active)s,
        %(api_security_score)s,
        %(api_detail)s
    )
    ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO UPDATE SET
        api_auth_type                 = EXCLUDED.api_auth_type,
        api_has_waf                   = EXCLUDED.api_has_waf,
        api_has_rate_limit            = EXCLUDED.api_has_rate_limit,
        api_publicly_accessible       = EXCLUDED.api_publicly_accessible,
        api_deprecated_version_active = EXCLUDED.api_deprecated_version_active,
        api_security_score            = EXCLUDED.api_security_score,
        api_detail                    = EXCLUDED.api_detail
"""

_SEVERITY_SCORE_PENALTY = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 5,
}


def write_api_posture_signals(
    inv_conn,
    findings: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> None:
    """
    Aggregate findings per resource and upsert posture signals into
    resource_security_posture (threat_engine_inventory DB).
    """
    if not findings:
        return

    # Group findings by resource_uid
    by_resource: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        uid = f.get("resource_uid", "")
        if uid:
            by_resource.setdefault(uid, []).append(f)

    rows = []
    for resource_uid, res_findings in by_resource.items():
        rows.append(_build_row(resource_uid, res_findings, scan_run_id, tenant_id))

    with inv_conn.cursor() as cur:
        psycopg2.extras.execute_batch(cur, _UPSERT_SQL, rows, page_size=200)
    inv_conn.commit()
    logger.info(f"Posture signals: upserted {len(rows)} resource rows")


def _build_row(
    resource_uid: str,
    findings: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> Dict[str, Any]:
    # Aggregate booleans (any finding sets the flag)
    has_waf = any(f.get("has_waf") for f in findings)
    has_rate_limit = any(f.get("has_rate_limit") for f in findings)
    is_public = any(f.get("is_publicly_accessible") for f in findings)
    is_deprecated = any(f.get("is_deprecated_version") for f in findings)

    # Auth type: pick the most-recently-seen (last in list wins)
    auth_type = None
    for f in findings:
        if f.get("auth_type") and f["auth_type"] != "none":
            auth_type = f["auth_type"]

    # Security score: 100 minus penalties per finding (floor 0)
    score = 100
    for f in findings:
        sev = f.get("severity", "low")
        score -= _SEVERITY_SCORE_PENALTY.get(sev, 0)
    score = max(0, score)

    # API detail JSONB summary
    rule_ids = list({f.get("rule_id", "") for f in findings if f.get("rule_id")})
    api_names = list({f.get("api_name", "") for f in findings if f.get("api_name")})
    owasp_cats = list({f.get("owasp_api_category", "") for f in findings if f.get("owasp_api_category")})

    api_detail = {
        "finding_count": len(findings),
        "rule_ids": rule_ids[:20],
        "api_names": api_names[:10],
        "owasp_categories": owasp_cats,
    }

    return {
        "resource_uid":               resource_uid,
        "scan_run_id":                scan_run_id,
        "tenant_id":                  tenant_id,
        "api_auth_type":              auth_type,
        "api_has_waf":                has_waf,
        "api_has_rate_limit":         has_rate_limit,
        "api_publicly_accessible":    is_public,
        "api_deprecated_version_active": is_deprecated,
        "api_security_score":         score,
        "api_detail":                 psycopg2.extras.Json(api_detail),
    }
```

## Notes

- Writes to `threat_engine_inventory` DB (not the api_security DB) via `inv_conn`.
- ON CONFLICT key is `(resource_uid, scan_run_id, tenant_id)` — same UNIQUE constraint used by all engine posture signal writers.
- Only updates the `api_*` columns — does not touch `is_encrypted_at_rest`, `db_auth_type`, or other engine columns.
- `api_security_score` degrades with findings; starts at 100 and subtracts per severity. Floors at 0 (no negative scores).

## Acceptance Criteria

- [ ] AC-1: Resource with 2 `high` findings → `api_security_score = 50` (100 − 25 − 25)
- [ ] AC-2: Resource with `is_publicly_accessible=True` finding → `api_publicly_accessible = TRUE` in posture row
- [ ] AC-3: Resource already has a posture row (other engine wrote it) → ON CONFLICT updates only `api_*` columns, leaves other columns unchanged
- [ ] AC-4: `api_detail` is JSONB object: `SELECT jsonb_typeof(api_detail) FROM resource_security_posture WHERE resource_uid = %s` returns `'object'`
- [ ] AC-5: 0 findings → no DB write (function returns early)
- [ ] AC-6: `tenant_id` always in the UPSERT row — no cross-tenant write path

## Definition of Done
- [ ] `posture_signals.py` committed at correct path
- [ ] Called from `run_scan.py`: `write_api_posture_signals(inv_conn, findings, scan_run_id, tenant_id)`
- [ ] AC-3 verified: posture row from network engine not overwritten for non-api columns
