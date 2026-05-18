# Story UIBFF-BFF-01: BFF Shared `read_findings()` Helper

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-BFF — Shared Query Layer
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P1 (prerequisite for Phase 5 BFF migration to two-table architecture)
- **Depends on**: All WRITER stories must be done (security_findings populated by all engines)
- **Blocks**: UIBFF-ARCH-01 through ARCH-07 (all BFF migrations use this helper)

## User Story

As a developer, I want a single shared `read_findings()` function in the BFF layer that reads from the `security_findings` table so every BFF handler can query a single source of truth instead of calling individual engine endpoints.

## Context

Currently each BFF handler (misconfig, IAM, network, datasec, CDR, encryption, container) calls its own engine's `/ui-data` HTTP endpoint to get findings. This creates:
- N×engine HTTP calls per page load
- Each engine must be healthy for the BFF to work
- No cross-engine aggregation

The `security_findings` table in `threat_engine_inventory` DB already collects from 7 engines (check, iam, network, datasec, cdr, container, api_security). After WRITER stories complete, it will cover 12 engines total.

This story adds a shared DB-direct helper to `_shared.py`.

## What to Build

### 1. Add `read_findings()` to `shared/api_gateway/bff/_shared.py`

```python
from typing import Optional, List, Dict, Any
from engine_common.db_connections import get_inventory_conn

async def read_findings(
    tenant_id: str,
    source_engines: Optional[List[str]] = None,
    posture_category: Optional[str] = None,
    severity: Optional[List[str]] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    provider: Optional[str] = None,
    resource_uid: Optional[str] = None,
    scan_run_id: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
    order_by: str = "severity DESC, last_seen_at DESC",
) -> Dict[str, Any]:
    """Read findings from security_findings table. Always tenant-scoped.

    Returns:
        {"findings": [...], "total": int, "by_severity": {...}, "by_engine": {...}}
    """
    conditions = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]

    if source_engines:
        placeholders = ",".join(["%s"] * len(source_engines))
        conditions.append(f"source_engine IN ({placeholders})")
        params.extend(source_engines)

    if posture_category:
        conditions.append("posture_category = %s")
        params.append(posture_category)

    if severity:
        placeholders = ",".join(["%s"] * len(severity))
        conditions.append(f"severity IN ({placeholders})")
        params.extend(severity)

    if account_id:
        conditions.append("account_id = %s")
        params.append(account_id)

    if region:
        conditions.append("region = %s")
        params.append(region)

    if provider:
        conditions.append("provider = %s")
        params.append(provider)

    if resource_uid:
        conditions.append("resource_uid = %s")
        params.append(resource_uid)

    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)

    where = " AND ".join(conditions)

    count_sql = f"SELECT COUNT(*) FROM security_findings WHERE {where}"
    agg_sql = f"""
        SELECT source_engine, severity, COUNT(*) AS cnt
        FROM security_findings
        WHERE {where}
        GROUP BY source_engine, severity
    """
    data_sql = f"""
        SELECT
            finding_id, source_engine, source_finding_id, tenant_id,
            scan_run_id, account_id, provider, region,
            resource_uid, resource_type, rule_id, severity, status,
            title, description, remediation, posture_category,
            details, first_seen_at, last_seen_at
        FROM security_findings
        WHERE {where}
        ORDER BY {order_by}
        LIMIT %s OFFSET %s
    """

    with get_inventory_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(count_sql, params)
            total = cur.fetchone()[0]

            cur.execute(agg_sql, params)
            agg_rows = cur.fetchall()

            cur.execute(data_sql, params + [limit, offset])
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()

    findings = [dict(zip(cols, r)) for r in rows]

    # Build aggregations
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_engine: Dict[str, int] = {}
    for engine, sev, cnt in agg_rows:
        if sev in by_severity:
            by_severity[sev] += cnt
        by_engine[engine] = by_engine.get(engine, 0) + cnt

    return {
        "findings":    findings,
        "total":       total,
        "by_severity": by_severity,
        "by_engine":   by_engine,
    }
```

### 2. Add `read_findings_for_asset()` convenience wrapper

```python
async def read_findings_for_asset(
    tenant_id: str,
    resource_uid: str,
    source_engines: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """All findings for a specific resource_uid across engines."""
    return await read_findings(
        tenant_id=tenant_id,
        resource_uid=resource_uid,
        source_engines=source_engines,
        limit=500,
    )
```

### 3. Add unit tests

File: `shared/api_gateway/bff/tests/test_read_findings.py`

```python
def test_read_findings_tenant_isolation(mock_inventory_conn):
    """Verify tenant_id always appears as first WHERE condition."""
    result = asyncio.run(read_findings(tenant_id="t1"))
    executed_sql = mock_inventory_conn.last_query
    assert "tenant_id = %s" in executed_sql
    assert mock_inventory_conn.last_params[0] == "t1"

def test_read_findings_empty_returns_zeros(mock_inventory_conn_empty):
    result = asyncio.run(read_findings(tenant_id="t1"))
    assert result["findings"] == []
    assert result["total"] == 0
    assert result["by_severity"]["critical"] == 0
```

## Acceptance Criteria

### AC-01 — `read_findings()` returns correct shape
Calling `await read_findings(tenant_id="t1")` returns `{"findings": [...], "total": N, "by_severity": {...}, "by_engine": {...}}`.

### AC-02 — Tenant isolation enforced at SQL level
`tenant_id` is always the first WHERE condition. SQL never executes without it.

### AC-03 — Source engine filter works
`await read_findings(tenant_id="t1", source_engines=["check", "iam"])` only returns rows from those two engines.

### AC-04 — JSONB `details` auto-deserialized
`findings[0]["details"]` is a Python dict (not a string). psycopg2 returns JSONB as dict — no `json.loads()` needed.

### AC-05 — By_severity aggregation correct
`by_severity` counts match `SELECT COUNT(*) ... GROUP BY severity` for the same tenant.

### AC-06 — Empty result does not crash
Zero rows returns `{"findings": [], "total": 0, "by_severity": {"critical": 0, ...}, "by_engine": {}}`.

## Cleanup Steps (After Testing)

1. Run `pytest shared/api_gateway/bff/tests/test_read_findings.py -v` — all tests pass
2. Run `grep -rn "json.loads" shared/api_gateway/bff/` — confirm no new `json.loads()` calls on JSONB fields
3. Verify `get_inventory_conn()` is available in `engine_common.db_connections`

## Definition of Done

- [ ] `read_findings()` and `read_findings_for_asset()` added to `_shared.py`
- [ ] Unit tests added and passing
- [ ] AC-01 through AC-06 verified
- [ ] Cleanup steps completed
- [ ] No `json.loads()` on JSONB columns
