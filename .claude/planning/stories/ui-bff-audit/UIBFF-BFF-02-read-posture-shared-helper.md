# Story UIBFF-BFF-02: BFF Shared `read_posture()` Helper

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-BFF — Shared Query Layer
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 2
- **Priority**: P1 (prerequisite for Phase 5 BFF migration)
- **Depends on**: UIBFF-BFF-01 (same pattern, written together)
- **Blocks**: UIBFF-ARCH-01 through ARCH-07

## User Story

As a developer, I want a shared `read_posture()` function that reads per-resource posture signals from `resource_security_posture` so BFF handlers can get KPI dimensions (is_encrypted, risk_score, has_waf, etc.) without calling individual engine endpoints.

## Context

The `resource_security_posture` table in `threat_engine_inventory` DB aggregates per-resource posture dimensions written by all engines (check, iam, network, datasec, cdr, container, api_security, encryption, dbsec, ai_security, attack-path). It has 40+ columns covering every security dimension.

BFF handlers currently reconstruct posture from engine `/ui-data` HTTP calls. The `read_posture()` helper replaces those calls with direct DB reads — faster and more reliable.

## What to Build

### 1. Add `read_posture()` to `shared/api_gateway/bff/_shared.py`

```python
async def read_posture(
    tenant_id: str,
    resource_uid: Optional[str] = None,
    resource_uids: Optional[List[str]] = None,
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    resource_type: Optional[str] = None,
    has_critical: Optional[bool] = None,
    limit: int = 500,
    offset: int = 0,
) -> Dict[str, Any]:
    """Read posture signals from resource_security_posture. Always tenant-scoped.

    Returns:
        {"posture": [...], "total": int, "summary": {...}}
    """
    conditions = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]

    if resource_uid:
        conditions.append("resource_uid = %s")
        params.append(resource_uid)

    if resource_uids:
        placeholders = ",".join(["%s"] * len(resource_uids))
        conditions.append(f"resource_uid IN ({placeholders})")
        params.extend(resource_uids)

    if account_id:
        conditions.append("account_id = %s")
        params.append(account_id)

    if provider:
        conditions.append("provider = %s")
        params.append(provider)

    if resource_type:
        conditions.append("resource_type = %s")
        params.append(resource_type)

    if has_critical:
        conditions.append("critical_count > 0")

    where = " AND ".join(conditions)

    data_sql = f"""
        SELECT
            posture_id, resource_uid, resource_type, tenant_id,
            account_id, provider, region, scan_run_id,
            -- Check engine
            critical_count, high_count, medium_count, low_count, total_findings,
            overall_posture_score, posture_band,
            -- IAM
            iam_score, iam_detail,
            -- Network
            network_score, is_in_private_subnet, network_detail,
            -- Encryption
            is_encrypted_at_rest, is_encrypted_in_transit, has_kms_managed_key,
            has_valid_certificate, cert_days_remaining, tls_version, encryption_score,
            -- API Security
            api_auth_type, api_has_waf, api_has_rate_limit,
            api_publicly_accessible, api_security_score, api_detail,
            -- Container
            has_privileged_container, image_has_critical_cve,
            k8s_rbac_overpermissive, container_security_score,
            -- AI Security
            ai_security_score,
            -- DBSec
            db_auth_type, dbsec_score,
            -- Composite flags
            is_high_risk_crown_jewel, is_internet_exposed_with_critical,
            api_public_no_waf, api_public_no_auth,
            reachable_pii_store_count,
            -- Timestamps
            last_updated_at
        FROM resource_security_posture
        WHERE {where}
        ORDER BY overall_posture_score DESC NULLS LAST, critical_count DESC
        LIMIT %s OFFSET %s
    """

    count_sql = f"SELECT COUNT(*) FROM resource_security_posture WHERE {where}"

    with get_inventory_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(count_sql, params)
            total = cur.fetchone()[0]

            cur.execute(data_sql, params + [limit, offset])
            cols = [d[0] for d in cur.description]
            rows = cur.fetchall()

    posture_list = [dict(zip(cols, r)) for r in rows]

    # Build summary
    if posture_list:
        summary = {
            "avg_posture_score": round(
                sum(p.get("overall_posture_score") or 0 for p in posture_list) / len(posture_list), 1
            ),
            "high_risk_count":     sum(1 for p in posture_list if (p.get("overall_posture_score") or 100) < 40),
            "critical_findings":   sum(p.get("critical_count") or 0 for p in posture_list),
            "unencrypted_count":   sum(1 for p in posture_list if not p.get("is_encrypted_at_rest")),
            "internet_exposed":    sum(1 for p in posture_list if p.get("is_internet_exposed_with_critical")),
        }
    else:
        summary = {
            "avg_posture_score": 0, "high_risk_count": 0,
            "critical_findings": 0, "unencrypted_count": 0, "internet_exposed": 0,
        }

    return {"posture": posture_list, "total": total, "summary": summary}


async def read_posture_for_resource(tenant_id: str, resource_uid: str) -> Optional[Dict]:
    """Single resource posture row. Returns None if not found."""
    result = await read_posture(tenant_id=tenant_id, resource_uid=resource_uid, limit=1)
    return result["posture"][0] if result["posture"] else None
```

### 2. Add unit tests

File: `shared/api_gateway/bff/tests/test_read_posture.py`

```python
def test_read_posture_tenant_isolation(mock_inventory_conn):
    """tenant_id always first WHERE condition."""
    asyncio.run(read_posture(tenant_id="t1"))
    assert mock_inventory_conn.last_params[0] == "t1"

def test_read_posture_single_resource(mock_inventory_conn_with_row):
    result = asyncio.run(read_posture(tenant_id="t1", resource_uid="arn:aws:ec2:::i-123"))
    assert len(result["posture"]) == 1
    assert result["posture"][0]["resource_uid"] == "arn:aws:ec2:::i-123"

def test_read_posture_for_resource_returns_none_when_missing(mock_inventory_conn_empty):
    result = asyncio.run(read_posture_for_resource(tenant_id="t1", resource_uid="missing"))
    assert result is None
```

## Acceptance Criteria

### AC-01 — `read_posture()` returns correct shape
Returns `{"posture": [...], "total": N, "summary": {...}}`.

### AC-02 — Tenant isolation
`tenant_id` always first WHERE condition — no posture query without it.

### AC-03 — JSONB columns auto-deserialized
`iam_detail`, `network_detail`, `api_detail` are Python dicts — not strings.

### AC-04 — `read_posture_for_resource()` returns None when absent
Missing resource_uid returns `None`, not empty dict or crash.

### AC-05 — Summary fields correct
`summary.critical_findings` = sum of `critical_count` across all returned rows.

## Cleanup Steps (After Testing)

1. `pytest shared/api_gateway/bff/tests/test_read_posture.py -v` — all pass
2. Verify column names match live schema: run `\d resource_security_posture` against DB and cross-check the SELECT column list

## Definition of Done

- [ ] `read_posture()` and `read_posture_for_resource()` added to `_shared.py`
- [ ] Unit tests added and passing
- [ ] AC-01 through AC-05 verified
- [ ] Column names verified against live schema
- [ ] Cleanup steps completed
