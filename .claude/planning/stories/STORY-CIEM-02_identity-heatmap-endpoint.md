# STORY-CIEM-02: Identity Risk Heatmap Aggregation Endpoint

## Track
CIEM Investigation Journey — Sprint 1

## Priority
P1 — enables Stage 1 fleet overview heatmap chart

## Story
As a security analyst on the CIEM overview page, I need a matrix view showing which (account × principal_type) cells have critical findings, so I can instantly spot whether it is service accounts or human users causing risk in a specific account without reading through a full table.

## Current State

No heatmap aggregation exists. The current `/api/v1/ciem/identities` endpoint returns a flat per-identity list. The Stage 1 UI needs a matrix of (account_id × actor_principal_type) → max_severity + finding_count to render the heatmap grid.

## Files to Modify
- `engines/ciem/ciem_engine/api_server.py` — new endpoint
- `shared/api_gateway/bff/ciem.py` — new BFF view handler

## Exact Changes

### 1. `api_server.py` — new endpoint

```python
@router.get("/api/v1/ciem/identities/heatmap")
async def get_identity_heatmap(
    tenant_id: str = Depends(get_tenant_id),
    scan_run_id: Optional[str] = None,
    auth: AuthContext = Depends(require_permission("ciem:read")),
    db=Depends(get_db)
):
    query = """
        SELECT
            account_id,
            actor_principal_type,
            COUNT(*) AS finding_count,
            MAX(CASE severity
                WHEN 'critical' THEN 4
                WHEN 'high' THEN 3
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 1
                ELSE 0 END) AS max_severity_ord
        FROM ciem_findings
        WHERE tenant_id = %s
        {scan_filter}
        GROUP BY account_id, actor_principal_type
    """
    # Map max_severity_ord back to string: 4→critical, 3→high, 2→medium, 1→low
```

Response shape:
```json
{
  "matrix": [
    {
      "account_id": "123456789012",
      "principal_type": "iam_role",
      "max_severity": "critical",
      "finding_count": 12
    }
  ],
  "accounts": ["123456789012", "987654321098"],
  "principal_types": ["iam_user", "iam_role", "service_account", "root", "anonymous"]
}
```

`accounts` and `principal_types` are deduplicated sorted lists derived from the matrix rows — used by the frontend to build the heatmap grid axes.

### 2. `bff/ciem.py` — new view route

Add handler for `GET /api/v1/views/ciem/heatmap?scan_run_id=Y`:
- Calls `GET /api/v1/ciem/identities/heatmap?scan_run_id=Y` on the CIEM engine
- Returns response as-is (no transformation needed)
- Graceful degradation: if CIEM engine unreachable, return `{"matrix": [], "accounts": [], "principal_types": []}`

## Acceptance Criteria

- [ ] `GET /api/v1/ciem/identities/heatmap?tenant_id=X` returns `matrix[]`, `accounts[]`, `principal_types[]`
- [ ] Matrix rows cover all (account_id × actor_principal_type) combinations present in `ciem_findings` for the tenant
- [ ] `max_severity` is the highest severity finding in that cell (not an average)
- [ ] `finding_count` is total findings for that (account × principal_type) pair
- [ ] Tenant isolation: a tenant can only see its own accounts in the matrix
- [ ] BFF `/views/ciem/heatmap` proxies through the response
- [ ] Response time ≤ 300ms for a tenant with 10,000 findings (GROUP BY is indexed on tenant_id)

## Security Checklist
- [ ] `WHERE tenant_id = %s` — tenant from AuthContext, never from query param
- [ ] `require_permission("ciem:read")` on the new endpoint
- [ ] No JSONB parsing needed (only scalar columns aggregated)
- [ ] Rate-limit consideration: heatmap is a GROUP BY — add to BFF cache layer (60s TTL) if needed

## Definition of Done
- [ ] New endpoint in `api_server.py`
- [ ] New BFF view in `bff/ciem.py`
- [ ] Manual verify: call heatmap endpoint with a real `scan_run_id`, confirm matrix structure
- [ ] Confirm tenant isolation: two-tenant test, tenant A cannot see tenant B accounts