# STORY-CIEM-04: Identity Hourly Activity Distribution Endpoint

## Track
CIEM Investigation Journey — Sprint 1

## Priority
P1 — enables time-of-day heatmap on Stage 2 identity profile

## Story
As a security analyst on an identity's profile page, I need to see when (hour of day, day of week) this principal is most active over the past 14 days, so I can immediately spot off-hours access (e.g. 3am on a Saturday) that signals credential theft or anomalous behavior.

## Current State

No such endpoint exists. The `ciem_findings` table has `event_time` (timestamp) for every finding. A simple GROUP BY EXTRACT(HOUR) query produces the hourly distribution. The BFF currently does not request or pass this data.

## Files to Modify
- `engines/ciem/ciem_engine/api_server.py` — two new endpoints

## Exact Changes

### `api_server.py` — new endpoint

```python
@router.get("/api/v1/ciem/identities/{principal_encoded}/hourly-activity")
async def get_identity_hourly_activity(
    principal_encoded: str,
    tenant_id: str = Depends(get_tenant_id),
    scan_run_id: Optional[str] = None,
    auth: AuthContext = Depends(require_permission("ciem:read")),
    db=Depends(get_db)
):
    actor_principal = unquote(principal_encoded)  # URL-decode
    
    hourly_query = """
        SELECT EXTRACT(HOUR FROM event_time)::int AS hour, COUNT(*) AS count
        FROM ciem_findings
        WHERE tenant_id = %s AND actor_principal = %s
        {scan_filter}
        GROUP BY hour
        ORDER BY hour
    """
    
    dow_query = """
        SELECT EXTRACT(DOW FROM event_time)::int AS dow, COUNT(*) AS count
        FROM ciem_findings
        WHERE tenant_id = %s AND actor_principal = %s
        {scan_filter}
        GROUP BY dow
        ORDER BY dow
    """
```

Response:
```json
{
  "actor_principal": "arn:aws:iam::123456789012:role/ExecRole",
  "hourly_distribution": [
    {"hour": 0, "count": 0},
    {"hour": 1, "count": 2},
    ...
    {"hour": 23, "count": 7}
  ],
  "day_of_week_distribution": [
    {"dow": 0, "dow_name": "Sun", "count": 1},
    {"dow": 1, "dow_name": "Mon", "count": 15},
    ...
    {"dow": 6, "dow_name": "Sat", "count": 3}
  ]
}
```

- `hourly_distribution` is always a 24-element array (hours with 0 events included as `{"hour": N, "count": 0}`)
- `day_of_week_distribution` is always a 7-element array (PostgreSQL DOW: 0=Sun, 1=Mon, ..., 6=Sat)
- `principal_encoded` is URL-decoded before DB query (ARNs contain `/` and `:`)

## Security Review Fixes (from pre-dev security gate)

**BLOCK-CIEM-04-1 — Validate URL-decoded principal length and content:**
`unquote(principal_encoded)` before parameterized use is correct (no SQL injection). However no length or null-byte validation exists. Add immediately after `unquote()`:

```python
actor_principal = unquote(principal_encoded)
if len(actor_principal) > 512 or '\x00' in actor_principal:
    raise HTTPException(status_code=400, detail="Invalid principal identifier")
```

**WARN-CIEM-04-1 — Add 14-day window to both queries:**
Both the hourly and DOW queries aggregate all-time data unless constrained. Add to both:
```sql
AND event_time >= NOW() - INTERVAL '14 days'
```

## Acceptance Criteria

- [ ] `GET /api/v1/ciem/identities/{principal_encoded}/hourly-activity` returns 24-element hourly array and 7-element dow array
- [ ] Returns `400` if decoded principal exceeds 512 characters or contains null bytes (`\x00`)
- [ ] URL-decodes `principal_encoded` before querying DB (handles `arn%3Aaws%3A...` format)
- [ ] Both hourly and DOW queries include `AND event_time >= NOW() - INTERVAL '14 days'`
- [ ] Distribution covers last 14 days only — narrative and SQL must agree
- [ ] Hours with zero findings are explicitly included (not omitted) — array always length 24
- [ ] Days with zero findings are explicitly included — array always length 7
- [ ] Returns `404` if the decoded principal has no findings in the tenant
- [ ] Tenant-scoped: only returns data for the requesting tenant's findings
- [ ] Optional `scan_run_id` filter: if provided, limits to that scan run

## Security Checklist
- [ ] `WHERE tenant_id = %s AND actor_principal = %s` — both conditions present
- [ ] URL-decode is applied before DB parameterization (not concatenated into SQL)
- [ ] `require_permission("ciem:read")` on endpoint
- [ ] No JSONB parsing — `event_time` and `actor_principal` are scalar columns

## Definition of Done
- [ ] Endpoint in `api_server.py`
- [ ] Manual test: call with a known principal ARN, verify 24 hourly buckets returned
- [ ] Test with URL-encoded ARN: `arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2FExecRole` resolves correctly
