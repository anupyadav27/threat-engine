# Story APISEC-S1-06: Layer 1 — Check Finding Reader

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 2
- **Depends on**: APISEC-S1-03
- **Blocks**: APISEC-S1-08 (AWS provider imports this)
- **Security Gate**: bmad-security-reviewer (tenant-scoped query only)

## Implementation

**File**: `engines/api-security/api_security_engine/input/check_finding_reader.py`

```python
from typing import List, Dict, Any

_API_RULE_PREFIXES = (
    "aws.apigateway.",
    "aws.apigatewayv2.",
    "azure.apimanagement.",
    "azure.apim.",
    "gcp.apigee.",
    "gcp.apigateway.",
    "oci.apigateway.",
    "alicloud.apigateway.",
    "k8s.ingress.",
    "k8s.gateway.",
)


def load_check_findings(
    check_conn,
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """
    Layer 1: Load existing FAIL check_findings for API gateway rule IDs.
    Returns list of dicts — one per finding. JSONB columns arrive as dicts (no json.loads).
    """
    prefix_clauses = " OR ".join(
        f"rule_id LIKE '{p}%'" for p in _API_RULE_PREFIXES
    )
    sql = f"""
        SELECT
            finding_id,
            rule_id,
            resource_uid,
            resource_type,
            severity,
            status,
            account_id,
            provider,
            region,
            evidence,
            title,
            description,
            remediation,
            first_seen_at,
            last_seen_at
        FROM check_findings
        WHERE tenant_id = %s
          AND scan_run_id = %s
          AND result = 'FAIL'
          AND ({prefix_clauses})
        ORDER BY severity DESC, rule_id
    """
    with check_conn.cursor() as cur:
        cur.execute(sql, (tenant_id, scan_run_id))
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    return [dict(zip(cols, row)) for row in rows]
```

## Notes

- `evidence` is JSONB — psycopg2 deserializes it to dict automatically. Never call `json.loads()`.
- Prefix list covers all 6 CSPs plus K8s ingress/gateway objects.
- Query uses parameterized `tenant_id` + `scan_run_id` — no cross-tenant leakage.
- Returns `[]` (empty list) if no API gateway findings exist yet — provider Layer 2 still runs.

## Acceptance Criteria

- [ ] AC-1: Function returns list of dicts keyed by column name — no tuples
- [ ] AC-2: Cross-tenant query blocked — `tenant_id` always in WHERE clause
- [ ] AC-3: Empty list returned when no API gateway rules have FAIL findings (not None, not exception)
- [ ] AC-4: `evidence` field is a `dict`, not a JSON string — no `json.loads()` call present in file
- [ ] AC-5: Non-API rule IDs (e.g., `aws.s3.bucket.*`) never appear in results

## Definition of Done
- [ ] `check_finding_reader.py` committed at correct path
- [ ] Imported and called from `AWSAPISecProvider.analyze()` (APISEC-S1-08)
- [ ] Unit test verifies empty-list behavior when cursor returns no rows
