# Story APISEC-S1-07: Layer 2 — Discovery Finding Reader

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 2
- **Depends on**: APISEC-S1-03
- **Blocks**: APISEC-S1-08 (AWS provider imports this)
- **Security Gate**: bmad-security-reviewer (tenant-scoped query, no cross-tenant leak)

## Implementation

**File**: `engines/api-security/api_security_engine/input/discovery_reader.py`

```python
from typing import List, Dict, Any

_API_RESOURCE_TYPES = (
    # AWS
    "aws.apigateway.rest_api",
    "aws.apigateway.stage",
    "aws.apigatewayv2.api",
    "aws.apigatewayv2.stage",
    # Azure
    "azure.apimanagement.service",
    "azure.apimanagement.api",
    # GCP
    "gcp.apigee.environment",
    "gcp.apigee.api_proxy",
    "gcp.apigateway.api",
    "gcp.apigateway.api_config",
    # OCI
    "oci.apigateway.gateway",
    "oci.apigateway.deployment",
    # AliCloud
    "alicloud.apigateway.api_group",
    "alicloud.apigateway.api",
    # K8s
    "k8s.networking.ingress",
    "k8s.gateway.gateway",
    "k8s.gateway.httproute",
)


def load_api_discoveries(
    discoveries_conn,
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """
    Layer 2: Load discovery_findings rows for API gateway resource types.
    Returns list of dicts. JSONB columns (configuration, tags) arrive as dicts.
    """
    resource_types = [r for r in _API_RESOURCE_TYPES if r.startswith(provider.lower() + ".")]

    if not resource_types:
        return []

    placeholders = ",".join(["%s"] * len(resource_types))
    sql = f"""
        SELECT
            discovery_id,
            resource_uid,
            resource_type,
            resource_name,
            account_id,
            region,
            provider,
            configuration,
            tags,
            discovered_at
        FROM discovery_findings
        WHERE tenant_id = %s
          AND scan_run_id = %s
          AND provider = %s
          AND resource_type IN ({placeholders})
        ORDER BY resource_type, resource_uid
    """
    params = [tenant_id, scan_run_id, provider.lower()] + resource_types

    with discoveries_conn.cursor() as cur:
        cur.execute(sql, params)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    return [dict(zip(cols, row)) for row in rows]


def load_waf_associations(
    discoveries_conn,
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> Dict[str, bool]:
    """
    Return mapping of api_gateway_arn → bool (has_waf).
    Source: discovery_findings WHERE resource_type = 'aws.wafv2.web_acl_association'
    """
    if provider.lower() != "aws":
        return {}

    sql = """
        SELECT configuration
        FROM discovery_findings
        WHERE tenant_id = %s
          AND scan_run_id = %s
          AND resource_type IN ('aws.wafv2.web_acl_association', 'aws.waf.web_acl')
    """
    with discoveries_conn.cursor() as cur:
        cur.execute(sql, (tenant_id, scan_run_id))
        rows = cur.fetchall()

    waf_arns: Dict[str, bool] = {}
    for (config,) in rows:
        if not config:
            continue
        # config is JSONB dict — do NOT call json.loads()
        resource_arn = config.get("ResourceArn") or config.get("resourceArn", "")
        if resource_arn:
            waf_arns[resource_arn] = True
    return waf_arns
```

## Notes

- `configuration` and `tags` are JSONB — arrive as Python dicts from psycopg2. Never call `json.loads()`.
- `load_waf_associations()` returns a dict for O(1) lookups in the analysis modules.
- Resource type list is filtered by `provider` so a single reader handles all CSPs without cross-CSP noise.
- K8s ingress/gateway objects are included for in-cluster API gateway analysis.

## Acceptance Criteria

- [ ] AC-1: `load_api_discoveries()` returns only rows matching the given `provider` — no cross-CSP rows
- [ ] AC-2: `configuration` field is a `dict` in every returned row, not a string
- [ ] AC-3: `load_api_discoveries()` with unknown provider returns `[]` without exception
- [ ] AC-4: `load_waf_associations()` returns `{}` for non-AWS providers
- [ ] AC-5: `tenant_id` and `scan_run_id` always appear in WHERE clause — no full-table scan path
- [ ] AC-6: Parameterized query used for IN clause — no string interpolation of resource types

## Definition of Done
- [ ] `discovery_reader.py` committed at correct path
- [ ] Imported and called from `AWSAPISecProvider.analyze()` (APISEC-S1-08)
- [ ] Unit test: mocked cursor returning 0 rows → `[]` returned, no exception
