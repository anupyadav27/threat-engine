"""
API Security DI reader — queries asset_inventory instead of discovery_findings.

load_api_assets() and load_waf_associations() have identical signatures to
the functions in discovery_reader.py but use a DI DB connection.
"""

from __future__ import annotations

from typing import Any, Dict, List

_API_RESOURCE_TYPES = (
    "aws.apigateway.rest_api",
    "aws.apigateway.stage",
    "aws.apigatewayv2.api",
    "aws.apigatewayv2.stage",
    "aws.apigateway.api_key",
    "azure.apimanagement.service",
    "azure.apimanagement.api",
    "gcp.apigee.environment",
    "gcp.apigee.api_proxy",
    "gcp.apigateway.api",
    "gcp.apigateway.api_config",
    "oci.apigateway.gateway",
    "oci.apigateway.deployment",
    "alicloud.apigateway.api_group",
    "alicloud.apigateway.api",
    "k8s.networking.ingress",
    "k8s.gateway.gateway",
    "k8s.gateway.httproute",
)


def load_api_assets(
    di_conn,
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """Load API gateway assets from asset_inventory.

    Same return shape as discovery_reader.load_api_discoveries() — callers
    just substitute the function and a DI connection.
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
            emitted_fields AS configuration,
            NULL AS tags,
            first_seen_at AS discovered_at
        FROM asset_inventory
        WHERE tenant_id = %s
          AND scan_run_id = %s
          AND provider = %s
          AND resource_type IN ({placeholders})
        ORDER BY resource_type, resource_uid
    """
    params = [tenant_id, scan_run_id, provider.lower()] + resource_types

    with di_conn.cursor() as cur:
        cur.execute(sql, params)
        cols = [d[0] for d in cur.description]
        rows = cur.fetchall()
    return [dict(zip(cols, row)) for row in rows]


def load_waf_associations(
    di_conn,
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> Dict[str, bool]:
    """Return mapping resource_arn → True for resources with a WAF association."""
    if provider.lower() != "aws":
        return {}

    sql = """
        SELECT emitted_fields
        FROM asset_inventory
        WHERE tenant_id = %s
          AND scan_run_id = %s
          AND resource_type IN ('aws.wafv2.web_acl_association', 'aws.waf.web_acl')
    """
    with di_conn.cursor() as cur:
        cur.execute(sql, (tenant_id, scan_run_id))
        rows = cur.fetchall()

    waf_arns: Dict[str, bool] = {}
    for (config,) in rows:
        if not config:
            continue
        resource_arn = config.get("ResourceArn") or config.get("resourceArn", "")
        if resource_arn:
            waf_arns[resource_arn] = True
    return waf_arns
