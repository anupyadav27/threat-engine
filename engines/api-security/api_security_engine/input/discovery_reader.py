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


def load_api_discoveries(
    discoveries_conn,
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """Layer 2: Load discovery_findings rows for API gateway resource types.
    configuration and tags are JSONB — arrive as Python dicts, never call json.loads().
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
    """Return mapping of resource_arn → True for resources that have a WAF association.
    Only implemented for AWS; returns {} for all other providers.
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
