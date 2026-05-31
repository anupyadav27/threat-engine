from typing import Any, Dict, List

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
    """Layer 1: Load FAIL check_findings for API gateway rule IDs.
    JSONB columns arrive as dicts — never call json.loads() on them.
    """
    prefix_clauses = " OR ".join(f"rule_id LIKE '{p}%'" for p in _API_RULE_PREFIXES)
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
