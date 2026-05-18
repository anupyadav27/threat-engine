"""GraphQLIntrospectionModule — OWASP API7 / API9: exposed schema disclosure.

GraphQL APIs with introspection enabled in production allow attackers to
enumerate the full schema, discover hidden endpoints, and craft targeted
injection queries. Detects GraphQL APIs exposed via API Gateway.
"""

import re
from typing import Any, Dict, List

# Patterns in resource_type, path, or name indicating a GraphQL API
_GRAPHQL_INDICATORS = re.compile(
    r"(graphql|graph-ql|gql|appsync|hasura)",
    re.IGNORECASE,
)

# AppSync resource types (AWS managed GraphQL)
_APPSYNC_TYPES = {
    "aws.appsync.graphql_api",
    "aws.appsync.api_key",
}


def _is_graphql_resource(res: dict) -> bool:
    """Heuristically determine if a resource is a GraphQL endpoint."""
    rtype = res.get("resource_type", "")
    name = res.get("resource_name", "")
    config = res.get("configuration") or {}

    if rtype in _APPSYNC_TYPES:
        return True
    if _GRAPHQL_INDICATORS.search(rtype) or _GRAPHQL_INDICATORS.search(name):
        return True

    # Check path mappings in REST API stages
    paths = config.get("paths", {}) or {}
    for path in paths:
        if _GRAPHQL_INDICATORS.search(path):
            return True

    return False


def _appsync_has_introspection_disabled(config: dict) -> bool:
    """Return True if AppSync API has introspection explicitly disabled."""
    # introspectionConfig field: ENABLED (default) | DISABLED
    introspection = (config.get("introspectionConfig") or "ENABLED").upper()
    return introspection == "DISABLED"


def _appsync_has_field_logging(config: dict) -> bool:
    """Return True if AppSync logging is configured (needed to detect introspection abuse)."""
    log_config = config.get("logConfig") or {}
    return bool(log_config.get("cloudWatchLogsRoleArn"))


class GraphQLIntrospectionModule:
    """Detect GraphQL APIs with introspection enabled or weak logging in production."""

    def run(
        self,
        api_resources: List[Dict[str, Any]],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for res in api_resources:
            if not _is_graphql_resource(res):
                continue

            config = res.get("configuration") or {}
            rtype = res["resource_type"]
            name = config.get("name") or res.get("resource_name", "")

            if rtype in _APPSYNC_TYPES:
                introspection_disabled = _appsync_has_introspection_disabled(config)
                has_logging = _appsync_has_field_logging(config)

                if not introspection_disabled:
                    findings.append({
                        "rule_id": "aws.appsync.graphql_api.introspection_enabled",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "AppSync GraphQL API has introspection enabled",
                        "description": (
                            "The AppSync GraphQL API has introspectionConfig=ENABLED (default). "
                            "Introspection allows anyone with API access to enumerate the full "
                            "schema, discover fields, and craft targeted injection queries."
                        ),
                        "remediation": (
                            "Set introspectionConfig=DISABLED on the AppSync API for production. "
                            "If introspection is needed, restrict it behind an authorizer."
                        ),
                        "owasp_api_category": "API9",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": "",
                        "evidence": {
                            "introspectionConfig": config.get("introspectionConfig", "ENABLED"),
                            "authenticationType": config.get("authenticationType", ""),
                        },
                    })

                if not has_logging:
                    findings.append({
                        "rule_id": "aws.appsync.graphql_api.no_field_logging",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "AppSync GraphQL API has no CloudWatch field-level logging",
                        "description": (
                            "The AppSync API has no logConfig.cloudWatchLogsRoleArn. "
                            "Without field-level logging, introspection queries and resolver "
                            "errors are invisible, hindering incident response."
                        ),
                        "remediation": (
                            "Enable field-level logging by configuring logConfig with a "
                            "cloudWatchLogsRoleArn and fieldLogLevel=ERROR or ALL."
                        ),
                        "owasp_api_category": "API9",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": "",
                        "evidence": {"logConfig": config.get("logConfig", {})},
                    })

            else:
                # Generic GraphQL detected via name/path heuristic — flag for review
                findings.append({
                    "rule_id": "api.gateway.graphql_endpoint_detected",
                    "resource_uid": res["resource_uid"],
                    "resource_type": rtype,
                    "severity": "low",
                    "title": "GraphQL endpoint detected — verify introspection controls",
                    "description": (
                        f"API resource '{name}' appears to expose a GraphQL endpoint. "
                        "Ensure introspection is disabled in production and depth/complexity "
                        "limits are enforced to prevent denial-of-service via query abuse."
                    ),
                    "remediation": (
                        "Disable GraphQL introspection in production. Add query complexity "
                        "and depth limits. Use persisted queries where possible."
                    ),
                    "owasp_api_category": "API9",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": False,
                    "has_rate_limit": False,
                    "is_publicly_accessible": True,
                    "api_gateway_id": res["resource_uid"],
                    "api_name": name,
                    "api_stage": "",
                    "evidence": {"resourceType": rtype, "detectionMethod": "name_heuristic"},
                })

        return findings
