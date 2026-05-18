import re
from typing import Any, Dict, List

_DEPRECATED_VERSION_PATTERN = re.compile(
    r"(v0|v1\b|beta|alpha|test|dev|old|legacy|deprecated)", re.IGNORECASE
)


class VersioningAuditModule:
    def run(
        self,
        api_resources: List[Dict[str, Any]],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        for res in api_resources:
            if res["resource_type"] not in (
                "aws.apigateway.rest_api", "aws.apigatewayv2.api"
            ):
                continue
            config = res.get("configuration") or {}
            api_name = config.get("name") or res.get("resource_name", "")
            api_version = config.get("version", "")
            description = config.get("description", "")

            search_string = f"{api_name} {api_version} {description}"
            if _DEPRECATED_VERSION_PATTERN.search(search_string):
                findings.append({
                    "rule_id": "aws.apigateway.api.deprecated_version_active",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "medium",
                    "title": "API appears to be a deprecated or legacy version",
                    "description": (
                        f"The API '{api_name}' (version='{api_version}') appears to be "
                        "a deprecated or legacy version based on its name/version string. "
                        "Deprecated APIs often lack security patches and monitoring."
                    ),
                    "remediation": (
                        "Migrate consumers to the current API version and disable or "
                        "delete the deprecated stage/API. Ensure deprecated APIs are "
                        "tracked in your API inventory (API9)."
                    ),
                    "owasp_api_category": "API9",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": False,
                    "has_rate_limit": False,
                    "is_publicly_accessible": False,
                    "is_deprecated_version": True,
                    "api_gateway_id": res["resource_uid"],
                    "api_name": api_name,
                    "api_version": api_version,
                    "api_stage": "",
                    "evidence": {
                        "apiName": api_name,
                        "apiVersion": api_version,
                        "matchedPattern": _DEPRECATED_VERSION_PATTERN.pattern,
                    },
                })
        return findings
