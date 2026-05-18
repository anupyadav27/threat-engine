import logging
from typing import Any, Dict, List

from api_security_engine.providers.base import BaseAPISecProvider
from api_security_engine.input.check_finding_reader import load_check_findings
from api_security_engine.input.discovery_reader import load_api_discoveries

logger = logging.getLogger("api_security.azure_provider")

_AUTH_POLICIES = {"jwt-validate", "validate-jwt", "validate-azure-ad-token", "oauth2"}
_RATE_LIMIT_POLICIES = {"rate-limit", "rate-limit-by-key", "quota", "quota-by-key"}


def _extract_apim_policies(config: dict) -> dict:
    """Parse APIM properties.policies or serviceUrl config into a flat dict."""
    policies = config.get("properties", {}).get("policies", {}) or {}
    policy_xml = policies.get("value", "") or ""
    has_auth = any(p in policy_xml.lower() for p in _AUTH_POLICIES)
    has_rate = any(p in policy_xml.lower() for p in _RATE_LIMIT_POLICIES)
    return {"has_auth": has_auth, "has_rate_limit": has_rate, "policy_xml": policy_xml}


class AzureAPISecProvider(BaseAPISecProvider):
    """Azure API Security provider — APIM posture analysis."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        check_findings = load_check_findings(check_conn, scan_run_id, tenant_id)
        logger.info(f"Azure provider: {len(check_findings)} check findings")

        api_resources = load_api_discoveries(
            discoveries_conn, scan_run_id, tenant_id, provider="azure"
        )
        logger.info(f"Azure provider: {len(api_resources)} APIM resources")

        all_findings: List[Dict[str, Any]] = list(check_findings)

        for res in api_resources:
            if res["resource_type"] not in (
                "azure.apimanagement.service", "azure.apimanagement.api"
            ):
                continue
            config = res.get("configuration") or {}
            props = config.get("properties", {}) or {}
            policy = _extract_apim_policies(config)

            # Check WAF (Application Gateway / Front Door association)
            has_waf = bool(
                props.get("virtualNetworkType") in ("External", "Internal")
                or config.get("wafAssociated")
            )

            # Check auth
            if not policy["has_auth"]:
                all_findings.append({
                    "rule_id": "azure.apimanagement.api.no_auth_policy",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "high",
                    "title": "Azure APIM API has no authentication policy",
                    "description": (
                        "The API Management API has no JWT validation, OAuth2, or "
                        "Azure AD token validation policy configured."
                    ),
                    "remediation": (
                        "Add a validate-jwt or validate-azure-ad-token policy to "
                        "the inbound processing section of the API policy XML."
                    ),
                    "owasp_api_category": "API2",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": has_waf,
                    "has_rate_limit": policy["has_rate_limit"],
                    "is_publicly_accessible": True,
                    "api_gateway_id": res["resource_uid"],
                    "api_name": config.get("name", res.get("resource_name", "")),
                    "api_stage": "",
                    "evidence": {"hasAuthPolicy": False, "resourceType": res["resource_type"]},
                })

            # Check rate limit
            if not policy["has_rate_limit"]:
                all_findings.append({
                    "rule_id": "azure.apimanagement.api.no_rate_limit_policy",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "medium",
                    "title": "Azure APIM API has no rate limit or quota policy",
                    "description": (
                        "No rate-limit, rate-limit-by-key, quota, or quota-by-key "
                        "policy found. APIs without rate limiting are vulnerable to "
                        "resource exhaustion (OWASP API4)."
                    ),
                    "remediation": (
                        "Add a rate-limit-by-key policy to the inbound section. "
                        "Example: <rate-limit-by-key calls='100' renewal-period='60' "
                        "counter-key='@(context.Subscription.Id)' />"
                    ),
                    "owasp_api_category": "API4",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": has_waf,
                    "has_rate_limit": False,
                    "is_publicly_accessible": True,
                    "api_gateway_id": res["resource_uid"],
                    "api_name": config.get("name", res.get("resource_name", "")),
                    "api_stage": "",
                    "evidence": {"hasRateLimitPolicy": False},
                })

            # Check WAF gap for public services
            if res["resource_type"] == "azure.apimanagement.service" and not has_waf:
                all_findings.append({
                    "rule_id": "azure.apimanagement.service.no_waf",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "high",
                    "title": "Azure APIM service not protected by Application Gateway WAF",
                    "description": (
                        "The API Management service is not deployed behind an "
                        "Application Gateway or Azure Front Door with WAF enabled."
                    ),
                    "remediation": (
                        "Deploy API Management in Internal or External virtual network "
                        "mode behind Application Gateway with WAF_v2 SKU enabled."
                    ),
                    "owasp_api_category": "API8",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": False,
                    "has_rate_limit": policy["has_rate_limit"],
                    "is_publicly_accessible": True,
                    "api_gateway_id": res["resource_uid"],
                    "api_name": config.get("name", res.get("resource_name", "")),
                    "api_stage": "",
                    "evidence": {"virtualNetworkType": props.get("virtualNetworkType", "None")},
                })

        logger.info(f"Azure provider complete: {len(all_findings)} findings")
        return all_findings
