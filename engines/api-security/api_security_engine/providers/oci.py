import logging
from typing import Any, Dict, List

from api_security_engine.providers.base import BaseAPISecProvider
from api_security_engine.input.check_finding_reader import load_check_findings
from api_security_engine.input.discovery_reader import load_api_discoveries

logger = logging.getLogger("api_security.oci_provider")

_NO_AUTH_TYPES = {"STOCK_RESPONSES", "CUSTOM_AUTHENTICATION"}


def _check_oci_gateway_tls(config: dict) -> bool:
    """Return True if the OCI API Gateway enforces HTTPS/TLS."""
    ca_bundles = config.get("caCertificates", []) or []
    endpoint_type = (config.get("endpointType") or "").upper()
    return bool(ca_bundles) or endpoint_type == "PRIVATE"


class OCIAPISecProvider(BaseAPISecProvider):
    """OCI API Security provider — API Gateway + Deployment analysis."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        check_findings = load_check_findings(check_conn, scan_run_id, tenant_id)
        logger.info(f"OCI provider: {len(check_findings)} check findings")

        api_resources = load_api_discoveries(
            discoveries_conn, scan_run_id, tenant_id, provider="oci"
        )
        logger.info(f"OCI provider: {len(api_resources)} OCI API resources")

        all_findings: List[Dict[str, Any]] = list(check_findings)

        for res in api_resources:
            config = res.get("configuration") or {}
            rtype = res["resource_type"]
            name = config.get("displayName") or res.get("resource_name", "")

            if rtype == "oci.apigateway.gateway":
                has_tls = _check_oci_gateway_tls(config)
                endpoint_type = (config.get("endpointType") or "PUBLIC").upper()
                is_public = endpoint_type == "PUBLIC"

                if is_public and not has_tls:
                    all_findings.append({
                        "rule_id": "oci.apigateway.gateway.no_tls_enforcement",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "OCI API Gateway is public without TLS enforcement",
                        "description": (
                            "The OCI API Gateway is internet-facing with no CA certificate bundle "
                            "configured. Traffic may be transmitted unencrypted."
                        ),
                        "remediation": (
                            "Configure a CA certificate bundle on the gateway or switch to a "
                            "private endpoint type for internal APIs."
                        ),
                        "owasp_api_category": "API8",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": "",
                        "evidence": {"endpointType": endpoint_type, "hasCACertBundle": False},
                    })

            elif rtype == "oci.apigateway.deployment":
                spec = config.get("specification", {}) or {}
                request_policies = spec.get("requestPolicies", {}) or {}
                authentication = request_policies.get("authentication", {}) or {}
                rate_limiting = request_policies.get("rateLimiting", {}) or {}
                cors = request_policies.get("cors", {}) or {}

                auth_type = authentication.get("type", "")
                has_auth = bool(auth_type) and auth_type.upper() not in {"", "ANONYMOUS"}
                has_rate_limit = bool(rate_limiting.get("rateInRequestsPerSecond"))
                cors_allowed = cors.get("allowedOrigins", []) or []
                has_wildcard_cors = "*" in cors_allowed

                if not has_auth:
                    all_findings.append({
                        "rule_id": "oci.apigateway.deployment.no_authentication",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "OCI API Gateway deployment has no authentication policy",
                        "description": (
                            "The API deployment's request policy has no authentication configured "
                            "or is set to ANONYMOUS. All callers can access the API without credentials."
                        ),
                        "remediation": (
                            "Set requestPolicies.authentication.type to JWT_AUTHENTICATION, "
                            "CUSTOM_AUTHENTICATION, or HTTP_BACKEND_IDCS_OAUTH2 in the deployment spec."
                        ),
                        "owasp_api_category": "API2",
                        "finding_source": "config",
                        "auth_type": auth_type or "none",
                        "has_waf": False,
                        "has_rate_limit": has_rate_limit,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": config.get("pathPrefix", ""),
                        "evidence": {"authType": auth_type, "pathPrefix": config.get("pathPrefix", "")},
                    })

                if not has_rate_limit:
                    all_findings.append({
                        "rule_id": "oci.apigateway.deployment.no_rate_limiting",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "OCI API Gateway deployment has no rate limiting",
                        "description": (
                            "The deployment has no rateLimiting request policy. "
                            "Without throttling, the API is vulnerable to abuse and resource exhaustion."
                        ),
                        "remediation": (
                            "Add requestPolicies.rateLimiting.rateInRequestsPerSecond in the "
                            "deployment specification."
                        ),
                        "owasp_api_category": "API4",
                        "finding_source": "config",
                        "auth_type": auth_type or "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": config.get("pathPrefix", ""),
                        "evidence": {"rateLimiting": rate_limiting},
                    })

                if has_wildcard_cors:
                    all_findings.append({
                        "rule_id": "oci.apigateway.deployment.wildcard_cors",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "OCI API Gateway deployment allows wildcard CORS origin",
                        "description": (
                            "CORS policy allows '*' as an allowed origin. Any web page can send "
                            "cross-origin requests to this API, increasing CSRF exposure."
                        ),
                        "remediation": (
                            "Restrict allowedOrigins to specific trusted domains instead of '*'."
                        ),
                        "owasp_api_category": "API8",
                        "finding_source": "config",
                        "auth_type": auth_type or "none",
                        "has_waf": False,
                        "has_rate_limit": has_rate_limit,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": config.get("pathPrefix", ""),
                        "evidence": {"allowedOrigins": cors_allowed},
                    })

        logger.info(f"OCI provider complete: {len(all_findings)} findings")
        return all_findings
