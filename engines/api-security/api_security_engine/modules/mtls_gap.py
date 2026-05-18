"""MTLSGapModule — mutual TLS coverage check.

For APIs where mTLS provides machine-to-machine authentication,
flags REST APIs and API gateway stages that have client-cert auth
not enforced. Checks AWS API Gateway mutual TLS and Azure APIM
client certificate policies.
"""

from typing import Any, Dict, List


def _aws_has_mtls(config: dict) -> bool:
    """Return True if the AWS API Gateway resource has mTLS configured."""
    # REST API v1: mutualTlsAuthentication block
    mtls = config.get("mutualTlsAuthentication") or {}
    if mtls.get("truststoreUri"):
        return True
    # V2 API
    if config.get("disableExecuteApiEndpoint") and mtls:
        return True
    return False


def _azure_has_mtls(config: dict) -> bool:
    """Return True if APIM service has client certificate negotiation enabled."""
    props = config.get("properties", {}) or {}
    return bool(
        props.get("clientCertificateEnabled")
        or props.get("hostnameConfigurations")  # custom domain with cert
    )


_MTLS_CHECKERS = {
    "aws": _aws_has_mtls,
    "azure": _azure_has_mtls,
}

# Resource types that support mTLS and should be audited
_MTLS_ELIGIBLE = {
    "aws.apigateway.rest_api",
    "aws.apigatewayv2.api",
    "azure.apimanagement.service",
}


class MTLSGapModule:
    """Flag API gateways that do not enforce mutual TLS (machine auth gap)."""

    def run(
        self,
        api_resources: List[Dict[str, Any]],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for res in api_resources:
            rtype = res["resource_type"]
            if rtype not in _MTLS_ELIGIBLE:
                continue

            config = res.get("configuration") or {}
            provider = res.get("provider", "aws").lower()
            checker = _MTLS_CHECKERS.get(provider, lambda _: False)
            has_mtls = checker(config)

            if not has_mtls:
                findings.append({
                    "rule_id": f"{provider}.apigateway.no_mtls",
                    "resource_uid": res["resource_uid"],
                    "resource_type": rtype,
                    "severity": "medium",
                    "title": f"API Gateway does not enforce mutual TLS (mTLS)",
                    "description": (
                        "The API gateway has no mutual TLS (client certificate) authentication. "
                        "Machine-to-machine APIs should require client certificates to prevent "
                        "unauthorized service-to-service calls."
                    ),
                    "remediation": (
                        "For AWS API Gateway: configure mutualTlsAuthentication.truststoreUri. "
                        "For Azure APIM: enable clientCertificateEnabled on the service and "
                        "add validate-client-certificate inbound policy."
                    ),
                    "owasp_api_category": "API2",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": False,
                    "has_rate_limit": False,
                    "is_publicly_accessible": True,
                    "api_gateway_id": res["resource_uid"],
                    "api_name": config.get("name") or res.get("resource_name", ""),
                    "api_stage": "",
                    "evidence": {"resourceType": rtype, "mtlsConfigured": False},
                })

        return findings
