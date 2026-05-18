import logging
import re
from typing import Any, Dict, List

from api_security_engine.providers.base import BaseAPISecProvider
from api_security_engine.input.check_finding_reader import load_check_findings
from api_security_engine.input.discovery_reader import load_api_discoveries

logger = logging.getLogger("api_security.gcp_provider")

_QUOTA_LIMIT_KEYS = {"quota_limit", "quota-limit", "requestsPerMinute", "requestsPerDay"}
_AUTH_METHODS = {"api_key", "oauth2", "jwt", "oidc", "service_account"}


def _parse_apigee_env_config(config: dict) -> dict:
    """Extract security posture from an Apigee environment or proxy config dict."""
    props = config.get("properties", {}) or {}
    policies = config.get("policies", []) or []

    policy_types = {p.get("policyType", "").lower() for p in policies if isinstance(p, dict)}
    has_auth = bool(policy_types & {"verifyapikey", "oauthv2", "verifyjwt", "validatejwt"})
    has_quota = bool(policy_types & {"quota", "spikearrest"})
    has_mtls = bool(props.get("clientTLSEnabled") or props.get("mutualTlsEnabled"))

    return {
        "has_auth": has_auth,
        "has_quota": has_quota,
        "has_mtls": has_mtls,
        "policy_types": list(policy_types),
    }


class GCPAPISecProvider(BaseAPISecProvider):
    """GCP API Security provider — Apigee + Cloud API Gateway analysis."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        check_findings = load_check_findings(check_conn, scan_run_id, tenant_id)
        logger.info(f"GCP provider: {len(check_findings)} check findings")

        api_resources = load_api_discoveries(
            discoveries_conn, scan_run_id, tenant_id, provider="gcp"
        )
        logger.info(f"GCP provider: {len(api_resources)} GCP API resources")

        all_findings: List[Dict[str, Any]] = list(check_findings)

        for res in api_resources:
            config = res.get("configuration") or {}
            props = config.get("properties", {}) or {}
            rtype = res["resource_type"]
            name = config.get("name") or res.get("resource_name", "")

            if rtype == "gcp.apigee.environment":
                parsed = _parse_apigee_env_config(config)

                if not parsed["has_auth"]:
                    all_findings.append({
                        "rule_id": "gcp.apigee.environment.no_auth_policy",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "Apigee environment has no authentication policy",
                        "description": (
                            "No VerifyAPIKey, OAuthV2, VerifyJWT, or ValidateJWT policy found in "
                            "the Apigee environment. API traffic is unprotected from unauthorized access."
                        ),
                        "remediation": (
                            "Attach a VerifyAPIKey or OAuthV2 policy to the PreFlow request segment "
                            "of the environment-level proxy."
                        ),
                        "owasp_api_category": "API2",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": parsed["has_quota"],
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": "",
                        "evidence": {"policyTypes": parsed["policy_types"]},
                    })

                if not parsed["has_quota"]:
                    all_findings.append({
                        "rule_id": "gcp.apigee.environment.no_quota_policy",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "Apigee environment has no Quota or SpikeArrest policy",
                        "description": (
                            "No Quota or SpikeArrest policy found in the Apigee environment. "
                            "Absence of rate limiting exposes APIs to resource exhaustion (OWASP API4)."
                        ),
                        "remediation": (
                            "Add a SpikeArrest policy to the environment PreFlow with an appropriate "
                            "requests-per-minute limit based on expected traffic."
                        ),
                        "owasp_api_category": "API4",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": "",
                        "evidence": {"policyTypes": parsed["policy_types"]},
                    })

            elif rtype == "gcp.apigee.api_proxy":
                # Check for unsafe/deprecated proxy basepaths
                basepath = props.get("basepaths", [])
                if isinstance(basepath, list):
                    basepath_str = ",".join(basepath)
                else:
                    basepath_str = str(basepath)

                if re.search(r"(v0|v1\b|beta|alpha|test|dev|old|legacy|deprecated)", basepath_str, re.IGNORECASE):
                    all_findings.append({
                        "rule_id": "gcp.apigee.api_proxy.deprecated_basepath",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "Apigee API proxy has deprecated version in basepath",
                        "description": (
                            f"API proxy basepath '{basepath_str}' indicates a deprecated or "
                            "pre-production version is still publicly accessible."
                        ),
                        "remediation": (
                            "Retire deprecated API proxy revisions and redirect clients to the "
                            "current stable version. Use the Apigee deploy/undeploy APIs."
                        ),
                        "owasp_api_category": "API9",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": basepath_str,
                        "evidence": {"basepaths": basepath},
                    })

            elif rtype in ("gcp.apigateway.api", "gcp.apigateway.api_config"):
                # Cloud API Gateway: check if backend auth and security definitions are configured
                openapi_docs = config.get("openapiDocuments", []) or []
                has_security = any(
                    "securityDefinitions" in str(doc) or "security:" in str(doc)
                    for doc in openapi_docs
                )

                if not has_security:
                    all_findings.append({
                        "rule_id": "gcp.apigateway.api_config.no_security_definition",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "GCP Cloud API Gateway config has no security definition",
                        "description": (
                            "The Cloud API Gateway OpenAPI config has no securityDefinitions. "
                            "All requests pass through without authentication."
                        ),
                        "remediation": (
                            "Add a securityDefinitions block to the OpenAPI config with "
                            "x-google-backend auth and a firebase/jwt security scheme."
                        ),
                        "owasp_api_category": "API2",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": "",
                        "evidence": {"openApiDocumentCount": len(openapi_docs)},
                    })

        logger.info(f"GCP provider complete: {len(all_findings)} findings")
        return all_findings
