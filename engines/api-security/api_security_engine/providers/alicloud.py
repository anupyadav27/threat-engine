import logging
from typing import Any, Dict, List

from api_security_engine.providers.base import BaseAPISecProvider
from api_security_engine.input.check_finding_reader import load_check_findings
from api_security_engine.input.discovery_reader import load_api_discoveries

logger = logging.getLogger("api_security.alicloud_provider")

_OPEN_AUTH_STYLES = {"ANONYMOUS", "APP", ""}


class AliCloudAPISecProvider(BaseAPISecProvider):
    """AliCloud API Security provider — API Gateway group/API analysis."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        check_findings = load_check_findings(check_conn, scan_run_id, tenant_id)
        logger.info(f"AliCloud provider: {len(check_findings)} check findings")

        api_resources = load_api_discoveries(
            discoveries_conn, scan_run_id, tenant_id, provider="alicloud"
        )
        logger.info(f"AliCloud provider: {len(api_resources)} AliCloud API resources")

        all_findings: List[Dict[str, Any]] = list(check_findings)

        # Build group-level context (traffic control, HTTPS enforcement)
        group_meta: Dict[str, dict] = {}
        for res in api_resources:
            if res["resource_type"] == "alicloud.apigateway.api_group":
                config = res.get("configuration") or {}
                group_meta[res["resource_uid"]] = {
                    "https_policy": (config.get("HttpsPolicy") or "").upper(),
                    "traffic_limit": config.get("TrafficLimit") or 0,
                    "name": config.get("GroupName") or res.get("resource_name", ""),
                }

        for res in api_resources:
            config = res.get("configuration") or {}
            rtype = res["resource_type"]
            name = config.get("ApiName") or res.get("resource_name", "")

            if rtype == "alicloud.apigateway.api_group":
                https_policy = (config.get("HttpsPolicy") or "").upper()
                traffic_limit = config.get("TrafficLimit") or 0

                if https_policy not in ("HTTPS_ONLY", "HTTPS_AND_HTTP"):
                    all_findings.append({
                        "rule_id": "alicloud.apigateway.api_group.no_https_only",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "AliCloud API Gateway group does not enforce HTTPS",
                        "description": (
                            f"API group HttpsPolicy is '{https_policy}'. "
                            "Plain HTTP traffic is allowed, exposing data in transit."
                        ),
                        "remediation": (
                            "Set HttpsPolicy to HTTPS_ONLY for the API group to redirect "
                            "all HTTP requests to HTTPS."
                        ),
                        "owasp_api_category": "API8",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": bool(traffic_limit),
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": config.get("GroupName") or name,
                        "api_stage": "",
                        "evidence": {"httpsPolicy": https_policy},
                    })

                if not traffic_limit:
                    all_findings.append({
                        "rule_id": "alicloud.apigateway.api_group.no_traffic_control",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "medium",
                        "title": "AliCloud API Gateway group has no traffic control limit",
                        "description": (
                            "No TrafficLimit is set on the API group. "
                            "Unlimited request throughput risks resource exhaustion attacks."
                        ),
                        "remediation": (
                            "Configure a TrafficControl rule for the API group specifying a "
                            "maximum requests-per-minute threshold."
                        ),
                        "owasp_api_category": "API4",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": config.get("GroupName") or name,
                        "api_stage": "",
                        "evidence": {"trafficLimit": traffic_limit},
                    })

            elif rtype == "alicloud.apigateway.api":
                auth_type = (config.get("AuthType") or "ANONYMOUS").upper()
                request_config = config.get("RequestConfig", {}) or {}
                request_protocol = (request_config.get("RequestProtocol") or "HTTP").upper()
                service_config = config.get("ServiceConfig", {}) or {}
                mock = config.get("Mock") or ""

                is_anonymous = auth_type in {"ANONYMOUS", ""}
                is_http_only = "HTTPS" not in request_protocol

                if is_anonymous:
                    all_findings.append({
                        "rule_id": "alicloud.apigateway.api.no_authentication",
                        "resource_uid": res["resource_uid"],
                        "resource_type": rtype,
                        "severity": "high",
                        "title": "AliCloud API Gateway API has anonymous (no) authentication",
                        "description": (
                            "API AuthType is ANONYMOUS. Any caller can invoke this API "
                            "without presenting credentials."
                        ),
                        "remediation": (
                            "Change AuthType to APP (AppKey/AppSecret) or APPOPENID (OpenID Connect) "
                            "and require signed requests."
                        ),
                        "owasp_api_category": "API2",
                        "finding_source": "config",
                        "auth_type": "none",
                        "has_waf": False,
                        "has_rate_limit": False,
                        "is_publicly_accessible": True,
                        "api_gateway_id": res["resource_uid"],
                        "api_name": name,
                        "api_stage": config.get("DeployedInfos", [{}])[0].get("StageName", "") if config.get("DeployedInfos") else "",
                        "evidence": {"authType": auth_type, "requestProtocol": request_protocol},
                    })

        logger.info(f"AliCloud provider complete: {len(all_findings)} findings")
        return all_findings
