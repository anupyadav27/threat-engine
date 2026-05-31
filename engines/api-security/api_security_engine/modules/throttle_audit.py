from typing import Any, Dict, List

_DEFAULT_THROTTLE_BURST = 5000
_DEFAULT_THROTTLE_RATE = 10000
_SAFE_BURST_THRESHOLD = 1000
_SAFE_RATE_THRESHOLD = 500


class ThrottleAuditModule:
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
                "aws.apigateway.stage", "aws.apigatewayv2.stage"
            ):
                continue
            config = res.get("configuration") or {}
            default_settings = config.get("defaultRouteSettings") or config.get(
                "methodSettings", {}
            ).get("*/*", {})
            burst = default_settings.get("throttlingBurstLimit") or default_settings.get(
                "ThrottlingBurstLimit", _DEFAULT_THROTTLE_BURST
            )
            rate = default_settings.get("throttlingRateLimit") or default_settings.get(
                "ThrottlingRateLimit", _DEFAULT_THROTTLE_RATE
            )

            if burst >= _SAFE_BURST_THRESHOLD and rate >= _SAFE_RATE_THRESHOLD:
                findings.append({
                    "rule_id": "aws.apigateway.stage.no_throttling",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "medium",
                    "title": "API stage has no rate limit configured",
                    "description": (
                        f"The API Gateway stage is using AWS default throttle limits "
                        f"(burst={burst}, rate={rate}/s), providing no effective "
                        "rate-limiting protection against resource exhaustion attacks."
                    ),
                    "remediation": (
                        "Set stage-level throttling: burst limit ≤500 req/s, "
                        "rate limit ≤200 req/s. Enable usage plans for API key-based "
                        "consumers to enforce per-client quotas."
                    ),
                    "owasp_api_category": "API4",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": False,
                    "has_rate_limit": False,
                    "is_publicly_accessible": True,
                    "api_gateway_id": config.get("restApiId") or config.get("ApiId", ""),
                    "api_name": config.get("stageName", res.get("resource_name", "")),
                    "api_stage": config.get("stageName", ""),
                    "evidence": {
                        "throttlingBurstLimit": burst,
                        "throttlingRateLimit": rate,
                        "effectivelyUnlimited": True,
                    },
                })
        return findings
