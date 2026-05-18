from typing import Any, Dict, List


class WAFCoverageModule:
    def __init__(self, waf_map: Dict[str, bool]):
        self._waf_map = waf_map

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
            resource_arn = res["resource_uid"]
            has_waf = self._waf_map.get(resource_arn, False)

            if not has_waf:
                findings.append({
                    "rule_id": "aws.apigateway.stage.no_waf",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "high",
                    "title": "Public API stage has no WAF association",
                    "description": (
                        "The API Gateway stage has no AWS WAF web ACL associated. "
                        "Without WAF protection the API is vulnerable to OWASP Top 10 "
                        "attacks (SQLi, XSS, path traversal) and volumetric abuse."
                    ),
                    "remediation": (
                        "Create a WAFv2 web ACL with AWS Managed Rules and associate "
                        "it with the API Gateway stage via "
                        "wafv2:AssociateWebACL targeting the stage ARN."
                    ),
                    "owasp_api_category": "API8",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": False,
                    "has_rate_limit": False,
                    "is_publicly_accessible": True,
                    "api_gateway_id": config.get("restApiId") or config.get("ApiId", ""),
                    "api_name": config.get("stageName", res.get("resource_name", "")),
                    "api_stage": config.get("stageName", ""),
                    "evidence": {
                        "wafAssociated": False,
                        "resourceArn": resource_arn,
                    },
                })
        return findings
