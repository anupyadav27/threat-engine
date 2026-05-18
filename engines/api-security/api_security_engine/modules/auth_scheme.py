from typing import Any, Dict, List

_NO_AUTH_TYPES = {"NONE", "CUSTOM", ""}
_AUTH_FIELD_MAP = {
    "AWS_IAM": "iam",
    "COGNITO_USER_POOLS": "oauth2",
    "JWT": "jwt",
    "API_KEY": "apikey",
    "LAMBDA": "custom",
}


class AuthSchemeModule:
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
            auth_type_raw = (
                config.get("authorizationType")
                or config.get("AuthorizationType")
                or "NONE"
            ).upper()
            is_public = (
                config.get("endpointConfiguration", {}).get("types", []) == ["INTERNET"]
                or config.get("deploymentId") is not None
            )

            if auth_type_raw in _NO_AUTH_TYPES and is_public:
                findings.append({
                    "rule_id": "aws.apigateway.stage.no_auth",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "high",
                    "title": "API stage has no authentication",
                    "description": (
                        "The API Gateway stage is publicly accessible with no "
                        "authentication method configured (NONE). Any caller can "
                        "invoke all methods."
                    ),
                    "remediation": (
                        "Set authorization type to AWS_IAM, Cognito User Pool, "
                        "or Lambda authorizer. For HTTP APIs, configure a JWT authorizer."
                    ),
                    "owasp_api_category": "API2",
                    "finding_source": "config",
                    "auth_type": "none",
                    "has_waf": False,
                    "has_rate_limit": False,
                    "is_publicly_accessible": True,
                    "api_gateway_id": config.get("restApiId") or config.get("ApiId", ""),
                    "api_name": config.get("stageName", res.get("resource_name", "")),
                    "api_stage": config.get("stageName", ""),
                    "evidence": {
                        "authorizationType": auth_type_raw,
                        "endpointTypes": config.get("endpointConfiguration", {}).get("types", []),
                    },
                })
        return findings
