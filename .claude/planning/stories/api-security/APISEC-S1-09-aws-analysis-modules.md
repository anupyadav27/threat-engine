# Story APISEC-S1-09: AWS Analysis Modules — 5 Depth Checks

## Status: done

## Metadata
- **Sprint**: APISEC Sprint 1
- **Points**: 8
- **Depends on**: APISEC-S1-07 (discovery reader), APISEC-S1-08 (provider imports these)
- **Blocks**: APISEC-S1-08
- **Security Gate**: bmad-security-reviewer (evidence dict must not include raw credentials)

## Directory

```
engines/api-security/api_security_engine/modules/
├── __init__.py
├── auth_scheme.py
├── throttle_audit.py
├── waf_coverage.py
├── versioning_audit.py
└── api_key_exposure.py
```

---

## Module 1: `auth_scheme.py` — OWASP API2 (Broken Authentication)

```python
from typing import List, Dict, Any

_NO_AUTH_TYPES = {"NONE", "CUSTOM", ""}
_AUTH_FIELD_MAP = {
    "AWS_IAM": "iam",
    "COGNITO_USER_POOLS": "oauth2",
    "JWT": "jwt",
    "API_KEY": "apikey",
    "LAMBDA": "custom",
}

class AuthSchemeModule:
    def run(self, api_resources, scan_run_id, tenant_id, account_id) -> List[Dict[str, Any]]:
        findings = []
        for res in api_resources:
            if res["resource_type"] not in (
                "aws.apigateway.stage", "aws.apigatewayv2.stage"
            ):
                continue
            config = res["configuration"] or {}
            # REST API stage: defaultRouteSettings or methodSettings
            auth_type_raw = (
                config.get("authorizationType")
                or config.get("AuthorizationType")
                or "NONE"
            ).upper()
            auth_type = _AUTH_FIELD_MAP.get(auth_type_raw, "none")
            is_public = config.get("endpointConfiguration", {}).get(
                "types", []
            ) == ["INTERNET"] or config.get("deploymentId") is not None

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
                    "api_name": config.get("stageName", res["resource_name"]),
                    "api_stage": config.get("stageName", ""),
                    "evidence": {
                        "authorizationType": auth_type_raw,
                        "endpointTypes": config.get(
                            "endpointConfiguration", {}
                        ).get("types", []),
                    },
                })
        return findings
```

---

## Module 2: `throttle_audit.py` — OWASP API4 (Unrestricted Resource Consumption)

```python
from typing import List, Dict, Any

_DEFAULT_THROTTLE_BURST = 5000
_DEFAULT_THROTTLE_RATE = 10000
_SAFE_BURST_THRESHOLD = 1000
_SAFE_RATE_THRESHOLD = 500

class ThrottleAuditModule:
    def run(self, api_resources, scan_run_id, tenant_id, account_id) -> List[Dict[str, Any]]:
        findings = []
        for res in api_resources:
            if res["resource_type"] not in (
                "aws.apigateway.stage", "aws.apigatewayv2.stage"
            ):
                continue
            config = res["configuration"] or {}
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
                # No throttle configured or set to AWS defaults (effectively unlimited)
                findings.append({
                    "rule_id": "aws.apigateway.stage.no_throttling",
                    "resource_uid": res["resource_uid"],
                    "resource_type": res["resource_type"],
                    "severity": "medium",
                    "title": "API stage has no rate limit configured",
                    "description": (
                        "The API Gateway stage is using AWS default throttle limits "
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
                    "api_name": config.get("stageName", res["resource_name"]),
                    "api_stage": config.get("stageName", ""),
                    "evidence": {
                        "throttlingBurstLimit": burst,
                        "throttlingRateLimit": rate,
                        "effectivelyUnlimited": True,
                    },
                })
        return findings
```

---

## Module 3: `waf_coverage.py` — OWASP API8 (Security Misconfiguration)

```python
from typing import List, Dict, Any

class WAFCoverageModule:
    def __init__(self, waf_map: Dict[str, bool]):
        self._waf_map = waf_map  # resource_arn → True

    def run(self, api_resources, scan_run_id, tenant_id, account_id) -> List[Dict[str, Any]]:
        findings = []
        for res in api_resources:
            if res["resource_type"] not in (
                "aws.apigateway.stage", "aws.apigatewayv2.stage"
            ):
                continue
            config = res["configuration"] or {}
            resource_arn = res["resource_uid"]
            has_waf = self._waf_map.get(resource_arn, False)
            is_public = True  # if we have a stage in scope, treat as potentially public

            if not has_waf and is_public:
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
                    "api_name": config.get("stageName", res["resource_name"]),
                    "api_stage": config.get("stageName", ""),
                    "evidence": {
                        "wafAssociated": False,
                        "resourceArn": resource_arn,
                    },
                })
        return findings
```

---

## Module 4: `versioning_audit.py` — OWASP API9 (Improper Inventory / Deprecated Versions)

```python
import re
from typing import List, Dict, Any

_DEPRECATED_VERSION_PATTERN = re.compile(
    r"(v0|v1\b|beta|alpha|test|dev|old|legacy|deprecated)", re.IGNORECASE
)

class VersioningAuditModule:
    def run(self, api_resources, scan_run_id, tenant_id, account_id) -> List[Dict[str, Any]]:
        findings = []
        for res in api_resources:
            if res["resource_type"] not in (
                "aws.apigateway.rest_api", "aws.apigatewayv2.api"
            ):
                continue
            config = res["configuration"] or {}
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
```

---

## Module 5: `api_key_exposure.py` — OWASP API2 (Broken Auth — Key Lifecycle)

**Unique differentiator**: No Orca/Wiz/Prisma covers API key rotation/expiry lifecycle.

```python
from datetime import datetime, timezone
from typing import List, Dict, Any

_KEY_AGE_HIGH_DAYS = 90
_KEY_AGE_CRITICAL_DAYS = 180


class APIKeyExposureModule:
    def run(self, api_resources, scan_run_id, tenant_id, account_id) -> List[Dict[str, Any]]:
        findings = []
        for res in api_resources:
            if res["resource_type"] != "aws.apigateway.api_key":
                continue
            config = res["configuration"] or {}
            enabled = config.get("enabled", True)
            created_date = config.get("createdDate")

            if not enabled:
                continue  # disabled keys are not a risk

            age_days = None
            if created_date:
                try:
                    if isinstance(created_date, str):
                        created_dt = datetime.fromisoformat(
                            created_date.replace("Z", "+00:00")
                        )
                    else:
                        created_dt = created_date
                    age_days = (
                        datetime.now(timezone.utc) - created_dt
                    ).days
                except (ValueError, TypeError):
                    pass

            if age_days is None or age_days < _KEY_AGE_HIGH_DAYS:
                continue

            severity = "critical" if age_days >= _KEY_AGE_CRITICAL_DAYS else "high"
            findings.append({
                "rule_id": "aws.apigateway.api_key.stale_key",
                "resource_uid": res["resource_uid"],
                "resource_type": res["resource_type"],
                "severity": severity,
                "title": f"API key has not been rotated in {age_days} days",
                "description": (
                    f"The API Gateway API key has been active for {age_days} days "
                    f"without rotation. Long-lived API keys are a persistent credential "
                    "exposure risk — if leaked, the window of compromise is unbounded."
                ),
                "remediation": (
                    "Rotate API keys every 90 days. Create new key, update consumers, "
                    "then disable and delete the old key. Consider migrating to "
                    "short-lived JWT tokens or IAM SigV4 authentication."
                ),
                "owasp_api_category": "API2",
                "finding_source": "config",
                "auth_type": "apikey",
                "has_waf": False,
                "has_rate_limit": False,
                "is_publicly_accessible": True,
                "api_gateway_id": "",
                "api_name": config.get("name", ""),
                "api_stage": "",
                "evidence": {
                    "keyAgeDays": age_days,
                    "createdDate": str(created_date),
                    "enabled": enabled,
                },
            })
        return findings
```

## Acceptance Criteria

- [ ] AC-1: `AuthSchemeModule.run()` — stage with `authorizationType=NONE` + INTERNET endpoint → 1 `high` finding with `owasp_api_category=API2`
- [ ] AC-2: `ThrottleAuditModule.run()` — stage with default burst/rate (≥1000/≥500) → 1 `medium` finding with `owasp_api_category=API4`
- [ ] AC-3: `WAFCoverageModule.run()` — stage ARN not in waf_map → 1 `high` finding with `owasp_api_category=API8`; stage ARN in waf_map → 0 findings
- [ ] AC-4: `VersioningAuditModule.run()` — API named "payments-v1-legacy" → 1 `medium` finding with `owasp_api_category=API9`
- [ ] AC-5: `APIKeyExposureModule.run()` — key with `createdDate` 200 days ago → 1 `critical` finding; 100 days → `high`; 30 days → 0 findings
- [ ] AC-6: `evidence` field is a dict in every finding — never a JSON string
- [ ] AC-7: No `credential_ref`, `tenant_id`, or `scan_run_id` keys in the finding dict (writer injects those)

## Definition of Done
- [ ] All 5 module files committed under `api_security_engine/modules/`
- [ ] `__init__.py` created (may be empty)
- [ ] Each module passes its AC unit tests (APISEC-S1-14)
- [ ] Imported without error in AWSAPISecProvider (APISEC-S1-08)
