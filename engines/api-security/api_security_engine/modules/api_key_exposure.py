from datetime import datetime, timezone
from typing import Any, Dict, List

_KEY_AGE_HIGH_DAYS = 90
_KEY_AGE_CRITICAL_DAYS = 180


class APIKeyExposureModule:
    def run(
        self,
        api_resources: List[Dict[str, Any]],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        findings = []
        for res in api_resources:
            if res["resource_type"] != "aws.apigateway.api_key":
                continue
            config = res.get("configuration") or {}
            enabled = config.get("enabled", True)
            created_date = config.get("createdDate")

            if not enabled:
                continue

            age_days = None
            if created_date:
                try:
                    if isinstance(created_date, str):
                        created_dt = datetime.fromisoformat(
                            created_date.replace("Z", "+00:00")
                        )
                    else:
                        created_dt = created_date
                    age_days = (datetime.now(timezone.utc) - created_dt).days
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
                    "without rotation. Long-lived API keys are a persistent credential "
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
