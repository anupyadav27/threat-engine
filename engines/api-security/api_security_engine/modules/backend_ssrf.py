"""BackendSSRFModule — OWASP API7: Server-Side Request Forgery.

Scans API gateway backend integration URLs for RFC 1918 addresses and
cloud metadata endpoints. A public API proxying to an internal/metadata
endpoint exposes the backend network to SSRF pivots.
"""

import re
from typing import Any, Dict, List

_RFC1918 = re.compile(
    r"(^|\D)(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"
)
_METADATA_PATTERNS = re.compile(
    r"(169\.254\.169\.254|fd00:ec2::254|metadata\.google\.internal"
    r"|metadata\.azure\.internal|100\.100\.100\.200)",
    re.IGNORECASE,
)

_BACKEND_URL_FIELDS = (
    "uri",
    "backendUri",
    "backend_uri",
    "serviceUrl",
    "httpIntegration",
    "integrationUri",
    "connectionUri",
)


def _extract_backend_url(config: dict) -> str:
    """Walk common config fields to find the backend URL string."""
    for field in _BACKEND_URL_FIELDS:
        val = config.get(field)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, dict):
            inner = val.get("uri") or val.get("url", "")
            if inner:
                return inner.strip()

    # AWS: integration block
    for stage in config.get("stages", []) or []:
        if isinstance(stage, dict):
            integ = stage.get("integration") or {}
            url = integ.get("uri") or integ.get("integrationUri", "")
            if url:
                return url

    return ""


class BackendSSRFModule:
    """Detect API backends pointing to RFC1918 / cloud metadata addresses (OWASP API7)."""

    def run(
        self,
        api_resources: List[Dict[str, Any]],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for res in api_resources:
            config = res.get("configuration") or {}
            backend_url = _extract_backend_url(config)
            if not backend_url:
                continue

            is_metadata = bool(_METADATA_PATTERNS.search(backend_url))
            is_rfc1918 = bool(_RFC1918.search(backend_url))

            if not (is_metadata or is_rfc1918):
                continue

            severity = "critical" if is_metadata else "high"
            category = "metadata endpoint" if is_metadata else "RFC 1918 address"

            findings.append({
                "rule_id": "api.gateway.backend_ssrf_risk",
                "resource_uid": res["resource_uid"],
                "resource_type": res["resource_type"],
                "severity": severity,
                "title": f"API Gateway backend URL contains {category} (SSRF risk)",
                "description": (
                    f"The API gateway backend URL '{backend_url[:120]}' resolves to a "
                    f"{category}. A public API proxying to this address exposes your "
                    "internal network or cloud instance metadata to server-side request forgery."
                ),
                "remediation": (
                    "Never expose internal RFC 1918 or metadata endpoints through a public "
                    "API gateway. Use VPC endpoints or private integrations with explicit "
                    "allow-lists. Block outbound requests to 169.254.169.254."
                ),
                "owasp_api_category": "API7",
                "finding_source": "config",
                "auth_type": "none",
                "has_waf": False,
                "has_rate_limit": False,
                "is_publicly_accessible": True,
                "api_gateway_id": res["resource_uid"],
                "api_name": config.get("name") or res.get("resource_name", ""),
                "api_stage": "",
                "evidence": {
                    "backendUrl": backend_url[:256],
                    "isMetadata": is_metadata,
                    "isRFC1918": is_rfc1918,
                },
            })

        return findings
