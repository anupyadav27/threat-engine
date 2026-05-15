"""
Shared helpers and engine base URLs for BFF view modules.

Provides: fetch_many() for parallel fan-out, safe_get() for nested access,
engine URL registry, and query string builder.
"""

import asyncio
import os
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("api-gateway.bff")

# ── Internal engine base URLs ────────────────────────────────────────────────

ENGINE_URLS: Dict[str, str] = {
    "discoveries":   os.getenv("DISCOVERIES_ENGINE_URL",    "http://engine-discoveries"),
    "inventory":     os.getenv("INVENTORY_ENGINE_URL",      "http://engine-inventory:8022"),
    "threat":        os.getenv("THREAT_ENGINE_URL",         "http://engine-threat:8020"),
    "check":         os.getenv("CHECK_ENGINE_URL",          "http://engine-check:8002"),
    "compliance":    os.getenv("COMPLIANCE_ENGINE_URL",     "http://engine-compliance:8010"),
    "iam":           os.getenv("IAM_ENGINE_URL",            "http://engine-iam:8003"),
    "datasec":       os.getenv("DATASEC_ENGINE_URL",        "http://engine-datasec:8004"),
    # K8s service exposes port 80 → targetPort 8006
    "encryption":    os.getenv("ENCRYPTION_ENGINE_URL",     "http://engine-encryption"),
    "secops":        os.getenv("SECOPS_ENGINE_URL",         "http://engine-secops:8009"),
    "risk":          os.getenv("RISK_ENGINE_URL",           "http://engine-risk:8009"),
    "onboarding":    os.getenv("ONBOARDING_ENGINE_URL",     "http://engine-onboarding:8008"),
    "rule":          os.getenv("RULE_ENGINE_URL",           "http://engine-rule:8000"),
    "network":       os.getenv("NETWORK_ENGINE_URL",        "http://engine-network:80"),
    "cdr":          os.getenv("CDR_ENGINE_URL",           "http://engine-cdr"),
    "ai_security":   os.getenv("AI_SECURITY_ENGINE_URL",    "http://engine-ai-security"),
    "container_sec": os.getenv("CONTAINER_SEC_ENGINE_URL",  "http://engine-container-sec"),
    "cnapp":         os.getenv("CNAPP_ENGINE_URL",          "http://engine-cnapp"),
    "cwpp":          os.getenv("CWPP_ENGINE_URL",           "http://engine-cwpp"),
    "vulnerability": os.getenv("VULNERABILITY_ENGINE_URL",  "http://engine-vulnerability"),
    # K8s service exposes port 80 → targetPort 8007
    "dbsec":         os.getenv("DBSEC_ENGINE_URL",          "http://engine-dbsec"),
    "billing":        os.getenv("BILLING_ENGINE_URL",         "http://engine-billing:8040"),
    "platform_admin": os.getenv("PLATFORM_ADMIN_ENGINE_URL",  "http://engine-platform-admin:8041"),
    "threat_v1":      os.getenv("THREAT_V1_ENGINE_URL",       "http://engine-threat-v1:8021"),
}

# Convenience constants for backward compat
INVENTORY_URL = ENGINE_URLS["inventory"]
THREAT_URL = ENGINE_URLS["threat"]
CHECK_URL = ENGINE_URLS["check"]
COMPLIANCE_URL = ENGINE_URLS["compliance"]
IAM_URL = ENGINE_URLS["iam"]
DATASEC_URL = ENGINE_URLS["datasec"]
RISK_URL = ENGINE_URLS["risk"]
ONBOARDING_URL = ENGINE_URLS["onboarding"]
RULE_URL = ENGINE_URLS["rule"]

# Per-engine timeout overrides (seconds)
ENGINE_TIMEOUTS: Dict[str, float] = {
    "threat": 30.0,
    "inventory": 10.0,
    "compliance": 8.0,
    "iam": 15.0,
    "datasec": 12.0,
    "risk": 5.0,
    "onboarding": 5.0,
    "check": 30.0,
    "secops": 8.0,
    "rule": 5.0,
    "ai_security": 8.0,
    "cnapp": 40.0,        # aggregates 7 pillars in parallel (~20s each internally)
    "cwpp": 20.0,
    "container_sec": 15.0,
    "network": 15.0,
    "dbsec": 10.0,
    "encryption": 10.0,
    "billing": 10.0,
    "platform_admin": 15.0,
    "vulnerability": 30.0,   # severity stats scans 5k+ rows joined with scans table
    "threat_v1": 15.0,        # incident list joins threat_scenario_patterns
}

DEFAULT_TIMEOUT = float(os.getenv("BFF_ENGINE_TIMEOUT", "8"))


# ── Fetch helpers ────────────────────────────────────────────────────────────

async def _fetch_engine(
    client: httpx.AsyncClient,
    engine: str,
    path: str,
    params: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    auth_headers: Optional[Dict[str, str]] = None,
) -> Optional[Any]:
    """GET a single engine endpoint; returns parsed JSON or None on failure."""
    base = ENGINE_URLS.get(engine)
    if not base:
        logger.warning("Unknown engine: %s", engine)
        return None

    url = f"{base}{path}"
    t = timeout or ENGINE_TIMEOUTS.get(engine, DEFAULT_TIMEOUT)

    # Merge auth headers into outgoing request headers.
    # auth_headers are forwarded verbatim — BFF never re-encodes or logs them.
    headers: Dict[str, str] = {}
    if auth_headers:
        headers.update(auth_headers)

    try:
        resp = await client.get(url, params=params or {}, headers=headers, timeout=t)
        if resp.status_code == 200:
            data = resp.json()
            # Validate that "latest" scan_run_id resolved to actual data
            if params and params.get("scan_run_id") == "latest":
                if isinstance(data, dict) and not data:
                    logger.warning(
                        "BFF %s %s: 'latest' scan_run_id resolved to empty response",
                        engine, path,
                    )
            return data
        logger.warning("BFF fetch %s %s -> %s", engine, path, resp.status_code)
    except httpx.TimeoutException:
        logger.warning("BFF fetch %s %s timed out (%.1fs)", engine, path, t)
    except Exception as exc:
        logger.warning("BFF fetch %s %s error: %s", engine, path, exc)
    return None


async def fetch_many(
    calls: List[Tuple[str, str, Optional[Dict[str, str]]]],
    auth_headers: Optional[Dict[str, str]] = None,
) -> List[Optional[Any]]:
    """
    Parallel fan-out to multiple engines.

    Args:
        calls:        List of (engine_name, path, params) tuples.
        auth_headers: Optional headers (e.g. {"X-Auth-Context": <value>}) forwarded
                      verbatim to every engine call.  Pass as None when no auth
                      context is available — engines will return 401 which is
                      the correct behaviour.  Never log auth_headers content.

    Returns:
        List of results in same order. Failed calls return None.
    """
    async with httpx.AsyncClient() as client:
        return list(await asyncio.gather(
            *[
                _fetch_engine(client, engine, path, params, auth_headers=auth_headers)
                for engine, path, params in calls
            ]
        ))


async def fetch_all_check_findings(
    params: Dict[str, str],
    page_size: int = 500,
    max_pages: int = 20,
    timeout: Optional[float] = None,
    auth_headers: Optional[Dict[str, str]] = None,
) -> List[dict]:
    """
    Fetch ALL check engine findings by paginating automatically.

    The check engine caps page_size at 500. This helper fetches page 1,
    reads total_pages, then fetches remaining pages in parallel.

    Args:
        params:       Query params dict (must include tenant_id; domain/posture_category optional)
        page_size:    Items per page (max 500 for check engine)
        max_pages:    Safety cap on total pages to fetch
        timeout:      Per-request timeout in seconds
        auth_headers: Optional headers forwarded verbatim to every page request.

    Returns:
        Flat list of all finding dicts across all pages.
    """
    t = timeout or ENGINE_TIMEOUTS.get("check", DEFAULT_TIMEOUT)
    base = ENGINE_URLS.get("check", "")
    path = "/api/v1/check/findings"

    page_params = {**params, "page": "1", "page_size": str(page_size)}

    async with httpx.AsyncClient() as client:
        # Fetch page 1
        first = await _fetch_engine(client, "check", path, page_params, t, auth_headers=auth_headers)
        if not first or not isinstance(first, dict):
            return []

        findings = list(first.get("findings", []))
        total_pages = first.get("total_pages", 1) or 1
        total_pages = min(total_pages, max_pages)

        if total_pages <= 1:
            return findings

        # Fetch remaining pages in parallel
        remaining = list(await asyncio.gather(*[
            _fetch_engine(
                client, "check", path,
                {**params, "page": str(pg), "page_size": str(page_size)},
                t,
                auth_headers=auth_headers,
            )
            for pg in range(2, total_pages + 1)
        ]))

        for result in remaining:
            if result and isinstance(result, dict):
                findings.extend(result.get("findings", []))

        return findings


async def _fetch(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    auth_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """GET an internal engine URL and return parsed JSON (or empty dict on error)."""
    headers: Dict[str, str] = {}
    if auth_headers:
        headers.update(auth_headers)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            logger.warning("BFF fetch %s -> %d", url, resp.status_code)
    except Exception as exc:
        logger.warning("BFF fetch %s failed: %s", url, exc)
    return {}


# ── Utility helpers ──────────────────────────────────────────────────────────

def safe_get(data: Optional[dict], dotpath: str, default: Any = None) -> Any:
    """Safely get a nested value from a dict using dot notation."""
    if data is None:
        return default
    keys = dotpath.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
        if current is None:
            return default
    return current


def _qs(params: Dict[str, Any]) -> str:
    """Build query string from non-None params."""
    parts = [f"{k}={v}" for k, v in params.items() if v is not None]
    return ("?" + "&".join(parts)) if parts else ""


def _risk_level(score: int) -> str:
    """Map numeric risk score to human-readable level."""
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "minimal"


# ── Mock data fallback ──────────────────────────────────────────────────────

MOCK_ENABLED = os.getenv("BFF_MOCK_FALLBACK", "false").lower() in ("true", "1", "yes")


def is_empty_or_health(data) -> bool:
    """Check if engine response is empty or just a health/info response."""
    if not data or not isinstance(data, dict):
        return True
    # Engine health/info responses contain "status" + "service"/"version" keys
    # but no actual data keys (findings, threats, assets, rules, summary, etc.)
    _HEALTH_STATUSES = {"operational", "healthy", "ok", "up", "running"}
    if str(data.get("status", "")).lower() in _HEALTH_STATUSES:
        return True
    if "service" in data and "version" in data:
        return True
    return False


class BFFMeta:
    """Diagnostic envelope attached to every BFF response under ``_meta``.

    Handlers create one instance, record engine call outcomes, log warnings
    for unexpected shapes or missing fields, and embed the result in the
    return dict so both the UI dev-tools and backend logs surface the same
    context.  The ``_meta`` key is never used by the UI for rendering.
    """

    def __init__(self, view: str) -> None:
        self.view = view
        self._engine_calls: list[dict] = []
        self.warnings: list[str] = []
        self.fallback_triggered = False
        self.data_source = "engine"

    def record_engine(
        self,
        engine: str,
        path: str,
        result: Any,
        *,
        http_status: Optional[int] = None,
    ) -> None:
        """Record the outcome of a single engine call."""
        if result is None:
            status = "failed"
        elif isinstance(result, dict) and is_empty_or_health(result):
            status = "empty"
        else:
            status = "ok"
        entry: dict = {"engine": engine, "path": path, "status": status}
        if http_status is not None:
            entry["http_status"] = http_status
        self._engine_calls.append(entry)
        if status in ("failed", "empty"):
            logger.warning("BFF[%s] engine %s %s → %s", self.view, engine, path, status)

    def set_fallback(self, reason: str, source: str = "check_engine_fallback") -> None:
        """Mark that the primary engine failed and a fallback was used."""
        self.fallback_triggered = True
        self.data_source = source
        self.warn(f"Fallback triggered — {reason}")

    def warn(self, msg: str) -> None:
        """Append a warning that will appear in ``_meta.warnings`` and the log."""
        logger.warning("BFF[%s] %s", self.view, msg)
        self.warnings.append(msg)

    def expect_fields(
        self,
        data: Any,
        fields: list[str],
        context: str = "engine response",
    ) -> None:
        """Warn for each expected field missing from *data*."""
        if not isinstance(data, dict):
            self.warn(f"Expected dict for {context}, got {type(data).__name__}")
            return
        for field in fields:
            if field not in data:
                self.warn(f"Expected field '{field}' missing from {context}")

    def to_dict(self) -> dict:
        return {
            "view": self.view,
            "data_source": self.data_source,
            "fallback_triggered": self.fallback_triggered,
            "engine_calls": self._engine_calls,
            "warnings": self.warnings,
        }


def mock_fallback(view_name: str):
    """
    Return mock data for a BFF view when engine calls fail.

    Usage in a view:
        results = await fetch_many([...])
        if all(r is None for r in results):
            m = mock_fallback("threats")
            if m is not None:
                return m
    """
    if not MOCK_ENABLED:
        return None
    try:
        from . import _mock_data
        fn = getattr(_mock_data, f"mock_{view_name}", None)
        if fn:
            logger.info("BFF mock fallback for view: %s", view_name)
            return fn()
    except Exception as exc:
        logger.warning("BFF mock fallback error for %s: %s", view_name, exc)
    return None
