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
    "inventory":  os.getenv("INVENTORY_ENGINE_URL",  "http://engine-inventory:8022"),
    "threat":     os.getenv("THREAT_ENGINE_URL",     "http://engine-threat:8020"),
    "check":      os.getenv("CHECK_ENGINE_URL",      "http://engine-check:8002"),
    "compliance": os.getenv("COMPLIANCE_ENGINE_URL",  "http://engine-compliance:8010"),
    "iam":        os.getenv("IAM_ENGINE_URL",         "http://engine-iam:8003"),
    "datasec":    os.getenv("DATASEC_ENGINE_URL",     "http://engine-datasec:8004"),
    "encryption": os.getenv("ENCRYPTION_ENGINE_URL",  "http://engine-encryption:8006"),
    "secops":     os.getenv("SECOPS_ENGINE_URL",      "http://engine-secops:8009"),
    "risk":       os.getenv("RISK_ENGINE_URL",        "http://engine-risk:8009"),
    "onboarding": os.getenv("ONBOARDING_ENGINE_URL",  "http://engine-onboarding:8008"),
    "rule":       os.getenv("RULE_ENGINE_URL",        "http://engine-rule:8000"),
    "network":    os.getenv("NETWORK_ENGINE_URL",      "http://engine-network:80"),
    "ciem":        os.getenv("CIEM_ENGINE_URL",        "http://engine-ciem"),
    "ai_security":     os.getenv("AI_SECURITY_ENGINE_URL", "http://engine-ai-security"),
    "container_sec":   os.getenv("CONTAINER_SEC_ENGINE_URL", "http://engine-container-sec:80"),
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
    "threat": 10.0,
    "inventory": 10.0,
    "compliance": 8.0,
    "iam": 8.0,
    "datasec": 8.0,
    "risk": 5.0,
    "onboarding": 5.0,
    "check": 8.0,
    "secops": 8.0,
    "rule": 5.0,
    "ai_security": 8.0,
}

DEFAULT_TIMEOUT = float(os.getenv("BFF_ENGINE_TIMEOUT", "8"))


# ── Fetch helpers ────────────────────────────────────────────────────────────

async def _fetch_engine(
    client: httpx.AsyncClient,
    engine: str,
    path: str,
    params: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
) -> Optional[Any]:
    """GET a single engine endpoint; returns parsed JSON or None on failure."""
    base = ENGINE_URLS.get(engine)
    if not base:
        logger.warning("Unknown engine: %s", engine)
        return None

    url = f"{base}{path}"
    t = timeout or ENGINE_TIMEOUTS.get(engine, DEFAULT_TIMEOUT)

    try:
        resp = await client.get(url, params=params or {}, timeout=t)
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
) -> List[Optional[Any]]:
    """
    Parallel fan-out to multiple engines.

    Args:
        calls: List of (engine_name, path, params) tuples.

    Returns:
        List of results in same order. Failed calls return None.
    """
    async with httpx.AsyncClient() as client:
        return list(await asyncio.gather(
            *[
                _fetch_engine(client, engine, path, params)
                for engine, path, params in calls
            ]
        ))


async def _fetch(url: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """GET an internal engine URL and return parsed JSON (or empty dict on error)."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url)
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

MOCK_ENABLED = os.getenv("BFF_MOCK_FALLBACK", "true").lower() in ("true", "1", "yes")


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
