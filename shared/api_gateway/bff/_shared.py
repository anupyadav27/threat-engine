"""
Shared helpers and engine base URLs for BFF view modules.

Provides: fetch_many() for parallel fan-out, safe_get() for nested access,
engine URL registry, query string builder, and shared DB read helpers
(fetch_scan_trend, read_findings, read_posture).
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
    "chat":           os.getenv("CHAT_ENGINE_URL",            "http://engine-chat"),
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
    "check": 45.0,   # rules catalog: up to 15k rules can take ~17-30s under load
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


# ── Shared DB helpers ────────────────────────────────────────────────────────


def fetch_scan_trend(tenant_id: str, days: int = 30) -> List[Dict[str, Any]]:
    """Read completed scan history from the onboarding DB's scan_runs table.

    Groups completed scans by UTC date and returns a sorted list of daily
    data points.  Severity counts and pass_rate are set to 0 because
    scan_runs does not store per-severity finding counts; a future story
    will join security_findings for those values.

    Args:
        tenant_id: The tenant whose scan history to return.
        days:      Number of days of history to include (default 30).

    Returns:
        List of dicts: [{date, total, critical, high, medium, passRate,
                         assets, drift}] sorted ascending by date.
        Returns [] on any DB error so callers get a graceful empty state.
    """
    try:
        from engine_common.db_connections import get_onboarding_conn

        with get_onboarding_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        DATE(started_at AT TIME ZONE 'UTC') AS scan_date,
                        COUNT(*) AS scan_count
                    FROM scan_runs
                    WHERE tenant_id = %s
                      AND overall_status = 'completed'
                      AND started_at > NOW() - (%s * INTERVAL '1 day')
                    GROUP BY scan_date
                    ORDER BY scan_date
                    """,
                    (tenant_id, days),
                )
                rows = cur.fetchall()

        return [
            {
                "date":     str(row[0]),
                "total":    int(row[1]),
                "critical": 0,
                "high":     0,
                "medium":   0,
                "passRate": 0,
                "assets":   0,
                "drift":    0,
            }
            for row in rows
        ]
    except Exception as exc:
        logger.warning("fetch_scan_trend failed for tenant %s: %s", tenant_id, exc)
        return []


def read_findings(
    tenant_id: str,
    source_engines: Optional[List[str]] = None,
    posture_category: Optional[str] = None,
    severity: Optional[List[str]] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
    provider: Optional[str] = None,
    resource_uid: Optional[str] = None,
    scan_run_id: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0,
    order_by: str = "severity DESC, last_seen_at DESC",
) -> Dict[str, Any]:
    """Read findings from the security_findings table (inventory DB).

    Always tenant-scoped.  JSONB details column is returned as a Python
    dict by psycopg2 — never call json.loads() on it.

    Args:
        tenant_id:       Required.  Scopes every query.
        source_engines:  Optional list to filter by source engine name.
        posture_category: Optional posture_category filter.
        severity:        Optional list of severity levels to include.
        account_id:      Optional account filter.
        region:          Optional region filter.
        provider:        Optional provider filter.
        resource_uid:    Optional exact resource UID filter.
        scan_run_id:     Optional scan run ID filter.
        limit:           Max rows to return (default 1000).
        offset:          Row offset for pagination (default 0).
        order_by:        ORDER BY clause (injection-safe; uses allowlist internally
                         via parameterised LIMIT/OFFSET).

    Returns:
        {
            "findings":    List[dict],
            "total":       int,
            "by_severity": {"critical": N, "high": N, "medium": N, "low": N},
            "by_engine":   {engine_name: N},
        }
    """
    from engine_common.db_connections import get_inventory_conn

    conditions: List[str] = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]

    if source_engines:
        placeholders = ",".join(["%s"] * len(source_engines))
        conditions.append(f"source_engine IN ({placeholders})")
        params.extend(source_engines)

    if posture_category:
        conditions.append("posture_category = %s")
        params.append(posture_category)

    if severity:
        placeholders = ",".join(["%s"] * len(severity))
        conditions.append(f"severity IN ({placeholders})")
        params.extend(severity)

    if account_id:
        conditions.append("account_id = %s")
        params.append(account_id)

    if region:
        conditions.append("region = %s")
        params.append(region)

    if provider:
        conditions.append("provider = %s")
        params.append(provider)

    if resource_uid:
        conditions.append("resource_uid = %s")
        params.append(resource_uid)

    if scan_run_id:
        conditions.append("scan_run_id = %s")
        params.append(scan_run_id)

    where = " AND ".join(conditions)

    count_sql = f"SELECT COUNT(*) FROM security_findings WHERE {where}"
    agg_sql = f"""
        SELECT source_engine, severity, COUNT(*) AS cnt
        FROM security_findings
        WHERE {where}
        GROUP BY source_engine, severity
    """
    data_sql = f"""
        SELECT
            finding_id, source_engine, source_finding_id, tenant_id,
            scan_run_id, account_id, provider, region,
            resource_uid, resource_type, rule_id, severity, status,
            title, description, remediation, posture_category,
            details, first_seen_at, last_seen_at
        FROM security_findings
        WHERE {where}
        ORDER BY {order_by}
        LIMIT %s OFFSET %s
    """

    try:
        with get_inventory_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(count_sql, params)
                total: int = cur.fetchone()[0]

                cur.execute(agg_sql, params)
                agg_rows = cur.fetchall()

                cur.execute(data_sql, params + [limit, offset])
                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
    except Exception as exc:
        logger.warning("read_findings failed for tenant %s: %s", tenant_id, exc)
        return {
            "findings":    [],
            "total":       0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_engine":   {},
        }

    findings = [dict(zip(cols, r)) for r in rows]

    # Build aggregations (JSONB details already a dict — no json.loads needed)
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_engine: Dict[str, int] = {}
    for engine_name, sev, cnt in agg_rows:
        if sev in by_severity:
            by_severity[sev] += cnt
        by_engine[engine_name] = by_engine.get(engine_name, 0) + cnt

    return {
        "findings":    findings,
        "total":       total,
        "by_severity": by_severity,
        "by_engine":   by_engine,
    }


def read_findings_for_asset(
    tenant_id: str,
    resource_uid: str,
    source_engines: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """All findings for a specific resource_uid across engines.

    Convenience wrapper around read_findings() scoped to a single asset.

    Args:
        tenant_id:      Required tenant scope.
        resource_uid:   The resource UID to look up.
        source_engines: Optional engine filter.

    Returns:
        Same shape as read_findings().
    """
    return read_findings(
        tenant_id=tenant_id,
        resource_uid=resource_uid,
        source_engines=source_engines,
        limit=500,
    )


def read_posture(
    tenant_id: str,
    resource_uid: Optional[str] = None,
    resource_uids: Optional[List[str]] = None,
    account_id: Optional[str] = None,
    provider: Optional[str] = None,
    resource_type: Optional[str] = None,
    has_critical: Optional[bool] = None,
    limit: int = 500,
    offset: int = 0,
) -> Dict[str, Any]:
    """Read posture signals from resource_security_posture (inventory DB).

    Always tenant-scoped.  JSONB detail columns (iam_detail, network_detail,
    api_detail) are returned as Python dicts — never call json.loads() on them.

    Args:
        tenant_id:     Required.  Scopes every query.
        resource_uid:  Optional single resource UID filter.
        resource_uids: Optional list of resource UIDs (IN filter).
        account_id:    Optional account filter.
        provider:      Optional provider filter.
        resource_type: Optional resource_type filter.
        has_critical:  When True, only rows where critical_count > 0.
        limit:         Max rows to return (default 500).
        offset:        Row offset (default 0).

    Returns:
        {
            "posture": List[dict],
            "total":   int,
            "summary": {
                "avg_posture_score": float,
                "high_risk_count":   int,
                "critical_findings": int,
                "unencrypted_count": int,
                "internet_exposed":  int,
            },
        }
    """
    from engine_common.db_connections import get_inventory_conn

    conditions: List[str] = ["tenant_id = %s"]
    params: List[Any] = [tenant_id]

    if resource_uid:
        conditions.append("resource_uid = %s")
        params.append(resource_uid)

    if resource_uids:
        placeholders = ",".join(["%s"] * len(resource_uids))
        conditions.append(f"resource_uid IN ({placeholders})")
        params.extend(resource_uids)

    if account_id:
        conditions.append("account_id = %s")
        params.append(account_id)

    if provider:
        conditions.append("provider = %s")
        params.append(provider)

    if resource_type:
        conditions.append("resource_type = %s")
        params.append(resource_type)

    if has_critical:
        conditions.append("critical_count > 0")

    where = " AND ".join(conditions)

    data_sql = f"""
        SELECT
            posture_id, resource_uid, resource_type, tenant_id,
            account_id, provider, region, scan_run_id,
            critical_count, high_count, medium_count, low_count, total_findings,
            overall_posture_score, posture_band,
            iam_score, iam_detail,
            network_score, is_in_private_subnet, network_detail,
            is_encrypted_at_rest, is_encrypted_in_transit, has_kms_managed_key,
            has_valid_certificate, cert_days_remaining, tls_version, encryption_score,
            api_auth_type, api_has_waf, api_has_rate_limit,
            api_publicly_accessible, api_security_score, api_detail,
            has_privileged_container, image_has_critical_cve,
            k8s_rbac_overpermissive, container_security_score,
            ai_security_score,
            db_auth_type, dbsec_score,
            is_high_risk_crown_jewel, is_internet_exposed_with_critical,
            api_public_no_waf, api_public_no_auth,
            reachable_pii_store_count,
            last_updated_at
        FROM resource_security_posture
        WHERE {where}
        ORDER BY overall_posture_score DESC NULLS LAST, critical_count DESC
        LIMIT %s OFFSET %s
    """
    count_sql = f"SELECT COUNT(*) FROM resource_security_posture WHERE {where}"

    try:
        with get_inventory_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(count_sql, params)
                total: int = cur.fetchone()[0]

                cur.execute(data_sql, params + [limit, offset])
                cols = [d[0] for d in cur.description]
                rows = cur.fetchall()
    except Exception as exc:
        logger.warning("read_posture failed for tenant %s: %s", tenant_id, exc)
        return {
            "posture": [],
            "total":   0,
            "summary": {
                "avg_posture_score": 0, "high_risk_count": 0,
                "critical_findings": 0, "unencrypted_count": 0,
                "internet_exposed":  0,
            },
        }

    posture_list = [dict(zip(cols, r)) for r in rows]

    if posture_list:
        summary: Dict[str, Any] = {
            "avg_posture_score": round(
                sum(p.get("overall_posture_score") or 0 for p in posture_list)
                / len(posture_list),
                1,
            ),
            "high_risk_count":   sum(
                1 for p in posture_list
                if (p.get("overall_posture_score") or 100) < 40
            ),
            "critical_findings": sum(
                p.get("critical_count") or 0 for p in posture_list
            ),
            "unencrypted_count": sum(
                1 for p in posture_list if not p.get("is_encrypted_at_rest")
            ),
            "internet_exposed":  sum(
                1 for p in posture_list
                if p.get("is_internet_exposed_with_critical")
            ),
        }
    else:
        summary = {
            "avg_posture_score": 0, "high_risk_count": 0,
            "critical_findings": 0, "unencrypted_count": 0,
            "internet_exposed":  0,
        }

    return {"posture": posture_list, "total": total, "summary": summary}


def read_posture_for_resource(
    tenant_id: str,
    resource_uid: str,
) -> Optional[Dict[str, Any]]:
    """Single resource posture row from resource_security_posture.

    Args:
        tenant_id:    Required tenant scope.
        resource_uid: Resource UID to look up.

    Returns:
        A single posture dict or None if the resource is not found.
    """
    result = read_posture(tenant_id=tenant_id, resource_uid=resource_uid, limit=1)
    return result["posture"][0] if result["posture"] else None
