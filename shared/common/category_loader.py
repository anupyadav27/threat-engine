"""
CategoryLoader — loads rule categorization data from rule_metadata at startup.

The rule_metadata table in the check DB is the single source of truth for:
  - Which rules belong to each domain engine (database_security, container_security,
    ai_security, encryption_security, data_security JSONB columns)
  - Rule domain / subcategory classification (domain, subcategory columns)
  - Posture category labels (posture_category column)
  - Service names per engine scope (service column)

Engines call these functions once at startup. Results are cached per process.

Usage:
    from engine_common.category_loader import load_rule_domain_map, load_engine_services
    from engine_common.db_connections import get_check_conn

    rule_map = load_rule_domain_map("database_security", get_check_conn, SUBCATEGORY_TO_DOMAIN)
    services  = load_engine_services("database_security", get_check_conn)
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Process-level cache keyed by "<scope>:<kind>"
_cache: Dict[str, object] = {}


def _fetch_rows(engine_scope: str, conn_fn: Callable) -> List[Dict]:
    """
    Query rule_metadata for rows where the engine_scope JSONB column
    has applicable=true.
    """
    from psycopg2.extras import RealDictCursor

    conn = conn_fn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                f"""
                SELECT rule_id,
                       service,
                       subcategory,
                       domain,
                       posture_category,
                       {engine_scope} AS scope_data,
                       data_security
                FROM rule_metadata
                WHERE ({engine_scope} ->> 'applicable')::boolean = true
                """,
            )
            rows = cur.fetchall()
    finally:
        conn.close()

    result = [dict(r) for r in rows]
    logger.info(
        "CategoryLoader: fetched %d rows from rule_metadata for scope=%s",
        len(result),
        engine_scope,
    )
    return result


def load_rule_domain_map(
    engine_scope: str,
    conn_fn: Callable,
    subcategory_to_domain: Dict[str, str],
    default_domain: str = "configuration",
) -> Dict[str, str]:
    """
    Build a rule_id → domain mapping from rule_metadata.

    For each rule applicable to engine_scope, the rule's subcategory is
    translated to a domain string via subcategory_to_domain. Falls back to
    posture_category column, then default_domain.

    Cached per process lifetime.
    """
    cache_key = f"{engine_scope}:rules"
    if cache_key in _cache:
        return _cache[cache_key]  # type: ignore[return-value]

    rows = _fetch_rows(engine_scope, conn_fn)

    rule_map: Dict[str, str] = {}
    for row in rows:
        rule_id = row.get("rule_id")
        if not rule_id:
            continue
        subcategory = row.get("subcategory") or ""
        posture_cat = row.get("posture_category") or ""
        domain = (
            subcategory_to_domain.get(subcategory)
            or subcategory_to_domain.get(posture_cat)
            or default_domain
        )
        rule_map[rule_id] = domain

    _cache[cache_key] = rule_map
    logger.info(
        "CategoryLoader: built domain map with %d rules for scope=%s",
        len(rule_map),
        engine_scope,
    )
    return rule_map


def load_engine_services(
    engine_scope: str,
    conn_fn: Callable,
) -> Set[str]:
    """
    Return the set of service names applicable to an engine scope.

    Cached per process lifetime.
    """
    cache_key = f"{engine_scope}:services"
    if cache_key in _cache:
        return _cache[cache_key]  # type: ignore[return-value]

    rows = _fetch_rows(engine_scope, conn_fn)
    services: Set[str] = {row["service"] for row in rows if row.get("service")}
    _cache[cache_key] = services
    logger.info(
        "CategoryLoader: loaded %d services for scope=%s",
        len(services),
        engine_scope,
    )
    return services


def load_rule_module_map(
    engine_scope: str,
    conn_fn: Callable,
) -> Dict[str, List[str]]:
    """
    Build a rule_id → [module, ...] mapping from the modules list stored in
    the data_security JSONB column.

    Cached per process lifetime.
    """
    cache_key = f"{engine_scope}:modules"
    if cache_key in _cache:
        return _cache[cache_key]  # type: ignore[return-value]

    rows = _fetch_rows(engine_scope, conn_fn)

    rule_map: Dict[str, List[str]] = {}
    for row in rows:
        rule_id = row.get("rule_id")
        if not rule_id:
            continue
        scope_data: Dict = row.get("scope_data") or {}
        ds_data: Dict = row.get("data_security") or {}
        modules: List[str] = ds_data.get("modules") or scope_data.get("modules") or []
        if modules:
            rule_map[rule_id] = modules

    _cache[cache_key] = rule_map
    logger.info(
        "CategoryLoader: loaded %d rule→module entries for scope=%s",
        len(rule_map),
        engine_scope,
    )
    return rule_map


def invalidate_cache(engine_scope: Optional[str] = None) -> None:
    """Clear cached data. Pass engine_scope to clear only that scope."""
    if engine_scope is None:
        _cache.clear()
        logger.info("CategoryLoader: full cache cleared")
    else:
        for kind in ("rules", "services", "modules"):
            _cache.pop(f"{engine_scope}:{kind}", None)
        logger.info("CategoryLoader: cache cleared for scope=%s", engine_scope)
