"""
Shared Rule Loader — Task 0.5.2 [Seq 45 | BD]

Generic rule loader that all 5 new engines use to fetch active rules from
their respective {engine}_rules tables. Handles:

  - Active-only filtering (is_active = TRUE)
  - CSP filtering (csp column contains 'all' or matches requested CSP)
  - Optional in-memory cache (1-minute TTL) to reduce DB queries
  - Set membership pre-loading (for set_membership rules, loads referenced
    set from DB and injects as rule["_set_values"])

Usage:
    from shared.common.rule_loader import RuleLoader, Rule

    loader = RuleLoader()
    rules = await loader.load_rules(db_pool, "container", filter_csp="aws")
    # rules → List[Rule] with .to_eval_dict() for the evaluator

Consumed by: Tasks 1.4, 2.4, 3.5, 4.4, 5.5 (all engine evaluators)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Default cache TTL in seconds
DEFAULT_CACHE_TTL = 60


# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    """
    Parsed rule from {engine}_rules table.

    Maps directly to the standard rule table schema defined in
    NEW_ENGINES_ETL_RULES.md.
    """

    rule_id: str
    title: str
    description: str = ""
    category: str = ""
    severity: str = "medium"
    condition_type: str = "field_check"
    condition: Dict[str, Any] = field(default_factory=dict)
    evidence_fields: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    csp: List[str] = field(default_factory=lambda: ["all"])
    is_active: bool = True

    # Injected by loader for set_membership rules
    _set_values: Set[str] = field(default_factory=set, repr=False)

    def to_eval_dict(self) -> Dict[str, Any]:
        """
        Return dict shaped for RuleEvaluator.evaluate(asset, rule).
        """
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "condition_type": self.condition_type,
            "condition": self.condition,
            "_set_values": self._set_values,
        }


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------

@dataclass
class _CacheEntry:
    rules: List[Rule]
    loaded_at: float


# ---------------------------------------------------------------------------
# Rule Loader
# ---------------------------------------------------------------------------

class RuleLoader:
    """
    Load active rules from {engine}_rules tables.

    Parameters:
        cache_ttl: Cache TTL in seconds (0 to disable caching).
    """

    def __init__(self, cache_ttl: int = DEFAULT_CACHE_TTL) -> None:
        self._cache_ttl = cache_ttl
        self._cache: Dict[str, _CacheEntry] = {}

    def clear_cache(self) -> None:
        """Clear the in-memory rule cache."""
        self._cache.clear()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def load_rules(
        self,
        db_pool,
        engine_name: str,
        filter_csp: str = "all",
    ) -> List[Rule]:
        """
        Load active rules for a given engine.

        Args:
            db_pool:     asyncpg connection pool (or psycopg2 pool — see _query_*).
            engine_name: Engine name (container, network, supplychain, api, risk).
            filter_csp:  CSP filter ('all', 'aws', 'azure', 'gcp', etc.).

        Returns:
            List of Rule objects with _set_values pre-loaded for set_membership rules.
        """
        cache_key = f"{engine_name}:{filter_csp}"

        # Check cache
        if self._cache_ttl > 0:
            entry = self._cache.get(cache_key)
            if entry and (time.time() - entry.loaded_at) < self._cache_ttl:
                logger.debug("Rule cache hit for %s (age %.1fs)",
                             cache_key, time.time() - entry.loaded_at)
                return entry.rules

        # Load from DB
        rules = await self._query_rules(db_pool, engine_name, filter_csp)

        # Pre-load sets for set_membership rules
        for rule in rules:
            if rule.condition_type == "set_membership":
                rule._set_values = await self._load_set(db_pool, rule.condition)

        # Update cache
        if self._cache_ttl > 0:
            self._cache[cache_key] = _CacheEntry(rules=rules, loaded_at=time.time())
            logger.debug("Cached %d rules for %s", len(rules), cache_key)

        return rules

    def load_rules_sync(
        self,
        db_conn,
        engine_name: str,
        filter_csp: str = "all",
    ) -> List[Rule]:
        """
        Synchronous variant for engines using psycopg2 (non-async).

        Args:
            db_conn:     psycopg2 connection (or connection from pool).
            engine_name: Engine name.
            filter_csp:  CSP filter.

        Returns:
            List of Rule objects.
        """
        cache_key = f"{engine_name}:{filter_csp}"

        if self._cache_ttl > 0:
            entry = self._cache.get(cache_key)
            if entry and (time.time() - entry.loaded_at) < self._cache_ttl:
                return entry.rules

        rules = self._query_rules_sync(db_conn, engine_name, filter_csp)

        for rule in rules:
            if rule.condition_type == "set_membership":
                rule._set_values = self._load_set_sync(db_conn, rule.condition)

        if self._cache_ttl > 0:
            self._cache[cache_key] = _CacheEntry(rules=rules, loaded_at=time.time())

        return rules

    # ------------------------------------------------------------------
    # Async DB queries (asyncpg)
    # ------------------------------------------------------------------

    async def _query_rules(
        self,
        db_pool,
        engine_name: str,
        filter_csp: str,
    ) -> List[Rule]:
        """Query {engine}_rules table using asyncpg pool."""
        table_name = f"{engine_name}_rules"

        query = f"""
            SELECT rule_id, title, description, category, severity,
                   condition_type, condition, evidence_fields, frameworks,
                   remediation, "references", csp, is_active
            FROM {table_name}
            WHERE is_active = TRUE
              AND ('all' = ANY(csp) OR $1 = ANY(csp))
            ORDER BY severity DESC, rule_id
        """

        try:
            async with db_pool.acquire() as conn:
                rows = await conn.fetch(query, filter_csp)
                return [self._row_to_rule(dict(row)) for row in rows]

        except Exception as exc:
            # Table might not exist yet (engine not deployed)
            logger.warning("Failed to load rules from %s: %s", table_name, exc)
            return []

    async def _load_set(
        self,
        db_pool,
        condition: Dict[str, Any],
    ) -> Set[str]:
        """
        Load referenced set for set_membership rule.

        Condition must contain:
            set_table  — table name (e.g., 'cve_kev_list')
            set_column — column name (e.g., 'cve_id')
        """
        set_table = condition.get("set_table")
        set_column = condition.get("set_column")

        if not set_table or not set_column:
            logger.warning("set_membership rule missing set_table/set_column")
            return set()

        # Sanitize table/column names (prevent SQL injection)
        if not _is_safe_identifier(set_table) or not _is_safe_identifier(set_column):
            logger.error("Unsafe identifier in set_membership: %s.%s",
                         set_table, set_column)
            return set()

        query = f"SELECT {set_column} FROM {set_table}"

        try:
            async with db_pool.acquire() as conn:
                rows = await conn.fetch(query)
                values = {str(row[set_column]) for row in rows}
                logger.debug("Loaded %d values from %s.%s", len(values),
                             set_table, set_column)
                return values
        except Exception as exc:
            logger.warning("Failed to load set from %s.%s: %s",
                           set_table, set_column, exc)
            return set()

    # ------------------------------------------------------------------
    # Sync DB queries (psycopg2)
    # ------------------------------------------------------------------

    def _query_rules_sync(
        self,
        db_conn,
        engine_name: str,
        filter_csp: str,
    ) -> List[Rule]:
        """Query {engine}_rules table using psycopg2 connection."""
        table_name = f"{engine_name}_rules"

        query = f"""
            SELECT rule_id, title, description, category, severity,
                   condition_type, condition, evidence_fields, frameworks,
                   remediation, "references", csp, is_active
            FROM {table_name}
            WHERE is_active = TRUE
              AND ('all' = ANY(csp) OR %s = ANY(csp))
            ORDER BY severity DESC, rule_id
        """

        try:
            cursor = db_conn.cursor()
            cursor.execute(query, (filter_csp,))
            columns = [desc[0] for desc in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
            cursor.close()
            return [self._row_to_rule(row) for row in rows]

        except Exception as exc:
            logger.warning("Failed to load rules from %s: %s", table_name, exc)
            return []

    def _load_set_sync(
        self,
        db_conn,
        condition: Dict[str, Any],
    ) -> Set[str]:
        """Sync variant of _load_set."""
        set_table = condition.get("set_table")
        set_column = condition.get("set_column")

        if not set_table or not set_column:
            return set()

        if not _is_safe_identifier(set_table) or not _is_safe_identifier(set_column):
            logger.error("Unsafe identifier in set_membership: %s.%s",
                         set_table, set_column)
            return set()

        query = f"SELECT {set_column} FROM {set_table}"

        try:
            cursor = db_conn.cursor()
            cursor.execute(query)
            values = {str(row[0]) for row in cursor.fetchall()}
            cursor.close()
            return values
        except Exception as exc:
            logger.warning("Failed to load set from %s.%s: %s",
                           set_table, set_column, exc)
            return set()

    # ------------------------------------------------------------------
    # Row parsing
    # ------------------------------------------------------------------

    def _row_to_rule(self, row: Dict[str, Any]) -> Rule:
        """Convert a DB row dict to a Rule dataclass."""
        # Handle JSONB columns that might come as strings
        condition = row.get("condition", {})
        if isinstance(condition, str):
            import json
            condition = json.loads(condition)

        evidence_fields = row.get("evidence_fields") or []
        frameworks = row.get("frameworks") or []
        references = row.get("references") or []
        csp = row.get("csp") or ["all"]

        return Rule(
            rule_id=row["rule_id"],
            title=row.get("title", ""),
            description=row.get("description", ""),
            category=row.get("category", ""),
            severity=row.get("severity", "medium"),
            condition_type=row.get("condition_type", "field_check"),
            condition=condition,
            evidence_fields=evidence_fields,
            frameworks=frameworks,
            remediation=row.get("remediation", ""),
            references=references,
            csp=csp,
            is_active=row.get("is_active", True),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_safe_identifier(name: str) -> bool:
    """
    Check that a table/column name is safe for use in SQL.
    Allows lowercase alphanumeric + underscores only.
    """
    import re
    return bool(re.match(r'^[a-z_][a-z0-9_]*$', name))
