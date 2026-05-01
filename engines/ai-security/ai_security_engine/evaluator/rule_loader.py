"""
DB-driven rule loader for AI Security engine.
Reads rules from ai_security_rules table in threat_engine_ai_security database.
"""
import logging
from typing import Dict, List, Optional, Any

from psycopg2.extras import RealDictCursor

from engine_common.db_connections import get_ai_security_conn

logger = logging.getLogger(__name__)


class AIRuleLoader:
    """Loads AI security rules from database."""

    def __init__(self) -> None:
        self._rules_cache: Dict[str, List[Dict[str, Any]]] = {}

    def load_rules(self, csp: str = "aws", tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load active AI security rules for a CSP.

        Reads from threat_engine_ai_security.ai_security_rules
        WHERE is_active = true AND csp contains the given provider.

        Args:
            csp: Cloud provider identifier ('aws', 'azure', 'gcp').
            tenant_id: Optional tenant for future tenant-specific overrides.

        Returns:
            List of rule dicts with: rule_id, title, description, severity,
            category, subcategory, condition (JSONB), condition_type, frameworks,
            mitre_techniques, remediation.
        """
        try:
            conn = get_ai_security_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT rule_id, title, description, severity, category,
                           subcategory, condition, condition_type, frameworks,
                           mitre_techniques, remediation, csp
                    FROM ai_security_rules
                    WHERE is_active = true
                      AND %s = ANY(csp)
                    ORDER BY category, rule_id
                    """,
                    (csp,),
                )
                rows = cur.fetchall()
            conn.close()
        except Exception as e:
            logger.error("Failed to load AI security rules: %s", e)
            return []

        rules = [dict(row) for row in rows]
        logger.info("Loaded %d AI security rules for csp=%s", len(rules), csp)
        return rules

    def get_rules_by_category(self, csp: str = "aws", tenant_id: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Group rules by category.

        Args:
            csp: Cloud provider identifier.
            tenant_id: Optional tenant filter.

        Returns:
            Dict mapping category name to list of rule dicts.
        """
        rules = self.load_rules(csp=csp, tenant_id=tenant_id)
        by_category: Dict[str, List[Dict[str, Any]]] = {}
        for rule in rules:
            cat = rule.get("category", "unknown")
            by_category.setdefault(cat, []).append(rule)

        self._rules_cache = by_category
        logger.info(
            "Grouped %d rules into %d categories",
            sum(len(v) for v in by_category.values()),
            len(by_category),
        )
        return by_category

    def get_cached_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return previously loaded rules without hitting DB.

        Returns:
            Cached rules grouped by category, or empty dict if not loaded.
        """
        return self._rules_cache
