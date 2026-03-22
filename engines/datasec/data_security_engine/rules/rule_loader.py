"""
DB-driven rule loader for DataSec engine.
Reads rules from datasec_rules table in threat_engine_datasec database.
"""
import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


def _get_datasec_conn():
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", "localhost"),
        port=int(os.getenv("DATASEC_DB_PORT", "5432")),
        database=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", "postgres"),
        password=os.getenv("DATASEC_DB_PASSWORD"),
    )


class DataSecRuleLoader:
    def __init__(self):
        self._rules_cache: Dict[str, List[Dict]] = {}

    def load_all_rules(self, csp: str = "aws", tenant_id: Optional[str] = None) -> Dict[str, List[Dict]]:
        """Load ALL active rules grouped by category.

        Global rules (tenant_id IS NULL) merged with tenant-specific overrides.
        Returns: {"data_protection_encryption": [rule_dict, ...], ...}
        """
        try:
            conn = _get_datasec_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM datasec_rules
                    WHERE csp = %s AND is_active = TRUE
                      AND (tenant_id IS NULL OR tenant_id = %s)
                    ORDER BY category, rule_id
                """, (csp, tenant_id))
                rows = cur.fetchall()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to load datasec rules: {e}")
            return {}

        # Group by category, tenant overrides replace globals
        by_category: Dict[str, Dict[str, Dict]] = {}  # category -> {rule_id -> rule}
        for row in rows:
            cat = row["category"]
            rid = row["rule_id"]
            if cat not in by_category:
                by_category[cat] = {}
            # Tenant-specific overrides global (appears later in query)
            if row.get("tenant_id"):
                by_category[cat][rid] = dict(row)
            elif rid not in by_category[cat]:
                by_category[cat][rid] = dict(row)

        result = {cat: list(rules.values()) for cat, rules in by_category.items()}
        self._rules_cache = result
        logger.info(f"Loaded {sum(len(v) for v in result.values())} datasec rules across {len(result)} categories")
        return result

    def load_rules_by_category(self, category: str, csp: str = "aws", tenant_id: Optional[str] = None) -> List[Dict]:
        if not self._rules_cache:
            self.load_all_rules(csp, tenant_id)
        return self._rules_cache.get(category, [])

    def load_sensitive_data_patterns(self) -> Dict[str, List[Dict]]:
        """Load regex patterns from datasec_sensitive_data_types table.
        Returns: {"pii": [{"type_key": "ssn", "pattern": "...", "confidence": 0.9}, ...]}
        """
        try:
            conn = _get_datasec_conn()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM datasec_sensitive_data_types WHERE is_active = TRUE ORDER BY category, type_key")
                rows = cur.fetchall()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to load sensitive data patterns: {e}")
            return {}

        result: Dict[str, List[Dict]] = {}
        for row in rows:
            cat = row["category"]
            if cat not in result:
                result[cat] = []
            result[cat].append({
                "type_key": row["type_key"],
                "display_name": row["display_name"],
                "pattern": row.get("detection_pattern"),
                "confidence": float(row.get("confidence_weight", 0.8)),
            })
        return result
