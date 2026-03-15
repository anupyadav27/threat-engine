"""
Rule Reader for Check Engine
Reads check rules from the rule_checks table in the check database.
This allows rules to be loaded from the central database instead of only from YAML files.
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List, Any, Optional
import logging
import json

logger = logging.getLogger(__name__)


class RuleReader:
    """Reads check rule definitions from the check database"""

    def __init__(self, db_config: Optional[Dict] = None):
        """
        Initialize with check engine database connection config.
        Uses the same DB as the check engine itself (CHECK_DB_* env vars).
        """
        self.db_config = db_config or {
            "host": os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
            "port": int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
            "database": os.getenv("CHECK_DB_NAME", "threat_engine_check"),
            "user": os.getenv("CHECK_DB_USER", os.getenv("SHARED_DB_USER", "postgres")),
            "password": os.getenv("CHECK_DB_PASSWORD", os.getenv("SHARED_DB_PASSWORD", "")),
        }
        logger.info(
            f"RuleReader: Using check database: {self.db_config['database']} "
            f"on {self.db_config['host']}"
        )

    def _get_connection(self):
        """Get database connection"""
        return psycopg2.connect(
            host=self.db_config["host"],
            port=self.db_config["port"],
            database=self.db_config["database"],
            user=self.db_config["user"],
            password=self.db_config["password"],
            connect_timeout=10,
        )

    def read_checks_for_service(
        self, service: str, provider: str = "aws"
    ) -> List[Dict]:
        """
        Read check rules from rule_checks table for a given service.

        The check_config JSONB column already contains the same structure as YAML:
        {"for_each": "aws.s3.list_buckets", "conditions": {...}}

        Returns:
            List of check dicts: [{"rule_id": "...", "for_each": "...", "conditions": {...}}]
        """
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT rule_id, check_config
                    FROM rule_checks
                    WHERE service = %s AND provider = %s
                      AND (is_active IS NULL OR is_active = true)
                    ORDER BY rule_id
                    """,
                    (service, provider),
                )
                checks = []
                for row in cur.fetchall():
                    config = row["check_config"]
                    if isinstance(config, str):
                        config = json.loads(config)
                    if config:
                        check = {"rule_id": row["rule_id"]}
                        check.update(config)
                        checks.append(check)

                logger.debug(
                    f"Loaded {len(checks)} checks for {provider}.{service} from database"
                )
                return checks
        except Exception as e:
            logger.warning(
                f"Failed to read checks from DB for {service}: {e}"
            )
            return []
        finally:
            if conn:
                conn.close()

    def read_metadata_for_rules(self, rule_ids: List[str]) -> Dict[str, Dict]:
        """
        Read rule metadata for enriching check results.

        Returns:
            Dict mapping rule_id to metadata dict with severity, title, description, etc.
        """
        if not rule_ids:
            return {}

        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                placeholders = ",".join(["%s"] * len(rule_ids))
                cur.execute(
                    f"""
                    SELECT rule_id, severity, title, description, remediation,
                           rationale, domain, subcategory, compliance_frameworks,
                           threat_category, threat_tags, risk_score, mitre_tactics, mitre_techniques,
                           resource_service
                    FROM rule_metadata
                    WHERE rule_id IN ({placeholders})
                    """,
                    rule_ids,
                )
                metadata = {}
                for row in cur.fetchall():
                    metadata[row["rule_id"]] = dict(row)
                return metadata
        except Exception as e:
            logger.warning(f"Failed to read rule metadata: {e}")
            return {}
        finally:
            if conn:
                conn.close()

    def count_rules_by_service(self, provider: str = "aws") -> Dict[str, int]:
        """Get count of rules per service"""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT service, COUNT(*) as count
                    FROM rule_checks
                    WHERE provider = %s AND (is_active IS NULL OR is_active = true)
                    GROUP BY service
                    ORDER BY count DESC
                    """,
                    (provider,),
                )
                return {row["service"]: row["count"] for row in cur.fetchall()}
        except Exception as e:
            logger.warning(f"Failed to count rules: {e}")
            return {}
        finally:
            if conn:
                conn.close()

    def check_connection(self, provider: str = "aws") -> bool:
        """Test database connection and report rules for the given provider"""
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM rule_checks WHERE provider = %s",
                    (provider,),
                )
                count = cur.fetchone()[0]
            conn.close()
            logger.info(f"RuleReader: Connected, {count} {provider} rules available")
            return True
        except Exception as e:
            logger.warning(f"RuleReader connection test failed: {e}")
            return False
