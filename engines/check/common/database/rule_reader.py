"""
Rule Reader — reads check rules from rule_checks table (check DB).

Used by the common orchestration layer. No CSP-specific logic.
All config from CHECK_DB_* env vars.
"""

import os
import json
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class RuleReader:
    """Reads check rule definitions from the rule_checks table."""

    def __init__(self, db_config: Optional[Dict] = None):
        self.db_config: Dict[str, Any] = db_config or {
            "host":     os.getenv("CHECK_DB_HOST",     os.getenv("DB_HOST",     "localhost")),
            "port":     int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT",     "5432"))),
            "database": os.getenv("CHECK_DB_NAME",     "threat_engine_check"),
            "user":     os.getenv("CHECK_DB_USER",     os.getenv("SHARED_DB_USER", "postgres")),
            "password": os.getenv("CHECK_DB_PASSWORD", os.getenv("SHARED_DB_PASSWORD", "")),
        }

    def _get_connection(self):
        return psycopg2.connect(
            host=self.db_config["host"],
            port=self.db_config["port"],
            database=self.db_config["database"],
            user=self.db_config["user"],
            password=self.db_config["password"],
            connect_timeout=10,
        )

    def check_connection(self, provider: str = "aws") -> bool:
        """Return True if DB is reachable and rules exist for the provider."""
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM rule_checks WHERE provider = %s",
                    (provider,),
                )
                count = cur.fetchone()[0]
            conn.close()
            logger.info("RuleReader: connected — %d %s rules available", count, provider)
            return True
        except Exception as exc:
            logger.warning("RuleReader connection test failed: %s", exc)
            return False

    def read_checks_for_service(self, service: str, provider: str = "aws") -> List[Dict]:
        """
        Return check rule dicts for a service from rule_checks.

        Each dict has the same shape as a YAML check:
            {"rule_id": "...", "for_each": "...", "conditions": {...}}
        """
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT rule_id, check_config
                    FROM   rule_checks
                    WHERE  service  = %s
                      AND  provider = %s
                      AND  (is_active IS NULL OR is_active = true)
                    ORDER BY rule_id
                    """,
                    (service, provider),
                )
                checks: List[Dict] = []
                for row in cur.fetchall():
                    cfg = row["check_config"]
                    if isinstance(cfg, str):
                        cfg = json.loads(cfg)
                    if cfg:
                        checks.append({"rule_id": row["rule_id"], **cfg})
                logger.debug(
                    "Loaded %d checks for %s.%s from rule_checks", len(checks), provider, service
                )
                return checks
        except Exception as exc:
            logger.warning("Failed to read checks for %s: %s", service, exc)
            return []
        finally:
            if conn:
                conn.close()

    def get_services_for_provider(self, provider: str = "aws") -> List[str]:
        """Return sorted list of services that have active rules for a provider."""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT DISTINCT service
                    FROM   rule_checks
                    WHERE  provider = %s
                      AND  (is_active IS NULL OR is_active = true)
                    ORDER BY service
                    """,
                    (provider,),
                )
                return [row[0] for row in cur.fetchall()]
        except Exception as exc:
            logger.warning("Failed to get services for %s: %s", provider, exc)
            return []
        finally:
            if conn:
                conn.close()

    def read_metadata_for_rules(self, rule_ids: List[str]) -> Dict[str, Dict]:
        """Return rule_metadata rows keyed by rule_id."""
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
                           threat_category, threat_tags, risk_score,
                           mitre_tactics, mitre_techniques, resource_service
                    FROM   rule_metadata
                    WHERE  rule_id IN ({placeholders})
                    """,
                    rule_ids,
                )
                return {row["rule_id"]: dict(row) for row in cur.fetchall()}
        except Exception as exc:
            logger.warning("Failed to read rule metadata: %s", exc)
            return {}
        finally:
            if conn:
                conn.close()

    def read_checks_for_service_tenant(
        self,
        service: str,
        provider: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> List[Dict]:
        """Return check rule dicts for a service, filtered by tenant suppressions.

        Identical shape to read_checks_for_service() but excludes rules that are
        suppressed at the tenant-wide level (account_id IS NULL) or at the
        specific account level (account_id = $4), and ignores expired suppressions.

        Args:
            service: Cloud service name (e.g. "s3", "iam").
            provider: CSP identifier (e.g. "aws", "azure").
            tenant_id: Tenant scope for suppression lookup.
            account_id: Account scope; if None only tenant-wide suppressions apply.

        Returns:
            List of active, non-suppressed check rule dicts.
        """
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT rc.rule_id, rc.check_config
                    FROM   rule_checks rc
                    WHERE  rc.service  = %s
                      AND  rc.provider = %s
                      AND  (rc.is_active IS NULL OR rc.is_active = true)
                      AND  NOT EXISTS (
                               SELECT 1
                               FROM   rule_suppressions rs
                               WHERE  rs.tenant_id = %s
                                 AND  (rs.account_id IS NULL OR rs.account_id = %s)
                                 AND  (rs.expires_at IS NULL OR rs.expires_at > now())
                                 AND  (
                                          (rs.scope_type = 'rule'       AND rs.scope_value = rc.rule_id)
                                       OR (rs.scope_type = 'service'    AND rs.scope_value = rc.service)
                                       OR (rs.scope_type = 'provider'   AND rs.scope_value = rc.provider)
                                       OR (rs.scope_type = 'technology' AND rs.scope_value = rc.service)
                                      )
                           )
                    ORDER BY rc.rule_id
                    """,
                    (service, provider, tenant_id, account_id),
                )
                checks: List[Dict] = []
                for row in cur.fetchall():
                    cfg = row["check_config"]
                    if isinstance(cfg, str):
                        cfg = json.loads(cfg)
                    if cfg:
                        checks.append({"rule_id": row["rule_id"], **cfg})
                logger.debug(
                    "Loaded %d checks for %s.%s (tenant=%s, account=%s) after suppression filter",
                    len(checks), provider, service, tenant_id, account_id,
                )
                return checks
        except Exception as exc:
            logger.warning("Failed to read suppressed checks for %s: %s", service, exc)
            return self.read_checks_for_service(service, provider)
        finally:
            if conn:
                conn.close()

    def count_rules_by_service(self, provider: str = "aws") -> Dict[str, int]:
        """Return {service: rule_count} for a provider."""
        conn = None
        try:
            conn = self._get_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT service, COUNT(*) AS cnt
                    FROM   rule_checks
                    WHERE  provider = %s AND (is_active IS NULL OR is_active = true)
                    GROUP  BY service
                    ORDER  BY cnt DESC
                    """,
                    (provider,),
                )
                return {row["service"]: row["cnt"] for row in cur.fetchall()}
        except Exception as exc:
            logger.warning("Failed to count rules: %s", exc)
            return {}
        finally:
            if conn:
                conn.close()
