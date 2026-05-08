"""
IAM Rule DB Reader

Reads IAM-relevant rules from rule_metadata table.
Filter: (iam_security ->> 'applicable')::boolean = true

This replaces the old YAML-file-based reader. rule_metadata is populated by:
  catalog/rule/upload_rule_metadata_all_csps.py
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from psycopg2.extras import RealDictCursor

from engine_common.db_connections import get_check_conn

logger = logging.getLogger(__name__)


class RuleDBReader:
    """Reads IAM-relevant rules from rule_metadata (DB-based)."""

    def get_iam_security_info(self, service: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Return iam_security JSONB for a rule if applicable=true, else None.
        Used by enrichers that check rule-by-rule.
        """
        conn = get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT iam_security
                    FROM   rule_metadata
                    WHERE  rule_id = %s
                      AND  (iam_security ->> 'applicable')::boolean = true
                    LIMIT 1
                    """,
                    (rule_id,),
                )
                row = cur.fetchone()
            return dict(row["iam_security"]) if row else None
        finally:
            conn.close()

    def is_iam_relevant(self, service: str, rule_id: str) -> bool:
        """True if rule_id has iam_security.applicable=true in rule_metadata."""
        return self.get_iam_security_info(service, rule_id) is not None

    def get_all_iam_security_rules(self, service: str) -> Dict[str, Dict[str, Any]]:
        """Return {rule_id: iam_security} for a service where applicable=true."""
        conn = get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT rule_id, iam_security
                    FROM   rule_metadata
                    WHERE  service = %s
                      AND  (iam_security ->> 'applicable')::boolean = true
                    """,
                    (service,),
                )
                rows = cur.fetchall()
            return {r["rule_id"]: dict(r["iam_security"]) for r in rows}
        finally:
            conn.close()

    def get_all_iam_security_rule_ids(
        self,
        services: Optional[List[str]] = None,
        provider: Optional[str] = None,
    ) -> Set[str]:
        """
        Set of all IAM-relevant rule IDs.
        Optionally filter by service list and/or provider.
        """
        conn = get_check_conn()
        try:
            with conn.cursor() as cur:
                sql = """
                    SELECT rule_id
                    FROM   rule_metadata
                    WHERE  (iam_security ->> 'applicable')::boolean = true
                """
                params: list = []
                if services:
                    sql += " AND service = ANY(%s)"
                    params.append(services)
                if provider:
                    sql += " AND provider = %s"
                    params.append(provider)
                cur.execute(sql, params)
                rows = cur.fetchall()
            rule_ids = {r[0] for r in rows}
            logger.info("Found %d IAM-relevant rule IDs from rule_metadata", len(rule_ids))
            return rule_ids
        finally:
            conn.close()

    def list_services(self, provider: Optional[str] = None) -> List[str]:
        """List services that have IAM-relevant rules."""
        conn = get_check_conn()
        try:
            with conn.cursor() as cur:
                if provider:
                    cur.execute(
                        """
                        SELECT DISTINCT service FROM rule_metadata
                        WHERE  (iam_security ->> 'applicable')::boolean = true
                          AND  provider = %s
                        ORDER  BY service
                        """,
                        (provider,),
                    )
                else:
                    cur.execute(
                        """
                        SELECT DISTINCT service FROM rule_metadata
                        WHERE  (iam_security ->> 'applicable')::boolean = true
                        ORDER  BY service
                        """
                    )
                return [r[0] for r in cur.fetchall()]
        finally:
            conn.close()
