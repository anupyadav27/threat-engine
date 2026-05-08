"""
Network Security — Check DB Reader

Primary data path: loads pre-evaluated check_findings for network-related
rules, then classifies them into network security modules.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor

from engine_common.db_connections import get_check_conn

logger = logging.getLogger(__name__)

# Service/resource-type lists removed — the network_security JSONB scope column
# in rule_metadata is the source of truth (set by migration 023).


class NetworkCheckReader:
    """Read network-related check findings."""

    def load_network_check_findings(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Load check_findings for network-related services.

        Returns:
            List of check finding dicts with rule_id, resource_uid, status,
            severity, finding_data, etc.
        """
        conn = get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT
                        cf.scan_run_id,
                        cf.tenant_id,
                        cf.account_id,
                        cf.provider,
                        cf.region,
                        cf.resource_uid,
                        cf.resource_type,
                        cf.severity,
                        cf.status,
                        cf.rule_id,
                        cf.credential_ref,
                        cf.credential_type,
                        cf.finding_data,
                        cf.first_seen_at,
                        cf.last_seen_at,
                        rm.title,
                        rm.description,
                        rm.remediation,
                        rm.service,
                        rm.mitre_tactics,
                        rm.mitre_techniques,
                        rm.action_category
                    FROM check_findings cf
                    LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                    WHERE cf.scan_run_id = %s
                      AND cf.tenant_id = %s
                      AND (rm.network_security ->> 'applicable')::boolean = true
                """
                params: list = [scan_run_id, tenant_id]

                if account_id:
                    query += " AND cf.account_id = %s"
                    params.append(account_id)

                cur.execute(query, params)
                rows = cur.fetchall()

            logger.info(
                "Loaded %d network check findings for scan %s",
                len(rows), scan_run_id,
            )
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def load_network_rules(self) -> List[Dict[str, Any]]:
        """Load rule_metadata for network-related services."""
        conn = get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT rule_id, title, description, remediation,
                           severity, service, category,
                           mitre_tactics, mitre_techniques,
                           compliance_frameworks, action_category,
                           is_active
                    FROM rule_metadata
                    WHERE (network_security ->> 'applicable')::boolean = true
                      AND is_active = TRUE
                """)
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def get_check_findings_summary(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, Any]:
        """Get summary counts of network check findings by severity/status."""
        conn = get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        COUNT(*) as total,
                        COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                        COUNT(*) FILTER (WHERE severity = 'high') as high,
                        COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                        COUNT(*) FILTER (WHERE severity = 'low') as low,
                        COUNT(*) FILTER (WHERE status = 'FAIL') as fail,
                        COUNT(*) FILTER (WHERE status = 'PASS') as pass_count
                    FROM check_findings cf
                    LEFT JOIN rule_metadata rm ON cf.rule_id = rm.rule_id
                    WHERE cf.scan_run_id = %s
                      AND cf.tenant_id = %s
                      AND (rm.network_security ->> 'applicable')::boolean = true
                """, [scan_run_id, tenant_id])
                row = cur.fetchone()
                return dict(row) if row else {}
        finally:
            conn.close()
