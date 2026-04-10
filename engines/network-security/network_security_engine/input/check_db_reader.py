"""
Network Security — Check DB Reader

Primary data path: loads pre-evaluated check_findings for network-related
rules, then classifies them into network security modules.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Services whose check_findings are network-relevant
NETWORK_SERVICES = {
    "ec2", "vpc", "elbv2", "elb", "wafv2", "waf",
    "cloudfront", "route53", "networkfirewall",
    "apigateway", "apigatewayv2", "vpcflowlogs",
    "directconnect",
}

# Resource types that are network-relevant
NETWORK_RESOURCE_TYPES = {
    "security_group", "vpc", "subnet", "route_table",
    "network_acl", "igw", "nat_gateway", "eip",
    "load_balancer", "listener", "target_group",
    "web_acl", "firewall", "flow_log",
    "hosted_zone", "health_check",
    "vpn_connection", "vpc_endpoint",
    "transit_gateway", "peering_connection",
}


def _get_check_conn():
    """Return a fresh psycopg2 connection to the check DB."""
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CHECK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CHECK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


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
        conn = _get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT
                        cf.finding_id,
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
                      AND (
                          rm.service = ANY(%s)
                          OR cf.resource_type = ANY(%s)
                      )
                """
                params: list = [
                    scan_run_id,
                    tenant_id,
                    list(NETWORK_SERVICES),
                    list(NETWORK_RESOURCE_TYPES),
                ]

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
        conn = _get_check_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT rule_id, title, description, remediation,
                           severity, service, category,
                           mitre_tactics, mitre_techniques,
                           compliance_frameworks, action_category,
                           is_active
                    FROM rule_metadata
                    WHERE service = ANY(%s)
                      AND is_active = TRUE
                """, [list(NETWORK_SERVICES)])
                return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def get_check_findings_summary(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> Dict[str, Any]:
        """Get summary counts of network check findings by severity/status."""
        conn = _get_check_conn()
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
                      AND (rm.service = ANY(%s) OR cf.resource_type = ANY(%s))
                """, [scan_run_id, tenant_id,
                      list(NETWORK_SERVICES), list(NETWORK_RESOURCE_TYPES)])
                row = cur.fetchone()
                return dict(row) if row else {}
        finally:
            conn.close()
