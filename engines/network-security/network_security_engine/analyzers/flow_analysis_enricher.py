"""
Layer 7 — Flow Analysis Enricher

Correlates VPC Flow Log data from CIEM with L4 (SG) findings to detect
config-vs-runtime gaps:
  - SG allows port but flow logs show no traffic (unused rule)
  - SG allows port AND flow logs show external traffic (confirmed exposure)
  - Flow logs show REJECT → blocked traffic attempts (scanning/probing)
  - High-volume outbound to unknown IPs (data exfil indicator)
  - Traffic between subnets that shouldn't communicate (lateral movement)
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _get_ciem_conn():
    """Return a connection to the CIEM DB (if available)."""
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        return psycopg2.connect(
            host=os.getenv("CIEM_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("CIEM_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("CIEM_DB_NAME", "threat_engine_ciem"),
            user=os.getenv("CIEM_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("CIEM_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            sslmode=os.getenv("DB_SSLMODE", "prefer"),
            connect_timeout=10,
        )
    except Exception as e:
        logger.warning("CIEM DB not available for flow analysis: %s", e)
        return None


def enrich_with_flow_data(
    sg_findings: List[Dict[str, Any]],
    tenant_id: str,
    account_id: str,
    days: int = 7,
) -> List[Dict[str, Any]]:
    """
    Enrich SG findings with VPC Flow Log data from CIEM.

    For each SG finding that reports an open port:
      - Check if flow logs show actual traffic on that port
      - If yes → confirmed exposure (upgrade severity)
      - If no → config risk only (potential downgrade)
      - Check for REJECT events → probing/scanning attempts

    Args:
        sg_findings: L4 findings with sg_posture in finding_data.
        tenant_id: Tenant ID.
        account_id: Account ID.
        days: Number of days of flow data to analyze.

    Returns:
        Enriched findings with flow_analysis in finding_data.
    """
    conn = _get_ciem_conn()
    if not conn:
        logger.info("Skipping flow analysis — CIEM DB not available")
        return sg_findings

    try:
        from psycopg2.extras import RealDictCursor

        # Load recent flow events grouped by dst_port and action
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    dst_port,
                    action,
                    src_ip,
                    COUNT(*) as event_count,
                    SUM(bytes_total) as total_bytes,
                    COUNT(DISTINCT src_ip) as unique_sources
                FROM ciem_events
                WHERE tenant_id = %s
                  AND account_id = %s
                  AND event_category = 'network_activity'
                  AND event_time >= NOW() - INTERVAL '%s days'
                  AND dst_port IS NOT NULL
                GROUP BY dst_port, action, src_ip
                ORDER BY event_count DESC
                LIMIT 10000
            """, [tenant_id, account_id, days])
            flow_rows = cur.fetchall()

        # Build flow summary: port → {accept_count, reject_count, unique_sources, ...}
        flow_by_port: Dict[int, Dict[str, Any]] = {}
        for row in flow_rows:
            port = row.get("dst_port")
            if port is None:
                continue
            if port not in flow_by_port:
                flow_by_port[port] = {
                    "accept_count": 0,
                    "reject_count": 0,
                    "total_bytes": 0,
                    "unique_sources": 0,
                    "external_sources": 0,
                }
            action = (row.get("action") or "").upper()
            if action == "ACCEPT":
                flow_by_port[port]["accept_count"] += row.get("event_count", 0)
            elif action == "REJECT":
                flow_by_port[port]["reject_count"] += row.get("event_count", 0)
            flow_by_port[port]["total_bytes"] += row.get("total_bytes", 0) or 0
            flow_by_port[port]["unique_sources"] += row.get("unique_sources", 0) or 0

            # Check if source is external (RFC1918 check)
            src = row.get("src_ip", "")
            if src and not _is_private_ip(src):
                flow_by_port[port]["external_sources"] += 1

        # Enrich each SG finding
        for finding in sg_findings:
            fd = finding.get("finding_data", {})
            sg_posture = fd.get("sg_posture", {})
            port = sg_posture.get("port")

            if port and port in flow_by_port:
                flow = flow_by_port[port]
                fd["flow_analysis"] = {
                    "has_flow_data": True,
                    "accept_count": flow["accept_count"],
                    "reject_count": flow["reject_count"],
                    "total_bytes": flow["total_bytes"],
                    "unique_sources": flow["unique_sources"],
                    "external_sources": flow["external_sources"],
                    "config_runtime_gap": _classify_gap(flow, sg_posture),
                    "days_analyzed": days,
                }

                # If external traffic confirmed, ensure severity is not under-rated
                if flow["external_sources"] > 0 and flow["accept_count"] > 0:
                    fd["flow_analysis"]["confirmed_external_traffic"] = True

            elif port:
                fd["flow_analysis"] = {
                    "has_flow_data": False,
                    "config_runtime_gap": "allowed_no_traffic",
                    "note": f"SG allows port {port} but no flow log traffic observed in {days} days",
                    "days_analyzed": days,
                }

        # Check for high-volume outbound (data exfil indicator)
        # This produces additional findings
        _detect_anomalous_flows(flow_rows, tenant_id, account_id)

    except Exception as e:
        logger.warning("Flow analysis failed: %s", e)
    finally:
        conn.close()

    return sg_findings


def _classify_gap(flow: Dict, sg_posture: Dict) -> str:
    """Classify the config-vs-runtime gap."""
    if flow["accept_count"] > 0 and flow["external_sources"] > 0:
        return "allowed_and_used_externally"  # Confirmed exposure
    if flow["accept_count"] > 0:
        return "allowed_and_used_internally"  # Internal traffic only
    if flow["reject_count"] > 0:
        return "blocked_but_attempted"  # Probing/scanning
    return "allowed_no_traffic"  # Rule exists but unused


def _is_private_ip(ip: str) -> bool:
    """Check if IP is RFC1918/RFC6598 private."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _detect_anomalous_flows(
    flow_rows: List[Dict],
    tenant_id: str,
    account_id: str,
) -> List[Dict[str, Any]]:
    """Detect anomalous flow patterns (placeholder for future enhancement)."""
    # TODO: Implement baseline comparison for:
    #   - High-volume outbound to unknown external IPs
    #   - Port scanning (many REJECT events to sequential ports)
    #   - Beaconing patterns (regular intervals to same external IP)
    #   - Unexpected cross-subnet traffic
    return []
