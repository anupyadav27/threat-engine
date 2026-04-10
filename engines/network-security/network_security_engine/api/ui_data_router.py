"""
Network Security — UI Data Router

Provides the unified /api/v1/network-security/ui-data endpoint
for frontend consumption.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_network_conn():
    return psycopg2.connect(
        host=os.getenv("NETWORK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("NETWORK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("NETWORK_DB_NAME", "threat_engine_network"),
        user=os.getenv("NETWORK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("NETWORK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _query_scan_trend(cur, tenant_id: str) -> list:
    """Return last 8 completed network scan summaries for trend charts (oldest-first)."""
    try:
        cur.execute(
            """
            SELECT
                to_char(generated_at, 'Mon DD')            AS date,
                COALESCE(total_findings, 0)                AS total,
                COALESCE(critical_findings, 0)             AS critical,
                COALESCE(high_findings, 0)                 AS high,
                COALESCE(medium_findings, 0)               AS medium,
                COALESCE(low_findings, 0)                  AS low,
                COALESCE(posture_score, 0)                 AS pass_rate,
                COALESCE(internet_exposed_resources, 0)    AS exposed_resources,
                COALESCE(waf_score, 0)                     AS waf_coverage
            FROM network_report
            WHERE tenant_id = %s AND status = 'completed'
            ORDER BY generated_at DESC
            LIMIT 8
            """,
            (tenant_id,),
        )
        return [dict(r) for r in reversed(cur.fetchall())]
    except Exception:
        logger.warning("network scan_trend query failed", exc_info=True)
        return []


def _resolve_scan_id(tenant_id: str, scan_id: str) -> Optional[str]:
    """Resolve 'latest' to actual scan_run_id."""
    if scan_id != "latest":
        return scan_id
    conn = _get_network_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT scan_run_id FROM network_report
                WHERE tenant_id = %s AND status = 'completed'
                ORDER BY generated_at DESC LIMIT 1
            """, (tenant_id,))
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        conn.close()


@router.get("/api/v1/network-security/ui-data")
async def get_ui_data(
    tenant_id: str = Query(...),
    scan_id: str = Query("latest"),
    limit: int = Query(10000),
) -> Dict[str, Any]:
    """
    Unified UI data endpoint for network security.

    Returns summary, per-layer scores, module breakdown, topology,
    and paginated findings.
    """
    resolved_id = _resolve_scan_id(tenant_id, scan_id)
    if not resolved_id:
        return {
            "summary": {},
            "modules": [],
            "layers": [],
            "findings": [],
            "topology": [],
            "total_findings": 0,
            "scan_id": None,
        }

    conn = _get_network_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Report summary
            cur.execute(
                "SELECT * FROM network_report WHERE scan_run_id = %s",
                (resolved_id,),
            )
            report = cur.fetchone()

            # Findings
            cur.execute("""
                SELECT finding_id, rule_id, title, description, severity, status,
                       network_layer, network_modules, effective_exposure,
                       resource_uid, resource_type, region, remediation, finding_data
                FROM network_findings
                WHERE scan_run_id = %s AND tenant_id = %s
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    status DESC
                LIMIT %s
            """, (resolved_id, tenant_id, limit))
            raw_findings = cur.fetchall()
            findings = []
            for f in raw_findings:
                row = dict(f)
                fd = row.get("finding_data") or {}
                if not isinstance(fd, dict):
                    fd = {}
                row["finding_data"] = fd
                # Unpack rule metadata from finding_data (compliance, MITRE, risk)
                row.setdefault("compliance_frameworks", fd.get("compliance_frameworks") or [])
                row.setdefault("mitre_tactics",         fd.get("mitre_tactics") or [])
                row.setdefault("mitre_techniques",      fd.get("mitre_techniques") or [])
                row.setdefault("risk_score",            fd.get("risk_score"))
                row.setdefault("posture_category",      fd.get("posture_category") or "")
                row.setdefault("checked_fields",        fd.get("checked_fields"))
                row.setdefault("actual_values",         fd.get("actual_values"))
                row.setdefault("source",                fd.get("source", "check"))
                findings.append(row)

            # Topology snapshots
            cur.execute("""
                SELECT vpc_id, vpc_cidr_blocks, is_default_vpc, flow_log_enabled,
                       igw_id, isolation_score, public_subnet_count,
                       private_subnet_count, has_internet_path,
                       subnets, nat_gateways, peering_connections, tgw_attachments
                FROM network_topology_snapshot
                WHERE scan_run_id = %s AND tenant_id = %s
            """, (resolved_id, tenant_id))
            topology = [dict(r) for r in cur.fetchall()]

            # Scan trend (last 8 scans, oldest-first)
            scan_trend = _query_scan_trend(cur, tenant_id)

        summary = {}
        if report:
            report = dict(report)
            summary = {
                "total_findings": report.get("total_findings", 0),
                "critical_findings": report.get("critical_findings", 0),
                "high_findings": report.get("high_findings", 0),
                "medium_findings": report.get("medium_findings", 0),
                "low_findings": report.get("low_findings", 0),
                "posture_score": report.get("posture_score", 0),
                "by_severity": report.get("severity_breakdown", {}),
                "by_module": report.get("findings_by_module", {}),
                "by_layer": report.get("findings_by_layer", {}),
                "by_status": report.get("findings_by_status", {}),
                "exposure_summary": report.get("exposure_summary", {}),
                "layer_scores": {
                    "topology": report.get("topology_score", 0),
                    "reachability": report.get("reachability_score", 0),
                    "nacl": report.get("nacl_score", 0),
                    "firewall": report.get("firewall_score", 0),
                    "load_balancer": report.get("lb_score", 0),
                    "waf": report.get("waf_score", 0),
                    "monitoring": report.get("monitoring_score", 0),
                },
                "inventory": {
                    "vpcs": report.get("total_vpcs", 0),
                    "subnets": report.get("total_subnets", 0),
                    "security_groups": report.get("total_security_groups", 0),
                    "nacls": report.get("total_nacls", 0),
                    "route_tables": report.get("total_route_tables", 0),
                    "load_balancers": report.get("total_load_balancers", 0),
                    "waf_acls": report.get("total_waf_acls", 0),
                    "nat_gateways": report.get("total_nat_gateways", 0),
                    "igws": report.get("total_igws", 0),
                    "tgws": report.get("total_tgws", 0),
                    "eips": report.get("total_eips", 0),
                },
                "internet_exposed_resources": report.get("internet_exposed_resources", 0),
                "cross_vpc_paths_count": report.get("cross_vpc_paths_count", 0),
                "orphaned_sg_count": report.get("orphaned_sg_count", 0),
            }

        return {
            "summary": summary,
            "modules": [
                "network_isolation", "network_reachability", "network_acl",
                "security_group_rules", "load_balancer_security",
                "waf_protection", "internet_exposure", "network_monitoring",
            ],
            "layers": [
                {"id": "L1_topology", "name": "Network Topology", "score": summary.get("layer_scores", {}).get("topology", 0)},
                {"id": "L2_reachability", "name": "Network Reachability", "score": summary.get("layer_scores", {}).get("reachability", 0)},
                {"id": "L3_nacl", "name": "Network ACL", "score": summary.get("layer_scores", {}).get("nacl", 0)},
                {"id": "L4_sg", "name": "Security Groups", "score": summary.get("layer_scores", {}).get("firewall", 0)},
                {"id": "L5_lb", "name": "Load Balancers", "score": summary.get("layer_scores", {}).get("load_balancer", 0)},
                {"id": "L6_waf", "name": "WAF Protection", "score": summary.get("layer_scores", {}).get("waf", 0)},
                {"id": "L7_flow", "name": "Flow Monitoring", "score": summary.get("layer_scores", {}).get("monitoring", 0)},
            ],
            "findings": findings,
            "topology": topology,
            "total_findings": len(findings),
            "scan_id": resolved_id,
            "scan_trend": scan_trend,
        }

    finally:
        conn.close()
