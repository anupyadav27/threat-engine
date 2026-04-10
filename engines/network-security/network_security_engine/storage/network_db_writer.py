"""
Network Security — Database Writer

Writes network_report, network_findings, network_topology_snapshot,
network_sg_analysis, and network_exposure_paths to the network DB.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import execute_values

logger = logging.getLogger(__name__)


def _get_network_conn():
    """Return a fresh psycopg2 connection to the network DB."""
    return psycopg2.connect(
        host=os.getenv("NETWORK_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("NETWORK_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("NETWORK_DB_NAME", "threat_engine_network"),
        user=os.getenv("NETWORK_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("NETWORK_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


def _ensure_tenant(conn, tenant_id: str) -> None:
    """Upsert tenant row (FK requirement)."""
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO tenants (tenant_id, tenant_name)
               VALUES (%s, %s)
               ON CONFLICT (tenant_id) DO NOTHING""",
            (tenant_id, tenant_id),
        )
    conn.commit()


def save_network_report(report: Dict[str, Any]) -> None:
    """Upsert network_report row."""
    conn = _get_network_conn()
    try:
        _ensure_tenant(conn, report["tenant_id"])
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO network_report (
                    scan_run_id, tenant_id, account_id, provider, status,
                    posture_score, topology_score, reachability_score,
                    nacl_score, firewall_score, lb_score, waf_score, monitoring_score,
                    total_findings, critical_findings, high_findings, medium_findings, low_findings,
                    total_vpcs, total_subnets, total_security_groups, total_nacls,
                    total_route_tables, total_load_balancers, total_waf_acls,
                    total_nat_gateways, total_igws, total_tgws,
                    total_vpc_endpoints, total_eips, total_network_firewalls,
                    internet_exposed_resources, cross_vpc_paths_count, orphaned_sg_count,
                    findings_by_module, findings_by_status, findings_by_layer,
                    severity_breakdown, exposure_summary, report_data,
                    started_at, completed_at, scan_duration_ms, generated_at
                ) VALUES (
                    %(scan_run_id)s, %(tenant_id)s, %(account_id)s, %(provider)s, %(status)s,
                    %(posture_score)s, %(topology_score)s, %(reachability_score)s,
                    %(nacl_score)s, %(firewall_score)s, %(lb_score)s, %(waf_score)s, %(monitoring_score)s,
                    %(total_findings)s, %(critical_findings)s, %(high_findings)s,
                    %(medium_findings)s, %(low_findings)s,
                    %(total_vpcs)s, %(total_subnets)s, %(total_security_groups)s, %(total_nacls)s,
                    %(total_route_tables)s, %(total_load_balancers)s, %(total_waf_acls)s,
                    %(total_nat_gateways)s, %(total_igws)s, %(total_tgws)s,
                    %(total_vpc_endpoints)s, %(total_eips)s, %(total_network_firewalls)s,
                    %(internet_exposed_resources)s, %(cross_vpc_paths_count)s, %(orphaned_sg_count)s,
                    %(findings_by_module)s, %(findings_by_status)s, %(findings_by_layer)s,
                    %(severity_breakdown)s, %(exposure_summary)s, %(report_data)s,
                    %(started_at)s, %(completed_at)s, %(scan_duration_ms)s, NOW()
                )
                ON CONFLICT (scan_run_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    posture_score = EXCLUDED.posture_score,
                    total_findings = EXCLUDED.total_findings,
                    critical_findings = EXCLUDED.critical_findings,
                    high_findings = EXCLUDED.high_findings,
                    medium_findings = EXCLUDED.medium_findings,
                    low_findings = EXCLUDED.low_findings,
                    findings_by_module = EXCLUDED.findings_by_module,
                    findings_by_status = EXCLUDED.findings_by_status,
                    findings_by_layer = EXCLUDED.findings_by_layer,
                    severity_breakdown = EXCLUDED.severity_breakdown,
                    exposure_summary = EXCLUDED.exposure_summary,
                    report_data = EXCLUDED.report_data,
                    completed_at = EXCLUDED.completed_at,
                    scan_duration_ms = EXCLUDED.scan_duration_ms
            """, {
                **report,
                "findings_by_module": json.dumps(report.get("findings_by_module", {})),
                "findings_by_status": json.dumps(report.get("findings_by_status", {})),
                "findings_by_layer": json.dumps(report.get("findings_by_layer", {})),
                "severity_breakdown": json.dumps(report.get("severity_breakdown", {})),
                "exposure_summary": json.dumps(report.get("exposure_summary", {})),
                "report_data": json.dumps(report.get("report_data", {})),
            })
        conn.commit()
        logger.info("Saved network_report for scan %s", report["scan_run_id"])
    finally:
        conn.close()


def save_network_findings(findings: List[Dict[str, Any]]) -> int:
    """Bulk insert network findings. Returns count saved."""
    if not findings:
        return 0

    conn = _get_network_conn()
    try:
        with conn.cursor() as cur:
            sql = """
                INSERT INTO network_findings (
                    finding_id, scan_run_id, tenant_id, account_id,
                    credential_ref, credential_type, provider, region,
                    resource_uid, resource_type,
                    network_layer, network_modules, effective_exposure,
                    severity, status, rule_id, title, description, remediation,
                    finding_data, first_seen_at, last_seen_at
                ) VALUES %s
                ON CONFLICT (finding_id) DO UPDATE SET
                    last_seen_at = NOW(),
                    severity = EXCLUDED.severity,
                    status = EXCLUDED.status,
                    finding_data = EXCLUDED.finding_data
            """
            now = datetime.now(timezone.utc)
            values = []
            for f in findings:
                values.append((
                    f["finding_id"], f["scan_run_id"], f["tenant_id"],
                    f.get("account_id", ""),
                    f.get("credential_ref", ""), f.get("credential_type", ""),
                    f.get("provider", "aws"), f.get("region", ""),
                    f["resource_uid"], f["resource_type"],
                    f.get("network_layer", ""), f.get("network_modules", []),
                    f.get("effective_exposure", ""),
                    f["severity"], f.get("status", "FAIL"),
                    f.get("rule_id", ""), f.get("title", ""),
                    f.get("description", ""), f.get("remediation", ""),
                    json.dumps(f.get("finding_data", {})),
                    now, now,
                ))

            execute_values(cur, sql, values, page_size=500)
        conn.commit()
        logger.info("Saved %d network findings", len(findings))
        return len(findings)
    finally:
        conn.close()


def save_topology_snapshots(snapshots: List[Dict[str, Any]]) -> None:
    """Save VPC topology snapshots."""
    if not snapshots:
        return

    conn = _get_network_conn()
    try:
        with conn.cursor() as cur:
            for snap in snapshots:
                cur.execute("""
                    INSERT INTO network_topology_snapshot (
                        scan_run_id, tenant_id, account_id, provider, region,
                        vpc_id, vpc_cidr_blocks, is_default_vpc, flow_log_enabled,
                        subnets, route_tables, peering_connections, tgw_attachments,
                        igw_id, nat_gateways, vpc_endpoints, network_firewalls,
                        isolation_score, public_subnet_count, private_subnet_count,
                        has_internet_path
                    ) VALUES (
                        %(scan_run_id)s, %(tenant_id)s, %(account_id)s, %(provider)s, %(region)s,
                        %(vpc_id)s, %(vpc_cidr_blocks)s, %(is_default_vpc)s, %(flow_log_enabled)s,
                        %(subnets)s, %(route_tables)s, %(peering_connections)s, %(tgw_attachments)s,
                        %(igw_id)s, %(nat_gateways)s, %(vpc_endpoints)s, %(network_firewalls)s,
                        %(isolation_score)s, %(public_subnet_count)s, %(private_subnet_count)s,
                        %(has_internet_path)s
                    )
                    ON CONFLICT (scan_run_id, vpc_id) DO UPDATE SET
                        subnets = EXCLUDED.subnets,
                        route_tables = EXCLUDED.route_tables,
                        flow_log_enabled = EXCLUDED.flow_log_enabled,
                        isolation_score = EXCLUDED.isolation_score,
                        public_subnet_count = EXCLUDED.public_subnet_count,
                        private_subnet_count = EXCLUDED.private_subnet_count
                """, {
                    **snap,
                    "subnets": json.dumps(snap.get("subnets", [])),
                    "route_tables": json.dumps(snap.get("route_tables", [])),
                    "peering_connections": json.dumps(snap.get("peering_connections", [])),
                    "tgw_attachments": json.dumps(snap.get("tgw_attachments", [])),
                    "nat_gateways": json.dumps(snap.get("nat_gateways", [])),
                    "vpc_endpoints": json.dumps(snap.get("vpc_endpoints", [])),
                    "network_firewalls": json.dumps(snap.get("network_firewalls", [])),
                })
        conn.commit()
        logger.info("Saved %d topology snapshots", len(snapshots))
    finally:
        conn.close()


def save_exposure_paths(paths: List[Dict[str, Any]]) -> None:
    """Save computed exposure paths for threat engine."""
    if not paths:
        return

    conn = _get_network_conn()
    try:
        with conn.cursor() as cur:
            for path in paths:
                cur.execute("""
                    INSERT INTO network_exposure_paths (
                        scan_run_id, tenant_id, account_id, provider, region,
                        path_type, source_type, source_id,
                        target_resource_uid, target_resource_type,
                        path_hops, exposed_ports, exposed_sensitive_ports,
                        severity, blocked_by, is_fully_exposed,
                        attack_path_category, blast_radius, mitre_techniques
                    ) VALUES (
                        %(scan_run_id)s, %(tenant_id)s, %(account_id)s, %(provider)s, %(region)s,
                        %(path_type)s, %(source_type)s, %(source_id)s,
                        %(target_resource_uid)s, %(target_resource_type)s,
                        %(path_hops)s, %(exposed_ports)s, %(exposed_sensitive_ports)s,
                        %(severity)s, %(blocked_by)s, %(is_fully_exposed)s,
                        %(attack_path_category)s, %(blast_radius)s, %(mitre_techniques)s
                    )
                """, {
                    **path,
                    "path_hops": json.dumps(path.get("path_hops", [])),
                    "exposed_ports": json.dumps(path.get("exposed_ports", [])),
                    "exposed_sensitive_ports": json.dumps(path.get("exposed_sensitive_ports", [])),
                })
        conn.commit()
        logger.info("Saved %d exposure paths", len(paths))
    finally:
        conn.close()


def update_report_status(
    scan_run_id: str,
    status: str,
    error_message: Optional[str] = None,
) -> None:
    """Update the status of an existing network_report row."""
    conn = _get_network_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE network_report
                SET status = %s,
                    error_message = %s,
                    completed_at = CASE WHEN %s IN ('completed', 'failed')
                                        THEN NOW() ELSE completed_at END
                WHERE scan_run_id = %s
            """, (status, error_message, status, scan_run_id))
        conn.commit()
    finally:
        conn.close()


def cleanup_old_scans(tenant_id: str, keep: int = 3) -> int:
    """Delete old network scan data, keeping the most recent N scans."""
    conn = _get_network_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT scan_run_id FROM network_report
                WHERE tenant_id = %s
                ORDER BY generated_at DESC
                OFFSET %s
            """, (tenant_id, keep))
            old_ids = [r[0] for r in cur.fetchall()]

            if not old_ids:
                return 0

            for table in ("network_findings", "network_topology_snapshot",
                          "network_sg_analysis", "network_exposure_paths"):
                cur.execute(
                    f"DELETE FROM {table} WHERE scan_run_id = ANY(%s)",
                    (old_ids,),
                )
            cur.execute(
                "DELETE FROM network_report WHERE scan_run_id = ANY(%s)",
                (old_ids,),
            )
        conn.commit()
        logger.info("Cleaned up %d old scans for tenant %s", len(old_ids), tenant_id)
        return len(old_ids)
    finally:
        conn.close()
