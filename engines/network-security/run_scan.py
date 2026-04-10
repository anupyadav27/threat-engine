"""
Network Security Engine — K8s Job Entry Point

Pipeline position: Layer 3 (parallel with compliance/iam/datasec, after threat)
Receives scan_run_id, loads discovery data, runs 7-layer analysis, saves findings.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

# ── Setup path ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "shared"))

from network_security_engine.input.discovery_db_reader import NetworkDiscoveryReader
from network_security_engine.input.inventory_reader import NetworkInventoryReader
from network_security_engine.analyzers.network_topology_analyzer import (
    build_topology, analyze_topology,
)
from network_security_engine.analyzers.network_reachability_analyzer import analyze_reachability
from network_security_engine.analyzers.nacl_analyzer import analyze_nacls
from network_security_engine.analyzers.security_group_analyzer import analyze_security_groups
from network_security_engine.analyzers.load_balancer_analyzer import (
    build_load_balancers, analyze_load_balancers,
)
from network_security_engine.analyzers.waf_analyzer import build_waf_acls, analyze_waf
from network_security_engine.analyzers.flow_analysis_enricher import enrich_with_flow_data
from network_security_engine.enricher.finding_enricher import (
    enrich_findings, compute_blast_radius,
)
from network_security_engine.storage.network_db_writer import (
    save_network_report, save_network_findings,
    save_topology_snapshots, update_report_status,
    cleanup_old_scans, _get_network_conn, _ensure_tenant,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("network_security.run_scan")


def get_orchestration_metadata(scan_run_id: str) -> Dict[str, Any]:
    """Read scan metadata from scan_orchestration table."""
    import psycopg2
    from psycopg2.extras import RealDictCursor

    conn = psycopg2.connect(
        host=os.getenv("ONBOARDING_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ONBOARDING_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
        user=os.getenv("ONBOARDING_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ONBOARDING_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM scan_orchestration WHERE scan_run_id = %s",
                (scan_run_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else {}
    finally:
        conn.close()


def run_network_scan(scan_run_id: str) -> Dict[str, Any]:
    """Execute the full 7-layer network security analysis."""
    start_time = time.time()
    logger.info("=== Network Security Scan START: %s ===", scan_run_id)

    # ── 1. Get orchestration metadata ─────────────────────────────────────
    metadata = get_orchestration_metadata(scan_run_id)
    tenant_id = metadata.get("tenant_id", os.getenv("TENANT_ID", "default-tenant"))
    account_id = metadata.get("account_id", os.getenv("ACCOUNT_ID", ""))
    provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
    credential_ref = metadata.get("credential_ref", "")
    credential_type = metadata.get("credential_type", "")

    logger.info("Tenant: %s, Account: %s, Provider: %s", tenant_id, account_id, provider)

    # ── 2. Pre-create report (status=running) ─────────────────────────────
    conn = _get_network_conn()
    try:
        _ensure_tenant(conn, tenant_id)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO network_report (scan_run_id, tenant_id, account_id, provider, status, started_at)
                VALUES (%s, %s, %s, %s, 'running', NOW())
                ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running', started_at = NOW()
            """, (scan_run_id, tenant_id, account_id, provider))
        conn.commit()
    finally:
        conn.close()

    try:
        # ── 3. Load discovery data ────────────────────────────────────────
        reader = NetworkDiscoveryReader()
        discovery_data = reader.load_all_network_resources(scan_run_id, tenant_id, account_id)

        if not discovery_data:
            logger.warning("No network discovery data found for scan %s", scan_run_id)
            update_report_status(scan_run_id, "completed", "No discovery data")
            return {"status": "completed", "findings": 0}

        # ── 4. Load inventory relationships (for SG attachments) ──────────
        sg_attachments = {}
        try:
            inv_reader = NetworkInventoryReader()
            sg_attachments = inv_reader.load_sg_attachments(scan_run_id, tenant_id)
            logger.info("Loaded SG attachments for %d security groups", len(sg_attachments))
        except Exception as e:
            logger.warning("Could not load inventory relationships: %s", e)

        # ── 5. Build topology (Layer 1) ───────────────────────────────────
        topology = build_topology(discovery_data, account_id)

        # ── 6. Build load balancers and WAF (Layer 5/6 data) ─────────────
        build_load_balancers(discovery_data, topology)
        build_waf_acls(discovery_data, topology)

        # ── 7. Run all 7 layers ───────────────────────────────────────────
        all_findings = []

        # L1: Network Topology
        l1_findings = analyze_topology(topology)
        logger.info("L1 Topology: %d findings", len(l1_findings))
        all_findings.extend(l1_findings)

        # L2: Network Reachability (marks subnets public/private)
        l2_findings = analyze_reachability(topology)
        logger.info("L2 Reachability: %d findings", len(l2_findings))
        all_findings.extend(l2_findings)

        # L3: Network ACLs
        l3_findings = analyze_nacls(topology)
        logger.info("L3 NACLs: %d findings", len(l3_findings))
        all_findings.extend(l3_findings)

        # L4: Security Groups
        l4_findings = analyze_security_groups(topology, sg_attachments)
        logger.info("L4 Security Groups: %d findings", len(l4_findings))
        all_findings.extend(l4_findings)

        # L5: Load Balancers
        l5_findings = analyze_load_balancers(topology)
        logger.info("L5 Load Balancers: %d findings", len(l5_findings))
        all_findings.extend(l5_findings)

        # L6: WAF
        l6_findings = analyze_waf(topology)
        logger.info("L6 WAF: %d findings", len(l6_findings))
        all_findings.extend(l6_findings)

        # L7: Flow Analysis (enrichment only, no new findings for now)
        try:
            l4_dicts = [f.finding_data for f in l4_findings if f.finding_data.get("sg_posture")]
            enrich_with_flow_data(l4_dicts, tenant_id, account_id)
            logger.info("L7 Flow analysis enrichment completed")
        except Exception as e:
            logger.warning("L7 Flow analysis skipped: %s", e)

        # ── 8. Enrich findings ────────────────────────────────────────────
        blast_map = compute_blast_radius(topology, sg_attachments)
        all_findings = enrich_findings(all_findings, blast_map)

        # ── 9. Convert to DB rows ────────────────────────────────────────
        finding_rows = []
        for f in all_findings:
            finding_rows.append(f.to_db_row(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                credential_ref=credential_ref,
                credential_type=credential_type,
            ))

        # ── 9b. CIEM network findings (log-based detections) ───────────���─
        try:
            from engine_common.ciem_reader import CIEMReader
            import hashlib
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            ciem_net_findings = ciem.get_ciem_findings(engine_filter="network")
            if ciem_net_findings:
                logger.info("CIEM: %d network findings from ciem_findings", len(ciem_net_findings))
                for cf in ciem_net_findings:
                    ciem_fid = hashlib.sha256(
                        f"{cf.get('rule_id','')}|{cf.get('resource_uid','')}|{cf.get('account_id','')}|{cf.get('region','')}".encode()
                    ).hexdigest()[:16]
                    finding_rows.append({
                        "finding_id": ciem_fid,
                        "scan_run_id": scan_run_id,
                        "tenant_id": tenant_id,
                        "account_id": cf.get("account_id", account_id or ""),
                        "region": cf.get("region", ""),
                        "provider": provider,
                        "credential_ref": credential_ref,
                        "credential_type": credential_type,
                        "resource_uid": cf.get("resource_uid", ""),
                        "resource_type": cf.get("resource_type", ""),
                        "rule_id": cf.get("rule_id", ""),
                        "network_modules": ["ciem_detection"],
                        "effective_exposure": None,
                        "blast_radius_score": 0,
                        "severity": (cf.get("severity") or "medium").upper(),
                        "status": "FAIL",
                        "finding_data": {
                            "source": "ciem",
                            "title": cf.get("title", ""),
                            "description": cf.get("description", ""),
                            "remediation": cf.get("remediation", ""),
                            "compliance_frameworks": cf.get("compliance_frameworks", []),
                            "mitre_tactics": cf.get("mitre_tactics", []),
                            "mitre_techniques": cf.get("mitre_techniques", []),
                            "risk_score": cf.get("risk_score"),
                            "domain": cf.get("domain", ""),
                            "actor": cf.get("actor_principal", ""),
                            "operation": cf.get("operation", ""),
                            "action_category": cf.get("action_category", ""),
                        },
                    })
        except Exception as ciem_net_err:
            logger.warning("CIEM network findings load failed (non-fatal): %s", ciem_net_err)

        # ── 10. Save findings ─────────────────────────────────────────────
        saved_count = save_network_findings(finding_rows)

        # ── 11. Save topology snapshots ───────────────────────────────────
        snapshots = []
        for vpc_id, vpc in topology.vpcs.items():
            snapshots.append({
                "scan_run_id": scan_run_id,
                "tenant_id": tenant_id,
                "account_id": account_id,
                "provider": provider,
                "region": vpc.region,
                "vpc_id": vpc_id,
                "vpc_cidr_blocks": vpc.cidr_blocks,
                "is_default_vpc": vpc.is_default,
                "flow_log_enabled": vpc.flow_log_enabled,
                "subnets": [{"subnet_id": s.subnet_id, "cidr": s.cidr_block,
                             "az": s.availability_zone, "is_public": s.is_public,
                             "nacl_id": s.nacl_id, "route_table_id": s.route_table_id}
                            for s in vpc.subnets.values()],
                "route_tables": [{"rtb_id": r.route_table_id, "is_main": r.is_main,
                                  "subnet_ids": r.subnet_ids}
                                 for r in vpc.route_tables.values()],
                "peering_connections": vpc.peering_connections,
                "tgw_attachments": vpc.tgw_attachments,
                "igw_id": vpc.igw_id,
                "nat_gateways": vpc.nat_gateways,
                "vpc_endpoints": vpc.vpc_endpoints,
                "network_firewalls": vpc.network_firewalls,
                "isolation_score": 100 - (50 if vpc.has_internet_gateway else 0)
                                  - (20 if vpc.is_default else 0)
                                  - (30 if not vpc.flow_log_enabled else 0),
                "public_subnet_count": len(vpc.public_subnets),
                "private_subnet_count": len(vpc.private_subnets),
                "has_internet_path": vpc.has_internet_gateway,
            })
        save_topology_snapshots(snapshots)

        # ── 12. Compute scores and save report ───────────────────────────
        severity_counts = Counter(f.severity for f in all_findings if f.status == "FAIL")
        layer_counts = Counter(f.network_layer for f in all_findings if f.status == "FAIL")
        module_counts = Counter()
        for f in all_findings:
            if f.status == "FAIL":
                for m in f.network_modules:
                    module_counts[m] += 1
        status_counts = Counter(f.status for f in all_findings)

        elapsed_ms = int((time.time() - start_time) * 1000)

        report = {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider": provider,
            "status": "completed",
            "posture_score": _compute_posture_score(severity_counts, len(all_findings)),
            "topology_score": _layer_score(l1_findings),
            "reachability_score": _layer_score(l2_findings),
            "nacl_score": _layer_score(l3_findings),
            "firewall_score": _layer_score(l4_findings),
            "lb_score": _layer_score(l5_findings),
            "waf_score": _layer_score(l6_findings),
            "monitoring_score": 100,  # L7 is enrichment-only for now
            "total_findings": len(all_findings),
            "critical_findings": severity_counts.get("critical", 0),
            "high_findings": severity_counts.get("high", 0),
            "medium_findings": severity_counts.get("medium", 0),
            "low_findings": severity_counts.get("low", 0),
            "total_vpcs": topology.total_vpcs,
            "total_subnets": topology.total_subnets,
            "total_security_groups": topology.total_security_groups,
            "total_nacls": topology.total_nacls,
            "total_route_tables": topology.total_route_tables,
            "total_load_balancers": len(topology.load_balancers),
            "total_waf_acls": len(topology.waf_acls),
            "total_nat_gateways": sum(len(v.nat_gateways) for v in topology.vpcs.values()),
            "total_igws": sum(1 for v in topology.vpcs.values() if v.igw_id),
            "total_tgws": len(topology.tgw_map),
            "total_vpc_endpoints": sum(len(v.vpc_endpoints) for v in topology.vpcs.values()),
            "total_eips": len(topology.eips),
            "total_network_firewalls": sum(len(v.network_firewalls) for v in topology.vpcs.values()),
            "internet_exposed_resources": sum(
                1 for f in all_findings if f.effective_exposure == "internet" and f.status == "FAIL"
            ),
            "cross_vpc_paths_count": sum(
                1 for f in all_findings if f.effective_exposure == "cross_vpc" and f.status == "FAIL"
            ),
            "orphaned_sg_count": sum(
                1 for f in all_findings if f.rule_id == "net.l4.orphaned_security_group"
            ),
            "findings_by_module": dict(module_counts),
            "findings_by_status": dict(status_counts),
            "findings_by_layer": dict(layer_counts),
            "severity_breakdown": dict(severity_counts),
            "exposure_summary": {
                "internet_exposed": sum(1 for f in all_findings if f.effective_exposure == "internet"),
                "cross_vpc": sum(1 for f in all_findings if f.effective_exposure == "cross_vpc"),
                "vpc_internal": sum(1 for f in all_findings if f.effective_exposure == "vpc_internal"),
            },
            "report_data": {},
            "started_at": datetime.now(timezone.utc),
            "completed_at": datetime.now(timezone.utc),
            "scan_duration_ms": elapsed_ms,
        }
        save_network_report(report)

        # ── 13. Cleanup old scans ─────────────────────────────────────────
        cleanup_old_scans(tenant_id, keep=3)

        logger.info(
            "=== Network Security Scan COMPLETE: %d findings (%d critical, %d high) in %dms ===",
            len(all_findings), severity_counts.get("critical", 0),
            severity_counts.get("high", 0), elapsed_ms,
        )

        return {
            "status": "completed",
            "findings": len(all_findings),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "posture_score": report["posture_score"],
            "scan_duration_ms": elapsed_ms,
        }

    except Exception as e:
        logger.exception("Network security scan failed: %s", e)
        update_report_status(scan_run_id, "failed", str(e))
        return {"status": "failed", "error": str(e)}


def _compute_posture_score(severity_counts: Counter, total: int) -> int:
    """Compute 0-100 posture score (higher = worse posture). Same formula as IAM."""
    if total == 0:
        return 0
    raw = (severity_counts.get("critical", 0) * 10
           + severity_counts.get("high", 0) * 5
           + severity_counts.get("medium", 0) * 2
           + severity_counts.get("low", 0) * 1) / max(total, 1) * 10
    return min(int(round(raw)), 100)


def _layer_score(findings: list) -> int:
    """Compute per-layer score (100 = no issues, 0 = all critical)."""
    if not findings:
        return 100
    fail_count = sum(1 for f in findings if f.status == "FAIL")
    critical = sum(1 for f in findings if f.severity == "critical" and f.status == "FAIL")
    high = sum(1 for f in findings if f.severity == "high" and f.status == "FAIL")
    penalty = critical * 20 + high * 10 + (fail_count - critical - high) * 3
    return max(0, 100 - penalty)


# ── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Security Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan_run_id")
    args = parser.parse_args()

    result = run_network_scan(args.scan_run_id)
    logger.info("Result: %s", result)
    sys.exit(0 if result.get("status") == "completed" else 1)
