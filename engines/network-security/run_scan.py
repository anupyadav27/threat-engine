"""
Network Security Engine — K8s Job Entry Point

Architecture:
  Layer 1 (all CSPs): Surface check_findings where rule_metadata.network_security=true.
                       Zero hardcoding — rules live in the DB, evaluated by check engine.
  Layer 2 (AWS only): Topology analysis — VPC graph, reachability paths, exposure chains.
                       Cross-resource correlation that per-rule check engine cannot do.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "shared"))

from network_security_engine.storage.network_db_writer import (
    save_network_report, save_network_findings,
    save_topology_snapshots, update_report_status,
    cleanup_old_scans, _ensure_tenant,
)
from engine_common.db_connections import get_network_conn, get_onboarding_conn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("network_security.run_scan")


def get_orchestration_metadata(scan_run_id: str) -> Dict[str, Any]:
    """Read scan metadata from scan_runs table."""
    from psycopg2.extras import RealDictCursor
    conn = get_onboarding_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM scan_runs WHERE scan_run_id = %s", (scan_run_id,))
            row = cur.fetchone()
            return dict(row) if row else {}
    finally:
        conn.close()


def _check_finding_to_network_row(
    cf: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
    credential_ref: str,
    credential_type: str,
) -> Dict[str, Any]:
    """Convert a check_finding row into the network_findings schema."""
    fid = hashlib.sha256(
        f"net|{cf.get('rule_id', '')}|{cf.get('resource_uid', '')}|{scan_run_id}".encode()
    ).hexdigest()[:16]

    fd = cf.get("finding_data") or {}
    return {
        "finding_id": fid,
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": cf.get("account_id", ""),
        "region": cf.get("region", ""),
        "provider": cf.get("provider", ""),
        "credential_ref": cf.get("credential_ref") or credential_ref,
        "credential_type": cf.get("credential_type") or credential_type,
        "resource_uid": cf.get("resource_uid", ""),
        "resource_type": cf.get("resource_type", ""),
        "rule_id": cf.get("rule_id", ""),
        "network_modules": ["check_findings"],
        "effective_exposure": fd.get("effective_exposure"),
        "blast_radius_score": 0,
        "severity": (cf.get("severity") or "medium").lower(),
        "status": cf.get("status", "FAIL"),
        "finding_data": {
            "source": "check_engine",
            "title": cf.get("title") or fd.get("title") or cf.get("rule_id", ""),
            "description": cf.get("description") or fd.get("description", ""),
            "remediation": cf.get("remediation") or fd.get("remediation", ""),
            "mitre_tactics": cf.get("mitre_tactics") or [],
            "mitre_techniques": cf.get("mitre_techniques") or [],
            "action_category": cf.get("action_category", ""),
        },
    }


def run_network_scan(scan_run_id: str) -> Dict[str, Any]:
    """Execute network security analysis."""
    start_time = time.time()
    logger.info("=== Network Security Scan START: %s ===", scan_run_id)

    # ── 1. Get orchestration metadata ──────────────────────────────────────
    metadata = get_orchestration_metadata(scan_run_id)
    tenant_id = metadata.get("tenant_id", os.getenv("TENANT_ID", "default-tenant"))
    account_id = metadata.get("account_id", os.getenv("ACCOUNT_ID", ""))
    provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
    credential_ref = metadata.get("credential_ref", "")
    credential_type = metadata.get("credential_type", "")

    logger.info("Tenant: %s, Account: %s, Provider: %s", tenant_id, account_id, provider)

    # ── 2. Pre-create report (status=running) ──────────────────────────────
    conn = get_network_conn()
    try:
        _ensure_tenant(conn, tenant_id)
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO network_report
                    (scan_run_id, tenant_id, account_id, provider, status, started_at)
                VALUES (%s, %s, %s, %s, 'running', NOW())
                ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running', started_at = NOW()
            """, (scan_run_id, tenant_id, account_id, provider))
        conn.commit()
    finally:
        conn.close()

    finding_rows: List[Dict[str, Any]] = []
    topology_snapshots: List[Dict[str, Any]] = []
    report_metrics: Dict[str, Any] = {}

    # ── 3. Layer 1: DB-driven check findings (ALL CSPs) ────────────────────
    # Uses rule_metadata.network_security = {"applicable": true}
    # No hardcoding — rules are in the DB, evaluated by the check engine.
    try:
        from network_security_engine.input.check_db_reader import NetworkCheckReader
        reader = NetworkCheckReader()
        check_findings = reader.load_network_check_findings(
            scan_run_id, tenant_id, account_id or None
        )
        logger.info("Layer 1: %d network check_findings loaded (provider=%s)", len(check_findings), provider)

        for cf in check_findings:
            finding_rows.append(
                _check_finding_to_network_row(cf, scan_run_id, tenant_id, credential_ref, credential_type)
            )
    except Exception as e:
        logger.warning("Layer 1 (check_findings) failed: %s", e, exc_info=True)

    # ── 4. Layer 2: Topology analysis — provider factory dispatch ─────────
    # AWS: full 7-layer VPC/SG/NACL/LB/WAF graph analysis.
    # OCI/AliCloud: lightweight VCN/VPC security-group topology.
    # Azure/GCP/K8s: deferred — topology stubs return skipped.
    _PROVIDER_MAP = {
        "aws":      "network_security_engine.providers.aws.AWSNetworkProvider",
        "azure":    "network_security_engine.providers.azure.AzureNetworkProvider",
        "gcp":      "network_security_engine.providers.gcp.GCPNetworkProvider",
        "oci":      "network_security_engine.providers.oci.OCINetworkProvider",
        "alicloud": "network_security_engine.providers.alicloud.AliCloudNetworkProvider",
        "ibm":      "network_security_engine.providers.ibm.IBMNetworkProvider",
        "k8s":      "network_security_engine.providers.k8s.K8sNetworkProvider",
    }

    provider_cls_path = _PROVIDER_MAP.get(provider)
    if provider_cls_path:
        try:
            module_path, cls_name = provider_cls_path.rsplit(".", 1)
            import importlib
            mod = importlib.import_module(module_path)
            provider_instance = getattr(mod, cls_name)()
            result = provider_instance.analyze(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                credential_ref=credential_ref,
                credential_type=credential_type,
            )
            if result.get("status") != "skipped":
                topo_findings = result.get("findings", [])
                topology_snapshots = result.get("topology_snapshots", [])
                report_metrics = result.get("report_metrics", {})
                logger.info(
                    "Layer 2 (%s topology): %d additional findings",
                    provider, len(topo_findings),
                )
                existing_rule_resource = {
                    (f["rule_id"], f["resource_uid"]) for f in finding_rows
                }
                for tf in topo_findings:
                    key = (tf.get("rule_id", ""), tf.get("resource_uid", ""))
                    if key not in existing_rule_resource:
                        finding_rows.append(tf)
            else:
                logger.info(
                    "Layer 2 (%s): skipped — %s",
                    provider, result.get("reason", ""),
                )
        except Exception as e:
            logger.warning("Layer 2 (%s topology) failed: %s", provider, e, exc_info=True)
    else:
        logger.info("Layer 2: no topology provider registered for provider=%s", provider)

    # ── 5. Build report metrics if not populated by topology layer ─────────
    # Build/fill report_metrics — ensure all network_report columns are present
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in finding_rows:
        s = (f.get("severity") or "medium").lower()
        sev[s] = sev.get(s, 0) + 1
    total = len(finding_rows)
    fail_count = sum(1 for f in finding_rows if f.get("status") == "FAIL")
    internet_exposed = sum(1 for f in finding_rows if f.get("effective_exposure") == "internet")

    _defaults = {
        "posture_score": max(0, 100 - sev["critical"] * 20 - sev["high"] * 10 - sev["medium"] * 5),
        "topology_score": 100,
        "reachability_score": 100,
        "nacl_score": 100,
        "firewall_score": max(0, 100 - sev["high"] * 10 - sev["critical"] * 20),
        "lb_score": 100,
        "waf_score": 100,
        "monitoring_score": 100,
        "total_findings": total,
        "critical_findings": sev["critical"],
        "high_findings": sev["high"],
        "medium_findings": sev["medium"],
        "low_findings": sev["low"],
        "total_vpcs": 0,
        "total_subnets": 0,
        "total_security_groups": 0,
        "total_nacls": 0,
        "total_route_tables": 0,
        "total_load_balancers": 0,
        "total_waf_acls": 0,
        "total_nat_gateways": 0,
        "total_igws": 0,
        "total_tgws": 0,
        "total_vpc_endpoints": 0,
        "total_eips": 0,
        "total_network_firewalls": 0,
        "internet_exposed_resources": internet_exposed,
        "cross_vpc_paths_count": 0,
        "orphaned_sg_count": 0,
        "findings_by_module": {"check_findings": total},
        "findings_by_status": {"FAIL": fail_count, "PASS": total - fail_count},
        "findings_by_layer": {"layer1_check": total},
        "severity_breakdown": sev,
        "exposure_summary": {
            "internet_exposed": internet_exposed,
            "cross_vpc": 0,
            "vpc_internal": 0,
        },
    }
    # Topology layer metrics (AWS) override defaults where present
    if not report_metrics:
        report_metrics = _defaults
    else:
        for k, v in _defaults.items():
            report_metrics.setdefault(k, v)

    # ── 6. Deduplicate by finding_id — prevents CardinalityViolation ─────
    # Multiple findings can hash to the same finding_id within one batch;
    # last-write-wins is fine here since the content is equivalent.
    _seen: dict = {}
    for _f in finding_rows:
        _seen[_f["finding_id"]] = _f
    finding_rows = list(_seen.values())

    # ── 7. Save findings + topology + report ──────────────────────────────
    save_network_findings(finding_rows)
    save_topology_snapshots(topology_snapshots)

    elapsed_ms = int((time.time() - start_time) * 1000)
    report = {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": provider,
        "status": "completed",
        "started_at": datetime.now(timezone.utc),
        "completed_at": datetime.now(timezone.utc),
        "scan_duration_ms": elapsed_ms,
        **report_metrics,
        "report_data": {},
    }
    save_network_report(report)
    cleanup_old_scans(tenant_id, keep=5)

    total_findings = len(finding_rows)
    logger.info(
        "=== Network Security Scan COMPLETE: %d findings (%d from check engine, provider=%s) in %dms ===",
        total_findings,
        sum(1 for f in finding_rows if "check_findings" in (f.get("network_modules") or [])),
        provider,
        elapsed_ms,
    )

    try:
        from engine_common.retention import run_retention
        run_retention("network", scan_run_id)
    except Exception as _ret_err:
        logger.warning("Retention cleanup skipped: %s", _ret_err)

    # Write network posture signals to resource_security_posture (non-fatal)
    try:
        from network_security_engine.posture_signals import write_network_posture_signals
        write_network_posture_signals(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id or "",
            provider=provider,
        )
    except Exception as _ps_err:
        logger.warning("Network posture signal write skipped: %s", _ps_err)

    # Write network FAIL findings to shared security_findings table (non-fatal)
    try:
        import psycopg2.extras
        from engine_common.security_findings_writer import upsert_findings
        from engine_common.db_connections import get_inventory_conn

        inv_conn = get_inventory_conn()
        rows: list = []
        for f in finding_rows:
            if f.get("status") != "FAIL":
                continue
            fd = f.get("finding_data", {})
            if isinstance(fd, str):
                import json as _json
                try:
                    fd = _json.loads(fd)
                except Exception:
                    fd = {}
            mitre_techniques = fd.get("mitre_techniques") or []
            mitre_tactics = fd.get("mitre_tactics") or []
            rows.append({
                "source_finding_id": f["finding_id"],
                "resource_uid": f.get("resource_uid") or "",
                "account_id": f.get("account_id", ""),
                "provider": f.get("provider", ""),
                "resource_type": f.get("resource_type", ""),
                "finding_type": "network_exposure",
                "severity": (f.get("severity") or "medium").lower(),
                "rule_id": f.get("rule_id", ""),
                "title": f.get("title", fd.get("title", "")),
                "description": f.get("description", fd.get("description", "")),
                "mitre_technique_id": mitre_techniques[0] if mitre_techniques else None,
                "mitre_tactic": mitre_tactics[0] if mitre_tactics else None,
                "detail": {
                    "network_layer": f.get("network_layer"),
                    "effective_exposure": f.get("effective_exposure"),
                    "network_modules": f.get("network_modules"),
                },
                "status": "open",
            })
        if rows:
            written = upsert_findings(
                conn=inv_conn,
                findings=rows,
                source_engine="network",
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
            )
            logger.info("security_findings: wrote %d network rows", written)
        inv_conn.close()
    except Exception as _sf_err:
        logger.warning("Network security_findings write skipped: %s", _sf_err)

    return {
        "status": "completed",
        "findings": total_findings,
        "critical": report_metrics.get("critical_findings", 0),
        "high": report_metrics.get("high_findings", 0),
        "posture_score": report_metrics.get("posture_score", 0),
        "scan_duration_ms": elapsed_ms,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Security Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan_run_id")
    args = parser.parse_args()

    result = run_network_scan(args.scan_run_id)
    logger.info("Result: %s", result)
    sys.exit(0 if result.get("status") == "completed" else 1)
