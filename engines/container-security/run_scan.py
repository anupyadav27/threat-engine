"""
Container Security Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Pipeline:
  1. Read discovery_findings (EKS, ECS, ECR, Fargate, Lambda)
  2. Read check_findings (148 container rules)
  3. Read CIEM events (K8s audit, container CloudTrail)
  4. Categorize by domain (cluster, workload, image, network, rbac, runtime)
  5. Build inventory + posture scores + attack surface
  6. Write results to container_security DB
"""

import argparse
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine_common.logger import setup_logger
from engine_common.orchestration import get_orchestration_metadata
from engine_common.db_connections import get_container_sec_conn

logger = setup_logger(__name__, engine_name="container-sec-scanner")


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    try:
        conn = get_container_sec_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE container_sec_report SET status = %s, error_message = %s WHERE scan_run_id = %s",
                    (status, error, scan_run_id),
                )
            else:
                cur.execute(
                    "UPDATE container_sec_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_run_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(scan_run_id: str, tenant_id: str, provider: str):
    try:
        conn = get_container_sec_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )
            cur.execute(
                """INSERT INTO container_sec_report
                   (scan_run_id, tenant_id, provider, status, started_at, report_data)
                   VALUES (%s, %s, %s, 'running', NOW(), '{}'::jsonb)
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running', started_at = NOW()""",
                (scan_run_id, tenant_id, provider),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="Container Security Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id
    logger.info(f"Container security scanner starting scan_run_id={scan_run_id}")

    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking container sec scan {scan_run_id} as failed")
        _update_report_status(scan_run_id, "failed", "Terminated by SIGTERM")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or "aws").lower()
        account_id = metadata.get("account_id", "")

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} account={account_id}")

        _create_report_row(scan_run_id, tenant_id, provider)

        # Provider guard — routes to the appropriate CSP provider module
        from container_security_engine.providers import get_provider as get_container_provider
        container_provider = get_container_provider(provider)
        if not container_provider.is_supported():
            logger.info(
                f"Container-security: provider='{provider}' not yet supported — completing with 0 findings"
            )
            _update_report_status(scan_run_id, "completed")
            return

        start = datetime.now(timezone.utc)

        # 1. Load data
        import os as _os
        if _os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true":
            from container_security_engine.input.di_reader import ContainerDIReader as ContainerDiscoveryReader
        else:
            from container_security_engine.input.discovery_reader import ContainerDiscoveryReader
        from container_security_engine.input.check_reader import ContainerCheckReader

        disc_reader = ContainerDiscoveryReader()
        check_reader = ContainerCheckReader()

        try:
            discovery_resources = disc_reader.load_all_container_resources(
                scan_run_id, tenant_id, account_id or None, services=container_provider.discovery_services
            )
            total_disc = sum(len(v) for v in discovery_resources.values())
            logger.info(f"Discovery: {total_disc} resources across {len(discovery_resources)} services")
            if total_disc == 0:
                logger.warning(
                    f"[DIAGNOSTIC] 0 container resources found for scan_run_id={scan_run_id} "
                    f"tenant={tenant_id} account={account_id}. "
                    "Likely causes: (1) EKS/ECS/ECR/Fargate not present in scanned regions, "
                    "(2) discovery failed — check service_scan_attempts for status=failed/access_denied "
                    "on eks/ecs/ecr/lambda services."
                )
            else:
                for svc, items in discovery_resources.items():
                    if items:
                        logger.info(f"  {svc}: {len(items)} resources")

            check_findings = check_reader.load_container_check_findings(scan_run_id, tenant_id)
            rule_metadata = check_reader.load_rule_metadata()
            logger.info(f"Check: {len(check_findings)} findings, {len(rule_metadata)} rules")
        finally:
            disc_reader.close()
            check_reader.close()

        # 2. CIEM events (non-fatal)
        ciem_events = []
        try:
            from container_security_engine.input.ciem_reader import ContainerCIEMReader
            ciem_reader = ContainerCIEMReader()
            try:
                ciem_events = ciem_reader.load_container_events(tenant_id, account_id or None, days=30)
                logger.info(f"CIEM: {len(ciem_events)} container events")
            finally:
                ciem_reader.close()
        except Exception as ciem_err:
            logger.warning(f"CIEM reader failed (non-fatal): {ciem_err}")

        # 2b. CIEM findings (pre-evaluated log-based detections)
        ciem_check_findings = []
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            ciem_check_findings = ciem.get_ciem_findings(engine_filter="container")
            if ciem_check_findings:
                logger.info(f"CIEM: {len(ciem_check_findings)} container findings from ciem_findings")
        except Exception as ciem_f_err:
            logger.warning(f"CIEM findings load failed (non-fatal): {ciem_f_err}")

        # 3. Categorize findings
        from container_security_engine.analyzer.rule_categorizer import categorize_finding, get_service_from_rule
        from container_security_engine.analyzer.inventory_builder import build_container_inventory
        from container_security_engine.analyzer.posture_scorer import compute_posture_scores
        from container_security_engine.analyzer.attack_surface import analyze_attack_surface
        from container_security_engine.storage.container_db_writer import (
            generate_finding_id, save_findings_to_db, save_container_inventory,
        )

        findings = []
        for cf in check_findings:
            rule_id = cf.get("rule_id", "")
            domain = categorize_finding(rule_id, cf)
            svc = get_service_from_rule(rule_id)
            sev = cf.get("severity") or rule_metadata.get(rule_id, {}).get("severity", "medium")
            meta = rule_metadata.get(rule_id, {})

            finding_id = generate_finding_id(
                rule_id, cf.get("resource_uid", ""),
                cf.get("account_id", ""), cf.get("region", ""),
            )

            findings.append({
                "finding_id": finding_id,
                "resource_uid": cf.get("resource_uid", ""),
                "resource_type": cf.get("resource_type", ""),
                "account_id": cf.get("account_id", ""),
                "region": cf.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "container_service": svc,
                "cluster_name": _extract_cluster_name(cf),
                "security_domain": domain,
                "severity": sev.upper() if sev else "MEDIUM",
                "status": cf.get("status", "FAIL"),
                "rule_id": rule_id,
                "title": meta.get("title", ""),
                "description": meta.get("description", ""),
                "remediation": meta.get("remediation", ""),
                "finding_data": cf.get("finding_data") or {},
            })

        # 3b. Merge CIEM findings (log-based detections)
        for cf in ciem_check_findings:
            rule_id = cf.get("rule_id", "")
            finding_id = generate_finding_id(
                rule_id, cf.get("resource_uid", ""),
                cf.get("account_id", account_id or ""), cf.get("region", ""),
            )
            findings.append({
                "finding_id": finding_id,
                "resource_uid": cf.get("resource_uid", ""),
                "resource_type": cf.get("resource_type", ""),
                "account_id": cf.get("account_id", account_id or ""),
                "region": cf.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "container_service": get_service_from_rule(rule_id),
                "cluster_name": "",
                "security_domain": categorize_finding(rule_id, cf),
                "severity": (cf.get("severity") or "medium").upper(),
                "status": "FAIL",
                "rule_id": rule_id,
                "title": cf.get("title", ""),
                "description": cf.get("description", ""),
                "remediation": cf.get("remediation", ""),
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
                },
            })

        logger.info(f"Categorized {len(findings)} findings (incl. {len(ciem_check_findings)} from CIEM)")

        # 4. Build inventory
        flat_resources = [r for items in discovery_resources.values() for r in items]
        container_inventory = build_container_inventory(flat_resources, findings)
        logger.info(f"Inventory: {len(container_inventory)} resources")

        # 5. Posture scores
        scores = compute_posture_scores(findings, container_inventory)
        logger.info(f"Posture: overall={scores.get('posture_score', 0)}")

        # 6. Attack surface
        attack_surface = analyze_attack_surface(container_inventory, ciem_events)
        logger.info(f"Attack surface: {len(attack_surface)} findings")

        for asf in attack_surface:
            asf_id = generate_finding_id(
                asf.get("attack_type", "attack_surface"),
                asf.get("resource_uid", ""),
                asf.get("account_id", ""),
                asf.get("region", ""),
            )
            findings.append({
                "finding_id": asf_id,
                "resource_uid": asf.get("resource_uid", ""),
                "resource_type": asf.get("resource_type", ""),
                "account_id": asf.get("account_id", ""),
                "region": asf.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "container_service": asf.get("container_service"),
                "cluster_name": asf.get("cluster_name"),
                "security_domain": asf.get("security_domain", "cluster_security"),
                "severity": asf.get("severity", "HIGH"),
                "status": "FAIL",
                "rule_id": None,
                "title": asf.get("title", ""),
                "description": asf.get("description", ""),
                "remediation": asf.get("remediation", ""),
                "finding_data": asf.get("finding_data", {}),
            })

        # 6b. Pattern A: provider.analyze() — workload-level rule findings (non-fatal)
        try:
            from engine_common.db_connections import get_discoveries_conn as _get_disc_conn
            _disc_conn = _get_disc_conn()
            try:
                pa_findings = container_provider.analyze(
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    account_id=account_id,
                    discoveries_conn=_disc_conn,
                )
                if pa_findings:
                    for pf in pa_findings:
                        pf.setdefault("credential_ref", metadata.get("credential_ref"))
                        pf.setdefault("credential_type", metadata.get("credential_type"))
                    findings.extend(pa_findings)
                    logger.info("Pattern A: %d additional workload findings from provider.analyze()", len(pa_findings))
            finally:
                _disc_conn.close()
        except Exception as _pa_err:
            logger.warning("Container Pattern A analyze() failed (non-fatal): %s", _pa_err)

        # 7. Summary
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        domain_counts = {}
        service_counts = {}
        pass_count = fail_count = 0

        for f in findings:
            sev_counts[f["severity"].lower()] = sev_counts.get(f["severity"].lower(), 0) + 1
            domain_counts[f.get("security_domain", "unknown")] = domain_counts.get(f.get("security_domain", "unknown"), 0) + 1
            service_counts[f.get("container_service", "unknown")] = service_counts.get(f.get("container_service", "unknown"), 0) + 1
            if f["status"] == "PASS":
                pass_count += 1
            else:
                fail_count += 1

        clusters = [i for i in container_inventory if i.get("resource_type") == "cluster"]
        images = [i for i in container_inventory if i.get("container_service") == "ecr"]

        summary = {
            **scores,
            "total_clusters": len(clusters),
            "total_workloads": len(container_inventory) - len(clusters) - len(images),
            "total_images": len(images),
            "total_findings": len(findings),
            "critical_findings": sev_counts["critical"],
            "high_findings": sev_counts["high"],
            "medium_findings": sev_counts["medium"],
            "low_findings": sev_counts["low"],
            "pass_count": pass_count,
            "fail_count": fail_count,
            "findings_by_service": service_counts,
            "findings_by_domain": domain_counts,
            "attack_surface_count": len(attack_surface),
        }

        # 8. Write legacy findings
        save_findings_to_db(scan_run_id, tenant_id, provider, findings, summary)
        save_container_inventory(scan_run_id, tenant_id, container_inventory)

        # 8b. CIS 7-layer analysis (writes directly to container_sec_findings)
        try:
            from container_security_engine.analyzer.cis_analyzer import run_cis_analysis
            from container_security_engine.storage.container_db_writer import save_cis_findings_to_db
            from engine_common.db_connections import get_discoveries_conn

            discoveries_conn = get_discoveries_conn()
            try:
                cis_findings = run_cis_analysis(
                    provider=provider,
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    account_id=account_id,
                    discoveries_conn=discoveries_conn,
                )
                if cis_findings:
                    cis_count = save_cis_findings_to_db(
                        scan_run_id=scan_run_id,
                        tenant_id=tenant_id,
                        provider=provider,
                        cis_findings=cis_findings,
                        credential_ref=metadata.get("credential_ref"),
                        credential_type=metadata.get("credential_type"),
                    )
                    logger.info(
                        f"CIS 7-layer analysis: {len(cis_findings)} findings ({cis_count} written) "
                        f"for provider={provider}"
                    )
                    fail_cis = sum(1 for f in cis_findings if f.get("status") == "FAIL")
                    logger.info(f"CIS FAIL count: {fail_cis} / {len(cis_findings)}")
                else:
                    logger.info(f"CIS 7-layer analysis: 0 findings for provider={provider}")
            finally:
                discoveries_conn.close()
        except Exception as cis_err:
            logger.error(f"CIS 7-layer analysis failed (non-fatal): {cis_err}", exc_info=True)

        # 9. Report JSON
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                csec_dir = os.path.join(output_dir, "container-security", "reports", tenant_id)
                os.makedirs(csec_dir, exist_ok=True)
                with open(os.path.join(csec_dir, f"{scan_run_id}_report.json"), "w") as f:
                    json.dump(summary, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving report: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()
        _update_report_status(scan_run_id, "completed")

        logger.info(
            f"Container security scan completed: {scan_run_id} — "
            f"score={scores.get('posture_score', 0)}, {len(findings)} findings, "
            f"{len(container_inventory)} resources in {duration:.1f}s"
        )

        # Retention: archive old scans to S3, keep last 5 in DB
        try:
            from engine_common.retention import run_retention
            run_retention("container", scan_run_id)
        except Exception as _ret_err:
            logger.warning("Retention cleanup skipped: %s", _ret_err)

        # Write container FAIL findings to shared security_findings table (SF-P1-03, non-fatal)
        # detail JSONB: namespace/kind/name/rule_id/cluster_provider ONLY — no raw pod spec or env vars
        try:
            import hashlib
            import psycopg2.extras as _extras
            from engine_common.security_findings_writer import upsert_findings
            from engine_common.db_connections import get_di_conn, get_container_sec_conn

            container_conn = get_container_sec_conn()
            inv_conn = get_di_conn()
            rows: list = []

            # Derive cluster_provider from provider string
            _PROVIDER_MAP = {
                "aws": "eks", "azure": "aks", "gcp": "gke",
                "oci": "oke", "k8s": "self_managed", "alicloud": "self_managed",
            }
            cluster_provider = _PROVIDER_MAP.get((provider or "").lower(), "self_managed")

            with container_conn.cursor(cursor_factory=_extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT finding_id, resource_uid, resource_type, account_id,
                           severity, status, rule_id, finding_data,
                           container_service, security_domain
                    FROM container_sec_findings
                    WHERE scan_run_id = %s AND tenant_id = %s AND status = 'FAIL'
                    ORDER BY severity DESC
                    LIMIT 2000
                    """,
                    (scan_run_id, tenant_id),
                )
                image_risk_count = 0
                for r in cur.fetchall():
                    fd = r.get("finding_data") or {}
                    if not isinstance(fd, dict):
                        fd = {}

                    # Determine finding_type
                    sec_domain = (r.get("security_domain") or "").lower()
                    rule = (r.get("rule_id") or "").lower()
                    is_image = ("image" in sec_domain or "image" in rule
                                or "registry" in sec_domain or "cve" in sec_domain)

                    if is_image:
                        if image_risk_count >= 200:  # cap per AC-8
                            continue
                        image_risk_count += 1
                        ftype = "container_risk"
                    else:
                        ftype = "k8s_violation"

                    uid = r.get("resource_uid") or ""
                    # Build k8s/{namespace}/{kind}/{name} if resource_uid not already in that format
                    if not uid.startswith("k8s/") and fd.get("namespace"):
                        kind = (fd.get("kind") or r.get("resource_type") or "resource").lower()
                        name = fd.get("name") or fd.get("resource_name") or uid.split("/")[-1]
                        uid = f"k8s/{fd['namespace']}/{kind}/{name}"

                    # detail: ONLY safe fields — no pod spec, no env vars, no image digests > 32 chars
                    detail = {
                        "namespace": fd.get("namespace"),
                        "kind": fd.get("kind") or r.get("resource_type"),
                        "name": fd.get("name") or fd.get("resource_name"),
                        "rule_id": r.get("rule_id"),
                        "cluster_provider": cluster_provider,
                    }

                    rows.append({
                        "source_finding_id": str(r["finding_id"]),
                        "resource_uid": uid,
                        "account_id": r.get("account_id", ""),
                        "provider": "k8s",
                        "resource_type": (r.get("resource_type") or "").lower(),
                        "finding_type": ftype,
                        "severity": (r.get("severity") or "medium").lower(),
                        "rule_id": r.get("rule_id", ""),
                        "title": fd.get("title", ""),
                        "detail": detail,
                        "status": "open",
                    })

            if rows:
                written = upsert_findings(
                    conn=inv_conn,
                    findings=rows,
                    source_engine="container",
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                )
                logger.info("security_findings: wrote %d container rows (k8s_violation + container_risk)", written)
            inv_conn.close()
            container_conn.close()
        except Exception as _sf_err:
            logger.warning("Container security_findings write skipped: %s", _sf_err)

        # Write container posture signals to resource_security_posture (PC-P1-03, non-fatal)
        try:
            from engine_common.db_connections import get_di_conn as _get_inv_conn, get_container_sec_conn as _get_csec_conn
            import psycopg2.extras as _pextras

            _csec_conn = _get_csec_conn()
            _clusters: dict = {}
            with _csec_conn.cursor(cursor_factory=_pextras.RealDictCursor) as _cur2:
                _cur2.execute(
                    """SELECT account_id, severity, rule_id, security_domain
                       FROM container_sec_findings
                       WHERE scan_run_id = %s AND tenant_id = %s""",
                    (scan_run_id, tenant_id),
                )
                for _r in _cur2.fetchall():
                    _cid = _r.get("account_id") or account_id or ""
                    if _cid not in _clusters:
                        _clusters[_cid] = {
                            "critical": 0, "high": 0, "medium": 0,
                            "has_privileged": False, "has_image_cve": False,
                            "has_rbac": False, "has_netpol": False,
                            "ecr_scan_on_push_disabled": False, "eks_node_ami_outdated": False,
                        }
                    _sev = (_r.get("severity") or "").lower()
                    _rule = (_r.get("rule_id") or "").lower()
                    _dom = (_r.get("security_domain") or "").lower()
                    _status = (_r.get("status") or "FAIL").upper()
                    if _status == "FAIL":
                        if _sev == "critical":
                            _clusters[_cid]["critical"] += 1
                        elif _sev == "high":
                            _clusters[_cid]["high"] += 1
                        elif _sev == "medium":
                            _clusters[_cid]["medium"] += 1
                        if "privileged" in _rule or "privileged" in _dom:
                            _clusters[_cid]["has_privileged"] = True
                        if _sev == "critical" and ("image" in _dom or "cve" in _dom or "image" in _rule):
                            _clusters[_cid]["has_image_cve"] = True
                        if "rbac" in _rule or "rbac" in _dom:
                            _clusters[_cid]["has_rbac"] = True
                        if "network_policy" in _rule or "netpol" in _rule or "network_policy" in _dom:
                            _clusters[_cid]["has_netpol"] = True
                        if "scan_on_push" in _rule or "imagescan" in _rule:
                            _clusters[_cid]["ecr_scan_on_push_disabled"] = True
                        if "eks" in _rule and ("nodegroup" in _rule or "node" in _rule) and ("version" in _rule or "ami" in _rule or "outdated" in _rule or "launch" in _rule):
                            _clusters[_cid]["eks_node_ami_outdated"] = True
            _csec_conn.close()

            if _clusters:
                _inv_conn2 = _get_inv_conn()
                try:
                    with _inv_conn2.cursor() as _cur3:
                        _cur3.execute(
                            "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                            (tenant_id, tenant_id),
                        )
                        _prsp_rows = []
                        for _cid, _cl in _clusters.items():
                            _score = max(0, 100 - _cl["critical"] * 20 - _cl["high"] * 10 - _cl["medium"] * 5)
                            _prsp_rows.append((
                                tenant_id, scan_run_id, _cid, provider, "", _cid, "k8s::cluster",
                                _cl["has_privileged"], _cl["has_image_cve"],
                                _cl["has_rbac"], _cl["has_netpol"], min(_score, 100),
                                not _cl["ecr_scan_on_push_disabled"],
                                _cl["eks_node_ami_outdated"],
                            ))
                        _cur3.executemany(
                            """INSERT INTO resource_security_posture
                               (tenant_id, scan_run_id, account_id, provider, region,
                                resource_uid, resource_type,
                                has_privileged_container, image_has_critical_cve,
                                k8s_rbac_overpermissive, container_network_policy_missing,
                                container_security_score,
                                ecr_scan_on_push_enabled, eks_node_ami_outdated)
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                               ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO UPDATE SET
                                   has_privileged_container         = EXCLUDED.has_privileged_container,
                                   image_has_critical_cve           = EXCLUDED.image_has_critical_cve,
                                   k8s_rbac_overpermissive          = EXCLUDED.k8s_rbac_overpermissive,
                                   container_network_policy_missing = EXCLUDED.container_network_policy_missing,
                                   container_security_score         = EXCLUDED.container_security_score,
                                   ecr_scan_on_push_enabled         = EXCLUDED.ecr_scan_on_push_enabled,
                                   eks_node_ami_outdated            = EXCLUDED.eks_node_ami_outdated,
                                   updated_at                       = NOW()""",
                            _prsp_rows,
                        )
                        _inv_conn2.commit()
                    logger.info("Posture: wrote %d container cluster rows to resource_security_posture", len(_prsp_rows))
                finally:
                    _inv_conn2.close()
        except Exception as _csec_posture_err:
            logger.warning("Container posture write failed (non-fatal): %s", _csec_posture_err)

    except Exception as e:
        logger.error(f"Container security scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


def _extract_cluster_name(finding: dict) -> str:
    """Extract cluster name from finding data."""
    fd = finding.get("finding_data") or {}
    if isinstance(fd, dict):
        return fd.get("ClusterName") or fd.get("cluster_name") or ""
    uid = finding.get("resource_uid", "")
    # Parse from ARN: arn:aws:eks:region:account:cluster/name
    if ":cluster/" in uid:
        return uid.split(":cluster/")[-1]
    return ""


if __name__ == "__main__":
    main()
