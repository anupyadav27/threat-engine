"""
Write network-security engine posture signals to resource_security_posture after scan.

Called at the end of run_scan.py after network_findings are persisted.
Queries network_findings for the scan and writes network-owned columns:
    is_internet_exposed, is_in_private_subnet, has_waf, has_load_balancer,
    network_exposure_score, network_detail

Column ownership: network-security engine writes ONLY these columns.
"""

from __future__ import annotations

import logging
from typing import Any

import psycopg2.extras

from engine_common.db_connections import get_network_conn, get_di_conn
from engine_common.posture_writer import upsert_posture_signals

logger = logging.getLogger(__name__)

_BATCH_SIZE = 500

# Rule ID patterns that indicate internet exposure
_INTERNET_RULE_PATTERNS = (
    "public_ip", "internet_exposed", "internet_facing", "public_access",
    "0.0.0.0/0", "open_to_internet", "publicly_accessible",
)
_WAF_RULE_PATTERNS = ("waf", "web_application_firewall",)
_LB_RULE_PATTERNS = ("load_balancer", "alb", "elb", "nlb", "clb", "application_gateway",)
_NACL_RULE_PATTERNS = ("nacl", "acl", "network_acl", "security_list",)
_SG_RULE_PATTERNS = ("security_group", "sg_", "_sg", "inbound_rule", "outbound_rule",)


def write_network_posture_signals(
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Aggregate network signals from network_findings + IEDS findings and upsert to posture.

    Reads:
      - network_findings: for has_waf, has_load_balancer, network_exposure_score, network_detail
      - network_exposure_findings: for is_internet_exposed (overrides pattern-based heuristic)

    Returns number of posture rows written.
    """
    try:
        signals_by_uid = _aggregate_network_signals(scan_run_id, tenant_id)

        # Augment is_internet_exposed from IEDS network_exposure_findings
        _augment_from_ieds(signals_by_uid, scan_run_id, tenant_id)

        if not signals_by_uid:
            logger.info("Network posture signals: no signals for scan %s", scan_run_id)
            return 0

        inv_conn = get_di_conn()
        try:
            written = _batch_upsert(
                inv_conn, signals_by_uid,
                scan_run_id, tenant_id, account_id, provider,
            )
            logger.info("Network posture signals: wrote %d rows for scan %s", written, scan_run_id)
            return written
        finally:
            inv_conn.close()

    except Exception as exc:
        logger.warning("Network posture signal write failed (non-fatal): %s", exc, exc_info=True)
        return 0


def _augment_from_ieds(
    signals_by_uid: dict[str, dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> None:
    """
    Read network_exposure_findings for this scan and set is_internet_exposed=True on
    any resource that IEDS Phase L0 flagged — overriding the pattern-based heuristic.

    Also ensures resources with IEDS findings have a signals entry even if they had
    no entries in network_findings (e.g. CloudFront distributions not in check rules).
    """
    try:
        net_conn = get_network_conn()
        try:
            with net_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT DISTINCT resource_uid, resource_type, severity, origin_type
                    FROM   network_exposure_findings
                    WHERE  scan_run_id = %s
                      AND  tenant_id   = %s
                      AND  status      = 'OPEN'
                      AND  origin_type = 'internet'
                """, (scan_run_id, tenant_id))
                rows = cur.fetchall()
        finally:
            net_conn.close()

        for row in rows:
            uid = row["resource_uid"]
            if uid not in signals_by_uid:
                signals_by_uid[uid] = {
                    "resource_type": row.get("resource_type", ""),
                    "is_internet_exposed": True,
                    "is_in_private_subnet": False,
                    "has_waf": False,
                    "has_load_balancer": False,
                    "network_exposure_score": 0,
                    "_fail_count": 0,
                    "_total_count": 0,
                    "_open_ports": set(),
                    "_vpc_ids": set(),
                    "_sg_violations": [],
                    "_nacl_violations": [],
                }
            else:
                signals_by_uid[uid]["is_internet_exposed"] = True
                signals_by_uid[uid]["is_in_private_subnet"] = False

        if rows:
            logger.info(
                "IEDS augment: set is_internet_exposed=True on %d resources for scan %s",
                len(rows), scan_run_id,
            )
    except Exception as exc:
        logger.debug("IEDS augment failed (non-fatal): %s", exc)


def _aggregate_network_signals(scan_run_id: str, tenant_id: str) -> dict[str, dict[str, Any]]:
    """Query network_findings and aggregate per resource_uid."""
    net_conn = get_network_conn()
    signals: dict[str, dict[str, Any]] = {}

    try:
        with net_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    resource_uid,
                    resource_type,
                    rule_id,
                    severity,
                    status,
                    network_modules,
                    finding_data
                FROM network_findings
                WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid IS NOT NULL
            """, (scan_run_id, tenant_id))

            for row in cur.fetchall():
                uid = row["resource_uid"]
                rule_id = (row.get("rule_id") or "").lower()
                if uid not in signals:
                    signals[uid] = {
                        "resource_type": row.get("resource_type", "network_resource"),
                        "is_internet_exposed": False,
                        "is_in_private_subnet": True,  # assume private until proven otherwise
                        "has_waf": False,
                        "has_load_balancer": False,
                        "network_exposure_score": 0,
                        "_fail_count": 0,
                        "_total_count": 0,
                        "_open_ports": set(),
                        "_vpc_ids": set(),
                        "_sg_violations": [],
                        "_nacl_violations": [],
                    }

                sig = signals[uid]
                sig["_total_count"] += 1
                if row.get("status") == "FAIL":
                    sig["_fail_count"] += 1

                fd = row.get("finding_data") or {}
                if not isinstance(fd, dict):
                    fd = {}

                if any(pat in rule_id for pat in _INTERNET_RULE_PATTERNS):
                    if row.get("status") == "FAIL":
                        sig["is_internet_exposed"] = True
                        sig["is_in_private_subnet"] = False
                if any(pat in rule_id for pat in _WAF_RULE_PATTERNS):
                    if row.get("status") == "PASS":
                        sig["has_waf"] = True
                if any(pat in rule_id for pat in _LB_RULE_PATTERNS):
                    sig["has_load_balancer"] = True

                # Accumulate network_detail fields from finding_data
                _vpc = fd.get("vpc_id") or fd.get("vnet_id") or fd.get("vcn_id")
                if _vpc:
                    sig["_vpc_ids"].add(str(_vpc))
                _port = fd.get("port") or fd.get("open_port")
                if _port:
                    sig["_open_ports"].add(int(_port) if str(_port).isdigit() else str(_port))
                for _p in (fd.get("open_ports") or []):
                    sig["_open_ports"].add(_p)

                if row.get("status") == "FAIL":
                    if any(pat in rule_id for pat in _SG_RULE_PATTERNS):
                        _sg_entry = {"rule_id": rule_id, "severity": row.get("severity")}
                        if len(sig["_sg_violations"]) < 20:
                            sig["_sg_violations"].append(_sg_entry)
                    if any(pat in rule_id for pat in _NACL_RULE_PATTERNS):
                        _nacl_entry = {"rule_id": rule_id, "severity": row.get("severity")}
                        if len(sig["_nacl_violations"]) < 20:
                            sig["_nacl_violations"].append(_nacl_entry)

        # Calculate exposure score and build network_detail
        for uid, sig in signals.items():
            total = sig.pop("_total_count", 0)
            fail = sig.pop("_fail_count", 0)
            if total > 0:
                sig["network_exposure_score"] = min(100, int((fail / total) * 100))

            sig["network_detail"] = {
                "vpc_ids": list(sig.pop("_vpc_ids", set())),
                "open_ports": sorted(sig.pop("_open_ports", set()), key=str)[:50],
                "sg_violations": sig.pop("_sg_violations", []),
                "nacl_violations": sig.pop("_nacl_violations", []),
            }

    finally:
        net_conn.close()

    return signals


def _batch_upsert(
    inv_conn: Any,
    signals_by_uid: dict[str, dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    provider: str,
) -> int:
    """Upsert signals in batches. Returns total rows written."""
    uids = list(signals_by_uid.keys())
    written = 0

    for i in range(0, len(uids), _BATCH_SIZE):
        batch = uids[i : i + _BATCH_SIZE]
        for uid in batch:
            sig = signals_by_uid[uid]
            resource_type = sig.pop("resource_type", "network_resource")
            network_detail = sig.pop("network_detail", None)
            upsert_posture_signals(
                inv_conn,
                resource_uid=uid,
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                resource_type=resource_type,
                network_detail=network_detail,
                **sig,
            )
            written += 1

    return written
