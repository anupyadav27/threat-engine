"""
OCI network-security provider — 7-layer topology analysis.

Layer mapping:
  L1 Isolation:   VCN + Internet Gateway presence
  L2 Routing:     Route tables with internet routes (0.0.0.0/0 → IGW)
  L3 ACL:         Security lists (subnet-boundary ingress rules)
  L4 Firewall:    Network Security Group rules (open ports, wildcard ingress)
  L5 LB:          Load balancer HTTP-only listeners (no TLS)
  L6 WAF:         WAAS policy protection mode
  L7 Monitoring:  VCN flow-log enablement via log groups
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor

from .base import BaseNetworkProvider
from .alicloud import _EMPTY_METRICS

logger = logging.getLogger(__name__)

# ── Discovery IDs ──────────────────────────────────────────────────────────────
_L1_ID = "oci.virtual_network.list_vcns"
_L2_ID = "oci.virtual_network.list_route_tables"
_L3_ID = "oci.virtual_network.list_security_lists"
_L4_ID = "oci.core.list_network_security_group_security_rules"
_L5_ID = "oci.load_balancer.list_load_balancers"
_L6_ID = "oci.waas.list_waas_policies"
_L7_ID = "oci.logging.list_log_groups"

# Supplementary — used for IGW presence check
_IGW_ID = "oci.virtual_network.list_internet_gateways"

_ALL_LAYER_IDS = [_L1_ID, _L2_ID, _L3_ID, _L4_ID, _L5_ID, _L6_ID, _L7_ID, _IGW_ID]

_CRITICAL_PORTS = {22, 3389, 1433, 3306, 5432, 6379, 27017}
_ALL_PROTOCOLS  = ["all", "17", "6", "*"]
_OPEN_CIDRS     = {"0.0.0.0/0", "::/0", "*", "0.0.0.0"}

_PORT_NAMES = {
    22: "SSH", 3389: "RDP", 1433: "MSSQL",
    3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB",
}


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _load_all_layers(
    conn,
    scan_run_id: str,
    tenant_id: str,
    discovery_ids: List[str],
    account_id: Optional[str],
) -> Dict[str, List[Dict]]:
    """Return discovery rows grouped by discovery_id."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        query = """
            SELECT resource_uid, region, emitted_fields, discovery_id
            FROM discovery_findings
            WHERE scan_run_id = %s AND tenant_id = %s
              AND discovery_id = ANY(%s)
        """
        params: list = [scan_run_id, tenant_id, discovery_ids]
        if account_id:
            query += " AND account_id = %s"
            params.append(account_id)
        cur.execute(query, params)
        result: Dict[str, List[Dict]] = {}
        for row in cur.fetchall():
            did = row["discovery_id"]
            result.setdefault(did, []).append(dict(row))
        return result


def _fid(rule_id: str, resource_uid: str, scan_run_id: str) -> str:
    return hashlib.sha256(
        f"oci_l2|{rule_id}|{resource_uid}|{scan_run_id}".encode()
    ).hexdigest()[:16]


def _finding(
    finding_id: str,
    rule_id: str,
    resource_uid: str,
    region: str,
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
    severity: str,
    title: str,
    description: str,
    exposure: str = "internal",
    network_layer: str = "L4_firewall_rules",
) -> Dict[str, Any]:
    return {
        "finding_id":         finding_id,
        "scan_run_id":        scan_run_id,
        "tenant_id":          tenant_id,
        "account_id":         account_id,
        "region":             region,
        "provider":           "oci",
        "credential_ref":     credential_ref,
        "credential_type":    credential_type,
        "resource_uid":       resource_uid,
        "resource_type":      rule_id.split(".")[2] if rule_id.count(".") >= 2 else "network",
        "rule_id":            rule_id,
        "network_modules":    ["topology_analysis"],
        "effective_exposure":  exposure,
        "blast_radius_score":  0,
        "severity":           severity,
        "status":             "FAIL",
        "finding_data": {
            "source":         "oci_topology_layer2",
            "title":          title,
            "description":    description,
            "network_layer":  network_layer,
            "remediation":    "Review OCI network security configuration and restrict access to required resources only.",
        },
    }


def _layer_score(findings: List[Dict]) -> int:
    """Compute 0-100 per-layer health score (100 = no issues)."""
    if not findings:
        return 100
    sev = {"critical": 0, "high": 0}
    for f in findings:
        s = f.get("severity", "")
        if s in sev:
            sev[s] += 1
    return max(0, 100 - sev["critical"] * 20 - sev["high"] * 10)


def _is_open_cidr(source: Any) -> bool:
    return str(source or "").strip() in _OPEN_CIDRS


def _port_in_range(port: int, dest_range: Any) -> bool:
    if dest_range is None:
        return True
    if isinstance(dest_range, dict):
        low  = dest_range.get("min") or dest_range.get("from_port") or 0
        high = dest_range.get("max") or dest_range.get("to_port") or 65535
        try:
            return int(low) <= port <= int(high)
        except (TypeError, ValueError):
            return False
    return True


# ── Layer analyzers ────────────────────────────────────────────────────────────

def _analyze_l1_isolation(
    vcn_rows: List[Dict],
    igw_rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L1: VCN isolation — IGW attached signals internet exposure.

    Returns (findings, has_igw, igw_vcn_ids).
    """
    findings: List[Dict] = []
    igw_vcn_ids: set = set()

    # Collect IGW → VCN mappings
    for igw in igw_rows:
        ef     = igw.get("emitted_fields") or {}
        vcn_id = ef.get("vcn_id") or ef.get("compartment_id") or ""
        if vcn_id:
            igw_vcn_ids.add(vcn_id)

    has_igw = len(igw_vcn_ids) > 0

    for row in vcn_rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}
        vcn_id = ef.get("id") or ef.get("vcnId") or uid

        if vcn_id in igw_vcn_ids or ef.get("internet_gateways") or ef.get("igwId"):
            fid = _fid("oci.network.vcn.internet_gateway_attached", uid, scan_run_id)
            findings.append(_finding(
                fid, "oci.network.vcn.internet_gateway_attached",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="OCI VCN has Internet Gateway attached",
                description=(
                    f"VCN {uid} has an Internet Gateway attached, enabling internet access. "
                    "Ensure subnets using this VCN are protected by security lists."
                ),
                exposure="internet",
                network_layer="L1_isolation",
            ))

    # IGW without any VCN data
    if has_igw and not vcn_rows:
        for igw in igw_rows:
            uid    = igw.get("resource_uid", "")
            region = igw.get("region", "")
            fid = _fid("oci.network.vcn.internet_gateway_no_security_list", uid, scan_run_id)
            findings.append(_finding(
                fid, "oci.network.vcn.internet_gateway_no_security_list",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="high",
                title="OCI Internet Gateway present but no VCN security lists found",
                description=(
                    f"Internet Gateway {uid} is attached but no security lists were discovered. "
                    "All subnets using this IGW may be unprotected."
                ),
                exposure="internet",
                network_layer="L1_isolation",
            ))

    return findings, has_igw, igw_vcn_ids


def _analyze_l2_routing(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L2: Route tables — detect 0.0.0.0/0 routes via Internet Gateway."""
    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        route_rules = ef.get("route_rules") or ef.get("routeRules") or []
        if not isinstance(route_rules, list):
            continue

        for rule in route_rules:
            if not isinstance(rule, dict):
                continue
            cidr     = str(rule.get("destination") or rule.get("cidrBlock") or "")
            nh_type  = str(rule.get("networkEntityId") or rule.get("nextHopType") or "").lower()
            desc     = str(rule.get("description") or "").lower()

            if cidr in ("0.0.0.0/0", "::/0") and (
                "internetgateway" in nh_type or "igw" in nh_type or "internet" in desc
            ):
                fid = _fid("oci.network.route_table.internet_route", uid, scan_run_id)
                findings.append(_finding(
                    fid, "oci.network.route_table.internet_route",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="medium",
                    title="OCI Route Table has default internet route via Internet Gateway",
                    description=(
                        f"Route table {uid} routes 0.0.0.0/0 via Internet Gateway. "
                        "Subnets using this route table have direct internet access."
                    ),
                    exposure="internet",
                    network_layer="L2_routing",
                ))
                break
    return findings


def _analyze_l3_security_lists(
    rows: List[Dict],
    has_igw: bool,
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L3: Security lists — subnet-boundary ACL analysis."""
    findings: List[Dict] = []
    exposure = "internet" if has_igw else "internal"

    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        ingress_rules = ef.get("ingress_security_rules") or []
        if not isinstance(ingress_rules, list):
            continue

        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            source   = rule.get("source", "")
            protocol = str(rule.get("protocol", "all")).lower()
            tcp_opts = rule.get("tcp_options") or rule.get("tcpOptions") or {}
            dest_range = (
                tcp_opts.get("destinationPortRange")
                or tcp_opts.get("destination_port_range")
            )

            if not _is_open_cidr(source):
                continue

            if protocol in _ALL_PROTOCOLS:
                fid = _fid("oci.network.security_list.unrestricted_all_traffic", uid, scan_run_id)
                findings.append(_finding(
                    fid, "oci.network.security_list.unrestricted_all_traffic",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="critical",
                    title="OCI Security List allows all traffic from 0.0.0.0/0",
                    description=f"Security list {uid} has an ingress rule allowing ALL traffic from 0.0.0.0/0.",
                    exposure=exposure,
                    network_layer="L3_acl",
                ))
                break

            if protocol in ("6", "tcp"):
                for port in _CRITICAL_PORTS:
                    if _port_in_range(port, dest_range):
                        port_name = _PORT_NAMES.get(port, str(port))
                        fid = _fid(f"oci.network.security_list.unrestricted_port_{port}", uid, scan_run_id)
                        findings.append(_finding(
                            fid, f"oci.network.security_list.unrestricted_port_{port}",
                            uid, region, account_id, tenant_id, scan_run_id,
                            credential_ref, credential_type,
                            severity="critical" if port in (22, 3389) else "high",
                            title=f"OCI Security List allows unrestricted {port_name} ({port}) from internet",
                            description=f"Security list {uid} permits inbound {port_name} (port {port}) from 0.0.0.0/0.",
                            exposure=exposure,
                            network_layer="L3_acl",
                        ))
    return findings


def _analyze_l4_nsg_rules(
    rows: List[Dict],
    has_igw: bool,
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L4: NSG rules — open ingress from 0.0.0.0/0."""
    findings: List[Dict] = []
    for row in rows:
        uid       = row.get("resource_uid", "")
        region    = row.get("region", "")
        ef        = row.get("emitted_fields") or {}
        source    = ef.get("source") or ef.get("Source", "")
        direction = str(ef.get("direction") or ef.get("Direction") or "").upper()
        protocol  = str(ef.get("protocol") or ef.get("Protocol") or "all").lower()

        if direction != "INGRESS" or not _is_open_cidr(source):
            continue

        if protocol in _ALL_PROTOCOLS:
            fid = _fid("oci.network.nsg.unrestricted_ingress", uid, scan_run_id)
            findings.append(_finding(
                fid, "oci.network.nsg.unrestricted_ingress",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="high",
                title="OCI Network Security Group allows unrestricted ingress from 0.0.0.0/0",
                description=f"NSG rule {uid} allows all inbound traffic from 0.0.0.0/0.",
                exposure="internet" if has_igw else "internal",
                network_layer="L4_firewall_rules",
            ))
    return findings


def _analyze_l5_load_balancers(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L5: Load balancer listener protocol — detect HTTP-only listeners."""
    if not rows:
        logger.warning("L5 LB: no discovery data for oci — add %s to scanner", _L5_ID)
        return []

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        listeners = ef.get("listeners") or ef.get("listenerSummaries") or {}
        if isinstance(listeners, dict):
            listeners = list(listeners.values())
        if not isinstance(listeners, list):
            listeners = []

        for listener in listeners:
            if not isinstance(listener, dict):
                continue
            protocol = str(listener.get("protocol") or "").upper()
            if protocol == "HTTP":
                fid = _fid("oci.network.lb.http_only_listener", uid, scan_run_id)
                findings.append(_finding(
                    fid, "oci.network.lb.http_only_listener",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="medium",
                    title="OCI Load Balancer has HTTP-only listener (no TLS)",
                    description=(
                        f"Load balancer {uid} has an HTTP listener. "
                        "Configure HTTPS/SSL to encrypt traffic in transit."
                    ),
                    exposure="internet",
                    network_layer="L5_load_balancer_security",
                ))
                break
    return findings


def _analyze_l6_waf(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L6: WAAS policy — check protection mode."""
    if not rows:
        logger.warning("L6 WAF: no discovery data for oci — add %s to scanner", _L6_ID)
        return []

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        lifecycle   = str(ef.get("lifecycle_state") or ef.get("lifecycleState") or "ACTIVE").upper()
        waf_config  = ef.get("waf_config") or ef.get("wafConfig") or {}
        has_protection = bool(waf_config.get("protections")) if isinstance(waf_config, dict) else False

        if lifecycle == "ACTIVE" and not has_protection:
            fid = _fid("oci.network.waf.no_protection_rules", uid, scan_run_id)
            findings.append(_finding(
                fid, "oci.network.waf.no_protection_rules",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="OCI WAF policy has no protection rules configured",
                description=(
                    f"WAF policy {uid} is active but has no protection rules configured. "
                    "Add OWASP protection rules to block malicious traffic."
                ),
                exposure="internet",
                network_layer="L6_waf_protection",
            ))
    return findings


def _analyze_l7_monitoring(
    log_rows: List[Dict],
    vcn_rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L7: VCN flow logging — each VCN without flow logs is a finding."""
    findings: List[Dict] = []

    if not log_rows:
        logger.warning("L7 Monitoring: no log group data for oci — add %s to scanner", _L7_ID)
        for row in vcn_rows:
            uid    = row.get("resource_uid", "")
            region = row.get("region", "")
            fid = _fid("oci.network.vcn.flow_logs_disabled", uid, scan_run_id)
            findings.append(_finding(
                fid, "oci.network.vcn.flow_logs_disabled",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="OCI VCN flow logging not configured",
                description=(
                    f"VCN {uid} does not have VCN flow logs enabled. "
                    "Enable flow logging for network traffic visibility and incident response."
                ),
                exposure="internal",
                network_layer="L7_network_monitoring",
            ))
        return findings

    # Build set of VCN IDs that have flow logs configured
    flow_log_vcns: set = set()
    for row in log_rows:
        ef     = row.get("emitted_fields") or {}
        config = ef.get("configuration") or {}
        if isinstance(config, dict):
            source = config.get("source") or {}
            if isinstance(source, dict) and source.get("sourceType") == "OCISERVICE":
                resource_id = source.get("resource") or ""
                if resource_id:
                    flow_log_vcns.add(resource_id)

    for row in vcn_rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}
        vcn_id = ef.get("id") or ef.get("vcnId") or uid

        if vcn_id not in flow_log_vcns:
            fid = _fid("oci.network.vcn.flow_logs_disabled", uid, scan_run_id)
            findings.append(_finding(
                fid, "oci.network.vcn.flow_logs_disabled",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="OCI VCN flow logging not configured",
                description=f"VCN {uid} does not have flow logs enabled in any log group.",
                exposure="internal",
                network_layer="L7_network_monitoring",
            ))
    return findings


# ── Provider ───────────────────────────────────────────────────────────────────

class OCINetworkProvider(BaseNetworkProvider):
    """7-layer topology analysis for OCI — VCN/Security-List/NSG graph."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        credential_ref: str,
        credential_type: str,
    ) -> Dict[str, Any]:
        start = time.time()
        logger.info("OCI 7-layer topology analysis starting for scan %s", scan_run_id)

        from engine_common.db_connections import get_discoveries_conn
        conn = get_discoveries_conn()

        try:
            layers = _load_all_layers(conn, scan_run_id, tenant_id, _ALL_LAYER_IDS, account_id)
        finally:
            conn.close()

        if not any(layers.values()):
            logger.info("OCI Layer 2: no network discovery data found for scan %s", scan_run_id)
            return {
                "status": "skipped",
                "reason": "No OCI network discovery data found",
                "findings": [],
                "topology_snapshots": [],
                "report_metrics": _EMPTY_METRICS,
                "scan_duration_ms": int((time.time() - start) * 1000),
            }

        l1_rows  = layers.get(_L1_ID, [])
        l2_rows  = layers.get(_L2_ID, [])
        l3_rows  = layers.get(_L3_ID, [])
        l4_rows  = layers.get(_L4_ID, [])
        l5_rows  = layers.get(_L5_ID, [])
        l6_rows  = layers.get(_L6_ID, [])
        l7_rows  = layers.get(_L7_ID, [])
        igw_rows = layers.get(_IGW_ID, [])

        # L1
        l1_findings, has_igw, igw_vcn_ids = _analyze_l1_isolation(
            l1_rows, igw_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L1 Isolation: %d findings (has_igw=%s)", len(l1_findings), has_igw)

        # L2
        l2_findings = _analyze_l2_routing(
            l2_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L2 Routing: %d findings", len(l2_findings))

        # L3
        l3_findings = _analyze_l3_security_lists(
            l3_rows, has_igw, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L3 Security Lists: %d findings", len(l3_findings))

        # L4
        l4_findings = _analyze_l4_nsg_rules(
            l4_rows, has_igw, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L4 NSG Rules: %d findings", len(l4_findings))

        # L5
        l5_findings = _analyze_l5_load_balancers(
            l5_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L5 Load Balancers: %d findings", len(l5_findings))

        # L6
        l6_findings = _analyze_l6_waf(
            l6_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L6 WAF: %d findings", len(l6_findings))

        # L7
        l7_findings = _analyze_l7_monitoring(
            l7_rows, l1_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L7 Monitoring: %d findings", len(l7_findings))

        all_findings = (
            l1_findings + l2_findings + l3_findings + l4_findings
            + l5_findings + l6_findings + l7_findings
        )

        # Dedup within provider
        seen: dict = {}
        for f in all_findings:
            seen[f["finding_id"]] = f
        all_findings = list(seen.values())

        duration_ms = int((time.time() - start) * 1000)
        total = len(all_findings)
        sev   = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in all_findings:
            s = f.get("severity", "medium")
            sev[s] = sev.get(s, 0) + 1

        logger.info(
            "OCI 7-layer complete: L1=%d L2=%d L3=%d L4=%d L5=%d L6=%d L7=%d total=%d in %dms",
            len(l1_findings), len(l2_findings), len(l3_findings), len(l4_findings),
            len(l5_findings), len(l6_findings), len(l7_findings), total, duration_ms,
        )

        metrics = {
            **_EMPTY_METRICS,
            "posture_score":       max(0, 100 - sev["critical"] * 20 - sev["high"] * 10 - sev["medium"] * 5),
            "topology_score":      _layer_score(l1_findings),
            "reachability_score":  _layer_score(l2_findings),
            "nacl_score":          _layer_score(l3_findings),
            "firewall_score":      _layer_score(l4_findings),
            "lb_score":            _layer_score(l5_findings),
            "waf_score":           _layer_score(l6_findings),
            "monitoring_score":    _layer_score(l7_findings),
            "total_findings":      total,
            "critical_findings":   sev["critical"],
            "high_findings":       sev["high"],
            "medium_findings":     sev["medium"],
            "low_findings":        sev["low"],
            "total_security_groups":  len(l3_rows) + len(l4_rows),
            "total_load_balancers":   len(l5_rows),
            "total_igws":             len(igw_rows),
            "internet_exposed_resources": sum(
                1 for f in all_findings if f.get("effective_exposure") == "internet"
            ),
            "findings_by_module":  {"topology_analysis": total},
            "findings_by_status":  {"FAIL": total},
            "findings_by_layer": {
                "L1_isolation":  len(l1_findings),
                "L2_routing":    len(l2_findings),
                "L3_acl":        len(l3_findings),
                "L4_firewall":   len(l4_findings),
                "L5_lb":         len(l5_findings),
                "L6_waf":        len(l6_findings),
                "L7_monitoring": len(l7_findings),
            },
            "severity_breakdown": sev,
            "exposure_summary": {
                "internet_exposed": sum(
                    1 for f in all_findings if f.get("effective_exposure") == "internet"
                ),
                "cross_vpc":  0,
                "vpc_internal": sum(
                    1 for f in all_findings if f.get("effective_exposure") == "internal"
                ),
            },
        }

        return {
            "status":             "completed",
            "findings":           all_findings,
            "topology_snapshots": [],
            "report_metrics":     metrics,
            "scan_duration_ms":   duration_ms,
        }
