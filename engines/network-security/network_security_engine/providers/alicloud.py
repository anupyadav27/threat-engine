"""
AliCloud network-security provider — 7-layer topology analysis.

Layer mapping:
  L1 Isolation:   VPC structure and internet-facing NAT
  L2 Routing:     Route tables with internet routes
  L3 ACL:         Network ACLs with permit-all inbound rules
  L4 Firewall:    Security group rules (open ports, wildcard ingress)
  L5 LB:          SLB internet-facing listener security
  L6 WAF:         WAF instance coverage
  L7 Monitoring:  ActionTrail enabled for audit logging
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from psycopg2.extras import RealDictCursor

from .base import BaseNetworkProvider

logger = logging.getLogger(__name__)

# ── Shared empty metrics (imported by azure.py, oci.py, gcp.py) ───────────────
_EMPTY_METRICS: Dict[str, Any] = {
    "posture_score": 0,
    "topology_score": 100,
    "reachability_score": 100,
    "nacl_score": 100,
    "firewall_score": 100,
    "lb_score": 100,
    "waf_score": 100,
    "monitoring_score": 100,
    "total_findings": 0,
    "critical_findings": 0,
    "high_findings": 0,
    "medium_findings": 0,
    "low_findings": 0,
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
    "internet_exposed_resources": 0,
    "cross_vpc_paths_count": 0,
    "orphaned_sg_count": 0,
    "findings_by_module": {},
    "findings_by_status": {},
    "findings_by_layer": {},
    "severity_breakdown": {},
    "exposure_summary": {"internet_exposed": 0, "cross_vpc": 0, "vpc_internal": 0},
}

# ── Discovery IDs ──────────────────────────────────────────────────────────────
_L1_ID = "alicloud.vpc.describe_vpcs"
_L2_ID = "alicloud.vpc.describe_route_tables"
_L3_ID = "alicloud.vpc.describe_network_acls"
_L4_ID = "alicloud.ecs.describe_security_groups"
_L5_ID = "alicloud.slb.describe_load_balancers"
_L6_ID = "alicloud.waf.describe_instances"
_L7_ID = "alicloud.actiontrail.describe_trails"

_ALL_LAYER_IDS = [_L1_ID, _L2_ID, _L3_ID, _L4_ID, _L5_ID, _L6_ID, _L7_ID]

_CRITICAL_PORTS = {22, 3389, 1433, 3306, 5432, 6379, 27017}
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
        f"alicloud_l2|{rule_id}|{resource_uid}|{scan_run_id}".encode()
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
    """Build a network topology finding.

    blast_radius_score is always 0 — the risk engine fills this from the
    full resource relationship graph. This engine only determines
    network-level reachability (effective_exposure).
    """
    return {
        "finding_id":         finding_id,
        "scan_run_id":        scan_run_id,
        "tenant_id":          tenant_id,
        "account_id":         account_id,
        "region":             region,
        "provider":           "alicloud",
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
            "source":         "alicloud_topology_layer2",
            "title":          title,
            "description":    description,
            "network_layer":  network_layer,
            "remediation":    "Restrict security group rules to specific CIDR ranges. Remove 0.0.0.0/0 ingress rules for critical ports.",
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


def _is_open_cidr(cidr: Any) -> bool:
    return str(cidr or "").strip() in _OPEN_CIDRS


# ── Layer analyzers ────────────────────────────────────────────────────────────

def _analyze_l1_isolation(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L1: VPC isolation — detect VPCs with attached internet NAT or EIP.

    Returns (findings, has_internet_exposure).
    """
    findings: List[Dict] = []
    has_internet_exposure = False

    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        # NAT gateways indicate internet-facing VPC
        nat_gateways = ef.get("nat_gateways") or ef.get("NatGateways") or []
        if isinstance(nat_gateways, list) and nat_gateways:
            has_internet_exposure = True
            fid = _fid("alicloud.network.vpc.nat_gateway_attached", uid, scan_run_id)
            findings.append(_finding(
                fid, "alicloud.network.vpc.nat_gateway_attached",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="AliCloud VPC has NAT Gateway attached — internet access enabled",
                description=(
                    f"VPC {uid} has {len(nat_gateways)} NAT Gateway(s) attached. "
                    "Ensure outbound internet access is restricted to required VSwitches only."
                ),
                exposure="internet",
                network_layer="L1_isolation",
            ))

        # CEN (Cloud Enterprise Network) attachments indicate cross-VPC peering
        cen_id = ef.get("cen_id") or ef.get("CenId") or ""
        if cen_id:
            has_internet_exposure = True

        # Broad CIDR flag — /16 or larger increases blast radius if VPC is compromised
        cidr = str(ef.get("CidrBlock") or ef.get("cidr_block") or "")
        if cidr and "/" in cidr:
            try:
                prefix = int(cidr.split("/")[1])
                if prefix <= 16:
                    fid = _fid("alicloud.network.vpc.broad_cidr", uid, scan_run_id)
                    findings.append(_finding(
                        fid, "alicloud.network.vpc.broad_cidr",
                        uid, region, account_id, tenant_id, scan_run_id,
                        credential_ref, credential_type,
                        severity="low",
                        title=f"AliCloud VPC uses broad CIDR /{prefix} — verify network segmentation",
                        description=(
                            f"VPC {uid} has a /{prefix} CIDR block ({cidr}). "
                            "Large address spaces increase the blast radius if a resource is compromised. "
                            "Consider segmenting into smaller subnets with Network ACLs."
                        ),
                        exposure="internal",
                        network_layer="L1_isolation",
                    ))
            except (ValueError, IndexError):
                pass

    return findings, has_internet_exposure


def _analyze_l2_routing(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L2: Route tables — detect custom routes to the internet or empty route tables."""
    if not rows:
        logger.warning("L2 Routing: no discovery data for alicloud — add %s to scanner", _L2_ID)
        return []

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        route_entries = ef.get("route_entries") or ef.get("RouteEntries") or []
        route_count   = ef.get("RouteCounts") or ef.get("route_counts") or 0

        # Empty route table — no routes configured; connectivity intent unclear
        if not route_entries and int(route_count) == 0:
            fid = _fid("alicloud.network.route_table.no_routes", uid, scan_run_id)
            findings.append(_finding(
                fid, "alicloud.network.route_table.no_routes",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="low",
                title="AliCloud Route Table has no routes configured — connectivity intent unclear",
                description=(
                    f"Route table {uid} has no route entries. "
                    "Verify that network routing is intentionally restricted or configure routes explicitly."
                ),
                exposure="internal",
                network_layer="L2_routing",
            ))
            continue

        if not isinstance(route_entries, list):
            continue

        for entry in route_entries:
            if not isinstance(entry, dict):
                continue
            dest = str(entry.get("destination_cidr_block") or entry.get("DestinationCidrBlock") or "")
            nh_type = str(entry.get("next_hop_type") or entry.get("NextHopType") or "").lower()
            status = str(entry.get("status") or entry.get("Status") or "available").lower()

            if dest in ("0.0.0.0/0", "::/0") and "internet" in nh_type and status == "available":
                fid = _fid("alicloud.network.route_table.internet_route", uid, scan_run_id)
                findings.append(_finding(
                    fid, "alicloud.network.route_table.internet_route",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="medium",
                    title="AliCloud Route Table has internet route for 0.0.0.0/0",
                    description=(
                        f"Route table {uid} routes 0.0.0.0/0 to the internet. "
                        "VSwitches using this route table have direct internet access."
                    ),
                    exposure="internet",
                    network_layer="L2_routing",
                ))
                break
    return findings


def _analyze_l3_acl(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L3: Network ACLs — permit-all inbound rules from 0.0.0.0/0, or absence of ACL."""
    if not rows:
        logger.warning("L3 ACL: no Network ACL discovery data for alicloud scan")
        fid = _fid("alicloud.network.acl.not_configured", account_id, scan_run_id)
        return [_finding(
            fid, "alicloud.network.acl.not_configured",
            account_id, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="medium",
            title="AliCloud Network ACL not configured — VPC subnet boundary unprotected",
            description=(
                "No Network ACL was found for this account. "
                "Network ACLs provide subnet-boundary traffic filtering. "
                "Configure ACLs for each VSwitch to enforce inbound/outbound rules."
            ),
            exposure="internal",
            network_layer="L3_acl",
        )]

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        ingress_rules = ef.get("ingress_acl_entries") or ef.get("IngressAclEntries") or []
        if not isinstance(ingress_rules, list):
            continue

        for rule in ingress_rules:
            if not isinstance(rule, dict):
                continue
            source_cidr = str(rule.get("source_cidr_ip") or rule.get("SourceCidrIp") or "")
            policy      = str(rule.get("policy") or rule.get("Policy") or "accept").lower()
            port        = str(rule.get("port") or rule.get("Port") or "-1/-1")

            if not _is_open_cidr(source_cidr) or policy not in ("accept", "allow"):
                continue

            if port in ("-1/-1", "1/65535", "*"):
                fid = _fid("alicloud.network.acl.unrestricted_inbound", uid, scan_run_id)
                findings.append(_finding(
                    fid, "alicloud.network.acl.unrestricted_inbound",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="high",
                    title="AliCloud Network ACL permits all inbound traffic from 0.0.0.0/0",
                    description=(
                        f"Network ACL {uid} has an inbound Accept rule for all ports from 0.0.0.0/0. "
                        "Restrict inbound traffic to required ports and sources only."
                    ),
                    exposure="internet",
                    network_layer="L3_acl",
                ))
                break
    return findings


def _analyze_l4_security_groups(
    rows: List[Dict],
    has_internet_exposure: bool,
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L4: Security group rules — open ingress from 0.0.0.0/0.

    Returns (findings, sg_count, eip_count).
    """
    findings: List[Dict] = []
    sg_count = 0
    eip_count = 0
    exposure = "internet" if has_internet_exposure else "internal"

    for row in rows:
        ef     = row.get("emitted_fields") or {}
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")

        # EIPs embedded in SG discovery
        if ef.get("eip_address") or ef.get("AllocationId"):
            eip_count += 1
            has_internet_exposure = True
            exposure = "internet"

        permissions = ef.get("permissions") or ef.get("Permissions") or []
        if not isinstance(permissions, list):
            perm_wrapper = ef.get("Permissions") or {}
            permissions = perm_wrapper.get("Permission") or []

        if not permissions:
            sg_id = ef.get("SecurityGroupId") or ef.get("security_group_id") or uid
            if sg_id or ef.get("security_group_id") or ef.get("SecurityGroupId"):
                sg_count += 1
                # Empty SG — no inbound rules means access control is not configured
                fid = _fid("alicloud.network.sg.no_rules", uid, scan_run_id)
                findings.append(_finding(
                    fid, "alicloud.network.sg.no_rules",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="medium",
                    title=f"AliCloud Security Group has no inbound rules — access control unconfigured",
                    description=(
                        f"Security group {uid} has no inbound rules defined. "
                        "Verify that resource access control is intentional or configure explicit allow rules."
                    ),
                    exposure="internal",
                    network_layer="L4_firewall_rules",
                ))
            continue

        sg_count += 1
        for perm in permissions:
            if not isinstance(perm, dict):
                continue
            direction   = str(perm.get("direction") or perm.get("Direction") or "ingress").lower()
            source_cidr = (
                perm.get("source_cidr_ip") or perm.get("SourceCidrIp")
                or perm.get("ipv6_source_cidr_ip") or ""
            )
            policy      = str(perm.get("policy") or perm.get("Policy") or "accept").lower()
            protocol    = str(perm.get("ip_protocol") or perm.get("IpProtocol") or "all").lower()
            port_range  = str(perm.get("port_range") or perm.get("PortRange") or "-1/-1")

            if direction not in ("ingress", "inbound", "in"):
                continue
            if policy not in ("accept", "allow", ""):
                continue
            if not _is_open_cidr(source_cidr):
                continue

            if protocol in ("all", "-1"):
                fid = _fid("alicloud.network.sg.unrestricted_all_traffic", uid, scan_run_id)
                findings.append(_finding(
                    fid, "alicloud.network.sg.unrestricted_all_traffic",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="critical",
                    title="AliCloud Security Group allows all inbound traffic from 0.0.0.0/0",
                    description=(
                        f"Security group {uid} has an ingress rule allowing ALL traffic from 0.0.0.0/0. "
                        "Remove this rule and restrict access to specific CIDRs."
                    ),
                    exposure=exposure,
                    network_layer="L4_firewall_rules",
                ))
                break

            if protocol in ("tcp", "6"):
                parts = port_range.split("/")
                try:
                    low  = int(parts[0]) if parts[0] not in ("-1", "*") else 1
                    high = int(parts[1]) if len(parts) > 1 and parts[1] not in ("-1", "*") else 65535
                except (ValueError, IndexError):
                    low, high = 1, 65535

                for port in _CRITICAL_PORTS:
                    if low <= port <= high:
                        port_name = _PORT_NAMES.get(port, str(port))
                        fid = _fid(f"alicloud.network.sg.unrestricted_port_{port}", uid, scan_run_id)
                        findings.append(_finding(
                            fid, f"alicloud.network.sg.unrestricted_port_{port}",
                            uid, region, account_id, tenant_id, scan_run_id,
                            credential_ref, credential_type,
                            severity="critical" if port in (22, 3389) else "high",
                            title=f"AliCloud Security Group allows unrestricted {port_name} ({port}) from 0.0.0.0/0",
                            description=(
                                f"Security group {uid} permits inbound {port_name} (port {port}) from 0.0.0.0/0."
                            ),
                            exposure=exposure,
                            network_layer="L4_firewall_rules",
                        ))

    return findings, sg_count, eip_count


def _analyze_l5_slb(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L5: SLB internet-facing detection. Returns (findings, internet_facing_set)."""
    if not rows:
        logger.warning("L5 LB: no SLB discovery data for alicloud scan")
        fid = _fid("alicloud.network.slb.not_configured", account_id, scan_run_id)
        return [_finding(
            fid, "alicloud.network.slb.not_configured",
            account_id, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="low",
            title="AliCloud SLB not found — load balancer TLS enforcement not assessed",
            description=(
                "No Server Load Balancer (SLB) instances were found. "
                "If internet-facing services exist, ensure HTTPS/TLS is enforced via SLB listeners."
            ),
            exposure="internal",
            network_layer="L5_load_balancer_security",
        )], set()

    findings: List[Dict] = []
    internet_facing_slbs: set = set()

    for row in rows:
        ef  = row.get("emitted_fields") or {}
        uid = row.get("resource_uid", "")

        addr_type = str(ef.get("address_type") or ef.get("AddressType") or "").lower()
        if "internet" in addr_type or "public" in addr_type:
            internet_facing_slbs.add(uid)

    for uid in internet_facing_slbs:
        fid = _fid("alicloud.network.slb.internet_facing", uid, scan_run_id)
        findings.append(_finding(
            fid, "alicloud.network.slb.internet_facing",
            uid, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="medium",
            title="AliCloud SLB is internet-facing — verify listener security",
            description=(
                f"Load balancer {uid} has an internet-facing address. "
                "Ensure HTTPS listeners are used and HTTP is redirected."
            ),
            exposure="internet",
            network_layer="L5_load_balancer_security",
        ))

    return findings, internet_facing_slbs


def _analyze_l6_waf(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L6: WAF instance coverage."""
    if not rows:
        logger.warning("L6 WAF: no WAF discovery data for alicloud scan")
        fid = _fid("alicloud.network.waf.not_configured", account_id, scan_run_id)
        return [_finding(
            fid, "alicloud.network.waf.not_configured",
            account_id, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="medium",
            title="AliCloud WAF instance not found — web application traffic unprotected",
            description=(
                "No WAF (Web Application Firewall) instances were found. "
                "Enable WAF to protect internet-facing applications from OWASP Top 10 attacks, "
                "DDoS, and bot traffic."
            ),
            exposure="internet",
            network_layer="L6_waf_protection",
        )]

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        status = str(ef.get("status") or ef.get("Status") or "1")
        # Status 1 = enabled; check if in detection-only mode
        in_detection = str(ef.get("in_debt") or ef.get("InDebt") or "0") == "1"

        if in_detection:
            fid = _fid("alicloud.network.waf.detection_mode", uid, scan_run_id)
            findings.append(_finding(
                fid, "alicloud.network.waf.detection_mode",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="AliCloud WAF instance is in debt/degraded state",
                description=(
                    f"WAF instance {uid} is in a degraded state (InDebt=true). "
                    "Renew the WAF subscription to restore full protection."
                ),
                exposure="internet",
                network_layer="L6_waf_protection",
            ))
    return findings


def _analyze_l7_monitoring(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L7: ActionTrail — detect disabled or absent audit trails."""
    if not rows:
        logger.warning("L7 Monitoring: no trail data for alicloud — add %s to scanner", _L7_ID)
        fid = _fid("alicloud.network.actiontrail.no_trail", account_id, scan_run_id)
        return [_finding(
            fid, "alicloud.network.actiontrail.no_trail",
            account_id, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="high",
            title="AliCloud ActionTrail not configured — no API audit logging",
            description=(
                "No ActionTrail trails were found. Enable ActionTrail to log all API calls "
                "to OSS or SLS for security monitoring and incident response."
            ),
            exposure="internal",
            network_layer="L7_network_monitoring",
        )]

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        status  = str(ef.get("status") or ef.get("Status") or "Enable").lower()
        enabled = status in ("enable", "enabled", "1", "true")

        if not enabled:
            fid = _fid("alicloud.network.actiontrail.disabled", uid, scan_run_id)
            findings.append(_finding(
                fid, "alicloud.network.actiontrail.disabled",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="high",
                title="AliCloud ActionTrail trail is disabled",
                description=(
                    f"ActionTrail trail {uid} is disabled. "
                    "Re-enable the trail to restore API audit logging."
                ),
                exposure="internal",
                network_layer="L7_network_monitoring",
            ))
    return findings


# ── Provider ───────────────────────────────────────────────────────────────────

class AliCloudNetworkProvider(BaseNetworkProvider):
    """7-layer topology analysis for AliCloud — VPC/SG/SLB graph."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        credential_ref: str,
        credential_type: str,
    ) -> Dict[str, Any]:
        start = time.time()
        logger.info("AliCloud 7-layer topology analysis starting for scan %s", scan_run_id)

        from engine_common.db_connections import get_discoveries_conn
        conn = get_discoveries_conn()

        try:
            layers = _load_all_layers(conn, scan_run_id, tenant_id, _ALL_LAYER_IDS, account_id)
        finally:
            conn.close()

        if not any(layers.values()):
            logger.info("AliCloud Layer 2: no network discovery data for scan %s", scan_run_id)
            return {
                "status": "skipped",
                "reason": "No AliCloud network discovery data found",
                "findings": [],
                "topology_snapshots": [],
                "report_metrics": _EMPTY_METRICS,
                "scan_duration_ms": int((time.time() - start) * 1000),
            }

        l1_rows = layers.get(_L1_ID, [])
        l2_rows = layers.get(_L2_ID, [])
        l3_rows = layers.get(_L3_ID, [])
        l4_rows = layers.get(_L4_ID, [])
        l5_rows = layers.get(_L5_ID, [])
        l6_rows = layers.get(_L6_ID, [])
        l7_rows = layers.get(_L7_ID, [])

        # L1
        l1_findings, has_internet = _analyze_l1_isolation(
            l1_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L1 Isolation: %d findings (internet=%s)", len(l1_findings), has_internet)

        # L2
        l2_findings = _analyze_l2_routing(
            l2_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L2 Routing: %d findings", len(l2_findings))

        # L3
        l3_findings = _analyze_l3_acl(
            l3_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L3 ACL: %d findings", len(l3_findings))

        # L4
        l4_findings, sg_count, eip_count = _analyze_l4_security_groups(
            l4_rows, has_internet, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L4 Security Groups: %d findings (sg_count=%d)", len(l4_findings), sg_count)

        # L5
        l5_findings, internet_facing_slbs = _analyze_l5_slb(
            l5_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        if internet_facing_slbs:
            has_internet = True
        logger.info("L5 SLB: %d findings (%d internet-facing)", len(l5_findings), len(internet_facing_slbs))

        # L6
        l6_findings = _analyze_l6_waf(
            l6_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L6 WAF: %d findings", len(l6_findings))

        # L7
        l7_findings = _analyze_l7_monitoring(
            l7_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
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
            "AliCloud 7-layer complete: L1=%d L2=%d L3=%d L4=%d L5=%d L6=%d L7=%d total=%d in %dms",
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
            "total_security_groups":  sg_count,
            "total_load_balancers":   len(internet_facing_slbs),
            "total_eips":             eip_count,
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
