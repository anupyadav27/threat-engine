"""
Azure network-security provider — 7-layer topology analysis.

Layer mapping:
  L1 Isolation:   VNet presence and VNet peering connections
  L2 Routing:     Route tables with custom internet routes
  L3 ACL:         Application Security Groups (structural check)
  L4 Firewall:    NSG inbound ALLOW rules (critical ports / wildcard)
  L5 LB:          Load balancers and App Gateways with public frontends
  L6 WAF:         Web Application Firewall policy coverage
  L7 Monitoring:  Network Watcher presence (enables NSG flow logs)

Discovery IDs use the verified actual values from discovery_findings DB
(dot-separated, no underscores, .list_all suffix).
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

# ── Discovery IDs (verified against discovery_findings.discovery_id) ──────────
_L1_ID = "azure.network.virtualnetworks.list_all"
_L2_ID = "azure.network.routetables.list_all"
_L3_ID = "azure.network.applicationsecuritygroups.list_all"
_L4_ID = "azure.network.networksecuritygroups.list_all"
_L5_ID = "azure.network.loadbalancers.list_all"
_L6_ID = "azure.network.webapplicationfirewallpolicies.list_all"
_L7_ID = "azure.network.networkwatchers.list_all"

# Also load app gateways for L5 (supplementary — may or may not exist)
_L5_APPGW_ID = "azure.network.applicationgateways.list_all"
# Public IPs for internet-exposure detection
_PUBLIC_IP_ID = "azure.network.publicipaddresses.list_all"

_ALL_LAYER_IDS = [
    _L1_ID, _L2_ID, _L3_ID, _L4_ID, _L5_ID, _L5_APPGW_ID, _L6_ID, _L7_ID,
    _PUBLIC_IP_ID,
]

_CRITICAL_PORTS = {22, 3389, 1433, 3306, 5432, 6379, 27017}
_INTERNET_SOURCES = {"0.0.0.0/0", "::/0", "*", "Internet", "Any", "internet", "any"}


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
        f"azure_l2|{rule_id}|{resource_uid}|{scan_run_id}".encode()
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
        "provider":           "azure",
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
            "source":         "azure_topology_layer2",
            "title":          title,
            "description":    description,
            "network_layer":  network_layer,
            "remediation":    "Review Azure network configuration and restrict access to required resources only.",
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


def _is_internet_source(source: Any) -> bool:
    return str(source or "").strip() in _INTERNET_SOURCES


def _port_matches(port_range: Any, target_port: int) -> bool:
    """Check if an Azure port range string covers the target port."""
    s = str(port_range or "").strip()
    if s in ("*", "Any", "any", ""):
        return True
    if "-" in s:
        parts = s.split("-", 1)
        try:
            return int(parts[0]) <= target_port <= int(parts[1])
        except (ValueError, IndexError):
            return False
    try:
        return int(s) == target_port
    except ValueError:
        return False


def _parse_nsg_security_rules(ef: Dict) -> List[Dict]:
    """Extract security rules from NSG emitted_fields — handles multiple shapes."""
    for key in ("security_rules", "securityRules"):
        rules = ef.get(key) or []
        if isinstance(rules, list) and rules:
            return rules

    props = ef.get("properties") or {}
    if isinstance(props, dict):
        for key in ("securityRules", "security_rules"):
            rules = props.get(key) or []
            if isinstance(rules, list) and rules:
                return rules

    rules = ef.get("rules") or []
    return rules if isinstance(rules, list) else []


# ── Layer analyzers ────────────────────────────────────────────────────────────

def _analyze_l1_isolation(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L1: VNet peering — each peering connection is a lateral-movement vector."""
    findings = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        peerings = (
            ef.get("virtual_network_peerings")
            or ef.get("virtualNetworkPeerings")
            or (ef.get("properties") or {}).get("virtualNetworkPeerings")
            or []
        )
        if not isinstance(peerings, list):
            peerings = []

        if peerings:
            fid = _fid("azure.network.vnet.peering_enabled", uid, scan_run_id)
            findings.append(_finding(
                fid, "azure.network.vnet.peering_enabled",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="Azure VNet has VNet peering connections — verify trust boundary",
                description=(
                    f"VNet {uid} has {len(peerings)} peering connection(s). "
                    "Ensure peered networks are trusted and NSGs restrict lateral movement."
                ),
                exposure="internal",
                network_layer="L1_isolation",
            ))
    return findings


def _analyze_l2_routing(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L2: Route tables — custom UDRs that route 0.0.0.0/0 to internet."""
    findings = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        routes = (
            ef.get("routes")
            or (ef.get("properties") or {}).get("routes")
            or []
        )
        if not isinstance(routes, list):
            continue

        for route in routes:
            if not isinstance(route, dict):
                continue
            route_props = route.get("properties") or route
            prefix = str(route_props.get("addressPrefix") or route_props.get("address_prefix") or "")
            next_hop = str(route_props.get("nextHopType") or route_props.get("next_hop_type") or "").lower()

            if prefix in ("0.0.0.0/0", "::/0") and "internet" in next_hop:
                fid = _fid("azure.network.route_table.internet_route", uid, scan_run_id)
                findings.append(_finding(
                    fid, "azure.network.route_table.internet_route",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="medium",
                    title="Azure Route Table has user-defined route to Internet for 0.0.0.0/0",
                    description=(
                        f"Route table {uid} routes all traffic (0.0.0.0/0) to the Internet. "
                        "Verify this is intentional and subnets are NSG-protected."
                    ),
                    exposure="internet",
                    network_layer="L2_routing",
                ))
                break
    return findings


def _analyze_l3_asg(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L3: Application Security Groups — structural check (count only, no L3 ACL in Azure)."""
    # Azure has no subnet-boundary ACL equivalent — ASGs are logical groupings.
    # No negative finding here; score=100 unless ASGs are absent when NSGs reference them.
    if not rows:
        logger.warning("L3 ASG: no discovery data for azure — add %s to scanner", _L3_ID)
    return []


def _analyze_l4_nsg(
    rows: List[Dict],
    has_internet_exposure: bool,
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L4: NSG inbound ALLOW rules — unrestricted ports, wildcard traffic.

    Returns (findings, nsg_count).
    """
    findings: List[Dict] = []
    nsg_count = 0
    exposure = "internet" if has_internet_exposure else "internal"

    for row in rows:
        ef     = row.get("emitted_fields") or {}
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")

        security_rules = _parse_nsg_security_rules(ef)
        if not security_rules:
            if ef.get("name") or ef.get("id") or "nsg" in uid.lower():
                nsg_count += 1
            continue

        nsg_count += 1

        for rule in security_rules:
            if not isinstance(rule, dict):
                continue

            rule_props = rule.get("properties") or rule
            direction  = str(rule_props.get("direction") or rule.get("direction") or "").title()
            access     = str(rule_props.get("access") or rule.get("access") or "").title()

            if direction != "Inbound" or access != "Allow":
                continue

            source = (
                rule_props.get("sourceAddressPrefix")
                or rule_props.get("source_address_prefix")
                or rule.get("sourceAddressPrefix")
                or rule.get("source_address_prefix")
                or ""
            )

            if not _is_internet_source(source):
                continue

            dest_port = (
                rule_props.get("destinationPortRange")
                or rule_props.get("destination_port_range")
                or rule.get("destinationPortRange")
                or rule.get("destination_port_range")
                or "*"
            )
            protocol = str(
                rule_props.get("protocol") or rule.get("protocol") or "*"
            ).lower()

            # All-traffic wildcard
            if str(dest_port).strip() in ("*", "Any", "any") and protocol in ("*", "any", "tcp", "udp"):
                fid = _fid("azure.network.nsg.unrestricted_all_traffic", uid, scan_run_id)
                findings.append(_finding(
                    fid, "azure.network.nsg.unrestricted_all_traffic",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="critical",
                    title="Azure NSG allows all inbound traffic from Internet/0.0.0.0/0",
                    description=f"NSG {uid} has an inbound Allow rule for all ports/protocols from {source}.",
                    exposure=exposure,
                    network_layer="L4_firewall_rules",
                ))
                break

            # Critical port checks
            if protocol in ("tcp", "*", "any", "6", ""):
                dest_port_ranges = (
                    rule_props.get("destinationPortRanges")
                    or rule_props.get("destination_port_ranges")
                    or rule.get("destinationPortRanges")
                    or []
                )
                if not isinstance(dest_port_ranges, list):
                    dest_port_ranges = []
                all_ranges = [dest_port] + dest_port_ranges

                for port in _CRITICAL_PORTS:
                    if any(_port_matches(pr, port) for pr in all_ranges):
                        port_name = {
                            22: "SSH", 3389: "RDP", 1433: "MSSQL",
                            3306: "MySQL", 5432: "PostgreSQL",
                            6379: "Redis", 27017: "MongoDB",
                        }.get(port, str(port))
                        severity = "critical" if port in (22, 3389) else "high"
                        fid = _fid(f"azure.network.nsg.unrestricted_port_{port}", uid, scan_run_id)
                        findings.append(_finding(
                            fid, f"azure.network.nsg.unrestricted_port_{port}",
                            uid, region, account_id, tenant_id, scan_run_id,
                            credential_ref, credential_type,
                            severity=severity,
                            title=f"Azure NSG allows unrestricted {port_name} ({port}) from Internet",
                            description=f"NSG {uid} permits inbound {port_name} (port {port}) from {source}.",
                            exposure=exposure,
                            network_layer="L4_firewall_rules",
                        ))

    return findings, nsg_count


def _analyze_l5_load_balancers(
    lb_rows: List[Dict],
    appgw_rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L5: LBs + App Gateways with public frontends. Returns (findings, internet_facing_set)."""
    findings: List[Dict] = []
    internet_facing_lbs: set = set()

    for row in lb_rows + appgw_rows:
        ef  = row.get("emitted_fields") or {}
        uid = row.get("resource_uid", "")

        frontend_configs = (
            ef.get("frontend_ip_configurations")
            or ef.get("frontendIPConfigurations")
            or (ef.get("properties") or {}).get("frontendIPConfigurations")
            or []
        )
        if isinstance(frontend_configs, list):
            for fc in frontend_configs:
                if isinstance(fc, dict):
                    fc_props = fc.get("properties") or fc
                    if fc_props.get("publicIPAddress") or fc_props.get("public_ip_address"):
                        internet_facing_lbs.add(uid)
                        break

    for uid in internet_facing_lbs:
        fid = _fid("azure.network.lb.internet_facing", uid, scan_run_id)
        findings.append(_finding(
            fid, "azure.network.lb.internet_facing",
            uid, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="medium",
            title="Azure Load Balancer is internet-facing — verify NSG protection",
            description=(
                f"Load balancer {uid} has a public frontend IP. "
                "Ensure backend subnets have NSGs with restricted ingress."
            ),
            exposure="internet",
            network_layer="L5_load_balancer_security",
        ))

    return findings, internet_facing_lbs


def _analyze_l6_waf(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L6: WAF policy coverage."""
    if not rows:
        logger.warning("L6 WAF: no discovery data for azure — add %s to scanner", _L6_ID)
        return []

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        props = ef.get("properties") or ef
        mode  = str(props.get("policySettings", {}).get("mode") or props.get("mode") or "").lower()

        if mode == "detection":
            fid = _fid("azure.network.waf.detection_mode_only", uid, scan_run_id)
            findings.append(_finding(
                fid, "azure.network.waf.detection_mode_only",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="Azure WAF policy is in Detection mode — switch to Prevention",
                description=(
                    f"WAF policy {uid} is in Detection mode and will not block malicious requests. "
                    "Switch to Prevention mode to actively protect applications."
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
    """L7: Network Watcher presence — required for NSG flow logs."""
    if not rows:
        logger.warning("L7 Monitoring: no Network Watcher data for azure — add %s to scanner", _L7_ID)
        fid = _fid("azure.network.watcher.not_configured", account_id, scan_run_id)
        return [_finding(
            fid, "azure.network.watcher.not_configured",
            account_id, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="medium",
            title="Azure Network Watcher not found — NSG flow logs cannot be enabled",
            description=(
                "No Network Watcher was discovered in this subscription. "
                "Enable Network Watcher in all regions to allow NSG flow log collection."
            ),
            exposure="internal",
            network_layer="L7_network_monitoring",
        )]

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}
        props  = ef.get("properties") or ef
        state  = str(props.get("provisioningState") or "Succeeded").lower()

        if state not in ("succeeded", "running"):
            fid = _fid("azure.network.watcher.not_active", uid, scan_run_id)
            findings.append(_finding(
                fid, "azure.network.watcher.not_active",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="Azure Network Watcher is not in Succeeded state",
                description=f"Network Watcher {uid} has provisioning state '{state}'. NSG flow logs may be unavailable.",
                exposure="internal",
                network_layer="L7_network_monitoring",
            ))
    return findings


# ── Provider ───────────────────────────────────────────────────────────────────

class AzureNetworkProvider(BaseNetworkProvider):
    """7-layer topology analysis for Azure — VNet/NSG/Public-IP graph."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        credential_ref: str,
        credential_type: str,
    ) -> Dict[str, Any]:
        start = time.time()
        logger.info("Azure 7-layer topology analysis starting for scan %s", scan_run_id)

        from engine_common.db_connections import get_discoveries_conn
        conn = get_discoveries_conn()

        try:
            layers = _load_all_layers(conn, scan_run_id, tenant_id, _ALL_LAYER_IDS, account_id)
        finally:
            conn.close()

        if not any(layers.values()):
            logger.info("Azure Layer 2: no network discovery data for scan %s", scan_run_id)
            return {
                "status": "skipped",
                "reason": "No Azure network discovery data found",
                "findings": [],
                "topology_snapshots": [],
                "report_metrics": _EMPTY_METRICS,
                "scan_duration_ms": int((time.time() - start) * 1000),
            }

        l1_rows     = layers.get(_L1_ID, [])
        l2_rows     = layers.get(_L2_ID, [])
        l3_rows     = layers.get(_L3_ID, [])
        l4_rows     = layers.get(_L4_ID, [])
        l5_rows     = layers.get(_L5_ID, [])
        l5_appgw    = layers.get(_L5_APPGW_ID, [])
        l6_rows     = layers.get(_L6_ID, [])
        l7_rows     = layers.get(_L7_ID, [])
        pip_rows    = layers.get(_PUBLIC_IP_ID, [])

        # Determine internet exposure from public IPs
        public_ip_count = sum(
            1 for row in pip_rows
            if str((row.get("emitted_fields") or {}).get("ip_address")
                   or (row.get("emitted_fields") or {}).get("ipAddress") or "").strip()
            not in ("", "null", "None")
        )
        has_internet_exposure = public_ip_count > 0

        # L1
        l1_findings = _analyze_l1_isolation(
            l1_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L1 Isolation: %d findings", len(l1_findings))

        # L2
        l2_findings = _analyze_l2_routing(
            l2_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L2 Routing: %d findings", len(l2_findings))

        # L3
        l3_findings = _analyze_l3_asg(
            l3_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L3 ASG: %d findings", len(l3_findings))

        # L4
        l4_findings, nsg_count = _analyze_l4_nsg(
            l4_rows, has_internet_exposure, account_id, tenant_id,
            scan_run_id, credential_ref, credential_type,
        )
        logger.info("L4 NSG: %d findings (nsg_count=%d)", len(l4_findings), nsg_count)

        # L5
        l5_findings, internet_facing_lbs = _analyze_l5_load_balancers(
            l5_rows, l5_appgw, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        if internet_facing_lbs:
            has_internet_exposure = True
        logger.info("L5 LBs: %d findings (%d internet-facing)", len(l5_findings), len(internet_facing_lbs))

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
            "Azure 7-layer complete: L1=%d L2=%d L3=%d L4=%d L5=%d L6=%d L7=%d total=%d in %dms",
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
            "total_security_groups":  nsg_count,
            "total_load_balancers":   len(internet_facing_lbs),
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
