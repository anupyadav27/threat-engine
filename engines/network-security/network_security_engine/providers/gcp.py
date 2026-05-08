"""
GCP network-security provider — 7-layer topology analysis.

Layer mapping:
  L1 Isolation:   VPC networks — auto-mode subnets risk
  L2 Routing:     Routes with 0.0.0.0/0 → internet next-hop
  L3 ACL:         N/A — GCP has no subnet-level ACL (score=100, no findings)
  L4 Firewall:    Firewall rules with 0.0.0.0/0 on critical ports
  L5 LB:          Forwarding rules with EXTERNAL load-balancing scheme
  L6 WAF:         Cloud Armor security policies on EXTERNAL backends
  L7 Monitoring:  Subnetwork VPC Flow Logs enablement
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
_L1_ID = "gcp.compute.networks.list"
_L2_ID = "gcp.compute.routes.list"
# L3: N/A for GCP
_L4_ID = "gcp.compute.firewalls.list"
_L5_ID = "gcp.compute.forwarding_rules.list"
_L6_ID = "gcp.compute.securityPolicies.list"
_L7_ID = "gcp.compute.subnetworks.aggregatedList"

_ALL_LAYER_IDS = [_L1_ID, _L2_ID, _L4_ID, _L5_ID, _L6_ID, _L7_ID]

_CRITICAL_PORTS = {22, 3389, 1433, 3306, 5432, 6379, 27017}
_OPEN_SOURCES   = {"0.0.0.0/0", "::/0", "*", "0.0.0.0"}

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
        f"gcp_l2|{rule_id}|{resource_uid}|{scan_run_id}".encode()
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
        "provider":           "gcp",
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
            "source":         "gcp_topology_layer2",
            "title":          title,
            "description":    description,
            "network_layer":  network_layer,
            "remediation":    "Restrict GCP firewall rules to specific source ranges. Add target tags to limit scope to specific instances.",
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


def _is_open_source(source: Any) -> bool:
    return str(source or "").strip() in _OPEN_SOURCES


def _ports_in_range(port_range_str: Any) -> set:
    """Parse GCP port range strings and return matching critical ports."""
    s = str(port_range_str or "").strip()
    if not s or s in ("all", "*", "0-65535"):
        return _CRITICAL_PORTS.copy()
    if "-" in s:
        parts = s.split("-", 1)
        try:
            low, high = int(parts[0]), int(parts[1])
            return {p for p in _CRITICAL_PORTS if low <= p <= high}
        except (ValueError, IndexError):
            return set()
    try:
        port = int(s)
        return {port} if port in _CRITICAL_PORTS else set()
    except ValueError:
        return set()


# ── Layer analyzers ────────────────────────────────────────────────────────────

def _analyze_l1_isolation(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L1: VPC network isolation — auto-mode VPCs create subnets in all regions (overly broad)."""
    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        auto_mode = ef.get("autoCreateSubnetworks") or ef.get("auto_create_subnetworks")
        if auto_mode:
            fid = _fid("gcp.network.vpc.auto_mode_enabled", uid, scan_run_id)
            findings.append(_finding(
                fid, "gcp.network.vpc.auto_mode_enabled",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="GCP VPC network is in auto-mode — subnets created in all regions",
                description=(
                    f"VPC network {uid} has autoCreateSubnetworks=true. "
                    "Auto-mode VPCs use a /20 subnet in every GCP region, expanding the attack surface. "
                    "Consider migrating to custom-mode VPCs."
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
) -> tuple:
    """L2: Routes — detect default internet routes (0.0.0.0/0 via internet gateway).

    Returns (findings, has_internet_route).
    """
    findings: List[Dict] = []
    has_internet_route = False

    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        dest_range = str(ef.get("destRange") or ef.get("dest_range") or "")
        next_hop   = str(
            ef.get("nextHopGateway") or ef.get("next_hop_gateway")
            or ef.get("nextHopInternet") or ef.get("next_hop_internet")
            or ""
        ).lower()
        priority = int(ef.get("priority") or 1000)

        if dest_range in ("0.0.0.0/0", "::/0") and (
            "internet" in next_hop or "default-internet-gateway" in next_hop
        ):
            has_internet_route = True
            # Only flag non-default (low priority) explicit internet routes as medium
            # The default GCP internet gateway route is expected; custom 0.0.0.0/0 routes are higher risk
            if priority < 1000 or "default" not in uid.lower():
                fid = _fid("gcp.network.route.internet_route", uid, scan_run_id)
                findings.append(_finding(
                    fid, "gcp.network.route.internet_route",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="medium",
                    title="GCP Route directs all traffic (0.0.0.0/0) to internet gateway",
                    description=(
                        f"Route {uid} routes 0.0.0.0/0 via internet gateway (priority={priority}). "
                        "Instances without no-external-ip will have internet access via this route."
                    ),
                    exposure="internet",
                    network_layer="L2_routing",
                ))

    return findings, has_internet_route


def _analyze_l4_firewall(
    rows: List[Dict],
    has_internet_route: bool,
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L4: Firewall rules — 0.0.0.0/0 ALLOW rules on critical ports.

    Returns (findings, fw_count).
    """
    findings: List[Dict] = []
    fw_count = 0
    exposure = "internet" if has_internet_route else "internal"

    for row in rows:
        ef     = row.get("emitted_fields") or {}
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")

        direction = str(ef.get("direction") or "INGRESS").upper()
        if direction != "INGRESS":
            continue

        allowed = ef.get("allowed") or []
        if not allowed or not isinstance(allowed, list):
            continue

        source_ranges = ef.get("sourceRanges") or ef.get("source_ranges") or []
        if not isinstance(source_ranges, list):
            source_ranges = [str(source_ranges)]

        if not any(_is_open_source(s) for s in source_ranges):
            continue

        fw_count += 1

        target_tags = ef.get("targetTags") or ef.get("target_tags") or []
        target_sas  = ef.get("targetServiceAccounts") or ef.get("target_service_accounts") or []
        no_target   = not target_tags and not target_sas
        scope_note  = " — no target tags, applies to ALL instances" if no_target else ""

        for rule_entry in allowed:
            if not isinstance(rule_entry, dict):
                continue
            protocol = str(
                rule_entry.get("IPProtocol") or rule_entry.get("ip_protocol") or "all"
            ).lower()
            ports = rule_entry.get("ports") or []

            if protocol in ("all", "-1"):
                fid = _fid("gcp.network.firewall.unrestricted_all_traffic", uid, scan_run_id)
                findings.append(_finding(
                    fid, "gcp.network.firewall.unrestricted_all_traffic",
                    uid, region, account_id, tenant_id, scan_run_id,
                    credential_ref, credential_type,
                    severity="critical",
                    title=f"GCP Firewall rule allows ALL inbound traffic from 0.0.0.0/0{scope_note}",
                    description=f"Firewall rule {uid} allows all protocols from 0.0.0.0/0.{scope_note}",
                    exposure=exposure,
                    network_layer="L4_firewall_rules",
                ))
                break

            if protocol in ("tcp", "6"):
                hit_ports: set = set()
                if not ports:
                    hit_ports = _CRITICAL_PORTS.copy()
                else:
                    for pr in ports:
                        hit_ports.update(_ports_in_range(pr))

                for port in hit_ports:
                    port_name = _PORT_NAMES.get(port, str(port))
                    severity  = "critical" if port in (22, 3389) else "high"
                    fid = _fid(f"gcp.network.firewall.unrestricted_port_{port}", uid, scan_run_id)
                    findings.append(_finding(
                        fid, f"gcp.network.firewall.unrestricted_port_{port}",
                        uid, region, account_id, tenant_id, scan_run_id,
                        credential_ref, credential_type,
                        severity=severity,
                        title=f"GCP Firewall allows unrestricted {port_name} ({port}) from 0.0.0.0/0{scope_note}",
                        description=(
                            f"Firewall rule {uid} permits inbound {port_name} (port {port}) "
                            f"from 0.0.0.0/0.{scope_note}"
                        ),
                        exposure=exposure,
                        network_layer="L4_firewall_rules",
                    ))

    return findings, fw_count


def _analyze_l5_load_balancers(
    rows: List[Dict],
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> tuple:
    """L5: Forwarding rules — EXTERNAL scheme = internet-facing LB.

    Returns (findings, internet_facing_set).
    """
    if not rows:
        logger.warning("L5 LB: no discovery data for gcp — add %s to scanner", _L5_ID)
        return [], set()

    findings: List[Dict] = []
    internet_facing_lbs: set = set()

    for row in rows:
        ef  = row.get("emitted_fields") or {}
        uid = row.get("resource_uid", "")

        lb_scheme = str(
            ef.get("loadBalancingScheme") or ef.get("load_balancing_scheme") or ""
        ).upper()

        if lb_scheme in ("EXTERNAL", "EXTERNAL_MANAGED"):
            internet_facing_lbs.add(uid)

    for uid in internet_facing_lbs:
        fid = _fid("gcp.network.lb.internet_facing", uid, scan_run_id)
        findings.append(_finding(
            fid, "gcp.network.lb.internet_facing",
            uid, "", account_id, tenant_id, scan_run_id,
            credential_ref, credential_type,
            severity="medium",
            title="GCP Forwarding Rule is internet-facing — verify backend security",
            description=(
                f"Forwarding rule {uid} uses EXTERNAL load balancing scheme. "
                "Ensure backend services restrict access and Cloud Armor policies are attached."
            ),
            exposure="internet",
            network_layer="L5_load_balancer_security",
        ))

    return findings, internet_facing_lbs


def _analyze_l6_waf(
    rows: List[Dict],
    internet_facing_lbs: set,
    account_id: str,
    tenant_id: str,
    scan_run_id: str,
    credential_ref: str,
    credential_type: str,
) -> List[Dict]:
    """L6: Cloud Armor — detect absence of security policies on EXTERNAL backends."""
    if not rows:
        logger.warning("L6 WAF: no Cloud Armor data for gcp — add %s to scanner", _L6_ID)
        if internet_facing_lbs:
            fid = _fid("gcp.network.armor.no_security_policies", account_id, scan_run_id)
            return [_finding(
                fid, "gcp.network.armor.no_security_policies",
                account_id, "", account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="GCP Cloud Armor: no security policies found for internet-facing load balancers",
                description=(
                    f"There are {len(internet_facing_lbs)} internet-facing forwarding rule(s) "
                    "but no Cloud Armor security policies were found. "
                    "Attach Cloud Armor policies to protect against DDoS and OWASP Top 10."
                ),
                exposure="internet",
                network_layer="L6_waf_protection",
            )]
        return []

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        # Check if policy has any rules beyond the default
        rules = ef.get("rules") or []
        if not isinstance(rules, list):
            rules = []

        # A policy with only the default-deny rule (priority 2147483647) is effectively empty
        non_default_rules = [
            r for r in rules
            if isinstance(r, dict) and int(r.get("priority") or 0) < 2147483647
        ]
        if not non_default_rules:
            fid = _fid("gcp.network.armor.policy_no_rules", uid, scan_run_id)
            findings.append(_finding(
                fid, "gcp.network.armor.policy_no_rules",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="GCP Cloud Armor policy has no custom protection rules",
                description=(
                    f"Cloud Armor policy {uid} only has the default rule. "
                    "Add OWASP Top 10 protection rules and rate limiting."
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
    """L7: VPC Flow Logs — detect subnetworks with flow logging disabled."""
    if not rows:
        logger.warning("L7 Monitoring: no subnetwork data for gcp — add %s to scanner", _L7_ID)
        return []

    findings: List[Dict] = []
    for row in rows:
        uid    = row.get("resource_uid", "")
        region = row.get("region", "")
        ef     = row.get("emitted_fields") or {}

        # GCP flow logs field: enableFlowLogs or logConfig.enable
        flow_logs_enabled = ef.get("enableFlowLogs") or ef.get("enable_flow_logs")
        log_config = ef.get("logConfig") or ef.get("log_config") or {}
        if isinstance(log_config, dict):
            flow_logs_enabled = flow_logs_enabled or log_config.get("enable")

        if not flow_logs_enabled:
            fid = _fid("gcp.network.subnet.flow_logs_disabled", uid, scan_run_id)
            findings.append(_finding(
                fid, "gcp.network.subnet.flow_logs_disabled",
                uid, region, account_id, tenant_id, scan_run_id,
                credential_ref, credential_type,
                severity="medium",
                title="GCP Subnetwork has VPC Flow Logs disabled",
                description=(
                    f"Subnetwork {uid} does not have VPC Flow Logs enabled. "
                    "Enable flow logs for network traffic visibility and security monitoring."
                ),
                exposure="internal",
                network_layer="L7_network_monitoring",
            ))
    return findings


# ── Provider ───────────────────────────────────────────────────────────────────

class GCPNetworkProvider(BaseNetworkProvider):
    """7-layer topology analysis for GCP — VPC/Firewall/LB graph."""

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        credential_ref: str,
        credential_type: str,
    ) -> Dict[str, Any]:
        start = time.time()
        logger.info("GCP 7-layer topology analysis starting for scan %s", scan_run_id)

        from engine_common.db_connections import get_discoveries_conn
        conn = get_discoveries_conn()

        try:
            layers = _load_all_layers(conn, scan_run_id, tenant_id, _ALL_LAYER_IDS, account_id)
        finally:
            conn.close()

        if not any(layers.values()):
            logger.info("GCP Layer 2: no network discovery data for scan %s", scan_run_id)
            return {
                "status": "skipped",
                "reason": "No GCP network discovery data found",
                "findings": [],
                "topology_snapshots": [],
                "report_metrics": _EMPTY_METRICS,
                "scan_duration_ms": int((time.time() - start) * 1000),
            }

        l1_rows = layers.get(_L1_ID, [])
        l2_rows = layers.get(_L2_ID, [])
        # L3: no data — GCP has no NACL
        l4_rows = layers.get(_L4_ID, [])
        l5_rows = layers.get(_L5_ID, [])
        l6_rows = layers.get(_L6_ID, [])
        l7_rows = layers.get(_L7_ID, [])

        # L1
        l1_findings = _analyze_l1_isolation(
            l1_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L1 Isolation: %d findings", len(l1_findings))

        # L2
        l2_findings, has_internet_route = _analyze_l2_routing(
            l2_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L2 Routing: %d findings (has_internet=%s)", len(l2_findings), has_internet_route)

        # L3: N/A for GCP — no NACL concept
        l3_findings: List[Dict] = []
        logger.info("L3 ACL: N/A for GCP (score=100)")

        # L4
        l4_findings, fw_count = _analyze_l4_firewall(
            l4_rows, has_internet_route, account_id, tenant_id,
            scan_run_id, credential_ref, credential_type,
        )
        logger.info("L4 Firewall: %d findings (fw_count=%d)", len(l4_findings), fw_count)

        # L5
        l5_findings, internet_facing_lbs = _analyze_l5_load_balancers(
            l5_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        if internet_facing_lbs:
            has_internet_route = True
        logger.info("L5 LBs: %d findings (%d internet-facing)", len(l5_findings), len(internet_facing_lbs))

        # L6
        l6_findings = _analyze_l6_waf(
            l6_rows, internet_facing_lbs, account_id, tenant_id,
            scan_run_id, credential_ref, credential_type,
        )
        logger.info("L6 Cloud Armor: %d findings", len(l6_findings))

        # L7
        l7_findings = _analyze_l7_monitoring(
            l7_rows, account_id, tenant_id, scan_run_id, credential_ref, credential_type,
        )
        logger.info("L7 Flow Logs: %d findings", len(l7_findings))

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
            "GCP 7-layer complete: L1=%d L2=%d L3=0(N/A) L4=%d L5=%d L6=%d L7=%d total=%d in %dms",
            len(l1_findings), len(l2_findings), len(l4_findings),
            len(l5_findings), len(l6_findings), len(l7_findings), total, duration_ms,
        )

        metrics = {
            **_EMPTY_METRICS,
            "posture_score":       max(0, 100 - sev["critical"] * 20 - sev["high"] * 10 - sev["medium"] * 5),
            "topology_score":      _layer_score(l1_findings),
            "reachability_score":  _layer_score(l2_findings),
            "nacl_score":          100,  # N/A for GCP
            "firewall_score":      _layer_score(l4_findings),
            "lb_score":            _layer_score(l5_findings),
            "waf_score":           _layer_score(l6_findings),
            "monitoring_score":    _layer_score(l7_findings),
            "total_findings":      total,
            "critical_findings":   sev["critical"],
            "high_findings":       sev["high"],
            "medium_findings":     sev["medium"],
            "low_findings":        sev["low"],
            "total_security_groups": fw_count,
            "total_load_balancers":  len(internet_facing_lbs),
            "internet_exposed_resources": sum(
                1 for f in all_findings if f.get("effective_exposure") == "internet"
            ),
            "findings_by_module":  {"topology_analysis": total},
            "findings_by_status":  {"FAIL": total},
            "findings_by_layer": {
                "L1_isolation":  len(l1_findings),
                "L2_routing":    len(l2_findings),
                "L3_acl":        0,
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
