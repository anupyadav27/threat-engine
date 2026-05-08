"""
Network Security — Finding Enricher

Adds MITRE ATT&CK technique mapping, remediation guidance, blast radius
computation, and compliance framework references to network findings.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from ..models import NetworkFinding, SENSITIVE_PORTS

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK Technique Mapping for Network Findings ──────────────────────

RULE_TO_MITRE: Dict[str, List[str]] = {
    # L1 Topology
    "net.l1.vpc_flow_logs_disabled":           ["T1040", "T1562.008"],
    "net.l1.default_vpc_in_use":               ["T1078"],
    "net.l1.overlapping_cidrs_peered_vpcs":    ["T1557"],
    "net.l1.tgw_broad_connectivity":           ["T1021"],

    # L2 Reachability
    "net.l2.overly_broad_peering_route":       ["T1048", "T1021"],
    "net.l2.subnet_implicit_public_via_main_rtb": ["T1190"],

    # L3 NACL
    "net.l3.default_nacl_on_public_subnet":    ["T1190"],
    "net.l3.nacl_allows_all_ports_inbound":    ["T1190", "T1133"],
    "net.l3.nacl_outbound_unrestricted":       ["T1048"],

    # L4 SG — sensitive ports
    "net.l4.sg_ssh_open_to_world":             ["T1133"],
    "net.l4.sg_rdp_open_to_world":             ["T1133"],
    "net.l4.sg_mysql_open_to_world":           ["T1190"],
    "net.l4.sg_postgresql_open_to_world":      ["T1190"],
    "net.l4.sg_mssql_open_to_world":           ["T1190"],
    "net.l4.sg_mongodb_open_to_world":         ["T1190"],
    "net.l4.sg_redis_open_to_world":           ["T1190"],
    "net.l4.sg_elasticsearch_open_to_world":   ["T1190"],
    "net.l4.sg_telnet_open_to_world":          ["T1133"],
    "net.l4.sg_smb_open_to_world":             ["T1021.002"],
    "net.l4.sg_vnc_open_to_world":             ["T1133"],
    "net.l4.sg_k8s_api_open_to_world":         ["T1190"],
    "net.l4.sg_kubelet_open_to_world":         ["T1190"],
    "net.l4.sg_all_traffic_from_any":          ["T1190", "T1133"],
    "net.l4.sg_cross_vpc_reference":           ["T1021"],
    "net.l4.sg_outbound_all_traffic":          ["T1048"],
    "net.l4.sg_wide_port_range":               ["T1190"],

    # L5 LB
    "net.l5.lb_http_without_https_redirect":   ["T1557"],
    "net.l5.lb_weak_tls_policy":               ["T1557.002"],
    "net.l5.lb_no_tls_listeners":              ["T1557"],

    # L6 WAF
    "net.l6.internet_facing_alb_no_waf":       ["T1190"],
    "net.l6.waf_no_rules":                     ["T1190"],
    "net.l6.waf_no_rate_limiting":             ["T1499"],
    "net.l6.waf_logging_disabled":             ["T1562.008"],
}

# ── Compliance Framework Mapping ──────────────────────────────────────────────

RULE_TO_FRAMEWORKS: Dict[str, List[str]] = {
    "net.l1.vpc_flow_logs_disabled":       ["CIS-3.9", "NIST-AU-12", "PCI-DSS-10.3", "SOC2-CC7.2"],
    "net.l4.sg_ssh_open_to_world":         ["CIS-5.2", "NIST-SC-7", "PCI-DSS-1.3", "HIPAA-164.312(e)(1)"],
    "net.l4.sg_rdp_open_to_world":         ["CIS-5.3", "NIST-SC-7", "PCI-DSS-1.3"],
    "net.l4.sg_all_traffic_from_any":      ["CIS-5.4", "NIST-SC-7", "PCI-DSS-1.2"],
    "net.l3.default_nacl_on_public_subnet": ["CIS-5.1", "NIST-SC-7"],
    "net.l6.internet_facing_alb_no_waf":   ["NIST-SC-7", "PCI-DSS-6.6"],
    "net.l5.lb_http_without_https_redirect": ["NIST-SC-8", "PCI-DSS-4.1", "HIPAA-164.312(e)(1)"],
    "net.l1.default_vpc_in_use":           ["CIS-2.1.5"],
}


def enrich_findings(
    findings: List[NetworkFinding],
    blast_radius_map: Dict[str, int] = None,
) -> List[NetworkFinding]:
    """
    Enrich network findings with MITRE techniques, compliance frameworks,
    and blast radius data.

    Args:
        findings: Raw findings from all analyzers.
        blast_radius_map: Optional resource_uid → count of downstream resources.

    Returns:
        Enriched findings.
    """
    blast_radius_map = blast_radius_map or {}

    for finding in findings:
        fd = finding.finding_data

        # 1. MITRE techniques (add to existing)
        existing_mitre = fd.get("mitre_techniques", [])
        rule_mitre = RULE_TO_MITRE.get(finding.rule_id, [])
        all_mitre = list(set(existing_mitre + rule_mitre))
        if all_mitre:
            fd["mitre_techniques"] = all_mitre

        # 2. Compliance frameworks
        frameworks = RULE_TO_FRAMEWORKS.get(finding.rule_id, [])
        if frameworks:
            fd["compliance_frameworks"] = frameworks

        # 3. Blast radius
        resource_uid = finding.resource_uid
        if resource_uid in blast_radius_map:
            fd["blast_radius"] = blast_radius_map[resource_uid]

        # 4. Attack path category (ensure set)
        if "attack_path_category" not in fd:
            if finding.effective_exposure == "internet":
                fd["attack_path_category"] = "exposure"
            elif finding.effective_exposure == "cross_vpc":
                fd["attack_path_category"] = "lateral_movement"

    return findings


def compute_blast_radius(
    topology: Any,
    sg_attachments: Dict[str, List[Dict]] = None,
) -> Dict[str, int]:
    """
    Compute blast radius for each security group.

    Blast radius = number of resources reachable through this SG.
    Used by threat engine for risk scoring.
    """
    blast_map: Dict[str, int] = {}
    sg_attachments = sg_attachments or {}

    for vpc_id, vpc in topology.vpcs.items():
        for sg_id, sg in vpc.security_groups.items():
            # Direct attachments
            direct_count = len(sg.attached_resources) or len(sg_attachments.get(sg_id, []))

            # SG-to-SG references: resources in referenced SGs are also reachable
            indirect_count = 0
            for ref_sg_id in sg.sg_to_sg_refs:
                ref_sg = vpc.security_groups.get(ref_sg_id)
                if ref_sg:
                    indirect_count += len(ref_sg.attached_resources)

            blast_map[sg.resource_uid or sg_id] = direct_count + indirect_count

    return blast_map
