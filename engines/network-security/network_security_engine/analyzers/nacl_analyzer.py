"""
Layer 3 — Network ACL Analyzer

Analyzes stateless firewall rules at the subnet boundary.
NACLs are the first firewall layer traffic hits after routing.

Findings:
  - Default NACL (allow all) on public subnet
  - NACL allows 0.0.0.0/0 inbound on SSH/RDP to public subnet
  - NACL allows all inbound ports (0-65535) from any
  - No deny rules (relying solely on implicit deny)
  - Outbound NACL allows all (no exfil control)
  - NACL not associated with any subnet (orphaned)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List

from ..models import (
    NACLNode, NetworkFinding, NetworkLayer, NetworkTopology,
    OPEN_CIDRS, SENSITIVE_PORTS,
)

logger = logging.getLogger(__name__)


def analyze_nacls(topology: NetworkTopology) -> List[NetworkFinding]:
    """
    Analyze NACLs across all VPCs (Layer 3).

    Depends on L2 having set subnet.is_public correctly.
    """
    findings: List[NetworkFinding] = []

    for vpc_id, vpc in topology.vpcs.items():
        for nacl_id, nacl in vpc.nacls.items():
            nacl_arn = f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:network-acl/{nacl_id}"

            # Determine if this NACL protects any public subnet
            protects_public = any(
                vpc.subnets.get(sid, None) and vpc.subnets[sid].is_public
                for sid in nacl.subnet_ids
            )

            # 1. Default NACL on public subnet
            if nacl.is_default and protects_public:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l3.default_nacl_public", nacl_arn),
                    rule_id="net.l3.default_nacl_on_public_subnet",
                    title="Default NACL (allow-all) on public subnet",
                    description=(
                        f"NACL {nacl_id} is the default NACL (allows all inbound/outbound) "
                        f"and protects {len(nacl.subnet_ids)} subnets including public ones. "
                        "Default NACLs provide no filtering at the subnet boundary."
                    ),
                    severity="high",
                    network_layer=NetworkLayer.L3_NACL,
                    network_modules=["network_acl"],
                    resource_uid=nacl_arn,
                    resource_type="network_acl",
                    region=vpc.region,
                    remediation="Create custom NACLs with explicit allow/deny rules for public subnets.",
                    finding_data={
                        "nacl_posture": {
                            "nacl_id": nacl_id,
                            "is_default_nacl": True,
                            "protects_public_subnets": True,
                            "subnet_ids": nacl.subnet_ids,
                            "filtering_score": 0,
                        }
                    },
                ))

            # 2. Sensitive ports open from 0.0.0.0/0 inbound
            for port, port_info in SENSITIVE_PORTS.items():
                if nacl.allows_port_inbound(port, "0.0.0.0/0"):
                    sev = port_info["severity"] if protects_public else "medium"
                    findings.append(NetworkFinding(
                        finding_id=_fid("net.l3.sensitive_port", f"{nacl_id}|{port}"),
                        rule_id=f"net.l3.nacl_allows_{port_info['service']}_from_any",
                        title=f"NACL allows {port_info['service'].upper()} (port {port}) from 0.0.0.0/0",
                        description=(
                            f"NACL {nacl_id} allows inbound traffic on port {port} "
                            f"({port_info['service']}) from 0.0.0.0/0. "
                            f"{'This NACL protects public subnets — internet traffic can reach this port.' if protects_public else 'Subnet is private but NACL allows from any CIDR.'}"
                        ),
                        severity=sev,
                        network_layer=NetworkLayer.L3_NACL,
                        network_modules=["network_acl", "internet_exposure"],
                        effective_exposure="internet" if protects_public else "vpc_internal",
                        resource_uid=nacl_arn,
                        resource_type="network_acl",
                        region=vpc.region,
                        remediation=f"Restrict NACL inbound rule for port {port} to specific CIDRs.",
                        finding_data={
                            "nacl_posture": {
                                "nacl_id": nacl_id,
                                "port": port,
                                "service": port_info["service"],
                                "allows_from_any": True,
                                "protects_public": protects_public,
                            },
                            "mitre_techniques": [port_info["mitre"]],
                        },
                    ))

            # 3. Inbound allows all ports (0-65535) from any
            has_all_ports_rule = False
            for rule in nacl.inbound_rules:
                if (rule.action == "allow"
                        and rule.cidr in OPEN_CIDRS
                        and rule.protocol in ("-1", "all")
                        and rule.rule_number != 32767):
                    has_all_ports_rule = True
                    break
                if (rule.action == "allow"
                        and rule.cidr in OPEN_CIDRS
                        and rule.port_from <= 0 and rule.port_to >= 65535
                        and rule.rule_number != 32767):
                    has_all_ports_rule = True
                    break

            if has_all_ports_rule and not nacl.is_default:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l3.all_ports_inbound", nacl_id),
                    rule_id="net.l3.nacl_allows_all_ports_inbound",
                    title="NACL allows all ports inbound from 0.0.0.0/0",
                    description=(
                        f"NACL {nacl_id} has an explicit rule allowing all inbound traffic "
                        "from 0.0.0.0/0. This is equivalent to no NACL filtering."
                    ),
                    severity="critical" if protects_public else "high",
                    network_layer=NetworkLayer.L3_NACL,
                    network_modules=["network_acl"],
                    resource_uid=nacl_arn,
                    resource_type="network_acl",
                    region=vpc.region,
                    remediation="Replace allow-all rule with specific port ranges.",
                    finding_data={
                        "nacl_posture": {
                            "nacl_id": nacl_id,
                            "allows_all_inbound": True,
                            "protects_public": protects_public,
                            "filtering_score": 0,
                        }
                    },
                ))

            # 4. Outbound allows all to 0.0.0.0/0 (no exfil control)
            outbound_allows_all = any(
                r.action == "allow" and r.cidr in OPEN_CIDRS
                and (r.protocol in ("-1", "all") or (r.port_from <= 0 and r.port_to >= 65535))
                and r.rule_number != 32767
                for r in nacl.outbound_rules
            )
            if outbound_allows_all and protects_public:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l3.outbound_unrestricted", nacl_id),
                    rule_id="net.l3.nacl_outbound_unrestricted",
                    title="NACL allows all outbound traffic on public subnet",
                    description=(
                        f"NACL {nacl_id} on public subnet allows all outbound traffic to 0.0.0.0/0. "
                        "No exfiltration controls at the subnet boundary."
                    ),
                    severity="medium",
                    network_layer=NetworkLayer.L3_NACL,
                    network_modules=["network_acl", "network_monitoring"],
                    resource_uid=nacl_arn,
                    resource_type="network_acl",
                    region=vpc.region,
                    remediation="Restrict outbound NACL to required ports and destinations.",
                    finding_data={
                        "nacl_posture": {
                            "nacl_id": nacl_id,
                            "outbound_unrestricted": True,
                            "has_outbound_restrictions": False,
                        },
                        "mitre_techniques": ["T1048"],
                    },
                ))

            # 5. No explicit deny rules (only implicit default deny at 32767)
            explicit_denies = [r for r in nacl.inbound_rules
                               if r.action == "deny" and r.rule_number != 32767]
            if not explicit_denies and not nacl.is_default and protects_public:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l3.no_deny_rules", nacl_id),
                    rule_id="net.l3.nacl_no_explicit_deny_rules",
                    title="NACL has no explicit deny rules",
                    description=(
                        f"NACL {nacl_id} has no explicit deny rules — relies solely on the "
                        "implicit deny at rule number 32767. Explicit deny rules before "
                        "allow rules are recommended for defense-in-depth."
                    ),
                    severity="low",
                    status="WARN",
                    network_layer=NetworkLayer.L3_NACL,
                    network_modules=["network_acl"],
                    resource_uid=nacl_arn,
                    resource_type="network_acl",
                    region=vpc.region,
                    remediation="Add explicit deny rules for known-bad CIDRs/ports before allow rules.",
                ))

            # 6. Orphaned NACL (not associated with any subnet)
            if not nacl.subnet_ids and not nacl.is_default:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l3.orphaned_nacl", nacl_id),
                    rule_id="net.l3.orphaned_nacl",
                    title="NACL not associated with any subnet",
                    description=f"NACL {nacl_id} in VPC {vpc_id} is not associated with any subnet.",
                    severity="low",
                    status="WARN",
                    network_layer=NetworkLayer.L3_NACL,
                    network_modules=["network_acl"],
                    resource_uid=nacl_arn,
                    resource_type="network_acl",
                    region=vpc.region,
                    remediation="Associate with subnets or delete if unused.",
                ))

    return findings


def _fid(rule_id: str, resource_key: str) -> str:
    raw = f"{rule_id}|{resource_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
