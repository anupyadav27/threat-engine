"""
Layer 2 — Network Reachability Analyzer

Determines what can reach what by analyzing route tables, IGWs, NATs,
peering routes, and TGW routes. Marks subnets as public/private.

Findings:
  - Subnet has direct IGW route (marks public)
  - Blackhole routes
  - Overly broad route: 0.0.0.0/0 via peering/TGW
  - Asymmetric routing (peering route in A but not B)
  - Subnet without explicit route table (uses main = risky)
  - Route table with no subnets (orphaned)
  - NAT gateway in public subnet without IGW route (broken)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional

from ..models import (
    ExposureLevel, NetworkFinding, NetworkLayer, NetworkTopology,
    OPEN_CIDRS, PathType, SubnetNode, VPCNode,
)

logger = logging.getLogger(__name__)


def analyze_reachability(topology: NetworkTopology) -> List[NetworkFinding]:
    """
    Analyze network reachability (Layer 2) and mark subnets public/private.

    This MUST run before L3/L4 analyzers because they depend on
    subnet.is_public being set correctly.
    """
    findings: List[NetworkFinding] = []

    for vpc_id, vpc in topology.vpcs.items():
        # ── Step 1: Determine main route table ────────────────────────────
        main_rtb = None
        for rtb in vpc.route_tables.values():
            if rtb.is_main:
                main_rtb = rtb
                break

        # ── Step 2: Mark subnets public/private ──────────────────────────
        for subnet_id, subnet in vpc.subnets.items():
            rtb_id = subnet.route_table_id
            rtb = vpc.route_tables.get(rtb_id) if rtb_id else main_rtb

            if rtb:
                subnet.is_public = rtb.has_igw_route
                # Link subnet to its route table (if using main)
                if not subnet.route_table_id and main_rtb:
                    subnet.route_table_id = main_rtb.route_table_id
            else:
                # No route table at all — unusual
                subnet.is_public = False

        # ── Step 3: Analyze routes per route table ────────────────────────
        for rtb_id, rtb in vpc.route_tables.items():
            rtb_arn = f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:route-table/{rtb_id}"

            for route in rtb.routes:
                # Blackhole routes
                if route.is_blackhole:
                    findings.append(NetworkFinding(
                        finding_id=_fid("net.l2.blackhole", f"{rtb_id}|{route.destination_cidr}"),
                        rule_id="net.l2.blackhole_route",
                        title="Route table contains blackhole route",
                        description=(
                            f"Route table {rtb_id} has a blackhole route to "
                            f"{route.destination_cidr} via {route.target_id}. "
                            "The target has been deleted — traffic is silently dropped."
                        ),
                        severity="medium",
                        network_layer=NetworkLayer.L2_REACHABILITY,
                        network_modules=["network_reachability"],
                        resource_uid=rtb_arn,
                        resource_type="route_table",
                        region=vpc.region,
                        remediation="Remove the blackhole route or recreate the target resource.",
                        finding_data={
                            "reachability": {
                                "route_table_id": rtb_id,
                                "destination": route.destination_cidr,
                                "target_id": route.target_id,
                                "is_blackhole": True,
                            }
                        },
                    ))

                # Overly broad route via peering/TGW (0.0.0.0/0 → pcx or tgw)
                if (route.destination_cidr in OPEN_CIDRS
                        and route.target_type in ("pcx", "tgw")):
                    findings.append(NetworkFinding(
                        finding_id=_fid("net.l2.broad_peering_route", f"{rtb_id}|{route.target_id}"),
                        rule_id="net.l2.overly_broad_peering_route",
                        title=f"All traffic (0.0.0.0/0) routed via {'peering' if route.target_type == 'pcx' else 'TGW'}",
                        description=(
                            f"Route table {rtb_id} sends ALL traffic (0.0.0.0/0) to "
                            f"{route.target_type.upper()} {route.target_id}. This creates a "
                            "broad lateral movement path and potential data exfiltration route."
                        ),
                        severity="critical",
                        network_layer=NetworkLayer.L2_REACHABILITY,
                        network_modules=["network_reachability", "internet_exposure"],
                        resource_uid=rtb_arn,
                        resource_type="route_table",
                        region=vpc.region,
                        remediation="Use specific CIDRs for peering/TGW routes instead of 0.0.0.0/0.",
                        finding_data={
                            "reachability": {
                                "route_table_id": rtb_id,
                                "destination": route.destination_cidr,
                                "target_type": route.target_type,
                                "target_id": route.target_id,
                            },
                            "mitre_techniques": ["T1048", "T1021"],
                            "attack_path_category": "lateral_movement",
                        },
                    ))

            # Route table with no subnet associations (orphaned)
            if not rtb.subnet_ids and not rtb.is_main:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l2.orphaned_rtb", rtb_id),
                    rule_id="net.l2.orphaned_route_table",
                    title="Route table has no subnet associations",
                    description=f"Route table {rtb_id} in VPC {vpc_id} is not associated with any subnet.",
                    severity="low",
                    status="WARN",
                    network_layer=NetworkLayer.L2_REACHABILITY,
                    network_modules=["network_reachability"],
                    resource_uid=rtb_arn,
                    resource_type="route_table",
                    region=vpc.region,
                    remediation="Associate to a subnet or delete if unused.",
                ))

        # ── Step 4: Subnets using main route table (implicit) ─────────────
        for subnet_id, subnet in vpc.subnets.items():
            if not subnet.route_table_id and main_rtb:
                # Subnet inherited the main route table — not explicitly set
                subnet_arn = f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:subnet/{subnet_id}"
                if main_rtb.has_igw_route:
                    findings.append(NetworkFinding(
                        finding_id=_fid("net.l2.implicit_public", subnet_id),
                        rule_id="net.l2.subnet_implicit_public_via_main_rtb",
                        title="Subnet is implicitly public via main route table",
                        description=(
                            f"Subnet {subnet_id} has no explicit route table association "
                            f"and inherits the main route table {main_rtb.route_table_id} "
                            "which has an IGW route. New subnets in this VPC will also be public."
                        ),
                        severity="high",
                        network_layer=NetworkLayer.L2_REACHABILITY,
                        network_modules=["network_reachability", "internet_exposure"],
                        resource_uid=subnet_arn,
                        resource_type="subnet",
                        region=vpc.region,
                        remediation="Create a private route table and explicitly associate subnets.",
                        finding_data={
                            "reachability": {
                                "subnet_id": subnet_id,
                                "is_public": True,
                                "via_main_rtb": True,
                                "main_rtb_id": main_rtb.route_table_id,
                            },
                            "mitre_techniques": ["T1190"],
                        },
                    ))

        # ── Step 5: Asymmetric peering (route in A but not B) ─────────────
        for pcx in vpc.peering_connections:
            pcx_id = pcx.get("pcx_id", "")
            peer_vpc_id = pcx.get("peer_vpc_id", "")
            peer_vpc = topology.vpcs.get(peer_vpc_id)
            if not peer_vpc:
                continue

            local_has_route = any(
                any(r.target_type == "pcx" and r.target_id == pcx_id for r in rtb.routes)
                for rtb in vpc.route_tables.values()
            )
            peer_has_route = any(
                any(r.target_type == "pcx" and r.target_id == pcx_id for r in rtb.routes)
                for rtb in peer_vpc.route_tables.values()
            )

            if local_has_route and not peer_has_route:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l2.asymmetric_peering", f"{vpc_id}|{peer_vpc_id}|{pcx_id}"),
                    rule_id="net.l2.asymmetric_peering_routes",
                    title="Asymmetric VPC peering routes",
                    description=(
                        f"VPC {vpc_id} has routes to peering {pcx_id} → {peer_vpc_id}, "
                        f"but {peer_vpc_id} has no return routes. Traffic is one-way only."
                    ),
                    severity="medium",
                    network_layer=NetworkLayer.L2_REACHABILITY,
                    network_modules=["network_reachability"],
                    resource_uid=f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:vpc-peering-connection/{pcx_id}",
                    resource_type="vpc_peering_connection",
                    region=vpc.region,
                    remediation="Add return routes in the peer VPC or remove one-way routes.",
                ))

        # ── Step 6: NAT gateway in subnet without IGW route (broken NAT) ─
        for nat in vpc.nat_gateways:
            nat_subnet_id = nat.get("subnet_id", "")
            nat_subnet = vpc.subnets.get(nat_subnet_id)
            if nat_subnet and not nat_subnet.is_public and nat.get("connectivity_type") == "public":
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l2.broken_nat", nat.get("nat_id", "")),
                    rule_id="net.l2.nat_in_private_subnet",
                    title="NAT Gateway in private subnet (no IGW route)",
                    description=(
                        f"NAT Gateway {nat.get('nat_id', '')} is in subnet {nat_subnet_id} "
                        "which has no route to an Internet Gateway. Public NAT gateways "
                        "require a public subnet with an IGW route to function."
                    ),
                    severity="high",
                    network_layer=NetworkLayer.L2_REACHABILITY,
                    network_modules=["network_reachability"],
                    resource_uid=f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:natgateway/{nat.get('nat_id', '')}",
                    resource_type="nat_gateway",
                    region=vpc.region,
                    remediation="Move NAT Gateway to a public subnet or add IGW route.",
                ))

    return findings


def _fid(rule_id: str, resource_key: str) -> str:
    raw = f"{rule_id}|{resource_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
