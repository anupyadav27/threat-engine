"""
Layer 1 — Network Topology Analyzer

Builds the VPC topology model from raw discovery data and produces
findings for topology-level issues:
  - Default VPC in use
  - VPC with no flow logs
  - Overlapping CIDRs across peered VPCs
  - Single-AZ subnet layout
  - Dead peering (no route table entries)
  - VPC without DNS hostnames (can't resolve private DNS)
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from itertools import combinations
from typing import Any, Dict, List, Optional, Tuple

from ..models import (
    NACLNode, NACLRule, NetworkFinding, NetworkLayer, NetworkTopology,
    RouteEntry, RouteTableNode, SGNode, SGRule, SubnetNode, VPCNode,
)

logger = logging.getLogger(__name__)


# ── Topology Builder ─────────────────────────────────────────────────────────

def build_topology(
    discovery_data: Dict[str, List[Dict[str, Any]]],
    account_id: str = "",
) -> NetworkTopology:
    """
    Build a NetworkTopology from raw discovery data.

    Args:
        discovery_data: Output of NetworkDiscoveryReader.load_all_network_resources().
        account_id: AWS account ID for context.

    Returns:
        Fully populated NetworkTopology.
    """
    topology = NetworkTopology()

    # ── VPCs ──────────────────────────────────────────────────────────────
    for row in discovery_data.get("vpcs", []):
        raw = row.get("raw_response") or {}
        vpc_id = raw.get("VpcId", row.get("resource_id", ""))
        if not vpc_id:
            continue

        cidr_blocks = [raw.get("CidrBlock", "")]
        for assoc in raw.get("CidrBlockAssociationSet", []):
            cidr = assoc.get("CidrBlock", "")
            if cidr and cidr not in cidr_blocks:
                cidr_blocks.append(cidr)

        vpc = VPCNode(
            vpc_id=vpc_id,
            cidr_blocks=[c for c in cidr_blocks if c],
            is_default=raw.get("IsDefault", False),
            region=row.get("region", ""),
            account_id=account_id,
        )
        topology.vpcs[vpc_id] = vpc

    # ── Subnets ───────────────────────────────────────────────────────────
    for row in discovery_data.get("subnets", []):
        raw = row.get("raw_response") or {}
        subnet_id = raw.get("SubnetId", row.get("resource_id", ""))
        vpc_id = raw.get("VpcId", "")
        if not subnet_id or vpc_id not in topology.vpcs:
            continue

        subnet = SubnetNode(
            subnet_id=subnet_id,
            vpc_id=vpc_id,
            cidr_block=raw.get("CidrBlock", ""),
            availability_zone=raw.get("AvailabilityZone", ""),
            map_public_ip_on_launch=raw.get("MapPublicIpOnLaunch", False),
        )
        topology.vpcs[vpc_id].subnets[subnet_id] = subnet

    # ── Route Tables ──────────────────────────────────────────────────────
    for row in discovery_data.get("route_tables", []):
        raw = row.get("raw_response") or {}
        rtb_id = raw.get("RouteTableId", row.get("resource_id", ""))
        vpc_id = raw.get("VpcId", "")
        if not rtb_id or vpc_id not in topology.vpcs:
            continue

        routes = []
        for r in raw.get("Routes", []):
            dest = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock", "")
            target_id = ""
            target_type = "unknown"
            for key_suffix, ttype in [
                ("GatewayId", "igw" if "igw-" in (r.get("GatewayId") or "") else "vgw"),
                ("NatGatewayId", "nat"),
                ("TransitGatewayId", "tgw"),
                ("VpcPeeringConnectionId", "pcx"),
                ("InstanceId", "instance"),
                ("NetworkInterfaceId", "eni"),
                ("LocalGatewayId", "lgw"),
                ("VpcEndpointId", "vpce"),
            ]:
                val = r.get(key_suffix)
                if val:
                    target_id = val
                    target_type = ttype
                    break

            if r.get("State") == "active" and dest == "local":
                target_type = "local"
                target_id = "local"

            routes.append(RouteEntry(
                destination_cidr=dest,
                target_type=target_type,
                target_id=target_id,
                is_propagated=r.get("Origin") == "EnableVgwRoutePropagation",
                is_blackhole=r.get("State") == "blackhole",
            ))

        # Subnet associations
        subnet_ids = []
        is_main = False
        for assoc in raw.get("Associations", []):
            if assoc.get("Main"):
                is_main = True
            sub = assoc.get("SubnetId")
            if sub:
                subnet_ids.append(sub)
                # Link subnet to route table
                if sub in topology.vpcs[vpc_id].subnets:
                    topology.vpcs[vpc_id].subnets[sub].route_table_id = rtb_id

        rtb = RouteTableNode(
            route_table_id=rtb_id,
            vpc_id=vpc_id,
            subnet_ids=subnet_ids,
            is_main=is_main,
            routes=routes,
        )
        topology.vpcs[vpc_id].route_tables[rtb_id] = rtb

    # ── NACLs ─────────────────────────────────────────────────────────────
    for row in discovery_data.get("nacls", []):
        raw = row.get("raw_response") or {}
        nacl_id = raw.get("NetworkAclId", row.get("resource_id", ""))
        vpc_id = raw.get("VpcId", "")
        if not nacl_id or vpc_id not in topology.vpcs:
            continue

        inbound, outbound = [], []
        for entry in raw.get("Entries", []):
            port_range = entry.get("PortRange", {})
            rule = NACLRule(
                rule_number=entry.get("RuleNumber", 32767),
                protocol=_normalize_protocol(entry.get("Protocol", "-1")),
                port_from=port_range.get("From", 0),
                port_to=port_range.get("To", 65535),
                cidr=entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", "0.0.0.0/0"),
                action=entry.get("RuleAction", "deny"),
                egress=entry.get("Egress", False),
            )
            if rule.egress:
                outbound.append(rule)
            else:
                inbound.append(rule)

        # Subnet associations
        subnet_ids = [a.get("SubnetId") for a in raw.get("Associations", [])
                      if a.get("SubnetId")]
        for sub_id in subnet_ids:
            if sub_id in topology.vpcs[vpc_id].subnets:
                topology.vpcs[vpc_id].subnets[sub_id].nacl_id = nacl_id

        nacl = NACLNode(
            nacl_id=nacl_id,
            vpc_id=vpc_id,
            subnet_ids=subnet_ids,
            is_default=raw.get("IsDefault", False),
            inbound_rules=inbound,
            outbound_rules=outbound,
        )
        topology.vpcs[vpc_id].nacls[nacl_id] = nacl

    # ── Security Groups ───────────────────────────────────────────────────
    for row in discovery_data.get("security_groups", []):
        raw = row.get("raw_response") or {}
        sg_id = raw.get("GroupId", row.get("resource_id", ""))
        vpc_id = raw.get("VpcId", "")
        if not sg_id or vpc_id not in topology.vpcs:
            continue

        inbound = _parse_sg_rules(raw.get("IpPermissions", []))
        outbound = _parse_sg_rules(raw.get("IpPermissionsEgress", []))

        sg = SGNode(
            sg_id=sg_id,
            sg_name=raw.get("GroupName", ""),
            vpc_id=vpc_id,
            resource_uid=row.get("resource_uid", ""),
            inbound_rules=inbound,
            outbound_rules=outbound,
            is_default=raw.get("GroupName") == "default",
        )
        topology.vpcs[vpc_id].security_groups[sg_id] = sg

    # ── Internet Gateways ─────────────────────────────────────────────────
    for row in discovery_data.get("igws", []):
        raw = row.get("raw_response") or {}
        igw_id = raw.get("InternetGatewayId", row.get("resource_id", ""))
        for att in raw.get("Attachments", []):
            vpc_id = att.get("VpcId", "")
            if vpc_id in topology.vpcs and att.get("State") == "available":
                topology.vpcs[vpc_id].igw_id = igw_id

    # ── NAT Gateways ─────────────────────────────────────────────────────
    for row in discovery_data.get("nat_gateways", []):
        raw = row.get("raw_response") or {}
        vpc_id = raw.get("VpcId", "")
        if vpc_id not in topology.vpcs:
            continue
        nat_info = {
            "nat_id": raw.get("NatGatewayId", ""),
            "subnet_id": raw.get("SubnetId", ""),
            "state": raw.get("State", ""),
            "connectivity_type": raw.get("ConnectivityType", "public"),
        }
        for addr in raw.get("NatGatewayAddresses", []):
            nat_info["eip"] = addr.get("PublicIp", "")
        topology.vpcs[vpc_id].nat_gateways.append(nat_info)

    # ── VPC Peering ───────────────────────────────────────────────────────
    for row in discovery_data.get("peering", []):
        raw = row.get("raw_response") or {}
        pcx_id = raw.get("VpcPeeringConnectionId", "")
        status = raw.get("Status", {}).get("Code", "")
        if status != "active":
            continue
        requester_vpc = raw.get("RequesterVpcInfo", {}).get("VpcId", "")
        accepter_vpc = raw.get("AccepterVpcInfo", {}).get("VpcId", "")

        for vpc_id in (requester_vpc, accepter_vpc):
            if vpc_id in topology.vpcs:
                peer = accepter_vpc if vpc_id == requester_vpc else requester_vpc
                topology.vpcs[vpc_id].peering_connections.append({
                    "pcx_id": pcx_id,
                    "peer_vpc_id": peer,
                    "peer_account": raw.get("AccepterVpcInfo", {}).get("OwnerId", ""),
                    "peer_region": raw.get("AccepterVpcInfo", {}).get("Region", ""),
                })
                topology.peering_map.setdefault(vpc_id, []).append(peer)

    # ── Transit Gateways ──────────────────────────────────────────────────
    for row in discovery_data.get("tgw_vpc_attachments", []):
        raw = row.get("raw_response") or {}
        vpc_id = raw.get("VpcId", "")
        tgw_id = raw.get("TransitGatewayId", "")
        if vpc_id in topology.vpcs and tgw_id:
            topology.vpcs[vpc_id].tgw_attachments.append({
                "tgw_id": tgw_id,
                "attachment_id": raw.get("TransitGatewayAttachmentId", ""),
                "state": raw.get("State", ""),
            })
            topology.tgw_map.setdefault(tgw_id, []).append(vpc_id)

    # ── VPC Endpoints ─────────────────────────────────────────────────────
    for row in discovery_data.get("vpc_endpoints", []):
        raw = row.get("raw_response") or {}
        vpc_id = raw.get("VpcId", "")
        if vpc_id in topology.vpcs:
            topology.vpcs[vpc_id].vpc_endpoints.append({
                "vpce_id": raw.get("VpcEndpointId", ""),
                "service_name": raw.get("ServiceName", ""),
                "type": raw.get("VpcEndpointType", "Gateway"),
                "state": raw.get("State", ""),
            })

    # ── Flow Logs ─────────────────────────────────────────────────────────
    flow_log_vpc_ids = set()
    for row in discovery_data.get("flow_logs", []):
        raw = row.get("raw_response") or {}
        resource_id = raw.get("ResourceId", "")
        if resource_id.startswith("vpc-"):
            flow_log_vpc_ids.add(resource_id)
    for vpc_id, vpc in topology.vpcs.items():
        vpc.flow_log_enabled = vpc_id in flow_log_vpc_ids

    # ── EIPs ──────────────────────────────────────────────────────────────
    for row in discovery_data.get("eips", []):
        raw = row.get("raw_response") or {}
        topology.eips.append({
            "allocation_id": raw.get("AllocationId", ""),
            "public_ip": raw.get("PublicIp", ""),
            "instance_id": raw.get("InstanceId"),
            "eni_id": raw.get("NetworkInterfaceId"),
            "association_id": raw.get("AssociationId"),
            "domain": raw.get("Domain", "vpc"),
        })

    # ── Network Firewalls ─────────────────────────────────────────────────
    for row in discovery_data.get("nfw_detail", []):
        raw = row.get("raw_response") or {}
        fw = raw.get("Firewall", raw)
        vpc_id = fw.get("VpcId", "")
        if vpc_id in topology.vpcs:
            topology.vpcs[vpc_id].network_firewalls.append({
                "fw_id": fw.get("FirewallId", ""),
                "fw_name": fw.get("FirewallName", ""),
                "policy_arn": fw.get("FirewallPolicyArn", ""),
                "subnet_mappings": fw.get("SubnetMappings", []),
            })

    logger.info(
        "Built topology: %d VPCs, %d subnets, %d SGs, %d route tables, %d NACLs",
        topology.total_vpcs, topology.total_subnets,
        topology.total_security_groups, topology.total_route_tables,
        topology.total_nacls,
    )
    return topology


# ── Topology Analyzer (produces L1 findings) ──────────────────────────────────

def analyze_topology(topology: NetworkTopology) -> List[NetworkFinding]:
    """
    Analyze network topology for L1 findings.

    Checks:
      1. Default VPC in use
      2. VPC without flow logs
      3. Overlapping CIDRs across peered VPCs
      4. Single-AZ subnet layout
      5. Dead peering (connected but no route)
      6. DNS hostnames disabled
      7. VPC with no subnets (empty VPC)
      8. TGW connects prod + dev VPCs (cross-env)
    """
    findings: List[NetworkFinding] = []

    for vpc_id, vpc in topology.vpcs.items():
        vpc_arn = f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:vpc/{vpc_id}"

        # 1. Default VPC in use
        if vpc.is_default and len(vpc.subnets) > 0:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l1.default_vpc", vpc_arn),
                rule_id="net.l1.default_vpc_in_use",
                title="Default VPC is in use",
                description=(
                    f"VPC {vpc_id} is the default VPC and has {len(vpc.subnets)} subnets. "
                    "Default VPCs have overly permissive defaults (public subnets, IGW, "
                    "default SG allows all internal traffic)."
                ),
                severity="medium",
                network_layer=NetworkLayer.L1_TOPOLOGY,
                network_modules=["network_isolation"],
                resource_uid=vpc_arn,
                resource_type="vpc",
                region=vpc.region,
                remediation="Migrate workloads to a custom VPC with least-privilege network design.",
                finding_data={
                    "network_context": {
                        "vpc_id": vpc_id,
                        "is_default": True,
                        "subnet_count": len(vpc.subnets),
                        "has_igw": vpc.has_internet_gateway,
                    }
                },
            ))

        # 2. VPC without flow logs
        if not vpc.flow_log_enabled:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l1.no_flow_logs", vpc_arn),
                rule_id="net.l1.vpc_flow_logs_disabled",
                title="VPC Flow Logs not enabled",
                description=(
                    f"VPC {vpc_id} does not have VPC Flow Logs enabled. "
                    "Without flow logs there is no visibility into network traffic, "
                    "making incident detection and forensics impossible."
                ),
                severity="high" if vpc.has_internet_gateway else "medium",
                network_layer=NetworkLayer.L1_TOPOLOGY,
                network_modules=["network_monitoring"],
                resource_uid=vpc_arn,
                resource_type="vpc",
                region=vpc.region,
                remediation="Enable VPC Flow Logs (ALL traffic, S3/CloudWatch destination).",
                finding_data={
                    "network_context": {
                        "vpc_id": vpc_id,
                        "has_igw": vpc.has_internet_gateway,
                        "flow_logging": False,
                    },
                    "mitre_techniques": ["T1040", "T1562.008"],
                    "attack_path_category": None,
                },
            ))

        # 3. Single-AZ subnet layout
        azs = set(s.availability_zone for s in vpc.subnets.values())
        if len(vpc.subnets) > 0 and len(azs) == 1:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l1.single_az", vpc_arn),
                rule_id="net.l1.single_az_subnets",
                title="All subnets in single availability zone",
                description=(
                    f"VPC {vpc_id} has {len(vpc.subnets)} subnets all in {list(azs)[0]}. "
                    "Single-AZ layout creates a single point of failure."
                ),
                severity="low",
                network_layer=NetworkLayer.L1_TOPOLOGY,
                network_modules=["network_isolation"],
                resource_uid=vpc_arn,
                resource_type="vpc",
                region=vpc.region,
                remediation="Distribute subnets across at least 2 availability zones.",
            ))

        # 4. DNS hostnames disabled (breaks private DNS for VPC endpoints)
        if not vpc.dns_hostnames and len(vpc.vpc_endpoints) > 0:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l1.no_dns_hostnames", vpc_arn),
                rule_id="net.l1.dns_hostnames_disabled",
                title="DNS hostnames disabled on VPC with endpoints",
                description=(
                    f"VPC {vpc_id} has {len(vpc.vpc_endpoints)} VPC endpoints but "
                    "DNS hostnames are disabled. Interface VPC endpoints require DNS "
                    "hostnames for private DNS resolution."
                ),
                severity="medium",
                network_layer=NetworkLayer.L1_TOPOLOGY,
                network_modules=["network_isolation"],
                resource_uid=vpc_arn,
                resource_type="vpc",
                region=vpc.region,
                remediation="Enable DNS hostnames on this VPC.",
            ))

        # 5. Empty VPC (no subnets)
        if len(vpc.subnets) == 0:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l1.empty_vpc", vpc_arn),
                rule_id="net.l1.empty_vpc",
                title="VPC has no subnets",
                description=f"VPC {vpc_id} has no subnets. This may be an unused or misconfigured VPC.",
                severity="low",
                status="WARN",
                network_layer=NetworkLayer.L1_TOPOLOGY,
                network_modules=["network_isolation"],
                resource_uid=vpc_arn,
                resource_type="vpc",
                region=vpc.region,
                remediation="Delete unused VPCs or create subnets for workloads.",
            ))

    # 6. Overlapping CIDRs across peered VPCs
    for vpc_id, peer_ids in topology.peering_map.items():
        vpc = topology.vpcs.get(vpc_id)
        if not vpc:
            continue
        for peer_id in peer_ids:
            peer_vpc = topology.vpcs.get(peer_id)
            if not peer_vpc:
                continue
            overlaps = _find_cidr_overlaps(vpc.cidr_blocks, peer_vpc.cidr_blocks)
            for local_cidr, peer_cidr in overlaps:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l1.cidr_overlap", f"{vpc_id}|{peer_id}|{local_cidr}"),
                    rule_id="net.l1.overlapping_cidrs_peered_vpcs",
                    title="Overlapping CIDRs between peered VPCs",
                    description=(
                        f"VPC {vpc_id} ({local_cidr}) and peered VPC {peer_id} ({peer_cidr}) "
                        "have overlapping CIDR ranges. This causes routing ambiguity and may "
                        "lead to traffic misrouting or data exposure."
                    ),
                    severity="high",
                    network_layer=NetworkLayer.L1_TOPOLOGY,
                    network_modules=["network_isolation", "network_reachability"],
                    resource_uid=f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:vpc/{vpc_id}",
                    resource_type="vpc",
                    region=vpc.region,
                    remediation="Re-IP one of the VPCs or use private NAT for translation.",
                    finding_data={
                        "network_context": {
                            "vpc_id": vpc_id,
                            "peer_vpc_id": peer_id,
                            "local_cidr": local_cidr,
                            "peer_cidr": peer_cidr,
                        },
                        "mitre_techniques": ["T1557"],
                    },
                ))

    # 7. Dead peering (connected but no route entries in any route table)
    for vpc_id, vpc in topology.vpcs.items():
        for pcx in vpc.peering_connections:
            pcx_id = pcx.get("pcx_id", "")
            has_route = any(
                any(r.target_type == "pcx" and r.target_id == pcx_id
                    for r in rtb.routes)
                for rtb in vpc.route_tables.values()
            )
            if not has_route:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l1.dead_peering", f"{vpc_id}|{pcx_id}"),
                    rule_id="net.l1.dead_peering_connection",
                    title="VPC peering connection has no route table entries",
                    description=(
                        f"VPC {vpc_id} has peering connection {pcx_id} to "
                        f"{pcx.get('peer_vpc_id', '?')} but no route table references it. "
                        "This peering is effectively dead."
                    ),
                    severity="low",
                    status="WARN",
                    network_layer=NetworkLayer.L1_TOPOLOGY,
                    network_modules=["network_reachability"],
                    resource_uid=f"arn:aws:ec2:{vpc.region}:{vpc.account_id}:vpc-peering-connection/{pcx_id}",
                    resource_type="vpc_peering_connection",
                    region=vpc.region,
                    remediation="Add routes for this peering or delete the unused connection.",
                ))

    # 8. TGW connecting potentially different environments
    for tgw_id, attached_vpcs in topology.tgw_map.items():
        if len(attached_vpcs) > 3:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l1.tgw_many_vpcs", tgw_id),
                rule_id="net.l1.tgw_broad_connectivity",
                title=f"Transit Gateway connects {len(attached_vpcs)} VPCs",
                description=(
                    f"Transit Gateway {tgw_id} connects {len(attached_vpcs)} VPCs. "
                    "Broad TGW connectivity increases lateral movement risk across environments."
                ),
                severity="medium",
                network_layer=NetworkLayer.L1_TOPOLOGY,
                network_modules=["network_isolation", "network_reachability"],
                resource_uid=tgw_id,
                resource_type="transit_gateway",
                finding_data={
                    "network_context": {"tgw_id": tgw_id, "attached_vpcs": attached_vpcs},
                    "mitre_techniques": ["T1021"],
                    "attack_path_category": "lateral_movement",
                },
                remediation="Use TGW route table segmentation to isolate VPC traffic.",
            ))

    return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fid(rule_id: str, resource_key: str) -> str:
    """Generate deterministic finding_id."""
    raw = f"{rule_id}|{resource_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _normalize_protocol(proto: str) -> str:
    """Convert AWS protocol number to name."""
    mapping = {"-1": "-1", "6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
    return mapping.get(proto, proto)


def _parse_sg_rules(ip_permissions: List[Dict]) -> List[SGRule]:
    """Parse AWS IpPermissions into SGRule list."""
    rules = []
    for perm in ip_permissions:
        proto = perm.get("IpProtocol", "-1")
        port_from = perm.get("FromPort", -1) if proto != "-1" else -1
        port_to = perm.get("ToPort", -1) if proto != "-1" else -1

        cidrs = [r.get("CidrIp", "") for r in perm.get("IpRanges", []) if r.get("CidrIp")]
        cidrs += [r.get("CidrIpv6", "") for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6")]
        sg_refs = [r.get("GroupId", "") for r in perm.get("UserIdGroupPairs", []) if r.get("GroupId")]
        prefix_ids = [r.get("PrefixListId", "") for r in perm.get("PrefixListIds", []) if r.get("PrefixListId")]
        desc = (perm.get("IpRanges", [{}])[0].get("Description", "")
                if perm.get("IpRanges") else "")

        rules.append(SGRule(
            protocol=proto,
            port_from=port_from,
            port_to=port_to,
            cidrs=cidrs,
            sg_refs=sg_refs,
            prefix_list_ids=prefix_ids,
            description=desc,
        ))
    return rules


def _find_cidr_overlaps(
    cidrs_a: List[str], cidrs_b: List[str],
) -> List[Tuple[str, str]]:
    """Find overlapping CIDRs between two lists."""
    overlaps = []
    for ca in cidrs_a:
        try:
            net_a = ipaddress.ip_network(ca, strict=False)
        except ValueError:
            continue
        for cb in cidrs_b:
            try:
                net_b = ipaddress.ip_network(cb, strict=False)
            except ValueError:
                continue
            if net_a.overlaps(net_b):
                overlaps.append((ca, cb))
    return overlaps
