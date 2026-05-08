"""
Network Security Engine — Domain Models

Layered network topology model used by all 7 analyzers.
Each layer builds on the one below it, mirroring the actual network stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Enums ────────────────────────────────────────────────────────────────────

class NetworkLayer(str, Enum):
    L1_TOPOLOGY = "L1_topology"
    L2_REACHABILITY = "L2_reachability"
    L3_NACL = "L3_nacl"
    L4_SG = "L4_sg"
    L5_LB = "L5_lb"
    L6_WAF = "L6_waf"
    L7_FLOW = "L7_flow"


class ExposureLevel(str, Enum):
    INTERNET = "internet"
    CROSS_VPC = "cross_vpc"
    VPC_INTERNAL = "vpc_internal"
    SUBNET_ONLY = "subnet_only"
    ISOLATED = "isolated"


class PathType(str, Enum):
    INTERNET_TO_RESOURCE = "internet_to_resource"
    CROSS_VPC = "cross_vpc"
    LATERAL_MOVEMENT = "lateral_movement"
    CROSS_SUBNET = "cross_subnet"


# ── Sensitive Ports (used by L3/L4 analyzers) ────────────────────────────────

SENSITIVE_PORTS: Dict[int, Dict[str, str]] = {
    22:    {"service": "ssh",         "severity": "critical", "mitre": "T1133"},
    3389:  {"service": "rdp",         "severity": "critical", "mitre": "T1133"},
    3306:  {"service": "mysql",       "severity": "critical", "mitre": "T1190"},
    5432:  {"service": "postgresql",  "severity": "critical", "mitre": "T1190"},
    1433:  {"service": "mssql",       "severity": "critical", "mitre": "T1190"},
    1521:  {"service": "oracle",      "severity": "critical", "mitre": "T1190"},
    27017: {"service": "mongodb",     "severity": "critical", "mitre": "T1190"},
    6379:  {"service": "redis",       "severity": "critical", "mitre": "T1190"},
    9200:  {"service": "elasticsearch", "severity": "high",   "mitre": "T1190"},
    9300:  {"service": "elasticsearch", "severity": "high",   "mitre": "T1190"},
    5601:  {"service": "kibana",      "severity": "high",     "mitre": "T1190"},
    11211: {"service": "memcached",   "severity": "high",     "mitre": "T1190"},
    2379:  {"service": "etcd",        "severity": "critical", "mitre": "T1190"},
    8080:  {"service": "http_alt",    "severity": "medium",   "mitre": "T1190"},
    8443:  {"service": "https_alt",   "severity": "medium",   "mitre": "T1190"},
    23:    {"service": "telnet",      "severity": "critical", "mitre": "T1133"},
    21:    {"service": "ftp",         "severity": "high",     "mitre": "T1133"},
    445:   {"service": "smb",         "severity": "critical", "mitre": "T1021"},
    135:   {"service": "rpc",         "severity": "high",     "mitre": "T1021"},
    53:    {"service": "dns",         "severity": "medium",   "mitre": "T1071"},
    25:    {"service": "smtp",        "severity": "medium",   "mitre": "T1071"},
    161:   {"service": "snmp",        "severity": "high",     "mitre": "T1040"},
    5900:  {"service": "vnc",         "severity": "critical", "mitre": "T1133"},
    6443:  {"service": "k8s_api",     "severity": "critical", "mitre": "T1190"},
    10250: {"service": "kubelet",     "severity": "critical", "mitre": "T1190"},
    2049:  {"service": "nfs",         "severity": "high",     "mitre": "T1021"},
    111:   {"service": "rpcbind",     "severity": "high",     "mitre": "T1021"},
    514:   {"service": "syslog",      "severity": "medium",   "mitre": "T1040"},
    8888:  {"service": "jupyter",     "severity": "critical", "mitre": "T1190"},
}

# Wildcard CIDRs
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


# ── Layer 1: Topology Models ─────────────────────────────────────────────────

@dataclass
class RouteEntry:
    """Single route in a route table."""
    destination_cidr: str
    target_type: str        # igw, nat, pcx, tgw, local, instance, eni, vpce, blackhole
    target_id: str
    is_propagated: bool = False
    is_blackhole: bool = False


@dataclass
class RouteTableNode:
    """Route table with its associations and routes."""
    route_table_id: str
    vpc_id: str
    subnet_ids: List[str] = field(default_factory=list)
    is_main: bool = False
    routes: List[RouteEntry] = field(default_factory=list)

    @property
    def has_igw_route(self) -> bool:
        return any(r.target_type == "igw" and r.destination_cidr in OPEN_CIDRS
                   for r in self.routes)

    @property
    def has_nat_route(self) -> bool:
        return any(r.target_type == "nat" and r.destination_cidr in OPEN_CIDRS
                   for r in self.routes)

    @property
    def internet_route_type(self) -> Optional[str]:
        """Return 'igw' (public), 'nat' (private+outbound), or None."""
        if self.has_igw_route:
            return "igw"
        if self.has_nat_route:
            return "nat"
        return None


@dataclass
class NACLRule:
    """Single NACL rule (inbound or outbound)."""
    rule_number: int
    protocol: str           # tcp, udp, icmp, -1 (all)
    port_from: int
    port_to: int
    cidr: str
    action: str             # allow, deny
    egress: bool = False


@dataclass
class NACLNode:
    """Network ACL with ordered rules."""
    nacl_id: str
    vpc_id: str
    subnet_ids: List[str] = field(default_factory=list)
    is_default: bool = False
    inbound_rules: List[NACLRule] = field(default_factory=list)
    outbound_rules: List[NACLRule] = field(default_factory=list)

    def allows_port_inbound(self, port: int, cidr: str = "0.0.0.0/0") -> bool:
        """Evaluate ordered NACL rules (lowest rule_number first). First match wins."""
        import ipaddress
        try:
            target_net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

        sorted_rules = sorted(self.inbound_rules, key=lambda r: r.rule_number)
        for rule in sorted_rules:
            if rule.rule_number == 32767:   # default deny — always last
                continue
            try:
                rule_net = ipaddress.ip_network(rule.cidr, strict=False)
            except ValueError:
                continue
            if not target_net.subnet_of(rule_net) and rule.cidr not in OPEN_CIDRS:
                continue
            if rule.protocol not in ("-1", "tcp", "udp", "all"):
                continue
            if rule.protocol != "-1" and not (rule.port_from <= port <= rule.port_to):
                continue
            return rule.action == "allow"
        return False  # implicit deny


@dataclass
class SubnetNode:
    """Subnet within a VPC."""
    subnet_id: str
    vpc_id: str
    cidr_block: str
    availability_zone: str
    is_public: bool = False             # set by L2 reachability (has IGW route)
    resource_uids: List[str] = field(default_factory=list)
    nacl_id: Optional[str] = None
    route_table_id: Optional[str] = None
    map_public_ip_on_launch: bool = False


@dataclass
class VPCNode:
    """VPC with all child resources."""
    vpc_id: str
    cidr_blocks: List[str] = field(default_factory=list)
    is_default: bool = False
    flow_log_enabled: bool = False
    dns_support: bool = True
    dns_hostnames: bool = False

    # Child resources
    subnets: Dict[str, SubnetNode] = field(default_factory=dict)
    route_tables: Dict[str, RouteTableNode] = field(default_factory=dict)
    nacls: Dict[str, NACLNode] = field(default_factory=dict)
    security_groups: Dict[str, SGNode] = field(default_factory=dict)

    # Connectivity
    igw_id: Optional[str] = None
    nat_gateways: List[Dict[str, Any]] = field(default_factory=list)
    peering_connections: List[Dict[str, Any]] = field(default_factory=list)
    tgw_attachments: List[Dict[str, Any]] = field(default_factory=list)
    vpc_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    network_firewalls: List[Dict[str, Any]] = field(default_factory=list)

    # Computed
    region: str = ""
    account_id: str = ""

    @property
    def has_internet_gateway(self) -> bool:
        return self.igw_id is not None

    @property
    def public_subnets(self) -> List[SubnetNode]:
        return [s for s in self.subnets.values() if s.is_public]

    @property
    def private_subnets(self) -> List[SubnetNode]:
        return [s for s in self.subnets.values() if not s.is_public]


# ── Layer 4: Security Group Models ───────────────────────────────────────────

@dataclass
class SGRule:
    """Single security group rule (inbound or outbound)."""
    protocol: str           # tcp, udp, icmp, -1 (all)
    port_from: int          # -1 for all
    port_to: int            # -1 for all
    cidrs: List[str] = field(default_factory=list)       # IP CIDRs
    sg_refs: List[str] = field(default_factory=list)     # referenced SG IDs
    prefix_list_ids: List[str] = field(default_factory=list)
    description: str = ""

    @property
    def is_open_to_world(self) -> bool:
        return bool(set(self.cidrs) & OPEN_CIDRS)

    @property
    def is_all_ports(self) -> bool:
        return (self.port_from == -1 and self.port_to == -1) or \
               (self.port_from == 0 and self.port_to == 65535)

    @property
    def port_range(self) -> int:
        if self.port_from < 0 or self.port_to < 0:
            return 65536
        return self.port_to - self.port_from + 1

    def exposes_port(self, port: int) -> bool:
        if self.port_from == -1:
            return True
        return self.port_from <= port <= self.port_to


@dataclass
class SGNode:
    """Security group with analysis results."""
    sg_id: str
    sg_name: str
    vpc_id: str
    resource_uid: str = ""              # SG ARN

    inbound_rules: List[SGRule] = field(default_factory=list)
    outbound_rules: List[SGRule] = field(default_factory=list)

    # Attachments
    attached_resources: List[Dict[str, Any]] = field(default_factory=list)
    is_default: bool = False

    @property
    def is_orphaned(self) -> bool:
        return len(self.attached_resources) == 0

    @property
    def inbound_open_to_world(self) -> bool:
        return any(r.is_open_to_world for r in self.inbound_rules)

    @property
    def inbound_all_traffic(self) -> bool:
        return any(r.is_open_to_world and r.is_all_ports for r in self.inbound_rules)

    @property
    def outbound_unrestricted(self) -> bool:
        return any(r.is_open_to_world and r.is_all_ports for r in self.outbound_rules)

    @property
    def sg_to_sg_refs(self) -> List[str]:
        refs = set()
        for r in self.inbound_rules + self.outbound_rules:
            refs.update(r.sg_refs)
        return list(refs)

    def get_open_inbound_ports(self) -> List[Dict[str, Any]]:
        """Get ports open from 0.0.0.0/0 or ::/0."""
        ports = []
        for rule in self.inbound_rules:
            if not rule.is_open_to_world:
                continue
            if rule.is_all_ports:
                ports.append({"port_from": 0, "port_to": 65535,
                              "protocol": rule.protocol, "cidrs": rule.cidrs})
            else:
                ports.append({"port_from": rule.port_from, "port_to": rule.port_to,
                              "protocol": rule.protocol, "cidrs": rule.cidrs})
        return ports

    def get_sensitive_ports_exposed(self) -> List[Dict[str, Any]]:
        """Get sensitive ports (SSH/RDP/DB/etc.) exposed to 0.0.0.0/0."""
        exposed = []
        for port, info in SENSITIVE_PORTS.items():
            for rule in self.inbound_rules:
                if rule.is_open_to_world and rule.exposes_port(port):
                    exposed.append({
                        "port": port,
                        "service": info["service"],
                        "severity": info["severity"],
                        "mitre": info["mitre"],
                        "protocol": rule.protocol,
                        "cidrs": rule.cidrs,
                    })
                    break
        return exposed


# ── Layer 5: Load Balancer Models ─────────────────────────────────────────────

@dataclass
class ListenerNode:
    """ALB/NLB listener."""
    listener_arn: str
    protocol: str           # HTTP, HTTPS, TCP, TLS, UDP, TCP_UDP
    port: int
    ssl_policy: Optional[str] = None
    certificates: List[str] = field(default_factory=list)
    default_actions: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def is_plaintext(self) -> bool:
        return self.protocol in ("HTTP", "TCP")

    @property
    def has_redirect_to_https(self) -> bool:
        return any(a.get("Type") == "redirect"
                   and a.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                   for a in self.default_actions)


@dataclass
class LoadBalancerNode:
    """ALB / NLB / CLB."""
    lb_arn: str
    lb_name: str
    lb_type: str            # application, network, classic
    scheme: str             # internet-facing, internal
    vpc_id: str
    security_groups: List[str] = field(default_factory=list)
    subnets: List[str] = field(default_factory=list)
    availability_zones: List[str] = field(default_factory=list)
    listeners: List[ListenerNode] = field(default_factory=list)
    waf_acl_arn: Optional[str] = None

    @property
    def is_internet_facing(self) -> bool:
        return self.scheme == "internet-facing"


# ── Layer 6: WAF Models ──────────────────────────────────────────────────────

@dataclass
class WAFRuleGroup:
    """WAF rule group within a Web ACL."""
    name: str
    vendor: str = ""        # AWS, custom
    priority: int = 0
    action: str = ""        # allow, block, count
    rules_count: int = 0


@dataclass
class WAFWebACL:
    """WAFv2 Web ACL."""
    acl_arn: str
    acl_name: str
    default_action: str     # allow, block
    rule_groups: List[WAFRuleGroup] = field(default_factory=list)
    associated_resources: List[str] = field(default_factory=list)
    has_rate_limiting: bool = False
    has_managed_core_ruleset: bool = False
    logging_enabled: bool = False
    capacity_used: int = 0


# ── Cross-Layer: Exposure Path ────────────────────────────────────────────────

@dataclass
class PathHop:
    """Single hop in an exposure path."""
    layer: str              # L1, L2, L3, L4, L5, L6
    hop_type: str           # igw, route, nacl, sg, lb, waf
    resource_id: str
    action: str = ""        # allow, deny, route, forward
    ports: List[int] = field(default_factory=list)
    detail: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExposurePath:
    """End-to-end reachability path through network layers."""
    path_type: PathType
    source_type: str        # internet, vpc, subnet, sg
    source_id: str
    target_resource_uid: str
    target_resource_type: str
    hops: List[PathHop] = field(default_factory=list)
    exposed_ports: List[Dict[str, Any]] = field(default_factory=list)
    severity: str = "medium"
    is_fully_exposed: bool = False
    blocked_by: Optional[str] = None
    attack_path_category: str = "exposure"
    blast_radius: int = 0
    mitre_techniques: List[str] = field(default_factory=list)


# ── Network Finding (unified output from all analyzers) ──────────────────────

@dataclass
class NetworkFinding:
    """Unified finding produced by any analyzer layer."""
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    status: str = "FAIL"
    network_layer: str = ""
    network_modules: List[str] = field(default_factory=list)
    effective_exposure: str = ""
    resource_uid: str = ""
    resource_type: str = ""
    region: str = ""
    remediation: str = ""
    finding_data: Dict[str, Any] = field(default_factory=dict)

    def to_db_row(self, scan_run_id: str, tenant_id: str, account_id: str,
                  provider: str, credential_ref: str = "",
                  credential_type: str = "") -> Dict[str, Any]:
        """Convert to dict matching network_findings table columns."""
        return {
            "finding_id": self.finding_id,
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "credential_ref": credential_ref,
            "credential_type": credential_type,
            "provider": provider,
            "region": self.region,
            "resource_uid": self.resource_uid,
            "resource_type": self.resource_type,
            "network_layer": self.network_layer,
            "network_modules": self.network_modules,
            "effective_exposure": self.effective_exposure,
            "severity": self.severity,
            "status": self.status,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "finding_data": self.finding_data,
        }


# ── Full Network Topology (aggregates all VPCs) ──────────────────────────────

@dataclass
class NetworkTopology:
    """Complete network topology for an account/region."""
    vpcs: Dict[str, VPCNode] = field(default_factory=dict)
    load_balancers: Dict[str, LoadBalancerNode] = field(default_factory=dict)
    waf_acls: Dict[str, WAFWebACL] = field(default_factory=dict)
    eips: List[Dict[str, Any]] = field(default_factory=list)
    peering_map: Dict[str, List[str]] = field(default_factory=dict)     # vpc→[peer_vpcs]
    tgw_map: Dict[str, List[str]] = field(default_factory=dict)         # tgw→[attached_vpcs]

    # Global counts
    @property
    def total_vpcs(self) -> int:
        return len(self.vpcs)

    @property
    def total_subnets(self) -> int:
        return sum(len(v.subnets) for v in self.vpcs.values())

    @property
    def total_security_groups(self) -> int:
        return sum(len(v.security_groups) for v in self.vpcs.values())

    @property
    def total_nacls(self) -> int:
        return sum(len(v.nacls) for v in self.vpcs.values())

    @property
    def total_route_tables(self) -> int:
        return sum(len(v.route_tables) for v in self.vpcs.values())
