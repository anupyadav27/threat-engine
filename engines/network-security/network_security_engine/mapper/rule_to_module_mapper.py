"""
Network Security — Rule-to-Module Mapper

Classifies check_findings and discovery resources into 8 network security
modules, following the IAM/DataSec pattern.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

# ── Network-relevant resource types ──────────────────────────────────────────

NETWORK_RESOURCE_TYPES: Set[str] = {
    "ec2", "vpc", "subnet", "security_group", "security_group_rule",
    "route_table", "network_acl", "igw", "internet_gateway",
    "nat_gateway", "egress_only_igw", "carrier_gateway",
    "customer_gateway", "vpn_connection",
    "vpc_endpoint", "vpc_peering_connection",
    "transit_gateway", "transit_gateway_attachment",
    "transit_gateway_route_table",
    "network_interface", "eip", "elastic_ip",
    "elbv2", "elb", "alb", "nlb", "load_balancer",
    "wafv2", "waf", "web_acl",
    "networkfirewall", "network_firewall", "firewall_policy",
    "cloudfront", "cloudfront_distribution",
    "route53", "hosted_zone",
    "apigateway", "apigatewayv2",
    "flow_log", "vpcflowlogs",
    "directconnect", "direct_connect_connection",
}

# ── Rule ID patterns that indicate network relevance ─────────────────────────

NETWORK_RULE_PATTERNS = [
    re.compile(r"\.security_group"),
    re.compile(r"\.sg[._]"),
    re.compile(r"\.vpc[._]"),
    re.compile(r"\.nacl"),
    re.compile(r"\.network_acl"),
    re.compile(r"\.network[._]"),
    re.compile(r"\.subnet"),
    re.compile(r"\.route[._]"),
    re.compile(r"\.igw|\.internet_gateway"),
    re.compile(r"\.nat_gateway"),
    re.compile(r"\.waf"),
    re.compile(r"\.elb|\.alb|\.nlb|\.load_balancer"),
    re.compile(r"\.elbv2"),
    re.compile(r"\.flow_log"),
    re.compile(r"\.vpcflowlog"),
    re.compile(r"\.firewall"),
    re.compile(r"\.peering"),
    re.compile(r"\.transit_gateway|\.tgw"),
    re.compile(r"\.public_ip|\.eip|\.elastic_ip"),
    re.compile(r"\.listener"),
    re.compile(r"\.cloudfront"),
    re.compile(r"\.apigateway"),
    re.compile(r"\.endpoint"),
    re.compile(r"\.vpn"),
    re.compile(r"\.directconnect|\.direct_connect"),
    re.compile(r"\.dns|\.route53"),
    re.compile(r"\.networkfirewall"),
    re.compile(r"\.shield"),
]

# ── 8 Network Security Modules with keyword mapping ──────────────────────────

MODULE_KEYWORDS: Dict[str, List[str]] = {
    "network_isolation": [
        "vpc", "cidr", "segment", "isolation", "peering",
        "transit_gateway", "tgw", "separate", "default_vpc",
        "vpc_endpoint", "private_link", "endpoint",
    ],
    "network_reachability": [
        "route", "route_table", "igw", "internet_gateway",
        "nat_gateway", "nat", "blackhole", "propagat",
        "destination", "reachab", "public_subnet",
    ],
    "network_acl": [
        "nacl", "network_acl", "acl_rule", "stateless",
        "subnet_firewall", "deny_rule",
    ],
    "security_group_rules": [
        "security_group", "sg_", "ingress", "egress",
        "inbound", "outbound", "port", "protocol",
        "0.0.0.0", "unrestricted", "open_to_world",
        "overly_permissive", "all_traffic", "orphan",
    ],
    "load_balancer_security": [
        "alb", "nlb", "elb", "load_balancer", "elbv2",
        "listener", "target_group", "scheme",
        "internet_facing", "tls", "ssl", "certificate",
        "redirect", "http_to_https",
    ],
    "waf_protection": [
        "waf", "shield", "web_acl", "rule_group",
        "rate_limit", "geo_block", "ip_reputation",
        "managed_rule", "owasp", "ddos",
        "cloudfront", "apigateway",
    ],
    "internet_exposure": [
        "public_ip", "elastic_ip", "eip",
        "internet", "exposure", "public_access",
        "publicly_accessible", "internet_routable",
        "direct_connect", "vpn", "external",
    ],
    "network_monitoring": [
        "flow_log", "vpcflowlog", "logging", "monitoring",
        "traffic_mirror", "packet_capture", "dns_log",
        "query_log", "guard_duty", "network_firewall_log",
    ],
}


def is_network_relevant(rule_id: str, resource_type: str = "",
                        service: str = "") -> bool:
    """Check if a rule or resource is relevant to network security."""
    rule_lower = rule_id.lower()
    res_lower = resource_type.lower()
    svc_lower = service.lower()

    # Match by resource type
    if res_lower in NETWORK_RESOURCE_TYPES:
        return True

    # Match by service name
    network_services = {
        "ec2", "vpc", "elbv2", "elb", "wafv2", "waf",
        "cloudfront", "route53", "networkfirewall",
        "directconnect", "apigateway", "apigatewayv2",
        "vpcflowlogs",
    }
    if svc_lower in network_services:
        return True

    # Match by rule_id pattern
    for pattern in NETWORK_RULE_PATTERNS:
        if pattern.search(rule_lower):
            return True

    return False


def derive_modules(rule_id: str, resource_type: str = "",
                   title: str = "") -> List[str]:
    """Derive which network security modules a rule maps to."""
    text = f"{rule_id} {resource_type} {title}".lower()
    modules = []

    for module, keywords in MODULE_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                modules.append(module)
                break

    # Default: if nothing matched but it's network-relevant, put in internet_exposure
    if not modules and is_network_relevant(rule_id, resource_type):
        modules.append("internet_exposure")

    return modules


def classify_findings(check_findings: List[Dict]) -> List[Dict]:
    """
    Filter and classify check_findings into network-relevant findings
    with module assignments.

    Args:
        check_findings: Raw check_findings rows from DB.

    Returns:
        Subset of findings that are network-relevant, each enriched with
        'network_modules' key.
    """
    network_findings = []
    for f in check_findings:
        rule_id = f.get("rule_id", "")
        resource_type = f.get("resource_type", "")
        service = f.get("service", "")
        title = f.get("title", "")

        if not is_network_relevant(rule_id, resource_type, service):
            continue

        modules = derive_modules(rule_id, resource_type, title)
        f["network_modules"] = modules
        network_findings.append(f)

    return network_findings
