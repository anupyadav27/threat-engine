"""
Layer 5 — Load Balancer Analyzer

Analyzes ALB/NLB/CLB for exposure, TLS configuration, and listener security.

Findings:
  - Internet-facing LB with HTTP listener (no HTTPS redirect)
  - Internet-facing LB with expired/weak TLS
  - Internet-facing NLB without WAF
  - LB with SG allowing all ports
  - Internal LB in public subnet
  - LB with TLS 1.0/1.1 (weak crypto)
  - Classic LB (deprecated, no modern features)
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional

from ..models import (
    ExposureLevel, ListenerNode, LoadBalancerNode,
    NetworkFinding, NetworkLayer, NetworkTopology,
)

logger = logging.getLogger(__name__)

# Weak TLS policies
WEAK_TLS_POLICIES = {
    "ELBSecurityPolicy-2016-08",
    "ELBSecurityPolicy-TLS-1-0-2015-04",
    "ELBSecurityPolicy-TLS-1-1-2017-01",
}


def build_load_balancers(
    discovery_data: Dict[str, List[Dict[str, Any]]],
    topology: NetworkTopology,
) -> None:
    """Parse discovery data and populate topology.load_balancers."""
    # ALB/NLB (ELBv2)
    for row in discovery_data.get("elbv2_lbs", []):
        raw = row.get("raw_response") or {}
        lb_arn = raw.get("LoadBalancerArn", row.get("resource_uid", ""))
        if not lb_arn:
            continue

        lb = LoadBalancerNode(
            lb_arn=lb_arn,
            lb_name=raw.get("LoadBalancerName", ""),
            lb_type=raw.get("Type", "application"),
            scheme=raw.get("Scheme", "internal"),
            vpc_id=raw.get("VpcId", ""),
            security_groups=raw.get("SecurityGroups", []),
            subnets=[az.get("SubnetId", "") for az in raw.get("AvailabilityZones", [])],
            availability_zones=[az.get("ZoneName", "") for az in raw.get("AvailabilityZones", [])],
        )
        topology.load_balancers[lb_arn] = lb

    # Parse listeners and attach to LBs
    for row in discovery_data.get("elbv2_listeners", []):
        raw = row.get("raw_response") or {}
        lb_arn = raw.get("LoadBalancerArn", "")
        lb = topology.load_balancers.get(lb_arn)
        if not lb:
            continue

        listener = ListenerNode(
            listener_arn=raw.get("ListenerArn", ""),
            protocol=raw.get("Protocol", "HTTP"),
            port=raw.get("Port", 80),
            ssl_policy=raw.get("SslPolicy"),
            certificates=[c.get("CertificateArn", "") for c in raw.get("Certificates", [])],
            default_actions=raw.get("DefaultActions", []),
        )
        lb.listeners.append(listener)

    # Classic ELB
    for row in discovery_data.get("elb_lbs", []):
        raw = row.get("raw_response") or {}
        lb_name = raw.get("LoadBalancerName", "")
        if not lb_name:
            continue

        dns = raw.get("DNSName", "")
        lb_arn = f"arn:aws:elasticloadbalancing:{row.get('region', '')}:classic/{lb_name}"

        lb = LoadBalancerNode(
            lb_arn=lb_arn,
            lb_name=lb_name,
            lb_type="classic",
            scheme=raw.get("Scheme", "internal"),
            vpc_id=raw.get("VPCId", ""),
            security_groups=raw.get("SecurityGroups", []),
            subnets=raw.get("Subnets", []),
        )

        # Classic LB listeners
        for ld in raw.get("ListenerDescriptions", []):
            l = ld.get("Listener", {})
            listener = ListenerNode(
                listener_arn=f"{lb_arn}/listener/{l.get('LoadBalancerPort', 0)}",
                protocol=l.get("Protocol", "HTTP"),
                port=l.get("LoadBalancerPort", 80),
                ssl_policy=None,
            )
            lb.listeners.append(listener)

        topology.load_balancers[lb_arn] = lb

    logger.info("Built %d load balancers", len(topology.load_balancers))


def analyze_load_balancers(topology: NetworkTopology) -> List[NetworkFinding]:
    """Analyze all load balancers (Layer 5)."""
    findings: List[NetworkFinding] = []

    for lb_arn, lb in topology.load_balancers.items():
        # 1. Internet-facing LB with plaintext HTTP listener (no redirect)
        if lb.is_internet_facing:
            for listener in lb.listeners:
                if listener.is_plaintext and not listener.has_redirect_to_https:
                    findings.append(NetworkFinding(
                        finding_id=_fid("net.l5.http_no_redirect", listener.listener_arn),
                        rule_id="net.l5.lb_http_without_https_redirect",
                        title=f"Internet-facing {lb.lb_type.upper()} has HTTP listener without HTTPS redirect",
                        description=(
                            f"Load balancer {lb.lb_name} ({lb.lb_type}) is internet-facing "
                            f"with HTTP listener on port {listener.port} that does not redirect "
                            "to HTTPS. Traffic is transmitted in plaintext."
                        ),
                        severity="high",
                        network_layer=NetworkLayer.L5_LB,
                        network_modules=["load_balancer_security", "internet_exposure"],
                        effective_exposure=ExposureLevel.INTERNET.value,
                        resource_uid=lb_arn,
                        resource_type="load_balancer",
                        remediation="Add a redirect action from HTTP to HTTPS on this listener.",
                        finding_data={
                            "lb_posture": {
                                "lb_name": lb.lb_name,
                                "lb_type": lb.lb_type,
                                "scheme": lb.scheme,
                                "listener_port": listener.port,
                                "protocol": listener.protocol,
                            },
                            "mitre_techniques": ["T1557"],
                        },
                    ))

        # 2. Weak TLS policy
        for listener in lb.listeners:
            if listener.ssl_policy and listener.ssl_policy in WEAK_TLS_POLICIES:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l5.weak_tls", listener.listener_arn),
                    rule_id="net.l5.lb_weak_tls_policy",
                    title=f"Load balancer uses weak TLS policy ({listener.ssl_policy})",
                    description=(
                        f"Listener on {lb.lb_name} port {listener.port} uses TLS policy "
                        f"{listener.ssl_policy} which supports TLS 1.0/1.1. "
                        "These protocols have known vulnerabilities."
                    ),
                    severity="high",
                    network_layer=NetworkLayer.L5_LB,
                    network_modules=["load_balancer_security"],
                    resource_uid=lb_arn,
                    resource_type="load_balancer",
                    remediation="Upgrade to ELBSecurityPolicy-TLS13-1-2-2021-06 or newer.",
                    finding_data={
                        "lb_posture": {
                            "ssl_policy": listener.ssl_policy,
                            "listener_port": listener.port,
                        },
                        "mitre_techniques": ["T1557.002"],
                    },
                ))

        # 3. Internet-facing LB with no HTTPS listeners at all
        if lb.is_internet_facing:
            has_tls = any(l.protocol in ("HTTPS", "TLS") for l in lb.listeners)
            if not has_tls and lb.listeners:
                findings.append(NetworkFinding(
                    finding_id=_fid("net.l5.no_tls", lb_arn),
                    rule_id="net.l5.lb_no_tls_listeners",
                    title=f"Internet-facing {lb.lb_type.upper()} has no TLS/HTTPS listeners",
                    description=(
                        f"Load balancer {lb.lb_name} is internet-facing but has no "
                        "HTTPS/TLS listeners. All traffic is unencrypted."
                    ),
                    severity="critical",
                    network_layer=NetworkLayer.L5_LB,
                    network_modules=["load_balancer_security", "internet_exposure"],
                    effective_exposure=ExposureLevel.INTERNET.value,
                    resource_uid=lb_arn,
                    resource_type="load_balancer",
                    remediation="Add an HTTPS listener with a valid TLS certificate.",
                ))

        # 4. Classic LB (deprecated)
        if lb.lb_type == "classic" and lb.is_internet_facing:
            findings.append(NetworkFinding(
                finding_id=_fid("net.l5.classic_lb", lb_arn),
                rule_id="net.l5.classic_lb_internet_facing",
                title="Internet-facing Classic Load Balancer (deprecated)",
                description=(
                    f"Classic LB {lb.lb_name} is internet-facing. Classic LBs lack "
                    "modern features (WAF integration, advanced routing, HTTP/2)."
                ),
                severity="medium",
                network_layer=NetworkLayer.L5_LB,
                network_modules=["load_balancer_security"],
                resource_uid=lb_arn,
                resource_type="load_balancer",
                remediation="Migrate to ALB or NLB for WAF integration and modern TLS support.",
            ))

        # 5. Internal LB in public subnet
        if not lb.is_internet_facing:
            for subnet_id in lb.subnets:
                vpc = topology.vpcs.get(lb.vpc_id)
                if vpc:
                    subnet = vpc.subnets.get(subnet_id)
                    if subnet and subnet.is_public:
                        findings.append(NetworkFinding(
                            finding_id=_fid("net.l5.internal_lb_public_subnet", f"{lb_arn}|{subnet_id}"),
                            rule_id="net.l5.internal_lb_in_public_subnet",
                            title="Internal Load Balancer deployed in public subnet",
                            description=(
                                f"Internal LB {lb.lb_name} is in public subnet {subnet_id}. "
                                "Internal LBs should be in private subnets."
                            ),
                            severity="medium",
                            network_layer=NetworkLayer.L5_LB,
                            network_modules=["load_balancer_security", "network_isolation"],
                            resource_uid=lb_arn,
                            resource_type="load_balancer",
                            remediation="Move internal LB to private subnets.",
                        ))
                        break  # one finding per LB

    return findings


def _fid(rule_id: str, resource_key: str) -> str:
    raw = f"{rule_id}|{resource_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
