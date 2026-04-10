"""
Inventory Builder — Build a unified container inventory from discovery resources.

Cross-references:
  - Discovery resources -> extract container metadata (K8s version, platform, etc.)
  - Check findings     -> compute pass/fail counts per resource

Supported services: eks, ecs, ecr, fargate, lambda
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .rule_categorizer import categorize_finding, get_service_from_rule, is_container_rule

logger = logging.getLogger(__name__)

# ── Service-specific config extractors ───────────────────────────────────────
# Each function receives the raw discovery resource dict and returns a partial
# inventory dict with service-specific fields.


def _extract_eks(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract EKS-specific fields from a discovery resource."""
    config = r.get("configuration") or r.get("config") or {}
    resources_vpc = config.get("ResourcesVpcConfig") or {}
    encryption_config = config.get("EncryptionConfig") or []
    logging_cfg = config.get("Logging") or {}
    cluster_logging = logging_cfg.get("ClusterLogging") or []

    # Check if any log types are enabled
    logging_enabled = False
    for log_group in cluster_logging:
        if log_group.get("Enabled"):
            logging_enabled = True
            break

    # Check if encryption is configured
    encryption_enabled = len(encryption_config) > 0

    return {
        "container_service": "eks",
        "k8s_version": config.get("Version", ""),
        "platform_version": config.get("PlatformVersion", ""),
        "endpoint_public": resources_vpc.get("EndpointPublicAccess", True),
        "encryption_enabled": encryption_enabled,
        "logging_enabled": logging_enabled,
        "network_policy_enabled": False,  # Not directly in API response
        "vpc_id": resources_vpc.get("VpcId", ""),
        "security_groups": resources_vpc.get("SecurityGroupIds", []),
        "subnet_ids": resources_vpc.get("SubnetIds", []),
        "cluster_status": config.get("Status", ""),
    }


def _extract_ecs(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract ECS-specific fields from a discovery resource."""
    config = r.get("configuration") or r.get("config") or {}
    settings = config.get("Settings") or []

    container_insights = False
    for setting in settings:
        if setting.get("Name") == "containerInsights" and setting.get("Value") == "enabled":
            container_insights = True

    return {
        "container_service": "ecs",
        "k8s_version": "",
        "platform_version": "",
        "endpoint_public": False,
        "encryption_enabled": False,
        "logging_enabled": container_insights,
        "network_policy_enabled": False,
        "vpc_id": "",
        "security_groups": [],
        "cluster_status": config.get("Status", "ACTIVE"),
        "capacity_providers": config.get("CapacityProviders", []),
    }


def _extract_ecr(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract ECR-specific fields from a discovery resource."""
    config = r.get("configuration") or r.get("config") or {}
    encryption_cfg = config.get("EncryptionConfiguration") or {}
    scan_cfg = config.get("ImageScanningConfiguration") or {}

    return {
        "container_service": "ecr",
        "k8s_version": "",
        "platform_version": "",
        "endpoint_public": False,
        "encryption_enabled": encryption_cfg.get("EncryptionType", "AES256") != "",
        "logging_enabled": False,
        "network_policy_enabled": False,
        "vpc_id": "",
        "security_groups": [],
        "image_scan_on_push": scan_cfg.get("ScanOnPush", False),
        "image_tag_mutability": config.get("ImageTagMutability", "MUTABLE"),
    }


def _extract_fargate(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Fargate-specific fields from a discovery resource."""
    config = r.get("configuration") or r.get("config") or {}
    network_cfg = config.get("NetworkConfiguration") or {}
    awsvpc_cfg = network_cfg.get("AwsvpcConfiguration") or {}

    return {
        "container_service": "fargate",
        "k8s_version": "",
        "platform_version": config.get("PlatformVersion", "LATEST"),
        "endpoint_public": awsvpc_cfg.get("AssignPublicIp") == "ENABLED",
        "encryption_enabled": False,
        "logging_enabled": bool(config.get("LogConfiguration")),
        "network_policy_enabled": False,
        "vpc_id": "",
        "security_groups": awsvpc_cfg.get("SecurityGroups", []),
        "subnets": awsvpc_cfg.get("Subnets", []),
    }


def _extract_lambda(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Lambda-specific fields from a discovery resource."""
    config = r.get("configuration") or r.get("config") or {}
    vpc_config = config.get("VpcConfig") or {}
    tracing_cfg = config.get("TracingConfig") or {}

    return {
        "container_service": "lambda",
        "k8s_version": "",
        "platform_version": "",
        "endpoint_public": not bool(vpc_config.get("VpcId")),
        "encryption_enabled": bool(config.get("KMSKeyArn")),
        "logging_enabled": True,  # Lambda always has CloudWatch logs
        "network_policy_enabled": False,
        "vpc_id": vpc_config.get("VpcId", ""),
        "security_groups": vpc_config.get("SecurityGroupIds", []),
        "runtime": config.get("Runtime", ""),
        "memory_size": config.get("MemorySize"),
        "tracing_enabled": tracing_cfg.get("Mode") == "Active",
    }


def _extract_generic(r: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback extractor for unrecognized container services."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "container_service": "unknown",
        "k8s_version": "",
        "platform_version": "",
        "endpoint_public": False,
        "encryption_enabled": False,
        "logging_enabled": False,
        "network_policy_enabled": False,
        "vpc_id": "",
        "security_groups": [],
    }


_SERVICE_EXTRACTORS = {
    "eks": _extract_eks,
    "ecs": _extract_ecs,
    "ecr": _extract_ecr,
    "fargate": _extract_fargate,
    "lambda": _extract_lambda,
}


def _detect_service(resource: Dict[str, Any]) -> str:
    """Infer the container service from a discovery resource dict.

    Checks ``resource_type`` first, then falls back to ``resource_uid`` (ARN).
    """
    rt = (resource.get("resource_type") or "").lower()
    uid = (resource.get("resource_uid") or "").lower()
    service_field = (resource.get("service") or "").lower()

    # Direct service field match
    if service_field in _SERVICE_EXTRACTORS:
        return service_field

    for svc in _SERVICE_EXTRACTORS:
        if svc in rt or f":{svc}:" in uid or f"/{svc}/" in uid:
            return svc

    # Additional patterns
    if "fargate" in rt or "fargate" in uid:
        return "fargate"

    return "unknown"


def build_container_inventory(
    discovery_resources: List[Dict[str, Any]],
    check_findings: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build a unified container inventory from discovery and check data.

    Args:
        discovery_resources: Raw discovery resource dicts.  Each should have
            at minimum ``resource_uid``, ``resource_type``, and a
            ``configuration`` / ``config`` sub-dict.
        check_findings: Optional check engine findings with ``rule_id``,
            ``resource_uid``, and ``status``.

    Returns:
        List of inventory dicts, one per container resource.
    """
    check_findings = check_findings or []

    # ── Index check findings by resource_uid ─────────────────────────────
    check_by_resource: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0}
    )
    domain_findings_by_resource: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"pass": 0, "fail": 0})
    )

    for f in check_findings:
        rule_id = f.get("rule_id", "")
        if not is_container_rule(rule_id):
            continue
        uid = f.get("resource_uid", "")
        status = (f.get("status") or "").upper()
        domain = categorize_finding(rule_id, f)

        if status == "PASS":
            check_by_resource[uid]["pass"] += 1
            domain_findings_by_resource[uid][domain]["pass"] += 1
        else:
            check_by_resource[uid]["fail"] += 1
            domain_findings_by_resource[uid][domain]["fail"] += 1

    # ── Build inventory entries ──────────────────────────────────────────
    inventory: List[Dict[str, Any]] = []

    for resource in discovery_resources:
        container_service = _detect_service(resource)
        if container_service == "unknown":
            continue

        resource_uid = resource.get("resource_uid", "")
        resource_name = (
            resource.get("resource_name")
            or resource.get("name")
            or resource_uid.split("/")[-1].split(":")[-1]
        )

        extractor = _SERVICE_EXTRACTORS.get(container_service, _extract_generic)
        entry = extractor(resource)

        # Common fields
        entry["resource_uid"] = resource_uid
        entry["resource_name"] = resource_name
        entry["resource_type"] = resource.get("resource_type", "")
        entry["account_id"] = resource.get("account_id", "")
        entry["region"] = resource.get("region", "")
        entry["provider"] = resource.get("provider", "aws")

        # Check findings cross-reference
        ck = check_by_resource.get(resource_uid, {"pass": 0, "fail": 0})
        entry["check_pass_count"] = ck["pass"]
        entry["check_fail_count"] = ck["fail"]
        entry["check_total"] = ck["pass"] + ck["fail"]

        # Per-domain check summary
        domain_summary = {}
        if resource_uid in domain_findings_by_resource:
            for domain, counts in domain_findings_by_resource[resource_uid].items():
                domain_summary[domain] = {
                    "pass": counts["pass"],
                    "fail": counts["fail"],
                }
        entry["domain_findings"] = domain_summary

        inventory.append(entry)

    logger.info(
        "Built container inventory: %d resources across %d services",
        len(inventory),
        len({e["container_service"] for e in inventory}),
    )

    return inventory
