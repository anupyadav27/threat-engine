"""
Rule Categorizer — Maps check rule_ids to container security domains.

Security domains:
  - cluster_security   — EKS cluster config, encryption, versions, endpoints
  - workload_security  — pod/task security, privileged containers, read-only root
  - image_security     — ECR image scanning, tag immutability, lifecycle policies
  - network_exposure   — public endpoints, network policies, VPC config
  - rbac_access        — RBAC, IAM roles, least privilege, access entries
  - runtime_audit      — control plane logging, tracing, CloudWatch logs
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Container services recognized by this engine ─────────────────────────────
CONTAINER_SERVICES = frozenset({
    "eks", "ecs", "ecr", "fargate", "lambda",
})

SECURITY_DOMAINS = frozenset({
    "cluster_security", "workload_security", "image_security",
    "network_exposure", "rbac_access", "runtime_audit",
})

# ── Exhaustive rule -> domain mapping ────────────────────────────────────────
RULE_DOMAIN_MAP: Dict[str, str] = {
    # ─── cluster_security (EKS cluster config) ───────────────────────────────
    "aws.eks.cluster.encryption_at_rest_enabled": "cluster_security",
    "aws.eks.cluster.encryption_provider_configured": "cluster_security",
    "aws.eks.cluster.secrets_encryption_enabled": "cluster_security",
    "aws.eks.cluster.logging_enabled": "cluster_security",
    "aws.eks.cluster.audit_logging_enabled": "cluster_security",
    "aws.eks.cluster.cloudwatch_logging_enabled": "cluster_security",
    "aws.eks.cluster.kubernetes_version_supported": "cluster_security",
    "aws.eks.cluster.platform_version_supported": "cluster_security",
    "aws.eks.cluster.endpoint_private_access_enabled": "cluster_security",
    "aws.eks.cluster.security_group_configured": "cluster_security",
    "aws.eks.cluster.vpc_config_validated": "cluster_security",

    # ─── workload_security (pod/task security) ───────────────────────────────
    "aws.ecs.container_instance.container_read_only_root_filesystem_configured": "workload_security",
    "aws.ecs.container_instance.container_no_privileged_configured": "workload_security",
    "aws.ecs.container_instance.container_logging_configured": "workload_security",
    "aws.eks.cluster.pod_security_standards_enforced": "workload_security",
    "aws.eks.cluster.security_context_configured": "workload_security",
    "aws.eks.pod.security_context_configured": "workload_security",
    "aws.eks.pod.no_privileged_containers": "workload_security",
    "aws.eks.pod.read_only_root_filesystem": "workload_security",
    "aws.eks.pod.no_host_network": "workload_security",
    "aws.eks.pod.no_host_pid": "workload_security",
    "aws.eks.pod.resource_limits_configured": "workload_security",
    "aws.fargate.task.secrets_management_configured": "workload_security",
    "aws.fargate.task.container_no_privileged_configured": "workload_security",
    "aws.fargate.task.read_only_root_filesystem_configured": "workload_security",
    "aws.ecs.task_definition.no_privileged_containers": "workload_security",
    "aws.ecs.task_definition.read_only_root_filesystem": "workload_security",
    "aws.ecs.task_definition.no_host_network": "workload_security",
    "aws.ecs.task_definition.resource_limits_configured": "workload_security",

    # ─── image_security (ECR) ────────────────────────────────────────────────
    "aws.ecr.resource.ecr_image_scan_on_push_enabled": "image_security",
    "aws.ecr.resource.ecr_image_tag_immutability_configured": "image_security",
    "aws.ecr.repository.encryption_at_rest_enabled": "image_security",
    "aws.ecr.repository.lifecycle_policy_configured": "image_security",
    "aws.ecr.repository.cross_region_replication_encrypted": "image_security",
    "aws.ecr.repository.image_scan_on_push_enabled": "image_security",
    "aws.ecr.repository.tag_immutability_enabled": "image_security",
    "aws.ecr.repository.no_public_access": "image_security",
    "aws.ecr.resource.ecr_repository_encryption_enabled": "image_security",

    # ─── network_exposure ────────────────────────────────────────────────────
    "aws.eks.cluster.endpoint_public_access_disabled": "network_exposure",
    "aws.eks.cluster.endpoint_public_access_restricted": "network_exposure",
    "aws.eks.cluster.network_policy_enabled": "network_exposure",
    "aws.fargate.task.vpc_private_networking_configured": "network_exposure",
    "aws.fargate.task.vpc_networking_configured": "network_exposure",
    "aws.lambda.function.vpc_configured": "network_exposure",
    "aws.lambda.function.public_access_disabled": "network_exposure",
    "aws.ecs.service.vpc_networking_configured": "network_exposure",
    "aws.ecs.service.private_networking_enforced": "network_exposure",
    "aws.eks.cluster.private_networking_enforced": "network_exposure",

    # ─── rbac_access ─────────────────────────────────────────────────────────
    "aws.eks.cluster.rbac_enabled": "rbac_access",
    "aws.eks.cluster.aws_auth_configured": "rbac_access",
    "aws.eks.access_entry.least_privilege_configured": "rbac_access",
    "aws.eks.access_entry.no_cluster_admin": "rbac_access",
    "aws.eks.access_entry.scoped_to_namespace": "rbac_access",
    "aws.eks.cluster.iam_role_least_privilege": "rbac_access",
    "aws.lambda.function.execution_role_least_privilege": "rbac_access",
    "aws.fargate.task.role_least_privilege": "rbac_access",
    "aws.ecs.task_definition.task_role_least_privilege": "rbac_access",
    "aws.ecs.task_definition.execution_role_least_privilege": "rbac_access",
    "aws.eks.cluster.service_account_token_projection": "rbac_access",

    # ─── runtime_audit ───────────────────────────────────────────────────────
    "aws.eks.cluster.control_plane_logging_enabled": "runtime_audit",
    "aws.lambda.function.tracing_enabled": "runtime_audit",
    "aws.lambda.function.cloudwatch_logs_configured": "runtime_audit",
    "aws.ecs.service.cloudwatch_logging_configured": "runtime_audit",
    "aws.ecs.task_definition.logging_configured": "runtime_audit",
    "aws.fargate.task.logging_configured": "runtime_audit",
    "aws.eks.cluster.cloudtrail_logging_enabled": "runtime_audit",
}

# ── Keyword patterns for fallback classification ─────────────────────────────
_KEYWORD_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"image_scan|tag_immutab|lifecycle_policy|ecr.*encrypt|repository.*encrypt|ecr.*public", re.I), "image_security"),
    (re.compile(r"privileged|read_only_root|host_network|host_pid|security_context|pod_security|resource_limit|secrets_management", re.I), "workload_security"),
    (re.compile(r"rbac|aws_auth|access_entry|least_privilege|execution_role|task_role|service_account|iam_role", re.I), "rbac_access"),
    (re.compile(r"public_access|endpoint_public|network_policy|vpc_config|vpc_network|private_network", re.I), "network_exposure"),
    (re.compile(r"control_plane_log|tracing|cloudwatch_log|cloudtrail_log|audit_log", re.I), "runtime_audit"),
    (re.compile(r"encrypt|secret.*encrypt|kms|version_supported|platform_version|security_group|vpc_config", re.I), "cluster_security"),
]


def categorize_finding(rule_id: str, finding: Optional[Dict[str, Any]] = None) -> str:
    """Classify a check finding into a container security domain.

    Args:
        rule_id: The check rule identifier (e.g. 'aws.eks.cluster.rbac_enabled').
        finding: Optional finding dict -- currently unused but reserved for
                 future content-based classification.

    Returns:
        One of the six security domain strings. Falls back to 'cluster_security'
        if no pattern matches.
    """
    # 1. Exact match
    domain = RULE_DOMAIN_MAP.get(rule_id)
    if domain:
        return domain

    # 2. Keyword-based fallback on the rule_id string
    for pattern, domain_name in _KEYWORD_PATTERNS:
        if pattern.search(rule_id):
            return domain_name

    # 3. Default
    return "cluster_security"


def get_service_from_rule(rule_id: str) -> Optional[str]:
    """Extract the container service name from a rule_id prefix.

    Rule IDs follow the pattern ``aws.<service>.<resource>.<check_name>``.
    Returns the service portion if it is a recognized container service, else None.

    Args:
        rule_id: The check rule identifier.

    Returns:
        Service name (e.g. 'eks', 'ecs') or None if not a container service.
    """
    parts = rule_id.split(".")
    if len(parts) >= 2:
        service = parts[1]
        if service in CONTAINER_SERVICES:
            return service
    return None


def is_container_rule(rule_id: str) -> bool:
    """Return True if the rule_id belongs to a known container service."""
    return get_service_from_rule(rule_id) is not None
