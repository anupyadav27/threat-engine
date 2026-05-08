"""
Attack Surface Analyzer — Identify container-specific attack vectors.

Evaluates each container resource in the inventory against a set of risk
conditions and emits prioritized attack-surface findings.  Each finding
carries a severity (CRITICAL / HIGH / MEDIUM) and a machine-readable risk_type.

Risk conditions evaluated:
  1. Public EKS API endpoint                            -> CRITICAL
  2. Privileged containers                              -> CRITICAL
  3. Public ECR repository                              -> CRITICAL
  4. No encryption at rest                              -> HIGH
  5. No RBAC enabled                                    -> HIGH
  6. No audit logging                                   -> HIGH
  7. No network policy                                  -> HIGH
  8. No image scanning                                  -> HIGH
  9. No VPC isolation                                   -> MEDIUM
  10. Outdated K8s version                              -> MEDIUM
  11. No pod security standards                         -> MEDIUM
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Risk type constants ──────────────────────────────────────────────────────
RISK_PUBLIC_EKS_ENDPOINT = "public_eks_api_endpoint"
RISK_PRIVILEGED_CONTAINERS = "privileged_containers"
RISK_PUBLIC_ECR_REPO = "public_ecr_repository"
RISK_NO_ENCRYPTION = "no_encryption_at_rest"
RISK_NO_RBAC = "no_rbac_enabled"
RISK_NO_AUDIT_LOGGING = "no_audit_logging"
RISK_NO_NETWORK_POLICY = "no_network_policy"
RISK_NO_IMAGE_SCANNING = "no_image_scanning"
RISK_NO_VPC = "no_vpc_isolation"
RISK_OUTDATED_K8S = "outdated_k8s_version"
RISK_NO_POD_SECURITY = "no_pod_security_standards"

# Minimum supported K8s version (anything below is "outdated")
_MIN_K8S_VERSION = "1.27"


def _finding_id(resource_uid: str, risk_type: str) -> str:
    """Deterministic finding ID from resource + risk type."""
    raw = f"{risk_type}|{resource_uid}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _has_audit_logging(entry: Dict[str, Any]) -> bool:
    """Check whether the container resource has audit logging configured."""
    if entry.get("logging_enabled"):
        return True
    domain_findings = entry.get("domain_findings") or {}
    audit = domain_findings.get("runtime_audit", {})
    return audit.get("pass", 0) > 0


def _has_rbac(entry: Dict[str, Any]) -> bool:
    """Check whether RBAC is enabled (primarily for EKS clusters)."""
    domain_findings = entry.get("domain_findings") or {}
    rbac = domain_findings.get("rbac_access", {})
    return rbac.get("pass", 0) > 0 and rbac.get("fail", 0) == 0


def _has_network_policy(entry: Dict[str, Any]) -> bool:
    """Check whether network policy is enabled."""
    if entry.get("network_policy_enabled"):
        return True
    domain_findings = entry.get("domain_findings") or {}
    net = domain_findings.get("network_exposure", {})
    return net.get("pass", 0) > 0 and net.get("fail", 0) == 0


def _has_image_scanning(entry: Dict[str, Any]) -> bool:
    """Check whether image scanning is enabled (primarily for ECR)."""
    if entry.get("image_scan_on_push"):
        return True
    domain_findings = entry.get("domain_findings") or {}
    img = domain_findings.get("image_security", {})
    return img.get("pass", 0) > 0 and img.get("fail", 0) == 0


def _has_pod_security(entry: Dict[str, Any]) -> bool:
    """Check whether pod security standards are enforced."""
    domain_findings = entry.get("domain_findings") or {}
    workload = domain_findings.get("workload_security", {})
    return workload.get("pass", 0) > 0 and workload.get("fail", 0) == 0


def _is_outdated_k8s(version: str) -> bool:
    """Return True if the K8s version is below the minimum supported version."""
    if not version:
        return False
    try:
        parts = version.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        min_parts = _MIN_K8S_VERSION.split(".")
        min_major = int(min_parts[0])
        min_minor = int(min_parts[1])
        return (major, minor) < (min_major, min_minor)
    except (ValueError, IndexError):
        return False


def _has_privileged_containers(entry: Dict[str, Any], ciem_events: List[Dict[str, Any]]) -> bool:
    """Check for privileged container evidence in check findings or CIEM events."""
    domain_findings = entry.get("domain_findings") or {}
    workload = domain_findings.get("workload_security", {})
    # If workload_security checks exist and some fail, privileged containers may be present
    if workload.get("fail", 0) > 0:
        return True

    # Check CIEM events for privileged container launches
    resource_uid = entry.get("resource_uid", "")
    for event in ciem_events:
        params = event.get("request_parameters") or {}
        if isinstance(params, dict):
            # Check for privileged flag in task/pod definitions
            if params.get("privileged") or params.get("hostNetwork"):
                resources = event.get("resources") or []
                for res in resources:
                    if resource_uid in str(res):
                        return True
    return False


def analyze_attack_surface(
    container_inventory: List[Dict[str, Any]],
    ciem_events: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Identify attack-surface risks across all container resources.

    Args:
        container_inventory: Output of ``inventory_builder.build_container_inventory``.
            Each entry must have at minimum: resource_uid, container_service,
            endpoint_public, encryption_enabled, logging_enabled,
            network_policy_enabled, vpc_id, k8s_version, domain_findings.
        ciem_events: Optional CIEM event list for runtime audit analysis.

    Returns:
        List of attack-surface finding dicts, sorted by severity
        (CRITICAL first).
    """
    ciem_events = ciem_events or []
    findings: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for entry in container_inventory:
        resource_uid = entry.get("resource_uid", "")
        container_service = entry.get("container_service", "unknown")
        resource_name = entry.get("resource_name", "")
        account_id = entry.get("account_id", "")
        region = entry.get("region", "")
        provider = entry.get("provider", "aws")

        base = {
            "resource_uid": resource_uid,
            "resource_name": resource_name,
            "container_service": container_service,
            "account_id": account_id,
            "region": region,
            "provider": provider,
            "detected_at": now,
        }

        # 1. Public EKS API endpoint (CRITICAL)
        if container_service == "eks" and entry.get("endpoint_public"):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_PUBLIC_EKS_ENDPOINT),
                "risk_type": RISK_PUBLIC_EKS_ENDPOINT,
                "severity": "CRITICAL",
                "title": f"Public EKS API endpoint on cluster '{resource_name}'",
                "description": (
                    f"EKS cluster '{resource_name}' has a publicly accessible "
                    f"Kubernetes API endpoint. This exposes the cluster control "
                    f"plane to potential unauthorized access from the internet."
                ),
                "recommendation": (
                    "Disable public endpoint access and use private endpoint "
                    "access only. Restrict access via allowed CIDR blocks if "
                    "public access is required."
                ),
            })

        # 2. Privileged containers (CRITICAL)
        if container_service in ("eks", "ecs", "fargate"):
            if _has_privileged_containers(entry, ciem_events):
                findings.append({
                    **base,
                    "finding_id": _finding_id(resource_uid, RISK_PRIVILEGED_CONTAINERS),
                    "risk_type": RISK_PRIVILEGED_CONTAINERS,
                    "severity": "CRITICAL",
                    "title": f"Privileged containers detected in {container_service.upper()} '{resource_name}'",
                    "description": (
                        f"{container_service.upper()} resource '{resource_name}' is "
                        f"running or configured to run privileged containers. "
                        f"Privileged containers have full host access and can "
                        f"escape container isolation."
                    ),
                    "recommendation": (
                        "Remove privileged mode from container definitions. Use "
                        "specific Linux capabilities instead. Enforce pod security "
                        "standards to prevent privileged containers."
                    ),
                })

        # 3. Public ECR repository (CRITICAL)
        if container_service == "ecr":
            # ECR repos are public if image_tag_mutability or explicit public flag
            repo_policy = entry.get("repository_policy", "")
            is_public = "ecr-public" in resource_uid or entry.get("is_public", False)
            if is_public:
                findings.append({
                    **base,
                    "finding_id": _finding_id(resource_uid, RISK_PUBLIC_ECR_REPO),
                    "risk_type": RISK_PUBLIC_ECR_REPO,
                    "severity": "CRITICAL",
                    "title": f"Public ECR repository '{resource_name}'",
                    "description": (
                        f"ECR repository '{resource_name}' is publicly accessible. "
                        f"Container images may contain proprietary code, secrets, "
                        f"or vulnerabilities that should not be exposed."
                    ),
                    "recommendation": (
                        "Convert to a private repository. Review repository "
                        "policies to restrict access to authorized accounts only."
                    ),
                })

        # 4. No encryption at rest (HIGH)
        if not entry.get("encryption_enabled") and container_service in ("eks", "ecr"):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_ENCRYPTION),
                "risk_type": RISK_NO_ENCRYPTION,
                "severity": "HIGH",
                "title": f"No encryption at rest on {container_service.upper()} '{resource_name}'",
                "description": (
                    f"{container_service.upper()} resource '{resource_name}' does not "
                    f"have encryption at rest enabled. Secrets and sensitive data "
                    f"stored in the cluster or repository are unprotected."
                ),
                "recommendation": (
                    "Enable encryption at rest using AWS KMS. For EKS, enable "
                    "secrets encryption. For ECR, use KMS encryption."
                ),
            })

        # 5. No RBAC (HIGH)
        if container_service == "eks" and not _has_rbac(entry):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_RBAC),
                "risk_type": RISK_NO_RBAC,
                "severity": "HIGH",
                "title": f"RBAC not properly configured on EKS cluster '{resource_name}'",
                "description": (
                    f"EKS cluster '{resource_name}' does not have RBAC properly "
                    f"configured. Without RBAC, all authenticated users may have "
                    f"unrestricted cluster access."
                ),
                "recommendation": (
                    "Enable and configure RBAC. Use aws-auth ConfigMap or EKS "
                    "access entries with least-privilege roles."
                ),
            })

        # 6. No audit logging (HIGH)
        if not _has_audit_logging(entry):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_AUDIT_LOGGING),
                "risk_type": RISK_NO_AUDIT_LOGGING,
                "severity": "HIGH",
                "title": f"No audit logging on {container_service.upper()} '{resource_name}'",
                "description": (
                    f"{container_service.upper()} resource '{resource_name}' has no "
                    f"audit logging configured. Security incidents and unauthorized "
                    f"access may go undetected."
                ),
                "recommendation": (
                    "Enable control plane logging for EKS. Configure CloudWatch "
                    "Container Insights for ECS. Enable X-Ray tracing for Lambda."
                ),
            })

        # 7. No network policy (HIGH)
        if container_service == "eks" and not _has_network_policy(entry):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_NETWORK_POLICY),
                "risk_type": RISK_NO_NETWORK_POLICY,
                "severity": "HIGH",
                "title": f"No network policy on EKS cluster '{resource_name}'",
                "description": (
                    f"EKS cluster '{resource_name}' does not have network policies "
                    f"configured. All pods can communicate with each other without "
                    f"restriction, enabling lateral movement."
                ),
                "recommendation": (
                    "Install a network policy engine (Calico, Cilium) and define "
                    "network policies to restrict pod-to-pod communication."
                ),
            })

        # 8. No image scanning (HIGH)
        if container_service == "ecr" and not _has_image_scanning(entry):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_IMAGE_SCANNING),
                "risk_type": RISK_NO_IMAGE_SCANNING,
                "severity": "HIGH",
                "title": f"No image scanning on ECR repository '{resource_name}'",
                "description": (
                    f"ECR repository '{resource_name}' does not have image scan "
                    f"on push enabled. Vulnerable container images may be deployed "
                    f"without detection."
                ),
                "recommendation": (
                    "Enable image scan on push in ECR. Configure Amazon Inspector "
                    "for continuous vulnerability scanning."
                ),
            })

        # 9. No VPC isolation (MEDIUM)
        if not entry.get("vpc_id") and container_service in ("eks", "lambda"):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_VPC),
                "risk_type": RISK_NO_VPC,
                "severity": "MEDIUM",
                "title": f"No VPC isolation for {container_service.upper()} '{resource_name}'",
                "description": (
                    f"{container_service.upper()} resource '{resource_name}' is not "
                    f"deployed inside a VPC. Network-level isolation is absent."
                ),
                "recommendation": (
                    "Deploy inside a private VPC with appropriate security groups "
                    "and NACLs. For Lambda, configure VPC access."
                ),
            })

        # 10. Outdated K8s version (MEDIUM)
        if container_service == "eks" and _is_outdated_k8s(entry.get("k8s_version", "")):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_OUTDATED_K8S),
                "risk_type": RISK_OUTDATED_K8S,
                "severity": "MEDIUM",
                "title": f"Outdated Kubernetes version on EKS cluster '{resource_name}'",
                "description": (
                    f"EKS cluster '{resource_name}' is running Kubernetes version "
                    f"{entry.get('k8s_version', 'unknown')} which is below the "
                    f"minimum supported version {_MIN_K8S_VERSION}. Older versions "
                    f"may have known CVEs and lack security patches."
                ),
                "recommendation": (
                    f"Upgrade the EKS cluster to Kubernetes version {_MIN_K8S_VERSION} "
                    f"or later. Follow the EKS upgrade documentation for safe "
                    f"cluster upgrades."
                ),
            })

        # 11. No pod security standards (MEDIUM)
        if container_service == "eks" and not _has_pod_security(entry):
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_POD_SECURITY),
                "risk_type": RISK_NO_POD_SECURITY,
                "severity": "MEDIUM",
                "title": f"No pod security standards on EKS cluster '{resource_name}'",
                "description": (
                    f"EKS cluster '{resource_name}' does not have pod security "
                    f"standards enforced. Workloads may run with excessive "
                    f"privileges including root access and host networking."
                ),
                "recommendation": (
                    "Enable Pod Security Standards (PSS) at the namespace level. "
                    "Use the 'restricted' or 'baseline' profile to limit pod "
                    "capabilities."
                ),
            })

    # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "LOW"), 3))

    logger.info(
        "Attack surface analysis: %d findings across %d container resources "
        "(CRITICAL=%d, HIGH=%d, MEDIUM=%d)",
        len(findings),
        len(container_inventory),
        sum(1 for f in findings if f["severity"] == "CRITICAL"),
        sum(1 for f in findings if f["severity"] == "HIGH"),
        sum(1 for f in findings if f["severity"] == "MEDIUM"),
    )

    return findings
