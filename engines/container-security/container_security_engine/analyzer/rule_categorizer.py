"""
Rule Categorizer — Maps check rule_ids to container security domains.

Security domains:
  - cluster_security  — EKS cluster config, encryption, versions, endpoints
  - workload_security — pod/task security, privileged containers, read-only root
  - image_security    — ECR image scanning, tag immutability, lifecycle policies
  - network_exposure  — public endpoints, network policies, VPC config
  - rbac_access       — RBAC, IAM roles, least privilege, access entries
  - runtime_audit     — control plane logging, tracing, CloudWatch logs

Source of truth: rule_metadata table (check DB).
  Scope column   : container_security JSONB {applicable: true}
  Classification : subcategory → domain via _SUBCATEGORY_TO_DOMAIN below.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

# ── Subcategory → domain (stable semantic mapping, not per-rule) ──────────────
_SUBCATEGORY_TO_DOMAIN: Dict[str, str] = {
    "encryption_at_rest":        "cluster_security",
    "encryption_in_transit":     "cluster_security",
    "storage_encryption":        "cluster_security",
    "configuration_baseline":    "cluster_security",
    "configuration_validation":  "cluster_security",
    "change_management":         "cluster_security",
    "policy_enforcement":        "workload_security",
    "malware_protection":        "workload_security",
    "data_classification":       "image_security",
    "data_lifecycle_management": "image_security",
    "network_access_control":    "network_exposure",
    "public_exposure_prevention": "network_exposure",
    "rate_limiting":             "network_exposure",
    "authentication":            "rbac_access",
    "authorization":             "rbac_access",
    "least_privilege":           "rbac_access",
    "identity_federation":       "rbac_access",
    "key_management":            "rbac_access",
    "credential_storage":        "rbac_access",
    "audit_logging":             "runtime_audit",
    "security_monitoring":       "runtime_audit",
    "alerting":                  "runtime_audit",
    "compliance_monitoring":     "runtime_audit",
    "intrusion_detection":       "runtime_audit",
}

SECURITY_DOMAINS = frozenset(_SUBCATEGORY_TO_DOMAIN.values())

# ── DB-loaded tables (lazy, cached via CategoryLoader) ───────────────────────
_rule_domain_map: Dict[str, str] = {}
_container_services: Set[str] = set()
_loaded = False


def _ensure_loaded() -> None:
    global _rule_domain_map, _container_services, _loaded
    if _loaded:
        return
    _loaded = True
    from engine_common.category_loader import load_rule_domain_map, load_engine_services
    from engine_common.db_connections import get_check_conn
    _rule_domain_map = load_rule_domain_map(
        "container_security", get_check_conn, _SUBCATEGORY_TO_DOMAIN, "cluster_security"
    )
    _container_services = load_engine_services("container_security", get_check_conn)
    logger.info("rule_categorizer: %d rules, %d services loaded", len(_rule_domain_map), len(_container_services))


def categorize_finding(rule_id: str, _finding: Optional[Dict[str, Any]] = None) -> str:
    """Return the container security domain for a rule_id."""
    _ensure_loaded()
    return _rule_domain_map.get(rule_id, "cluster_security")


def get_service_from_rule(rule_id: str) -> Optional[str]:
    """Return the container service name extracted from rule_id, or None."""
    _ensure_loaded()
    parts = rule_id.split(".")
    if len(parts) >= 2 and parts[1] in _container_services:
        return parts[1]
    return None


def is_container_rule(rule_id: str) -> bool:
    return get_service_from_rule(rule_id) is not None
