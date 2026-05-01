"""
Rule Categorizer — Maps check rule_ids to database security domains.

Security domains:
  - access_control   — public access, IAM auth, RBAC, sharing restrictions
  - encryption       — at-rest, in-transit, KMS/CMK, snapshot encryption
  - audit_logging    — audit logs, CloudWatch, monitoring, alerting
  - backup_recovery  — backups, PITR, snapshots, deletion protection, retention
  - network_security — VPC, subnets, TLS/SSL, security groups, ports, endpoints
  - configuration    — version upgrades, maintenance, parameter groups, misc config

Source of truth: rule_metadata table (check DB).
  Scope column    : database_security JSONB {applicable: true}
  Classification  : subcategory → domain via _SUBCATEGORY_TO_DOMAIN below.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

# ── Subcategory → domain (stable semantic mapping, not per-rule) ──────────────
_SUBCATEGORY_TO_DOMAIN: Dict[str, str] = {
    "encryption_at_rest":        "encryption",
    "encryption_in_transit":     "encryption",
    "storage_encryption":        "encryption",
    "key_management":            "encryption",
    "credential_storage":        "encryption",
    "authentication":            "access_control",
    "authorization":             "access_control",
    "least_privilege":           "access_control",
    "identity_federation":       "access_control",
    "public_exposure_prevention": "access_control",
    "network_access_control":    "access_control",
    "audit_logging":             "audit_logging",
    "security_monitoring":       "audit_logging",
    "alerting":                  "audit_logging",
    "compliance_monitoring":     "audit_logging",
    "backup_and_recovery":       "backup_recovery",
    "disaster_recovery":         "backup_recovery",
    "rate_limiting":             "network_security",
    "configuration_baseline":    "configuration",
    "configuration_validation":  "configuration",
    "change_management":         "configuration",
    "policy_enforcement":        "configuration",
    "data_classification":       "configuration",
    "data_lifecycle_management": "configuration",
}

SECURITY_DOMAINS = frozenset(_SUBCATEGORY_TO_DOMAIN.values())

# ── DB-loaded tables (lazy, cached via CategoryLoader) ───────────────────────
_rule_domain_map: Dict[str, str] = {}
_db_services: Set[str] = set()
_loaded = False

# Public alias — populated lazily on first categorize_finding() call
RULE_DOMAIN_MAP: Dict[str, str] = _rule_domain_map


def _ensure_loaded() -> None:
    global _rule_domain_map, _db_services, _loaded
    if _loaded:
        return
    _loaded = True
    from engine_common.category_loader import load_rule_domain_map, load_engine_services
    from engine_common.db_connections import get_check_conn
    loaded = load_rule_domain_map(
        "database_security", get_check_conn, _SUBCATEGORY_TO_DOMAIN, "configuration"
    )
    _rule_domain_map.update(loaded)
    RULE_DOMAIN_MAP.update(loaded)
    _db_services = load_engine_services("database_security", get_check_conn)
    logger.info("rule_categorizer: %d rules, %d services loaded", len(_rule_domain_map), len(_db_services))


def categorize_finding(rule_id: str, _finding: Optional[Dict[str, Any]] = None) -> str:
    """Return the database security domain for a rule_id."""
    _ensure_loaded()
    return _rule_domain_map.get(rule_id, "configuration")


def get_service_from_rule(rule_id: str) -> Optional[str]:
    """Return the DB service name extracted from rule_id, or None."""
    _ensure_loaded()
    parts = rule_id.split(".")
    if len(parts) >= 2:
        service = parts[1]
        if service in _db_services:
            return service
        if service.split("_")[0] in _db_services:
            return service.split("_")[0]
    return None


def is_db_rule(rule_id: str) -> bool:
    return get_service_from_rule(rule_id) is not None
