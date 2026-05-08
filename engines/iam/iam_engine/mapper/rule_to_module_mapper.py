"""
Map threat findings to IAM security modules.

Source of truth: rule_metadata table (check DB).
  Scope column : iam_security JSONB {applicable: true}
  Module list  : data_security.modules or iam_security.modules JSONB.
  Service list : service column WHERE iam_security applicable.

Lookup chain per finding:
  1. Exact rule_id match in DB-loaded rule→modules map
  2. resource_type membership in DB-loaded IAM service set
     → defaults to ['access_control']
  3. Pattern-based fallback for non-AWS CSPs whose rules may not yet
     have iam_security.applicable=true in rule_metadata
     (e.g. alicloud.ram.*, gcp.iam.*, k8s.rbac.*, oci.iam.*)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── DB-loaded tables (lazy, cached via CategoryLoader) ───────────────────────
_rule_module_map: Dict[str, List[str]] = {}
_iam_services: Set[str] = set()
_loaded = False

# Service-name tokens at position 1 in a rule_id (csp.SERVICE.resource.check)
# that always indicate IAM relevance regardless of rule_metadata flags.
_IAM_SERVICE_TOKENS: frozenset = frozenset({"iam", "ram", "rbac", "sts"})


def _ensure_loaded() -> None:
    global _rule_module_map, _iam_services, _loaded
    if _loaded:
        return
    _loaded = True
    from engine_common.category_loader import load_rule_module_map, load_engine_services
    from engine_common.db_connections import get_check_conn
    _rule_module_map = load_rule_module_map("iam_security", get_check_conn)
    _iam_services = load_engine_services("iam_security", get_check_conn)
    logger.info("rule_to_module_mapper: %d rules, %d services loaded",
                len(_rule_module_map), len(_iam_services))


def _is_iam_relevant(rule_id: str, resource_type: str = '') -> bool:
    _ensure_loaded()
    if rule_id and rule_id in _rule_module_map:
        return True
    if resource_type and resource_type.lower() in _iam_services:
        return True
    # Pattern fallback: alicloud.ram.*, gcp.iam.*, k8s.rbac.*, oci.iam.*, etc.
    if rule_id:
        parts = rule_id.lower().split('.')
        if len(parts) >= 2 and parts[1] in _IAM_SERVICE_TOKENS:
            return True
    return False


def _derive_modules(rule_id: str, resource_type: str = '') -> List[str]:
    _ensure_loaded()
    modules = _rule_module_map.get(rule_id)
    if modules:
        return list(modules)
    if resource_type and resource_type.lower() in _iam_services:
        return ['access_control']
    return ['access_control']


class RuleToModuleMapper:
    """Maps findings to IAM security modules."""

    def __init__(self, rule_db_path: Optional[str] = None):
        pass

    def get_modules_for_finding(self, finding: Dict) -> List[str]:
        rule_id = finding.get("rule_id", "")
        resource_type = finding.get("resource_type", "")
        if not _is_iam_relevant(rule_id, resource_type):
            return []
        return _derive_modules(rule_id, resource_type)

    def map_finding_to_modules(self, finding: Dict) -> Dict:
        modules = self.get_modules_for_finding(finding)
        out = finding.copy()
        out["iam_security_modules"] = modules
        out["is_iam_relevant"] = len(modules) > 0
        return out

    def map_findings_to_modules(self, findings: List[Dict]) -> List[Dict]:
        return [self.map_finding_to_modules(f) for f in findings]

    def get_module_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        stats: Dict[str, int] = {}
        for f in findings:
            for m in f.get("iam_security_modules", []):
                stats[m] = stats.get(m, 0) + 1
        return stats
