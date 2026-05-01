"""
Map threat findings to data security modules.

Source of truth: rule_metadata table (check DB).
  Scope column : data_security JSONB {applicable: true, modules: [...]}
  Service list : service column WHERE data_security applicable → resource type set.

Lookup chain per finding:
  1. Exact rule_id match in DB-loaded rule→modules map
  2. Resource-type membership (returns ['data_access_control'] as default)
"""

from __future__ import annotations

import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# ── DB-loaded tables (lazy, cached via CategoryLoader) ───────────────────────
_rule_module_map: Dict[str, List[str]] = {}
_resource_type_set: Set[str] = set()
_loaded = False


def _ensure_loaded() -> None:
    global _rule_module_map, _resource_type_set, _loaded
    if _loaded:
        return
    _loaded = True
    from engine_common.category_loader import load_rule_module_map, load_engine_services
    from engine_common.db_connections import get_check_conn
    _rule_module_map = load_rule_module_map("data_security", get_check_conn)
    _resource_type_set = load_engine_services("data_security", get_check_conn)
    logger.info("rule_to_module_mapper: %d rules, %d resource types loaded",
                len(_rule_module_map), len(_resource_type_set))


def _is_data_security_relevant(rule_id: str, resource_type: str = '') -> bool:
    _ensure_loaded()
    if rule_id and rule_id in _rule_module_map:
        return True
    if resource_type and resource_type.lower() in _resource_type_set:
        return True
    return False


def _derive_modules(rule_id: str, resource_type: str = '') -> List[str]:
    _ensure_loaded()
    modules = _rule_module_map.get(rule_id)
    if modules:
        return list(modules)
    if resource_type and resource_type.lower() in _resource_type_set:
        return ['data_access_control']
    return []


class RuleToModuleMapper:
    """Maps findings to data security modules."""

    def get_modules_for_finding(self, finding: Dict) -> List[str]:
        rule_id = finding.get("rule_id", "")
        resource_type = finding.get("resource_type", "") or finding.get("service", "")
        if not _is_data_security_relevant(rule_id, resource_type):
            return []
        return _derive_modules(rule_id, resource_type)

    def map_finding_to_modules(self, finding: Dict) -> Dict:
        modules = self.get_modules_for_finding(finding)
        enriched = finding.copy()
        enriched["data_security_modules"] = modules
        enriched["is_data_security_relevant"] = len(modules) > 0
        return enriched

    def map_findings_to_modules(self, findings: List[Dict]) -> List[Dict]:
        return [self.map_finding_to_modules(f) for f in findings]

    def group_findings_by_module(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        grouped: Dict[str, List[Dict]] = {}
        for f in findings:
            for module in f.get("data_security_modules", []):
                grouped.setdefault(module, []).append(f)
        return grouped

    def get_module_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        stats: Dict[str, int] = {}
        for f in findings:
            for module in f.get("data_security_modules", []):
                stats[module] = stats.get(module, 0) + 1
        return stats

    def filter_by_module(self, findings: List[Dict], module: str) -> List[Dict]:
        return [f for f in findings if module in f.get("data_security_modules", [])]
