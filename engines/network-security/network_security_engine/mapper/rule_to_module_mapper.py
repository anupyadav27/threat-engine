"""
Network Security — Rule-to-Module Mapper.

Source of truth: rule_metadata table (check DB).
  Scope column : network_security JSONB {applicable: true}
  Module list  : network_security.modules or data_security.modules JSONB.
  Service list : service column WHERE network_security applicable.

Lookup chain per finding:
  1. Exact rule_id match in DB-loaded rule→modules map
  2. resource_type / service membership in DB-loaded network service set
     → defaults to ['internet_exposure']
"""

from __future__ import annotations

import logging
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# ── DB-loaded tables (lazy, cached via CategoryLoader) ───────────────────────
_rule_module_map: Dict[str, List[str]] = {}
_network_services: Set[str] = set()
_network_resource_types: Set[str] = set()
_loaded = False


def _ensure_loaded() -> None:
    global _rule_module_map, _network_services, _network_resource_types, _loaded
    if _loaded:
        return
    _loaded = True
    from engine_common.category_loader import load_rule_module_map, load_engine_services
    from engine_common.db_connections import get_check_conn
    _rule_module_map = load_rule_module_map("network_security", get_check_conn)
    _network_services = load_engine_services("network_security", get_check_conn)
    # resource_type is often a sub-resource of a service (e.g. "security_group", "subnet")
    # derive from rule_ids already loaded: parts[2] is typically the resource
    _network_resource_types = {
        r.split(".")[2] for r in _rule_module_map if len(r.split(".")) >= 3
    }
    logger.info("rule_to_module_mapper: %d rules, %d services, %d resource types loaded",
                len(_rule_module_map), len(_network_services), len(_network_resource_types))


def is_network_relevant(rule_id: str, resource_type: str = '', service: str = '') -> bool:
    _ensure_loaded()
    if rule_id and rule_id in _rule_module_map:
        return True
    rt = resource_type.lower()
    svc = service.lower()
    if rt in _network_resource_types or rt in _network_services:
        return True
    if svc in _network_services:
        return True
    return False


def derive_modules(rule_id: str, resource_type: str = '', title: str = '') -> List[str]:
    _ensure_loaded()
    modules = _rule_module_map.get(rule_id)
    if modules:
        return list(modules)
    if is_network_relevant(rule_id, resource_type):
        return ['internet_exposure']
    return []


def classify_findings(check_findings: List[Dict]) -> List[Dict]:
    """Filter and classify check_findings into network-relevant findings with module assignments."""
    network_findings = []
    for f in check_findings:
        rule_id = f.get("rule_id", "")
        resource_type = f.get("resource_type", "")
        service = f.get("service", "")
        title = f.get("title", "")

        if not is_network_relevant(rule_id, resource_type, service):
            continue

        f["network_modules"] = derive_modules(rule_id, resource_type, title)
        network_findings.append(f)

    return network_findings
