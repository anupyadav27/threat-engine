#!/usr/bin/env python3
"""
Build a consolidated index of all CSP check definitions from YAML rule files.

Outputs a JSON file with one entry per check_id plus a small duplicate summary.

Usage:
    python compliance/build_check_index.py
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml


ROOT_DIR = Path(__file__).resolve().parents[1]

# Known engines and where their YAML rule files live
ENGINE_CONFIGS: List[Dict[str, Any]] = [
    {"csp": "aws", "root": ROOT_DIR / "aws_compliance_python_engine" / "services"},
    {"csp": "azure", "root": ROOT_DIR / "azure_compliance_python_engine" / "services"},
    {"csp": "gcp", "root": ROOT_DIR / "gcp_compliance_python_engine" / "services"},
    {"csp": "oci", "root": ROOT_DIR / "oci_compliance_python_engine" / "services"},
    {"csp": "ibm", "root": ROOT_DIR / "ibm_compliance_python_engine" / "services"},
    {"csp": "alicloud", "root": ROOT_DIR / "alicloud_compliance_python_engine" / "services"},
    {"csp": "k8s", "root": ROOT_DIR / "k8_engine" / "services"},
]

OUTPUT_PATH = ROOT_DIR / "compliance" / "all_csp_check_index.json"


def iter_yaml_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return []
    return sorted(root.rglob("*.yaml"))


def extract_actions_and_operators(check_def: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    actions = set()
    operators = set()

    for call in check_def.get("calls") or []:
        if not isinstance(call, dict):
            continue
        action = call.get("action")
        if action:
            actions.add(str(action))
        for field in call.get("fields") or []:
            if not isinstance(field, dict):
                continue
            op = field.get("operator")
            if op is not None:
                operators.add(str(op))

    return sorted(actions), sorted(operators)


def build_entry(
    *,
    csp: str,
    provider: str,
    service: str,
    component: str | None,
    file_path: Path,
    check_def: Dict[str, Any],
) -> Dict[str, Any]:
    rel_path = str(file_path.relative_to(ROOT_DIR))
    check_id = str(check_def.get("check_id", "")).strip()
    title = (check_def.get("title") or check_def.get("name") or "").strip()
    severity = (check_def.get("severity") or "").strip()
    for_each = check_def.get("for_each")
    logic = (check_def.get("logic") or "").strip()

    actions, operators = extract_actions_and_operators(check_def)

    return {
        "csp": csp,
        "provider": provider,
        "service": service,
        "component": component,
        "file": rel_path,
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "for_each": for_each,
        "logic": logic,
        "actions": actions,
        "operators": operators,
    }


def parse_k8s_file(csp: str, path: Path, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """K8s engine uses component-style YAML with top-level checks."""
    component = str(data.get("component") or data.get("component_type") or path.stem)
    checks = data.get("checks") or []
    if not isinstance(checks, list):
        return []

    entries: List[Dict[str, Any]] = []
    for chk in checks:
        if not isinstance(chk, dict):
            continue
        entry = build_entry(
            csp=csp,
            provider="k8s",
            service=component,
            component=component,
            file_path=path,
            check_def=chk,
        )
        if entry["check_id"]:
            entries.append(entry)
    return entries


def parse_generic_service_file(csp: str, path: Path, data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse engines where each YAML file contains a top-level key per service,
    and that value has provider/service/checks keys (AWS/Azure/GCP/OCI/IBM/Alicloud).
    """
    entries: List[Dict[str, Any]] = []

    if not isinstance(data, dict):
        return entries

    # Some files may have helper keys (like service_name) – we only care about
    # objects that look like service definitions.
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        if "checks" not in value:
            continue

        provider = str(value.get("provider") or csp)
        service = str(value.get("service") or key)
        component: str | None = None

        checks = value.get("checks") or []
        if not isinstance(checks, list):
            continue

        for chk in checks:
            if not isinstance(chk, dict):
                continue
            entry = build_entry(
                csp=csp,
                provider=provider,
                service=service,
                component=component,
                file_path=path,
                check_def=chk,
            )
            if entry["check_id"]:
                entries.append(entry)

    return entries


def parse_yaml_file(csp: str, path: Path) -> List[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        print(f"⚠️  Failed to parse YAML: {path} ({e})")
        return []

    # K8s engine has its own structure
    if csp == "k8s":
        if isinstance(data, dict) and "checks" in data:
            return parse_k8s_file(csp, path, data)
        return []

    return parse_generic_service_file(csp, path, data)


def build_index() -> Dict[str, Any]:
    all_entries: List[Dict[str, Any]] = []

    for cfg in ENGINE_CONFIGS:
        csp = cfg["csp"]
        root: Path = cfg["root"]
        if not root.exists():
            continue

        for yaml_path in iter_yaml_files(root):
            entries = parse_yaml_file(csp, yaml_path)
            all_entries.extend(entries)

    # Compute duplicates per CSP
    dup_map: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for entry in all_entries:
        key = (entry["csp"], entry["check_id"])
        dup_map[key].append(entry)

    duplicates: Dict[str, List[Dict[str, Any]]] = {}
    for (csp, check_id), items in dup_map.items():
        if len(items) > 1:
            duplicates[f"{csp}:{check_id}"] = items

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "root": str(ROOT_DIR),
        "total_checks": len(all_entries),
        "duplicates_per_csp": {k: len(v) for k, v in duplicates.items()},
        "entries": all_entries,
    }


def main() -> None:
    index = build_index()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, sort_keys=False)
    print(f"✅ Wrote index for {index['total_checks']} checks to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

