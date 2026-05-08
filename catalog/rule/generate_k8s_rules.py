#!/usr/bin/env python3
"""
Generate k8s_rule_check and k8s_rule_metadata from backup data.

Source: cspm-lgtech/engine_input/engine_check_k8s/input/rule_db/default/services/
Target:
  catalog/rule/k8s_rule_check/<service>/<service>.checks.yaml
  catalog/rule/k8s_rule_metadata/<service>/<rule_id>.yaml
"""

import os
import yaml
from pathlib import Path

BACKUP_ROOT = Path("/Users/apple/Desktop/threat-engine/cspm-lgtech/engine_input/engine_check_k8s/input/rule_db/default/services")
CATALOG_ROOT = Path("/Users/apple/Desktop/threat-engine/catalog/rule")
CHECK_OUT = CATALOG_ROOT / "k8s_rule_check"
META_OUT = CATALOG_ROOT / "k8s_rule_metadata"

OPERATOR_MAP = {
    "equals": "equals",
    "not_equals": "not_equals",
    "exists": "exists",
    "not_exists": "not_exists",
    "contains": "contains",
    "not_contains": "not_contains",
    "greater_than": "greater_than",
    "less_than": "less_than",
    "in": "in",
    "not_in": "not_in",
    "starts_with": "starts_with",
    "ends_with": "ends_with",
    "regex": "regex",
}


def normalize_var(path: str) -> str:
    """Ensure path has 'item.' prefix."""
    if path.startswith("item.") or path.startswith("arguments."):
        return path
    return f"item.{path}"


def convert_fields_to_conditions(fields: list, logic: str) -> dict:
    """Convert backup fields list to conditions dict."""
    if not fields:
        return {"var": "item", "op": "exists", "value": None}

    items = []
    for f in fields:
        path = f.get("path", "item")
        op = OPERATOR_MAP.get(f.get("operator", "exists"), f.get("operator", "exists"))
        expected = f.get("expected")
        items.append({"var": normalize_var(path), "op": op, "value": expected})

    if len(items) == 1:
        return items[0]

    key = "all" if logic.upper() == "AND" else "any"
    return {key: items}


def build_discovery_map(service_yaml: dict) -> dict:
    """Build mapping: discovery_id -> k8s.<service>.<action>"""
    mapping = {}
    service_name = service_yaml.get("component", "")
    for disc in service_yaml.get("discovery", []):
        disc_id = disc.get("discovery_id", "")
        calls = disc.get("calls", [])
        if calls:
            action = calls[0].get("action", "list_resources")
        else:
            action = "list_resources"
        mapping[disc_id] = f"k8s.{service_name}.{action}"
    return mapping


def convert_check(check: dict, disc_map: dict, service: str) -> dict:
    """Convert one backup check entry to catalog check format."""
    rule_id = check.get("check_id", "")
    for_each_raw = check.get("for_each", "")
    for_each = disc_map.get(for_each_raw, f"k8s.{service}.list_resources")

    calls = check.get("calls", [])
    logic = check.get("logic", "AND")

    # Gather all fields from all identity calls
    all_fields = []
    for call in calls:
        if call.get("action") == "identity":
            all_fields.extend(call.get("fields", []))

    conditions = convert_fields_to_conditions(all_fields, logic)

    return {
        "rule_id": rule_id,
        "for_each": for_each,
        "conditions": conditions,
    }


def process_service(service_dir: Path):
    service = service_dir.name
    rules_yaml_path = service_dir / f"{service}_rules.yaml"
    metadata_dir = service_dir / "metadata"

    if not rules_yaml_path.exists():
        print(f"  [SKIP] No rules yaml for {service}")
        return

    with open(rules_yaml_path) as f:
        rules_data = yaml.safe_load(f)

    disc_map = build_discovery_map(rules_data)
    checks_raw = rules_data.get("checks", [])

    # --- Write k8s_rule_check ---
    check_dir = CHECK_OUT / service
    check_dir.mkdir(parents=True, exist_ok=True)
    check_out_path = check_dir / f"{service}.checks.yaml"

    converted_checks = []
    for c in checks_raw:
        converted_checks.append(convert_check(c, disc_map, service))

    check_doc = {
        "version": "1.0",
        "provider": "k8s",
        "service": service,
        "checks": converted_checks,
    }

    with open(check_out_path, "w") as f:
        yaml.dump(check_doc, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # --- Write k8s_rule_metadata ---
    meta_dir = META_OUT / service
    meta_dir.mkdir(parents=True, exist_ok=True)

    meta_count = 0
    if metadata_dir.exists():
        for meta_file in sorted(metadata_dir.glob("*.yaml")):
            with open(meta_file) as f:
                meta = yaml.safe_load(f)

            # Add standard fields if missing
            if "metadata_source" not in meta:
                meta["metadata_source"] = "default"
            if "generated_by" not in meta:
                meta["generated_by"] = "k8s_rule_generator"
            if "remediation" not in meta:
                meta["remediation"] = (
                    f"Review and remediate the {meta.get('title', 'configuration')} "
                    f"according to Kubernetes security best practices."
                )

            out_path = meta_dir / meta_file.name
            with open(out_path, "w") as f:
                yaml.dump(meta, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            meta_count += 1

    print(f"  {service}: {len(converted_checks)} checks, {meta_count} metadata files")


def main():
    print("Generating k8s rule catalog...")
    CHECK_OUT.mkdir(parents=True, exist_ok=True)
    META_OUT.mkdir(parents=True, exist_ok=True)

    service_dirs = sorted([d for d in BACKUP_ROOT.iterdir() if d.is_dir()])
    total_checks = 0
    total_meta = 0

    for svc_dir in service_dirs:
        process_service(svc_dir)
        # tally
        check_file = CHECK_OUT / svc_dir.name / f"{svc_dir.name}.checks.yaml"
        meta_dir = META_OUT / svc_dir.name
        if check_file.exists():
            with open(check_file) as f:
                d = yaml.safe_load(f)
            total_checks += len(d.get("checks", []))
        if meta_dir.exists():
            total_meta += len(list(meta_dir.glob("*.yaml")))

    print(f"\nDone: {total_checks} checks, {total_meta} metadata files")
    print(f"  → {CHECK_OUT}")
    print(f"  → {META_OUT}")


if __name__ == "__main__":
    main()
