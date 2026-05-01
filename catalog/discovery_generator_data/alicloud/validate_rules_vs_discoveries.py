#!/usr/bin/env python3
"""
Validate AliCloud check rules against discovery step6 YAML files.

For each check rule:
  1. Verify that for_each → discovery_id exists in catalog/alicloud step6 YAMLs
  2. Verify that all item.X fields referenced in conditions are emitted by that discovery

Outputs:
  - Missing discovery IDs (for_each has no matching discovery_id)
  - Missing fields (field referenced in condition but not emitted)
  - Summary counts
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml

CHECK_ENGINE = Path("/Users/apple/Desktop/threat-engine/engines/check/engine_check_alicloud/services")
CATALOG = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Build discovery index — discovery_id → set of emitted field keys
# ─────────────────────────────────────────────────────────────────────────────

def parse_step6_emits(yaml_path: Path) -> dict[str, set[str]]:
    """Return {discovery_id: set_of_emitted_field_names} from a step6 YAML."""
    result: dict[str, set[str]] = {}
    try:
        data = yaml.safe_load(yaml_path.read_text())
    except Exception:
        return result

    for entry in data.get("discovery", []) or []:
        disc_id = entry.get("discovery_id", "")
        if not disc_id:
            continue
        emit = entry.get("emit", {}) or {}
        item_block = emit.get("item", {}) or {}
        # Emitted fields = keys of the item block
        fields = set(item_block.keys()) if isinstance(item_block, dict) else set()
        result[disc_id] = fields

    return result


def build_discovery_index() -> dict[str, set[str]]:
    """Walk all step6 files and build global discovery_id → emitted_fields index."""
    index: dict[str, set[str]] = {}
    for svc_dir in sorted(CATALOG.iterdir()):
        if not svc_dir.is_dir() or svc_dir.name.startswith("."):
            continue
        step6 = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
        if step6.exists():
            index.update(parse_step6_emits(step6))
    return index


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Extract field references from check rule conditions
# ─────────────────────────────────────────────────────────────────────────────

def extract_field_refs(conditions, refs: set[str] | None = None) -> set[str]:
    """Recursively extract top-level field names from item.X references."""
    if refs is None:
        refs = set()
    if isinstance(conditions, dict):
        var = conditions.get("var", "")
        if isinstance(var, str) and var.startswith("item."):
            parts = var.split(".")
            if len(parts) >= 2:
                refs.add(parts[1])  # top-level field only
        for val in conditions.values():
            extract_field_refs(val, refs)
    elif isinstance(conditions, list):
        for item in conditions:
            extract_field_refs(item, refs)
    return refs


def load_check_rules(svc_name: str) -> list[dict]:
    """Load check rules for a service."""
    path = CHECK_ENGINE / svc_name / "checks" / "default" / f"{svc_name}.checks.yaml"
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text())
        return data.get("checks", []) or []
    except Exception:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Validate
# ─────────────────────────────────────────────────────────────────────────────

def validate() -> None:
    print("Building discovery index from catalog/alicloud step6 files...")
    disc_index = build_discovery_index()
    print(f"  Found {len(disc_index)} discovery IDs across all step6 files\n")

    # Aggregate issues
    missing_discovery: dict[str, list[str]] = defaultdict(list)  # for_each → [rule_ids]
    missing_fields: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    # missing_fields[for_each][field] = [rule_ids]

    total_rules = 0
    total_ok = 0

    check_svcs = sorted(d.name for d in CHECK_ENGINE.iterdir() if d.is_dir())

    for svc in check_svcs:
        rules = load_check_rules(svc)
        for rule in rules:
            total_rules += 1
            rule_id = rule.get("rule_id", "?")
            for_each = rule.get("for_each", "")
            conditions = rule.get("conditions", {})

            refs = extract_field_refs(conditions)

            # Check 1: discovery_id exists
            if for_each not in disc_index:
                missing_discovery[for_each].append(rule_id)
                continue  # Can't check fields if discovery is missing

            # Check 2: all referenced fields are emitted
            emitted = disc_index[for_each]
            bad_fields = refs - emitted
            if bad_fields:
                for f in sorted(bad_fields):
                    missing_fields[for_each][f].append(rule_id)
            else:
                total_ok += 1

    # ─── Report ────────────────────────────────────────────────────────────
    print("=" * 70)
    print("VALIDATION RESULTS")
    print("=" * 70)

    # Missing discoveries
    print(f"\n[1] MISSING DISCOVERY IDs  ({len(missing_discovery)} unique for_each targets)")
    print("    for_each value not found in any step6 discovery_id:\n")
    for fe in sorted(missing_discovery):
        rule_count = len(missing_discovery[fe])
        print(f"    {fe}")
        print(f"      → {rule_count} rules affected")
    if not missing_discovery:
        print("    (none)")

    # Missing fields
    print(f"\n[2] MISSING EMITTED FIELDS  ({len(missing_fields)} unique for_each targets with gaps)\n")
    for fe in sorted(missing_fields):
        emitted = disc_index.get(fe, set())
        print(f"  for_each: {fe}")
        print(f"    emits:  {sorted(emitted) if emitted else '(nothing)'}")
        for field in sorted(missing_fields[fe]):
            rule_count = len(missing_fields[fe][field])
            print(f"    MISSING field '{field}'  ← {rule_count} rules need it")
            # Show first 3 rule IDs
            for rid in missing_fields[fe][field][:3]:
                print(f"      rule: {rid}")
            if len(missing_fields[fe][field]) > 3:
                print(f"      ... and {len(missing_fields[fe][field]) - 3} more")
        print()

    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total check rules          : {total_rules}")
    print(f"  Rules OK (all fields found): {total_ok}")
    print(f"  Missing discovery target   : {sum(len(v) for v in missing_discovery.values())}")
    print(f"  Field mismatch rules       : {total_rules - total_ok - sum(len(v) for v in missing_discovery.values())}")
    print(f"  Unique missing disc IDs    : {len(missing_discovery)}")
    print(f"  Unique for_each with gaps  : {len(missing_fields)}")

    # Collect all missing fields across all for_each targets
    all_missing = set()
    for fd in missing_fields.values():
        all_missing.update(fd.keys())
    print(f"  Unique missing field names : {len(all_missing)}")
    print(f"    → {sorted(all_missing)}")


if __name__ == "__main__":
    validate()
