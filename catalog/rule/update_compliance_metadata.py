#!/usr/bin/env python3
"""
update_compliance_metadata.py
==============================
Reads final_compliance_rules_mapped.csv and updates the `compliance` field
in every rule metadata YAML under catalog/rule/{csp}_rule_metadata/.

After running this, execute upload_rule_metadata_all_csps.py to push to DB.

Usage:
    python update_compliance_metadata.py                  # all CSPs
    python update_compliance_metadata.py --csp gcp k8s    # specific CSPs
    python update_compliance_metadata.py --dry-run        # count only, no writes
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

import yaml

ROOT        = Path(__file__).resolve().parents[2]
RULE_DIR    = ROOT / "catalog" / "rule"
CSV_PATH    = ROOT / "complaince_csv" / "final_compliance_rules_mapped.csv"

CSPS = ["aws", "azure", "gcp", "oci", "ibm", "alicloud", "k8s"]

# CSV columns that contain rule_id lists ('+' separated)
RULE_COLS = [
    "aws_checks", "aws_ciem_checks",
    "azure_checks", "azure_ciem_checks",
    "gcp_checks", "gcp_ciem_checks",
    "oracle_checks", "oracle_ciem_checks",
    "ibm_checks", "ibm_ciem_checks",
    "alicloud_checks", "alicloud_ciem_checks",
    "k8s_checks", "k8s_ciem_checks",
]


def build_rule_to_controls(csv_path: Path) -> Dict[str, List[str]]:
    """Parse CSV → {rule_id: [unique_compliance_id, ...]} sorted and deduped."""
    mapping: Dict[str, Set[str]] = defaultdict(set)
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            uid = row.get("unique_compliance_id", "").strip()
            if not uid:
                continue
            for col in RULE_COLS:
                cell = row.get(col, "").strip()
                if not cell:
                    continue
                for rule_id in cell.split("+"):
                    rule_id = rule_id.strip()
                    if rule_id and "." in rule_id:  # skip malformed entries
                        mapping[rule_id].add(uid)
    return {rid: sorted(cids) for rid, cids in mapping.items()}


def find_metadata_yamls(csp: str) -> Dict[str, Path]:
    """Return {rule_id: path} for all YAML files in {csp}_rule_metadata/."""
    meta_dir = RULE_DIR / f"{csp}_rule_metadata"
    if not meta_dir.exists():
        return {}
    result: Dict[str, Path] = {}
    for yaml_file in meta_dir.rglob("*.yaml"):
        # File name is rule_id.yaml
        rule_id = yaml_file.stem
        result[rule_id] = yaml_file
    return result


def update_yaml_compliance(path: Path, compliance_ids: List[str], dry_run: bool) -> bool:
    """Update the `compliance` field in a metadata YAML. Returns True if changed."""
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except Exception as e:
        print(f"  WARN: cannot parse {path.name}: {e}")
        return False

    if not isinstance(data, dict):
        return False

    # Get existing compliance value
    existing = data.get("compliance_frameworks") or data.get("compliance") or []
    if isinstance(existing, dict):
        existing = existing.get("frameworks", [])
    existing_set = set(existing) if isinstance(existing, list) else set()

    # Merge: keep existing + add new
    merged = sorted(existing_set | set(compliance_ids))

    if set(merged) == existing_set:
        return False  # no change

    if dry_run:
        return True

    # Write back — update the `compliance` key in place
    # Use ruamel or simple replacement to preserve YAML structure
    data["compliance"] = merged
    # Remove old compliance_frameworks key to avoid duplication
    data.pop("compliance_frameworks", None)

    # Dump preserving order as much as possible
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csp", nargs="+", choices=CSPS, default=CSPS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print(f"Reading CSV: {CSV_PATH}")
    rule_to_controls = build_rule_to_controls(CSV_PATH)
    print(f"Loaded {len(rule_to_controls)} rule→control mappings from CSV")

    total_updated = 0
    total_skipped = 0
    total_not_found = 0

    for csp in args.csp:
        yamls = find_metadata_yamls(csp)
        if not yamls:
            print(f"\n[{csp}] No metadata YAML dir found — skipping")
            continue

        updated = 0
        skipped = 0
        not_found = 0

        for rule_id, yaml_path in yamls.items():
            controls = rule_to_controls.get(rule_id)
            if not controls:
                not_found += 1
                continue
            changed = update_yaml_compliance(yaml_path, controls, args.dry_run)
            if changed:
                updated += 1
            else:
                skipped += 1

        action = "would update" if args.dry_run else "updated"
        print(f"[{csp}] {len(yamls)} files — {action} {updated}, already current {skipped}, no CSV mapping {not_found}")
        total_updated += updated
        total_skipped += skipped
        total_not_found += not_found

    print(f"\nTotal: {total_updated} {'would be ' if args.dry_run else ''}updated, "
          f"{total_skipped} already current, {total_not_found} no mapping in CSV")

    if args.dry_run:
        print("\nDry run — no files written. Remove --dry-run to apply.")
    else:
        print("\nDone. Now run:")
        print("  python upload_rule_metadata_all_csps.py")
        print("to push updated compliance fields to the rule_metadata DB table.")


if __name__ == "__main__":
    main()
