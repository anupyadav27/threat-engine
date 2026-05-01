#!/usr/bin/env python3
"""
fix_azure_rule_condition_paths.py — Fix incorrect flat condition var paths in Azure check rules.

For each FIELD_MISSING rule where a condition var uses a flat path (item.X)
but the correct path in the catalog is item.A.X or item.A.B.X, this script:
  1. Looks up the missing flat var in the catalog for the resolved op
  2. If exactly one catalog field ends with the same leaf name, use that as correction
  3. Updates the YAML files in-place with corrected var paths

Also handles multi-level renames (item.X.Y → item.A.X.Y) when the intermediate
parent is missing from the catalog but a deeper path matches.

Usage:
    python3 catalog/discovery_generator/scripts/fix_azure_rule_condition_paths.py
    python3 ...  --dry-run          # show changes without writing
    python3 ...  --service storage  # limit to one service dir
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ── paths ──────────────────────────────────────────────────────────────────────

REPO_ROOT   = Path(".")
RULES_DIR   = REPO_ROOT / "catalog/rule/azure_rule_check"
CATALOG_CSV = REPO_ROOT / "catalog/discovery_generator/azure/azure_master_field_catalog.csv"
REPORT_CSV  = REPO_ROOT / "catalog/discovery_generator/azure/check_rule_validation_report.csv"
FIX_REPORT  = REPO_ROOT / "catalog/discovery_generator/azure/condition_path_fix_report.csv"

# ── catalog loader ─────────────────────────────────────────────────────────────

def load_catalog() -> Dict[str, Set[str]]:
    """op_id → set of item_var_paths produced by that op."""
    op_to_fields: Dict[str, Set[str]] = defaultdict(set)
    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            op   = row["producing_op"]
            ivar = row["item_var_path"]
            if ivar:
                op_to_fields[op].add(ivar)
    return dict(op_to_fields)


def load_report() -> Dict[str, dict]:
    """rule_id → report row."""
    result: Dict[str, dict] = {}
    with open(REPORT_CSV) as f:
        for row in csv.DictReader(f):
            result[row["rule_id"]] = row
    return result


# ── path correction logic ──────────────────────────────────────────────────────

def find_correction(
    missing_var: str,
    op_fields: Set[str],
) -> Optional[str]:
    """
    Given a missing var like 'item.require_infrastructure_encryption',
    find the correct path in op_fields.

    Strategy:
      1. Extract leaf name from missing_var (e.g. 'require_infrastructure_encryption')
      2. Find all op_fields that end with '.{leaf}' (e.g. 'item.encryption.require_...')
      3. If exactly one match → return it as correction
      4. Otherwise: try matching last 2 components for 'item.X.Y' patterns
    """
    if not missing_var.startswith("item."):
        return None

    # Already in catalog exactly — shouldn't be called for these
    if missing_var in op_fields:
        return None

    # Already a sub-path of some produced field? sub-path acceptance handles this
    for p in op_fields:
        if missing_var.startswith(p + "."):
            return None  # sub-path OK, no correction needed

    parts = missing_var[len("item."):].split(".")
    leaf  = parts[-1]

    # Find all catalog fields whose last component matches leaf
    matches: List[str] = [
        f for f in op_fields
        if f.endswith("." + leaf)
    ]

    if len(matches) == 1:
        return matches[0]

    if len(matches) > 1:
        # Multiple matches — pick the shortest (shallowest path)
        # Only if all matches share the same parent prefix
        parents = {m.rsplit(".", 1)[0] for m in matches}
        if len(parents) == 1:
            # All under same parent → return shortest (the parent.leaf one)
            return min(matches, key=len)
        # Ambiguous — don't guess
        return None

    # No leaf match: try matching item.X.Y → look for partial path
    if len(parts) >= 2:
        # Look for item.*.{parts[-2]}.{parts[-1]}
        suffix = ".".join(parts[-2:])
        matches2 = [f for f in op_fields if f.endswith("." + suffix)]
        if len(matches2) == 1:
            return matches2[0]
        if len(matches2) > 1:
            parents2 = {m.rsplit(".", 2)[0] for m in matches2}
            if len(parents2) == 1:
                return min(matches2, key=len)

    return None


def build_corrections(
    report: Dict[str, dict],
    op_to_fields: Dict[str, Set[str]],
) -> Dict[str, Dict[str, str]]:
    """
    Returns: rule_id → {old_var: new_var}
    """
    result: Dict[str, Dict[str, str]] = {}

    for rule_id, row in report.items():
        if row["status"] != "FIELD_MISSING":
            continue
        resolved_op = row.get("resolved_op", "")
        missing_str = row.get("missing_vars", "").strip()
        if not missing_str or not resolved_op:
            continue

        op_fields = op_to_fields.get(resolved_op, set())
        if not op_fields:
            continue

        corrections: Dict[str, str] = {}
        for mv in missing_str.split(" | "):
            mv = mv.strip()
            if not mv:
                continue
            corrected = find_correction(mv, op_fields)
            if corrected:
                corrections[mv] = corrected

        if corrections:
            result[rule_id] = corrections

    return result


# ── YAML in-place updater ──────────────────────────────────────────────────────

def update_yaml_vars(
    yaml_path: Path,
    rule_corrections: Dict[str, Dict[str, str]],   # rule_id → {old_var → new_var}
    dry_run: bool,
) -> List[dict]:
    """
    For each rule in the YAML, replace incorrect var paths with corrected ones.
    Returns list of change records.
    """
    changes: List[dict] = []

    try:
        text = yaml_path.read_text()
        data = yaml.safe_load(text) or {}
    except Exception as e:
        return [{"file": str(yaml_path), "rule_id": "", "action": "PARSE_ERROR",
                 "old_var": "", "new_var": str(e)}]

    checks = data.get("checks", [])
    if not checks:
        return []

    new_text = text
    modified = False

    for check in checks:
        rule_id = str(check.get("rule_id", ""))
        corrections = rule_corrections.get(rule_id)
        if not corrections:
            continue

        for old_var, new_var in corrections.items():
            if old_var == new_var:
                continue

            # Replace all occurrences of "var: old_var" within this file
            # Use a pattern that matches the var line precisely
            pattern = r'(var:\s+)' + re.escape(old_var) + r'(\s*(?:\n|$))'
            replacement = r'\g<1>' + new_var + r'\g<2>'

            new_new_text, count = re.subn(pattern, replacement, new_text)
            if count > 0:
                new_text = new_new_text
                modified = True
                changes.append({
                    "file":    str(yaml_path),
                    "rule_id": rule_id,
                    "action":  f"CORRECTED ({count}x)",
                    "old_var": old_var,
                    "new_var": new_var,
                })

    if modified and not dry_run:
        yaml_path.write_text(new_text)

    return changes


# ── main ───────────────────────────────────────────────────────────────────────

FIX_COLS = ["file", "rule_id", "action", "old_var", "new_var"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Fix flat var paths in Azure check rules")
    parser.add_argument("--dry-run", action="store_true", help="Show without writing")
    parser.add_argument("--service", help="Comma-separated service dirs to limit scope")
    args = parser.parse_args()

    print("Loading catalog…")
    op_to_fields = load_catalog()
    print(f"  {len(op_to_fields)} ops in catalog")

    print("Loading validation report…")
    report = load_report()
    fm_count = sum(1 for r in report.values() if r["status"] == "FIELD_MISSING")
    print(f"  {len(report)} rules, {fm_count} FIELD_MISSING")

    print("Computing path corrections…")
    corrections = build_corrections(report, op_to_fields)
    total_vars = sum(len(v) for v in corrections.values())
    print(f"  {len(corrections)} rules have correctable paths ({total_vars} var replacements)")
    print()

    # Collect YAML files
    service_filter: Optional[Set[str]] = None
    if args.service:
        service_filter = {s.strip() for s in args.service.split(",")}

    yaml_files = sorted(RULES_DIR.rglob("*.yaml"))
    yaml_files = [f for f in yaml_files if not f.name.startswith("1_")]
    if service_filter:
        yaml_files = [f for f in yaml_files if f.parent.name in service_filter]

    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"Processing {len(yaml_files)} YAML files [{mode}]…")

    all_changes: List[dict] = []

    # Build per-file correction maps
    # First group corrections by YAML file
    file_rule_corrections: Dict[Path, Dict[str, Dict[str, str]]] = defaultdict(dict)
    for rule_id, var_map in corrections.items():
        row = report.get(rule_id, {})
        yaml_file = Path(row.get("file", ""))
        if yaml_file.name:
            file_rule_corrections[yaml_file][rule_id] = var_map

    for yaml_path in yaml_files:
        rule_corrs = file_rule_corrections.get(yaml_path)
        if not rule_corrs:
            continue

        changes = update_yaml_vars(yaml_path, rule_corrs, args.dry_run)
        all_changes.extend(changes)

        if changes:
            n_files = len({c["file"] for c in changes if c["action"] != "PARSE_ERROR"})
            fixed = sum(1 for c in changes if c["action"].startswith("CORRECTED"))
            print(f"  {yaml_path.name:<50} {fixed} vars corrected")

    # Write fix report
    with open(FIX_REPORT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIX_COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_changes)

    corrected = sum(1 for c in all_changes if c["action"].startswith("CORRECTED"))
    print()
    print("=" * 60)
    print(f"Var paths corrected: {corrected}")
    print(f"Fix report: {FIX_REPORT}")
    if args.dry_run:
        print("\n[DRY RUN] No files written.")


if __name__ == "__main__":
    main()
