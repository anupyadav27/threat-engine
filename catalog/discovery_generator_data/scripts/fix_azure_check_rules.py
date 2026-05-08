#!/usr/bin/env python3
"""
Fix Azure check rules based on the validation report.

Actions:
  OP_RESOLVED  — replace 3-part for_each with 4-part suggested_for_each
  FIELD_MISSING — find the best op in the catalog that produces the most
                  missing vars; update for_each (and suggested_for_each)
  CSV_GAP      — update for_each if it's still 3-part; keep vars as-is
  OP_MISSING   — skip (service not implemented in catalog)

Output:
  • In-place YAML updates
  • catalog/discovery_generator/azure/check_rule_fix_report.csv

Usage:
    python3 catalog/discovery_generator/scripts/fix_azure_check_rules.py
    python3 ...  --dry-run          # show changes without writing
    python3 ...  --service keyvault # limit to one service dir
"""

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ── paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT   = Path(".")
RULES_DIR   = REPO_ROOT / "catalog/rule/azure_rule_check"
CATALOG_CSV = REPO_ROOT / "catalog/discovery_generator/azure/azure_master_field_catalog.csv"
REPORT_CSV  = REPO_ROOT / "catalog/discovery_generator/azure/check_rule_validation_report.csv"
FIX_REPORT  = REPO_ROOT / "catalog/discovery_generator/azure/check_rule_fix_report.csv"

# ── catalog index ─────────────────────────────────────────────────────────────

def load_catalog() -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """
    Returns:
      op_to_fields  : op_id → set(item_var_paths)
      field_to_ops  : item_var_path → set(op_ids)   (reverse index)
    """
    op_to_fields: Dict[str, Set[str]] = defaultdict(set)
    field_to_ops: Dict[str, Set[str]] = defaultdict(set)

    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            op   = row["producing_op"]
            ivar = row["item_var_path"]
            if ivar:
                op_to_fields[op].add(ivar)
                field_to_ops[ivar].add(op)

    return dict(op_to_fields), dict(field_to_ops)


def load_report() -> Dict[str, dict]:
    """rule_id → report row  (last row wins if dup)"""
    result: Dict[str, dict] = {}
    with open(REPORT_CSV) as f:
        for row in csv.DictReader(f):
            result[row["rule_id"]] = row
    return result


# ── best-op finder for FIELD_MISSING ─────────────────────────────────────────

def best_op_for_missing_vars(
    missing_vars: List[str],
    current_op: str,
    for_each: str,
    op_to_fields: Dict[str, Set[str]],
    field_to_ops: Dict[str, Set[str]],
    svc_hint: str,
) -> Optional[str]:
    """
    Find the CSV op within the SAME SERVICE that covers more missing vars than current_op.
    Returns None if no same-service improvement found.

    Strictly same-service: only ops where op.split(".")[1] == service_of_current.
    This prevents cross-service contamination (e.g. storage→encryptionscopes vs storageaccounts).
    """
    if not missing_vars:
        return None

    service_of_current = current_op.split(".")[1] if current_op else ""
    if not service_of_current:
        return None

    # Count how many missing_vars each SAME-SERVICE op covers
    scores: Dict[str, int] = defaultdict(int)
    for var in missing_vars:
        for op in field_to_ops.get(var, set()):
            op_svc = op.split(".")[1] if op.count(".") >= 2 else ""
            if op_svc == service_of_current:
                scores[op] += 1

    if not scores:
        return None

    current_score = sum(1 for v in missing_vars if v in op_to_fields.get(current_op, set()))
    best_score    = max(scores.values())

    if best_score <= current_score:
        return None

    best_ops = [op for op, s in scores.items() if s == best_score]
    best_ops.sort(key=lambda op: len(op))
    winner = best_ops[0]
    return winner if winner != current_op else None


# ── YAML in-place updater ─────────────────────────────────────────────────────

def update_yaml_for_each(yaml_path: Path, rule_fixes: Dict[str, str],
                         dry_run: bool) -> List[dict]:
    """
    rule_fixes: rule_id → new_for_each value

    Reads YAML, replaces for_each values, writes back.
    Returns list of change records.
    """
    changes = []

    try:
        text = yaml_path.read_text()
        data = yaml.safe_load(text) or {}
    except Exception as e:
        return [{"file": str(yaml_path), "rule_id": "", "action": "PARSE_ERROR",
                 "old_for_each": "", "new_for_each": str(e)}]

    checks = data.get("checks", [])
    if not checks:
        return []

    new_text = text
    modified = False

    for check in checks:
        rule_id  = str(check.get("rule_id", ""))
        old_fe   = str(check.get("for_each", ""))
        new_fe   = rule_fixes.get(rule_id)

        if not new_fe or new_fe == old_fe:
            continue

        # Replace this specific for_each occurrence
        # Build a regex that matches the rule block's for_each line precisely
        # We match "for_each: <old_value>" with optional surrounding whitespace
        # Since rule_id lines immediately precede for_each, we use a targeted replace
        pattern = r'(for_each:\s+)' + re.escape(old_fe) + r'(\s*\n)'
        replacement = r'\g<1>' + new_fe + r'\g<2>'

        # Apply one replacement at a time via a stateful scanner to avoid
        # replacing identical for_each values in OTHER rules
        match = re.search(
            r'rule_id:\s+' + re.escape(rule_id) + r'.*?for_each:\s+' + re.escape(old_fe),
            new_text, re.DOTALL
        )
        if not match:
            # Fallback: simple first-occurrence replace after rule_id
            idx = new_text.find(f"rule_id: {rule_id}")
            if idx == -1:
                idx = new_text.find(f"rule_id: '{rule_id}'")
            if idx != -1:
                fe_idx = new_text.find(f"for_each: {old_fe}", idx)
                if fe_idx != -1 and fe_idx < idx + 500:
                    new_text = (
                        new_text[:fe_idx]
                        + f"for_each: {new_fe}"
                        + new_text[fe_idx + len(f"for_each: {old_fe}"):]
                    )
                    modified = True
                    changes.append({
                        "file": str(yaml_path),
                        "rule_id": rule_id,
                        "action": "UPDATED",
                        "old_for_each": old_fe,
                        "new_for_each": new_fe,
                    })
        else:
            # Replace the for_each line after the matched rule_id
            fe_idx = new_text.find(f"for_each: {old_fe}", match.start())
            if fe_idx != -1:
                new_text = (
                    new_text[:fe_idx]
                    + f"for_each: {new_fe}"
                    + new_text[fe_idx + len(f"for_each: {old_fe}"):]
                )
                modified = True
                changes.append({
                    "file": str(yaml_path),
                    "rule_id": rule_id,
                    "action": "UPDATED",
                    "old_for_each": old_fe,
                    "new_for_each": new_fe,
                })

    if modified and not dry_run:
        yaml_path.write_text(new_text)

    return changes


# ── main ──────────────────────────────────────────────────────────────────────

FIX_REPORT_COLS = ["file", "rule_id", "action", "old_for_each", "new_for_each",
                   "missing_vars_covered", "status_was"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Fix Azure check rules for_each IDs")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would change without writing files")
    parser.add_argument("--service", help="Comma-separated service dirs to limit scope")
    args = parser.parse_args()

    print("Loading catalog…")
    op_to_fields, field_to_ops = load_catalog()
    print(f"  {len(op_to_fields)} ops, {len(field_to_ops)} unique fields")

    print("Loading validation report…")
    report = load_report()
    print(f"  {len(report)} rules in report")

    service_filter: Optional[Set[str]] = None
    if args.service:
        service_filter = set(s.strip() for s in args.service.split(","))

    yaml_files = sorted(RULES_DIR.rglob("*.yaml"))
    yaml_files = [f for f in yaml_files if not f.name.startswith("1_")]
    if service_filter:
        yaml_files = [f for f in yaml_files if f.parent.name in service_filter]

    print(f"Processing {len(yaml_files)} YAML files{'  [DRY RUN]' if args.dry_run else ''}…")

    all_changes: List[dict] = []
    skipped = 0

    for yaml_path in yaml_files:
        try:
            with open(yaml_path) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            continue

        rule_fixes: Dict[str, str] = {}  # rule_id → new_for_each

        for check in data.get("checks", []):
            rule_id  = str(check.get("rule_id", ""))
            old_fe   = str(check.get("for_each", ""))
            row      = report.get(rule_id, {})
            status   = row.get("status", "")

            if status == "OK":
                skipped += 1
                continue

            if status == "OP_MISSING":
                skipped += 1
                continue

            suggested_fe = row.get("suggested_for_each", "").strip()
            missing_str  = row.get("missing_vars", "").strip()
            missing_vars = [v.strip() for v in missing_str.split(" | ") if v.strip()]

            new_fe: Optional[str] = None

            # ── OP_RESOLVED / CSV_GAP ──────────────────────────────────────
            if status in ("OP_RESOLVED", "CSV_GAP") and suggested_fe and suggested_fe != old_fe:
                new_fe = suggested_fe

            # ── FIELD_MISSING ──────────────────────────────────────────────
            elif status == "FIELD_MISSING":
                is_3part = old_fe.count(".") < 3
                if is_3part and suggested_fe and suggested_fe != old_fe:
                    # 3-part → explicit override is authoritative; don't run optimizer
                    # (optimizer would pick wrong service for generic field names)
                    new_fe = suggested_fe
                else:
                    # 4-part exact-match but fields wrong — try same-service optimizer
                    current_op = row.get("resolved_op", old_fe) or old_fe
                    svc_hint   = old_fe.split(".")[1] if old_fe.count(".") >= 2 else ""
                    better_op  = best_op_for_missing_vars(
                        missing_vars, current_op, old_fe,
                        op_to_fields, field_to_ops, svc_hint
                    )
                    if better_op:
                        new_fe = better_op
                    # else: keep old 4-part op; field is genuinely missing from CSV

            if new_fe and new_fe != old_fe:
                rule_fixes[rule_id] = new_fe

        if rule_fixes:
            changes = update_yaml_for_each(yaml_path, rule_fixes, args.dry_run)
            # Attach metadata to each change
            for ch in changes:
                rid = ch["rule_id"]
                row = report.get(rid, {})
                ch["status_was"] = row.get("status", "")
                mv = row.get("missing_vars", "")
                # How many missing vars does the new op cover?
                new_op_fields = op_to_fields.get(ch["new_for_each"], set())
                covered = sum(1 for v in mv.split(" | ") if v.strip() and v.strip() in new_op_fields)
                total   = len([v for v in mv.split(" | ") if v.strip()])
                ch["missing_vars_covered"] = f"{covered}/{total}" if total else "n/a"
            all_changes.extend(changes)

    # ── write fix report ────────────────────────────────────────────────────
    with open(FIX_REPORT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIX_REPORT_COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_changes)

    # ── summary ─────────────────────────────────────────────────────────────
    from collections import Counter
    status_dist = Counter(c["status_was"] for c in all_changes if c.get("action") == "UPDATED")
    updated = sum(1 for c in all_changes if c.get("action") == "UPDATED")
    errors  = sum(1 for c in all_changes if c.get("action") != "UPDATED")

    print()
    print("=" * 60)
    print(f"Rules updated:  {updated}")
    print(f"Rules skipped:  {skipped} (OK or OP_MISSING)")
    print(f"Errors:         {errors}")
    print()
    print("Updates by original status:")
    for st, cnt in status_dist.most_common():
        print(f"  {st:<22} {cnt}")
    print()
    print(f"Fix report:  {FIX_REPORT}")
    if args.dry_run:
        print("\n[DRY RUN] No files were written.")


if __name__ == "__main__":
    main()
