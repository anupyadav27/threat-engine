#!/usr/bin/env python3
"""
Merge AliCloud master field catalog + check rules into unified CSV.

Sources:
  1. alicloud_master_field_catalog.csv     — discovery + field metadata
  2. check_rules_specific.csv              — expert-reviewed rule conditions
  3. <service>/step7_*.checks.yaml         — per-service check YAML files (39 services)

Output:
  alicloud_field_rule_catalog.csv          — unified field-rule catalog

Usage:
  python3 merge_alicloud_field_rule_catalog.py
"""
from __future__ import annotations
import csv, json, re, sys
from collections import defaultdict
from pathlib import Path

import yaml

BASE         = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/alicloud")
MASTER_CSV   = BASE / "alicloud_master_field_catalog.csv"
SPECIFIC_CSV = BASE / "check_rules_specific.csv"
OUT_CSV      = BASE / "alicloud_field_rule_catalog.csv"

# ── Output column layout ──────────────────────────────────────────────────────
FIELD_COLS = [
    "csp", "service", "field_path", "item_var_path",
    "field_type", "is_id", "producing_op", "op_kind",
    "is_independent", "root_op", "chain_ops", "chain_length",
    "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value",
    "python_call", "http_path", "resource_type",
]

RULE_COLS = [
    "check_rule_id", "check_for_each",
    "check_var", "check_condition_op", "check_condition_value",
    "check_condition", "check_conditions_json",
    "check_severity", "check_frameworks", "check_description",
    "is_system_rule", "is_active",
]

ALL_COLS = FIELD_COLS + RULE_COLS


# ── Helpers ───────────────────────────────────────────────────────────────────

def parse_final_var(final_var: str) -> list[dict]:
    """
    Parse final_var strings from check_rules_specific.csv.
    Formats:
      "status equals Active"
      "encrypted equals true"
      "permissions not_contains *"
      "encrypted equals true AND kms_key_id exists"
      "encrypted equals"          (value-less)
    Returns list of {var, op, value} dicts.
    """
    if not final_var or not final_var.strip():
        return []

    conditions = []
    # Split on AND (case-insensitive)
    parts = re.split(r'\bAND\b', final_var, flags=re.IGNORECASE)
    for part in parts:
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 2)  # split into at most 3 tokens
        if len(tokens) < 2:
            continue
        var = tokens[0]
        op  = tokens[1]
        val = tokens[2].strip().strip("'\"") if len(tokens) > 2 else None
        # Normalise item. prefix
        if not var.startswith("item."):
            var = f"item.{var}"
        conditions.append({"var": var, "op": op, "value": val})
    return conditions


def conditions_to_json(conds: list[dict]) -> str:
    if len(conds) == 1:
        return json.dumps(conds[0])
    return json.dumps({"all": conds})


def primary_condition(conds: list[dict]) -> tuple[str, str, str]:
    """Extract var/op/value from first condition (for flat CSV columns)."""
    if not conds:
        return "", "", ""
    c = conds[0]
    return c.get("var",""), c.get("op",""), c.get("value") or ""


def rule_severity(rule_id: str) -> str:
    """Infer severity from rule_id keywords."""
    name = rule_id.lower()
    if any(k in name for k in ["critical", "root", "public_access", "no_mfa", "admin_star"]):
        return "critical"
    if any(k in name for k in ["encrypt", "kms", "cmek", "public", "internet_facing"]):
        return "high"
    if any(k in name for k in ["log", "monitor", "backup", "ssl", "tls", "versioning"]):
        return "medium"
    return "medium"


# ── Load master field catalog ─────────────────────────────────────────────────

def load_field_catalog() -> dict[str, list[dict]]:
    """
    Returns: discovery_id → list of field rows
    Key: producing_op (= discovery_id like alicloud.ack.addon)
    """
    catalog: dict[str, list[dict]] = defaultdict(list)
    if not MASTER_CSV.exists():
        print(f"ERROR: master catalog not found: {MASTER_CSV}")
        print("  Run: python3 generate_alicloud_master_catalog.py first")
        sys.exit(1)
    with open(MASTER_CSV) as f:
        for row in csv.DictReader(f):
            key = row.get("producing_op", "")
            if key:
                catalog[key].append(row)
    return catalog


# ── Load check rules ──────────────────────────────────────────────────────────

def load_check_rules_specific() -> list[dict]:
    """Load expert-reviewed rules from check_rules_specific.csv."""
    rules = []
    if not SPECIFIC_CSV.exists():
        return rules
    with open(SPECIFIC_CSV) as f:
        for row in csv.DictReader(f):
            rule_id   = row.get("rule_id", "").strip()
            for_each  = row.get("for_each", "").strip()
            final_var = row.get("final_var", "").strip()
            if not rule_id:
                continue
            conds = parse_final_var(final_var)
            if not conds:
                continue
            rules.append({
                "rule_id":   rule_id,
                "for_each":  for_each,
                "severity":  rule_severity(rule_id),
                "conditions": conds,
                "source":    "specific_csv",
            })
    return rules


def load_check_rules_step7() -> list[dict]:
    """Load check rules from step7 YAML files for all services."""
    rules = []
    for step7 in sorted(BASE.glob("*/step7_*.yaml")):
        try:
            data = yaml.safe_load(step7.read_text())
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for chk in data.get("checks", []) or []:
            rule_id  = chk.get("rule_id", "")
            for_each = chk.get("for_each", "")
            if not rule_id:
                continue
            conds_raw = chk.get("conditions", {}) or {}
            # Handle both single and all: list formats
            if "all" in conds_raw:
                conds = [
                    {"var": c.get("var",""), "op": c.get("op",""), "value": c.get("value")}
                    for c in conds_raw["all"]
                ]
            else:
                conds = [{"var": conds_raw.get("var",""),
                          "op":  conds_raw.get("op",""),
                          "value": conds_raw.get("value")}]
            conds = [c for c in conds if c.get("var") and c.get("op")]
            if not conds:
                continue
            rules.append({
                "rule_id":    rule_id,
                "for_each":   for_each,
                "severity":   chk.get("severity", rule_severity(rule_id)),
                "conditions": conds,
                "source":     "step7",
            })
    return rules


def merge_rules(specific: list[dict], step7: list[dict]) -> list[dict]:
    """
    Merge, preferring specific_csv (expert-reviewed) over step7.
    Deduplicate by rule_id — specific_csv wins.
    """
    merged: dict[str, dict] = {}
    # Add step7 first (lower priority)
    for r in step7:
        merged[r["rule_id"]] = r
    # Overwrite with specific_csv (higher priority)
    for r in specific:
        merged[r["rule_id"]] = r
    return list(merged.values())


# ── Build output rows ─────────────────────────────────────────────────────────

def empty_field_row() -> dict:
    return {c: "" for c in FIELD_COLS}


def empty_rule_row() -> dict:
    return {c: "" for c in RULE_COLS}


def make_rule_row(rule: dict) -> dict:
    conds     = rule["conditions"]
    var, op, val = primary_condition(conds)
    return {
        "check_rule_id":          rule["rule_id"],
        "check_for_each":         rule["for_each"],
        "check_var":              var,
        "check_condition_op":     op,
        "check_condition_value":  val,
        "check_condition":        f"{var} {op} {val}".strip(),
        "check_conditions_json":  conditions_to_json(conds),
        "check_severity":         rule.get("severity", "medium"),
        "check_frameworks":       "",
        "check_description":      "",
        "is_system_rule":         "true",
        "is_active":              "true",
    }


def main():
    print("Loading field catalog ...")
    field_catalog = load_field_catalog()
    print(f"  {len(field_catalog)} discovery_ids indexed")

    print("Loading check rules ...")
    specific = load_check_rules_specific()
    step7    = load_check_rules_step7()
    rules    = merge_rules(specific, step7)
    print(f"  {len(specific)} from check_rules_specific.csv")
    print(f"  {len(step7)} from step7 YAMLs")
    print(f"  {len(rules)} total unique rules after merge")

    # Build output rows
    output_rows: list[dict] = []

    # 1. All field rows (no rule data)
    field_count = 0
    for disc_id, frows in sorted(field_catalog.items()):
        for frow in frows:
            row = {**frow, **empty_rule_row()}
            output_rows.append(row)
            field_count += 1

    # 2. All rule rows (join field data where possible)
    matched   = 0
    unmatched = 0

    # Build index: for_each → first matching field row (for metadata)
    for_each_index: dict[str, dict] = {}
    for disc_id, frows in field_catalog.items():
        if frows and disc_id not in for_each_index:
            for_each_index[disc_id] = frows[0]

    for rule in rules:
        for_each = rule.get("for_each", "")
        field_row = for_each_index.get(for_each, {})

        if field_row:
            base = dict(field_row)   # copy field metadata
            matched += 1
        else:
            # Derive service from rule_id: alicloud.<service>.<resource>.<check>
            parts   = rule["rule_id"].split(".")
            service = parts[1] if len(parts) > 1 else ""
            base    = empty_field_row()
            base.update({
                "csp":        "alicloud",
                "service":    service,
                "producing_op": for_each,
                "is_active":  "true",
            })
            unmatched += 1

        row = {**base, **make_rule_row(rule)}
        output_rows.append(row)

    # Write output
    with open(OUT_CSV, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=ALL_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(output_rows)

    total_rows = len(output_rows)
    rule_rows  = matched + unmatched

    print(f"\nOutput: {OUT_CSV}")
    print(f"  Total rows       : {total_rows}")
    print(f"  Field rows       : {field_count}")
    print(f"  Rule rows        : {rule_rows}")
    print(f"    Matched fields : {matched}")
    print(f"    Unmatched      : {unmatched}")


if __name__ == "__main__":
    main()
