#!/usr/bin/env python3
"""
Merge IBM master field catalog + CIEM rule YAMLs into unified CSV.

Sources:
  1. ibm_master_field_catalog.csv        — discovery + field metadata (2,889 rows)
  2. catalog/rule/ibm_rule_ciem/**/*.yaml — 56 CIEM log-based threat detection rules

Output:
  ibm_field_rule_catalog.csv             — unified field-rule catalog

Rule types supported:
  - Single-event log rules (check_config.conditions)
  - Sequence/chain rules    (check_config.events + type: sequence)

Usage:
  python3 merge_ibm_field_rule_catalog.py
"""
from __future__ import annotations
import csv, json, sys
from collections import defaultdict
from pathlib import Path

import yaml

BASE       = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/ibm")
RULES_BASE = Path("/Users/apple/Desktop/threat-engine/catalog/rule/ibm_rule_ciem")
MASTER_CSV = BASE / "ibm_master_field_catalog.csv"
OUT_CSV    = BASE / "ibm_field_rule_catalog.csv"

# ── Column layout ─────────────────────────────────────────────────────────────

FIELD_COLS = [
    "csp", "service", "field_path", "item_var_path",
    "field_type", "is_id", "producing_op", "op_kind",
    "is_independent", "root_op", "chain_ops", "chain_length",
    "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value",
    "python_call", "http_path", "resource_type",
]

RULE_COLS = [
    "check_rule_id", "check_type",
    "check_var", "check_condition_op", "check_condition_value",
    "check_condition", "check_conditions_json",
    "check_severity", "check_description",
    "threat_category", "mitre_tactics", "mitre_techniques",
    "risk_score", "is_sequence", "window_seconds",
    "is_system_rule", "is_active",
]

ALL_COLS = FIELD_COLS + RULE_COLS


# ── Helpers ───────────────────────────────────────────────────────────────────

def conditions_to_str(conds: list[dict]) -> tuple[str, str, str, str]:
    """
    Extract (check_var, check_condition_op, check_condition_value, check_condition)
    from the first meaningful condition in a conditions list.
    Skips source_type discriminator — takes first non-source_type condition.
    """
    primary = None
    for c in conds:
        if c.get("field") != "source_type":
            primary = c
            break
    if primary is None and conds:
        primary = conds[0]
    if not primary:
        return "", "", "", ""

    var = primary.get("field", "")
    op  = primary.get("op", "")
    val = primary.get("value", "")
    if isinstance(val, list):
        val = ", ".join(str(v) for v in val)
    elif val is None:
        val = ""
    else:
        val = str(val)
    return var, op, val, f"{var} {op} {val}".strip()


def extract_single_rule_conditions(check_config: dict) -> tuple[list[dict], bool, int]:
    """
    Returns (flat_conditions_list, is_sequence, window_seconds).
    Handles both:
      - conditions.all: [...]
      - events: [{conditions.all:[...]}, ...]  (sequence)
    """
    if "events" in check_config:
        # Sequence/chain rule
        all_conds = []
        for ev in check_config["events"]:
            ev_conds = ev.get("conditions", {}).get("all", [])
            all_conds.extend(ev_conds)
        return all_conds, True, check_config.get("window_seconds", 0)
    else:
        conds_block = check_config.get("conditions", {}) or {}
        flat = conds_block.get("all", []) or []
        return flat, False, 0


def conditions_json(check_config: dict, is_seq: bool) -> str:
    """Serialize full check_config conditions to JSON string."""
    if is_seq:
        return json.dumps({"type": "sequence", "events": check_config.get("events", [])})
    block = check_config.get("conditions", {}) or {}
    return json.dumps(block)


# ── Load master field catalog ─────────────────────────────────────────────────

def load_field_catalog() -> tuple[list[dict], dict[str, dict]]:
    """
    Returns:
      (all_rows, service → first field row)
    """
    rows: list[dict] = []
    svc_index: dict[str, dict] = {}

    if not MASTER_CSV.exists():
        print(f"ERROR: master catalog not found: {MASTER_CSV}")
        print("  Run: python3 generate_ibm_master_catalog.py first")
        sys.exit(1)

    with open(MASTER_CSV) as f:
        for row in csv.DictReader(f):
            rows.append(row)
            svc = row.get("service", "")
            if svc and svc not in svc_index:
                svc_index[svc] = row

    return rows, svc_index


# ── Load CIEM rules ───────────────────────────────────────────────────────────

def load_ibm_rules() -> list[dict]:
    """Load all IBM CIEM rule YAMLs. Returns list of rule dicts."""
    rules: list[dict] = []
    for yaml_file in sorted(RULES_BASE.glob("**/*.yaml")):
        try:
            docs = list(yaml.safe_load_all(yaml_file.read_text()))
        except Exception as e:
            print(f"  WARN: {yaml_file.name}: {e}")
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            rule_id = doc.get("rule_id", "").strip()
            if not rule_id:
                continue
            rules.append(doc)
    return rules


# ── IBM service name → catalog service mapping ────────────────────────────────

# IBM rule service keys vs catalog service directory names may differ
SERVICE_MAP = {
    "iam":     "iam",
    "iks":     "vpc",         # IKS uses VPC networking; closest field catalog
    "db":      "resource_controller",
    "scc":     "iam",         # SCC uses IAM for posture
    "cos":     "resource_controller",
    "vpc":     "vpc",
    "vsi":     "vpc",
    "kms":     "resource_controller",
    "ciem":    "iam_identity",
    "logging": "iam",
    "secrets": "resource_controller",
}


def resolve_service_row(rule_service: str, svc_index: dict) -> dict:
    """Return a field-metadata base row for a rule service, or empty dict."""
    mapped = SERVICE_MAP.get(rule_service, rule_service)
    return dict(svc_index.get(mapped, {}))


# ── Build output rows ─────────────────────────────────────────────────────────

def empty_rule_row() -> dict:
    return {c: "" for c in RULE_COLS}


def empty_field_row() -> dict:
    return {c: "" for c in FIELD_COLS}


def make_rule_row(rule: dict) -> dict:
    check_config = rule.get("check_config", {}) or {}
    flat_conds, is_seq, win_secs = extract_single_rule_conditions(check_config)

    var, op, val, cond_str = conditions_to_str(flat_conds)

    return {
        "check_rule_id":          rule["rule_id"],
        "check_type":             rule.get("check_type", "log"),
        "check_var":              var,
        "check_condition_op":     op,
        "check_condition_value":  val,
        "check_condition":        cond_str,
        "check_conditions_json":  conditions_json(check_config, is_seq),
        "check_severity":         rule.get("severity", "medium"),
        "check_description":      rule.get("description", ""),
        "threat_category":        rule.get("threat_category", ""),
        "mitre_tactics":          ", ".join(rule.get("mitre_tactics", []) or []),
        "mitre_techniques":       ", ".join(rule.get("mitre_techniques", []) or []),
        "risk_score":             str(rule.get("risk_score", "")),
        "is_sequence":            "true" if is_seq else "false",
        "window_seconds":         str(win_secs) if win_secs else "",
        "is_system_rule":         "true",
        "is_active":              "true",
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("Loading IBM field catalog ...")
    field_rows, svc_index = load_field_catalog()
    print(f"  {len(field_rows)} field rows, {len(svc_index)} services indexed")

    print("Loading IBM CIEM rules ...")
    rules = load_ibm_rules()
    print(f"  {len(rules)} rules loaded")

    output_rows: list[dict] = []

    # 1. All field rows (no rule data)
    for frow in field_rows:
        output_rows.append({**frow, **empty_rule_row()})

    # 2. All rule rows (with partial field metadata from service)
    matched   = 0
    unmatched = 0

    by_type = defaultdict(int)

    for rule in rules:
        rule_service = rule.get("service", "")
        field_base   = resolve_service_row(rule_service, svc_index)

        if field_base:
            matched += 1
        else:
            field_base = empty_field_row()
            field_base.update({
                "csp":     "ibm",
                "service": rule_service,
            })
            unmatched += 1

        rule_row = make_rule_row(rule)
        # Override service/csp from rule (more accurate than field catalog's service)
        field_base["csp"]     = "ibm"
        field_base["service"] = rule_service

        output_rows.append({**field_base, **rule_row})
        by_type[rule.get("check_type", "unknown")] += 1

    # Write output
    with open(OUT_CSV, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=ALL_COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(output_rows)

    total = len(output_rows)
    print(f"\nOutput: {OUT_CSV}")
    print(f"  Total rows      : {total}")
    print(f"  Field rows      : {len(field_rows)}")
    print(f"  Rule rows       : {len(rules)}")
    print(f"    Matched svc   : {matched}")
    print(f"    Unmatched     : {unmatched}")
    print(f"  Rule types      : {dict(by_type)}")


if __name__ == "__main__":
    main()
