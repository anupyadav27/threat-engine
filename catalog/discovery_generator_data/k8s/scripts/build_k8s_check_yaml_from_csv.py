#!/usr/bin/env python3
"""
build_k8s_check_yaml_from_csv.py
==================================
Generates K8s check rule YAMLs from k8s_field_rule_catalog.csv.

For each service that has at least one non-empty check_rule_id:
  - Filter rows where check_rule_id is non-empty
  - Group by service
  - Emit {service}.checks.yaml in the standard format expected by the check engine

Output:
    catalog/rule/k8s_rule_check/{service}/{service}.checks.yaml

Check YAML format (matches what the engine executes):
  version: '1.0'
  provider: k8s
  service: {service}
  checks:
  - rule_id: k8s.pod.container.host_network_disabled
    for_each: k8s.pod.list
    conditions:
      var: item.spec.hostNetwork
      op: is_false

Usage:
    python catalog/discovery_generator/k8s/scripts/build_k8s_check_yaml_from_csv.py
    python ...  --services pod,deployment,rbac
    python ...  --dry-run
    python ...  --validate           # compare generated vs existing YAMLs
"""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parents[4]
K8S_DIR     = REPO_ROOT / "catalog/discovery_generator/k8s"
CHECKS_DIR  = REPO_ROOT / "catalog/rule/k8s_rule_check"
CATALOG_CSV = K8S_DIR / "k8s_field_rule_catalog.csv"


def _load_rules_from_csv(csv_path: Path) -> Dict[str, List[Dict]]:
    """
    Returns {service: [rule_dict, ...]} for all rows with a check_rule_id.
    De-duplicated by rule_id (first occurrence wins).
    """
    svc_rules: Dict[str, Dict[str, Dict]] = defaultdict(dict)

    with open(csv_path) as f:
        for row in csv.DictReader(f):
            rule_id = row.get("check_rule_id", "").strip()
            if not rule_id:
                continue

            svc      = row["service"]
            for_each = row.get("check_for_each", "").strip()
            var      = row.get("check_var", "").strip()
            op       = row.get("check_condition_op", "").strip()
            value    = row.get("check_condition_value", "").strip()
            severity = row.get("check_severity", "medium").strip()

            if rule_id in svc_rules[svc]:
                continue  # de-duplicate

            # Condition block
            cond: Dict[str, Any] = {"var": var, "op": op}
            # Only include value key for ops that use it
            if op not in ("exists", "not_empty", "is_false", "is_true"):
                cond["value"] = value if value else None
            elif value:
                cond["value"] = value

            svc_rules[svc][rule_id] = {
                "rule_id":    rule_id,
                "for_each":   for_each,
                "conditions": cond,
                "severity":   severity,
            }

    # Convert to sorted list per service
    result: Dict[str, List[Dict]] = {}
    for svc, rules_map in svc_rules.items():
        result[svc] = sorted(rules_map.values(), key=lambda r: r["rule_id"])
    return result


def _build_check_doc(svc: str, rules: List[Dict]) -> Dict:
    """Build the check YAML document dict."""
    checks = []
    for r in rules:
        entry: Dict[str, Any] = {
            "rule_id":    r["rule_id"],
            "for_each":   r["for_each"],
            "conditions": r["conditions"],
        }
        if r.get("severity"):
            entry["severity"] = r["severity"]
        checks.append(entry)

    return {
        "version":  "1.0",
        "provider": "k8s",
        "service":  svc,
        "checks":   checks,
    }


def _yaml_str(data: dict) -> str:
    return yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        width=120,
    )


def _validate(svc: str, generated: str) -> List[str]:
    """
    Compare generated YAML rule_ids against existing YAML.
    Returns list of diff strings (empty = identical rule set).
    """
    existing_path = CHECKS_DIR / svc / f"{svc}.checks.yaml"
    if not existing_path.exists():
        return [f"  [new] no existing file for '{svc}'"]

    with open(existing_path) as f:
        existing = yaml.safe_load(f)

    existing_ids = {c["rule_id"] for c in existing.get("checks", [])}
    generated_doc = yaml.safe_load(generated)
    generated_ids = {c["rule_id"] for c in generated_doc.get("checks", [])}

    diffs = []
    for rid in sorted(existing_ids - generated_ids):
        diffs.append(f"  MISSING from generated: {rid}")
    for rid in sorted(generated_ids - existing_ids):
        diffs.append(f"  EXTRA in generated:     {rid}")
    return diffs


def build_check_yaml(
    svc: str,
    rules: List[Dict],
    dry_run: bool = False,
    validate: bool = False,
) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = (
        f"# ============================================================\n"
        f"# K8s Check Rules — {svc}\n"
        f"# Generated: {ts}\n"
        f"# Source: k8s_field_rule_catalog.csv\n"
        f"# Rules: {len(rules)}\n"
        f"# ============================================================\n\n"
    )

    doc     = _build_check_doc(svc, rules)
    content = header + _yaml_str(doc)

    if validate:
        diffs = _validate(svc, content)
        if diffs:
            print(f"  DIFF {svc}:")
            for d in diffs:
                print(d)
        else:
            print(f"  ✓ {svc}  (identical rule set, {len(rules)} rules)")

    if not dry_run:
        out_dir = CHECKS_DIR / svc
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{svc}.checks.yaml"
        out_path.write_text(content)

    return content


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate K8s check rule YAMLs from k8s_field_rule_catalog.csv"
    )
    parser.add_argument("--services",  help="Comma-separated services (default: all)")
    parser.add_argument("--dry-run",   action="store_true",
                        help="Print to stdout, do not write files")
    parser.add_argument("--validate",  action="store_true",
                        help="Compare generated rule IDs against existing YAML files")
    args = parser.parse_args()

    if not CATALOG_CSV.exists():
        print(f"ERROR: {CATALOG_CSV} not found. Run build_k8s_catalog_csv.py first.")
        return

    svc_rules = _load_rules_from_csv(CATALOG_CSV)

    if args.services:
        requested = {s.strip() for s in args.services.split(",")}
        svc_rules = {k: v for k, v in svc_rules.items() if k in requested}

    written = 0
    for svc in sorted(svc_rules):
        rules = svc_rules[svc]
        content = build_check_yaml(svc, rules, dry_run=args.dry_run, validate=args.validate)
        if args.dry_run and not args.validate:
            print(f"  [dry-run] {svc}  {len(rules)} rules")
        elif not args.validate:
            print(f"  ✓ {svc:<30}  {len(rules)} rules → {svc}.checks.yaml")
            written += 1

    if not args.dry_run and not args.validate:
        print(f"\nWrote {written} check rule YAMLs")
    elif not args.dry_run and args.validate:
        print(f"\nValidated {len(svc_rules)} services")


if __name__ == "__main__":
    main()
