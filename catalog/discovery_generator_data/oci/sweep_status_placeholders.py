#!/usr/bin/env python3
"""
Third-pass cleanup: replace ALL remaining 'status equals ACTIVE' placeholder conditions
in OCI check YAML files with 'defined_tags not_empty' governance proxy.

Handles both:
  - Top-level var/op/value fields
  - conditions: {var, op, value} dict format
  - conditions: [{var, op, value}, ...] list format

Then rebuilds the unified catalog CSV.
"""
from __future__ import annotations
import subprocess, sys
from pathlib import Path

import yaml

BASE       = Path("/Users/apple/Desktop/threat-engine")
RULE_DIR   = BASE / "catalog/rule/oci_rule_check"
MERGE_SCRIPT = BASE / "catalog/discovery_generator/oci/merge_field_rule_catalog.py"

DRY_RUN = "--dry-run" in sys.argv


def _is_placeholder(var: str, op: str, val) -> bool:
    """True if this condition is a status=ACTIVE placeholder."""
    return (
        "status" in str(var)
        and str(op).strip() == "equals"
        and str(val).strip().upper() == "ACTIVE"
    )


def _governance_condition(var: str) -> dict:
    """Replace placeholder with governance proxy using same resource path."""
    # swap field: item.X.status → item.X.defined_tags
    parts = str(var).split(".")
    if len(parts) >= 2:
        parts[-1] = "defined_tags"
        new_var = ".".join(parts)
    else:
        new_var = "item.defined_tags"
    return {"var": new_var, "op": "not_empty", "value": None}


def fix_condition_block(cond: dict) -> tuple[dict, bool]:
    """Fix a single condition dict. Returns (fixed_cond, was_changed)."""
    var = cond.get("var", "")
    op  = cond.get("op",  "")
    val = cond.get("value", "")
    if _is_placeholder(var, op, val):
        return _governance_condition(var), True
    return cond, False


def fix_yaml_file(yaml_path: Path, dry_run: bool) -> int:
    """Fix all placeholder conditions in one YAML file. Returns # fixed."""
    data = yaml.safe_load(yaml_path.read_text())
    if not isinstance(data, dict) or "checks" not in data:
        return 0

    fixed = 0
    for chk in data["checks"]:
        # Top-level var/op/value
        if "var" in chk and "op" in chk:
            var = chk.get("var", "")
            op  = chk.get("op",  "")
            val = chk.get("value", "")
            if _is_placeholder(var, op, val):
                gc = _governance_condition(var)
                chk["var"]   = gc["var"]
                chk["op"]    = gc["op"]
                chk["value"] = gc["value"]
                fixed += 1

        # conditions: dict
        cond = chk.get("conditions")
        if isinstance(cond, dict):
            new_cond, changed = fix_condition_block(cond)
            if changed:
                chk["conditions"] = new_cond
                fixed += 1

        # conditions: list
        elif isinstance(cond, list):
            new_list = []
            for c in cond:
                if isinstance(c, dict):
                    nc, changed = fix_condition_block(c)
                    new_list.append(nc)
                    if changed:
                        fixed += 1
                else:
                    new_list.append(c)
            chk["conditions"] = new_list

    if fixed and not dry_run:
        yaml_path.write_text(
            yaml.dump(data, default_flow_style=False, allow_unicode=True,
                      sort_keys=False, width=120)
        )
    return fixed


def main():
    total_fixed  = 0
    total_services = 0

    for svc_dir in sorted(RULE_DIR.iterdir()):
        if not svc_dir.is_dir():
            continue
        yaml_files = list(svc_dir.glob("*.checks.yaml"))
        if not yaml_files:
            continue

        svc_fixed = 0
        for yf in yaml_files:
            svc_fixed += fix_yaml_file(yf, DRY_RUN)

        if svc_fixed:
            total_services += 1
            total_fixed    += svc_fixed
            flag = "(dry-run)" if DRY_RUN else ""
            print(f"  {svc_dir.name:<35}  {svc_fixed:>4} conditions fixed  {flag}")

    print()
    print(f"SWEEP TOTAL: {total_fixed} conditions fixed across {total_services} services")
    print(f"(dry_run={DRY_RUN})")

    if not DRY_RUN and total_fixed:
        print("\nRebuilding unified catalog...")
        r = subprocess.run(
            [sys.executable, str(MERGE_SCRIPT)],
            capture_output=True, text=True
        )
        print(r.stdout[-2000:] if len(r.stdout) > 2000 else r.stdout)
        if r.returncode:
            print("WARN: merge_field_rule_catalog.py returned error:")
            print(r.stderr[-500:])


if __name__ == "__main__":
    main()
