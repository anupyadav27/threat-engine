#!/usr/bin/env python3
"""
Apply final differentiated var assignments from check_rules_specific.csv
to all step7 check YAML files.

Reads: check_rules_specific.csv  (rule_id → final_var)
Writes: catalog/python_field_generator/alicloud/*/step7_*.checks.yaml
"""
import csv
import yaml
from pathlib import Path
from collections import Counter

BASE = Path("/Users/apple/Desktop/threat-engine/catalog/python_field_generator/alicloud")
CSV_PATH = BASE / "check_rules_specific.csv"


# ── Parse final_var string → condition dict ───────────────────────────────

def parse_single(token: str) -> dict:
    """Parse 'field op [value]' → condition dict."""
    parts = token.strip().split()
    if len(parts) == 2:
        field, op = parts
        return {"var": f"item.{field}", "op": op}
    elif len(parts) >= 3:
        field, op = parts[0], parts[1]
        value = " ".join(parts[2:])
        return {"var": f"item.{field}", "op": op, "value": value}
    raise ValueError(f"Cannot parse token: {token!r}")


def parse_final_var(final_var: str) -> dict:
    """Parse final_var string → YAML condition dict."""
    fv = final_var.strip()

    # Multi-condition: split on ' + '
    if " + " in fv:
        parts = [p.strip() for p in fv.split(" + ")]
        sub_conds = [parse_single(p) for p in parts]
        return {"all": sub_conds}

    # Single condition
    return parse_single(fv)


# ── Load CSV mapping ──────────────────────────────────────────────────────

def load_mapping() -> dict[str, str]:
    """Return {rule_id: final_var} from CSV."""
    m = {}
    with open(CSV_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rid = row["rule_id"].strip()
            fv = row["final_var"].strip()
            if rid and fv:
                m[rid] = fv
    return m


# ── Apply to step7 files ──────────────────────────────────────────────────

def conditions_equal(a: dict, b: dict) -> bool:
    """Deep equality check for condition dicts."""
    return yaml.dump(a, sort_keys=True) == yaml.dump(b, sort_keys=True)


def apply_all() -> None:
    mapping = load_mapping()
    print(f"Loaded {len(mapping)} rule→var assignments from CSV")

    step7_files = sorted(BASE.glob("*/step7_*.checks.yaml"))
    print(f"Found {len(step7_files)} step7 files\n")

    total_rules = 0
    total_changed = 0
    errors = []

    for step7 in step7_files:
        data = yaml.safe_load(step7.read_text())
        if not data:
            continue
        checks = data.get("checks", []) or []
        file_changed = False

        for rule in checks:
            total_rules += 1
            rid = rule.get("rule_id", "")
            if rid not in mapping:
                continue

            final_var = mapping[rid]
            try:
                desired_cond = parse_final_var(final_var)
            except Exception as e:
                errors.append(f"{rid}: {e}")
                continue

            current_cond = rule.get("conditions", {})
            if conditions_equal(current_cond, desired_cond):
                continue

            rule["conditions"] = desired_cond
            file_changed = True
            total_changed += 1

        if file_changed:
            data["checks"] = checks
            step7.write_text(
                yaml.dump(data, default_flow_style=False, allow_unicode=True,
                          sort_keys=False, width=120)
            )

    print(f"Total rules     : {total_rules}")
    print(f"Rules updated   : {total_changed}")
    print(f"Files updated   : {sum(1 for p in step7_files if yaml.safe_load(p.read_text()) is not None)}")

    if errors:
        print(f"\nErrors ({len(errors)}):")
        for e in errors[:20]:
            print(f"  {e}")

    # Final var distribution
    var_counter: Counter = Counter()
    for step7 in step7_files:
        data = yaml.safe_load(step7.read_text())
        for rule in (data.get("checks") or []):
            def collect(c):
                if isinstance(c, dict):
                    if "var" in c:
                        var_counter[c["var"]] += 1
                    for k in ("all", "any"):
                        if k in c:
                            for s in c[k]:
                                collect(s)
                elif isinstance(c, list):
                    for s in c:
                        collect(s)
            collect(rule.get("conditions", {}))

    print(f"\n{'='*60}")
    print("Final var distribution across all step7 rules:")
    print(f"{'='*60}")
    for var, cnt in var_counter.most_common():
        print(f"  {cnt:4d}  {var}")


if __name__ == "__main__":
    apply_all()
