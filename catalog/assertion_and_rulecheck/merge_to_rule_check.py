#!/usr/bin/env python3
"""
merge_to_rule_check.py — Merge generated check YAMLs into the production format.

Converts:
    generated/{csp}/{service}/{rule_id}.yaml      (one file per rule)

Into:
    catalog/rule/{csp}_rule_check/{service}/{service}.checks.yaml
    (one file per service, all rules in a `checks:` list)

Format matches existing production check YAMLs exactly:
    version: '1.0'
    provider: {csp}
    service: {service}
    checks:
    - rule_id: ...
      for_each: ...
      severity: ...
      conditions:
        ...

Internal fields stripped: fixture_validated, fixture_note, pattern
value: null added to conditions with op: exists / not_exists / is_true / is_false
(matches existing YAML style)

Usage:
    python merge_to_rule_check.py --csp aws          # merge AWS
    python merge_to_rule_check.py --csp aws --dry-run
    python merge_to_rule_check.py                    # all CSPs with generated output
"""

import argparse
import pathlib
import shutil
import yaml

BASE      = pathlib.Path(__file__).parent
GENERATED = BASE / "generated"
RULE_ROOT = BASE.parent.parent / "engines" if False else \
            pathlib.Path("/Users/apple/Desktop/threat-engine/catalog/rule")

# Internal fields written by generate_checks.py — must be stripped
_STRIP_FIELDS = {"fixture_validated", "fixture_note", "pattern"}

# Ops that never need a `value` field — but existing format writes `value: null`
_NULL_VALUE_OPS = {"exists", "not_exists", "is_true", "is_false", "not_empty", "is_empty"}


def _normalise_conditions(cond):
    """
    Recursively normalise a conditions dict:
    - Add value: null for ops that don't use a value (matches existing YAML style)
    - Leave compound all/any/not blocks intact
    """
    if not isinstance(cond, dict):
        return cond

    # Compound block
    for compound in ("all", "any", "not"):
        if compound in cond:
            inner = cond[compound]
            if isinstance(inner, list):
                return {compound: [_normalise_conditions(c) for c in inner]}
            else:
                return {compound: _normalise_conditions(inner)}

    # Single condition
    result = {}
    if "var" in cond:
        result["var"] = cond["var"]
    if "op" in cond:
        result["op"] = cond["op"]
        # Add value: null for ops that don't normally take a value
        if cond["op"] in _NULL_VALUE_OPS and "value" not in cond:
            result["value"] = None
        elif "value" in cond:
            result["value"] = cond["value"]
    return result


def load_generated_rules(csp: str) -> dict[str, list[dict]]:
    """
    Load all generated YAML files for a CSP.
    Returns: {service: [rule_dict, ...]}  sorted by rule_id within each service.
    """
    csp_dir = GENERATED / csp
    if not csp_dir.exists():
        return {}

    by_service: dict[str, list[dict]] = {}

    for yaml_file in sorted(csp_dir.rglob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_file.read_text())
        except Exception as e:
            print(f"  WARN: could not parse {yaml_file.name}: {e}")
            continue

        if not isinstance(data, dict) or "rule_id" not in data:
            continue

        rule_id = data["rule_id"]
        service = rule_id.split(".")[1] if len(rule_id.split(".")) > 1 else "unknown"

        # Build clean rule dict — strip internal fields
        rule = {
            "rule_id":    rule_id,
            "for_each":   data.get("for_each", ""),
            "severity":   data.get("severity", "MEDIUM"),
            "conditions": _normalise_conditions(data.get("conditions", {})),
        }

        by_service.setdefault(service, []).append(rule)

    # Sort rules within each service by rule_id
    for svc in by_service:
        by_service[svc].sort(key=lambda r: r["rule_id"])

    return by_service


def write_service_file(csp: str, service: str, rules: list[dict],
                       out_dir: pathlib.Path, dry_run: bool) -> None:
    """Write a single {service}.checks.yaml file."""
    doc = {
        "version":  "1.0",
        "provider": csp,
        "service":  service,
        "checks":   rules,
    }

    content = yaml.dump(doc, sort_keys=False, default_flow_style=False,
                        allow_unicode=True, width=120)

    service_dir = out_dir / service
    out_path    = service_dir / f"{service}.checks.yaml"

    if dry_run:
        print(f"  [dry-run] would write {out_path.relative_to(RULE_ROOT)} ({len(rules)} rules)")
        return

    service_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content)


def merge_csp(csp: str, dry_run: bool, replace: bool) -> None:
    print(f"\n{'='*60}")
    print(f"Merging {csp.upper()}")
    print(f"{'='*60}")

    by_service = load_generated_rules(csp)
    if not by_service:
        print(f"  No generated rules found in generated/{csp}/")
        return

    total_rules    = sum(len(v) for v in by_service.values())
    total_services = len(by_service)
    print(f"  {total_rules} rules across {total_services} services")

    out_dir = RULE_ROOT / f"{csp}_rule_check"

    if replace and out_dir.exists() and not dry_run:
        # Remove old service dirs that we're replacing
        # (keep any service dirs we don't have generated output for)
        replaced = 0
        for svc in by_service:
            old_svc_dir = out_dir / svc
            if old_svc_dir.exists():
                shutil.rmtree(old_svc_dir)
                replaced += 1
        if replaced:
            print(f"  Removed {replaced} old service directories")

    for service, rules in sorted(by_service.items()):
        write_service_file(csp, service, rules, out_dir, dry_run)
        if not dry_run:
            print(f"  ✓ {service:30s} {len(rules):4d} rules → {service}/{service}.checks.yaml")

    if not dry_run:
        print(f"\n  Done: {total_rules} rules written to {out_dir.relative_to(RULE_ROOT.parent)}/")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csp",      default=None,
                        help="CSP to merge (aws/azure/gcp/oci/k8s/alicloud/ibm). Default: all with generated output.")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Show what would be written without touching files")
    parser.add_argument("--replace",  action="store_true", default=True,
                        help="Replace existing service dirs (default: True)")
    args = parser.parse_args()

    # Determine which CSPs to process
    if args.csp:
        csps = [args.csp]
    else:
        csps = [d.name for d in sorted(GENERATED.iterdir()) if d.is_dir()]

    if args.dry_run:
        print("DRY RUN — no files will be written\n")

    for csp in csps:
        merge_csp(csp, dry_run=args.dry_run, replace=args.replace)

    print("\nAll done.")


if __name__ == "__main__":
    main()
