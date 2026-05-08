"""
build_fixture_index.py — Phase 2 Fixture Library Builder

Steps:
  1. Scan all discovery YAMLs (catalog/discovery_generator/{csp}/*/step6_*.discovery.yaml)
     and build: discovery_id → emit_item_fields dict
  2. Scan all check YAMLs (catalog/rule/{csp}_rule_check/**/*.yaml)
     and collect unique for_each values + which condition vars each op needs
  3. Match for_each ops to discovery emit schemas
  4. Generate synthetic fixture JSONs for each unique op
     → fixtures/{csp}/{service}/{op_leaf}.json   (PASS case)
     → fixtures/{csp}/{service}/{op_leaf}_fail.json (FAIL case — one field inverted)
  5. Write fixtures/index.json — lookup: op → {fixture_pass, fixture_fail, fields[]}
  6. Write capture_fixtures.sh — AWS CLI / az / gcloud / kubectl / aliyun commands

Usage:
    python build_fixture_index.py [--csp aws] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

BASE = Path(__file__).parent
CATALOG = BASE.parent            # threat-engine/catalog/
DISCO_ROOT  = CATALOG / "discovery_generator"
RULE_ROOT   = CATALOG / "rule"
FIXTURE_DIR = BASE / "fixtures"

CSP_LIST = ["aws", "azure", "gcp", "oci", "k8s", "alicloud", "ibm"]


# ══════════════════════════════════════════════════════════════════════════════
# Discovery YAML scanner
# ══════════════════════════════════════════════════════════════════════════════

def parse_discovery_yamls() -> dict[str, dict]:
    """
    Return: {discovery_id: {"fields": [...], "csp": ..., "service": ...}}
    """
    index: dict[str, dict] = {}
    pattern = DISCO_ROOT.rglob("step6_*.discovery.yaml")

    for path in pattern:
        try:
            data = yaml.safe_load(path.read_text())
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        csp     = data.get("provider", path.parts[-3] if len(path.parts) >= 3 else "")
        service = data.get("service", "")

        for disc in (data.get("discovery") or []):
            disc_id = disc.get("discovery_id")
            if not disc_id:
                continue

            emit = disc.get("emit", {}) or {}
            item_map = emit.get("item", {}) or {}
            fields   = list(item_map.keys()) if isinstance(item_map, dict) else []

            index[disc_id] = {
                "fields" : fields,
                "item_map": item_map,
                "csp"    : csp,
                "service": service,
                "has_items_for": bool(emit.get("items_for")),
            }

    return index


# ══════════════════════════════════════════════════════════════════════════════
# Check YAML scanner
# ══════════════════════════════════════════════════════════════════════════════

def _collect_vars(conditions: Any, out: set[str]) -> None:
    """Recursively collect all `var:` values from a conditions dict."""
    if isinstance(conditions, dict):
        if "var" in conditions:
            out.add(conditions["var"])
        for v in conditions.values():
            _collect_vars(v, out)
    elif isinstance(conditions, list):
        for item in conditions:
            _collect_vars(item, out)


def parse_check_yamls() -> dict[str, dict]:
    """
    Return: {for_each_op: {"rules": [rule_id,...], "vars": {var,...}, "csp": ...}}
    """
    ops: dict[str, dict] = defaultdict(lambda: {"rules": [], "vars": set(), "csp": ""})

    for csp in CSP_LIST:
        check_dir = RULE_ROOT / f"{csp}_rule_check"
        if not check_dir.exists():
            continue

        for yaml_file in check_dir.rglob("*.yaml"):
            try:
                data = yaml.safe_load(yaml_file.read_text())
            except Exception:
                continue
            if not isinstance(data, dict):
                continue

            for check in data.get("checks", []):
                for_each = check.get("for_each")
                rule_id  = check.get("rule_id", "")
                if not for_each:
                    continue
                ops[for_each]["rules"].append(rule_id)
                ops[for_each]["csp"] = csp
                conds = check.get("conditions", {})
                _collect_vars(conds, ops[for_each]["vars"])

    # Convert sets to sorted lists for JSON serialisation
    return {k: {**v, "vars": sorted(v["vars"])} for k, v in ops.items()}


def parse_fallback_ops(disco: dict[str, dict],
                       fallback_csps: list[str] | None = None) -> dict[str, dict]:
    """
    Fallback for CSPs with no check rule YAMLs yet (AliCloud, IBM).
    Reads their assertions YAML to find which services matter, then
    registers ALL matching discovery ops so fixtures get generated.
    """
    if fallback_csps is None:
        fallback_csps = ["alicloud", "ibm"]

    # Assertions YAML name pattern: {N}_{csp}_full_scope_assertions.yaml
    assertions_map = {
        "alicloud": BASE / "6_alicloud_full_scope_assertions.yaml",
        "ibm":      [BASE / "7_ibm_full_scope_assertions.yaml",
                     BASE / "8_ibm_posture_assertions.yaml"],
    }

    ops: dict[str, dict] = defaultdict(lambda: {"rules": [], "vars": [], "csp": ""})

    for csp in fallback_csps:
        assertions_entry = assertions_map.get(csp)
        if not assertions_entry:
            # No assertions file — just index ALL discovery ops for this CSP
            for op, meta in disco.items():
                if meta.get("csp") == csp:
                    ops[op]["csp"] = csp
            continue

        # Support single path or list of paths
        assertions_files = assertions_entry if isinstance(assertions_entry, list) else [assertions_entry]
        assertions_files = [f for f in assertions_files if f.exists()]
        if not assertions_files:
            for op, meta in disco.items():
                if meta.get("csp") == csp:
                    ops[op]["csp"] = csp
            continue

        # Collect rows from all assertions files for this CSP
        rows: list = []
        for assertions_file in assertions_files:
            try:
                data = yaml.safe_load(assertions_file.read_text())
            except Exception:
                continue
            if isinstance(data, list):
                rows.extend(data)
            elif isinstance(data, dict):
                for v1 in data.values():
                    if isinstance(v1, dict):
                        for v2 in v1.values():
                            if isinstance(v2, list):
                                rows.extend(v2)
                    elif isinstance(v1, list):
                        rows.extend(v1)

        # Get unique service prefixes from rule_ids
        prefixes: set[str] = set()
        for r in rows:
            if not isinstance(r, dict):
                continue
            rule_id = r.get("rule_id", "")
            parts   = rule_id.split(".")
            if len(parts) >= 2:
                prefixes.add(f"{parts[0]}.{parts[1]}.")

        # Register all discovery ops whose prefix matches
        for op, meta in disco.items():
            if any(op.startswith(pfx) for pfx in prefixes):
                if op not in ops:
                    ops[op]["csp"] = csp
                ops[op]["rules"]  # touch to initialise

    return {k: {**v, "vars": sorted(v.get("vars", []))} for k, v in ops.items()}


# ══════════════════════════════════════════════════════════════════════════════
# Synthetic fixture generator
# ══════════════════════════════════════════════════════════════════════════════

# Field-name heuristics → (pass_value, fail_value)
# Order matters: first match wins. More specific patterns go first.
_HEURISTICS: list[tuple[re.Pattern, Any, Any]] = [
    # ARN / Key identifiers
    (re.compile(r'(?i)(kmsKey|KMSMasterKey|KmsKeyId)'),
                                              "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123", None),
    (re.compile(r'(?i)Arn$'),                 "arn:aws:service:us-east-1:123456789012:resource/example", None),
    # Boolean fields — common prefixes
    (re.compile(r'^Require'),                 True,   False),   # RequireSymbols, RequireMFA …
    (re.compile(r'^Allow'),                   True,   False),   # AllowUsersToChangePassword …
    (re.compile(r'^Expire'),                  True,   False),   # ExpirePasswords
    (re.compile(r'^Hard'),                    False,  True),    # HardExpiry
    (re.compile(r'(?i)(Encrypted|encrypted)$'), True,  False),
    (re.compile(r'(?i)(Enabled|enabled)$'),   True,   False),
    (re.compile(r'(?i)(Disabled|disabled)$'), False,  True),
    (re.compile(r'(?i)(Active|activated)$'),  True,   False),
    (re.compile(r'(?i)(Privileged|privileged)$'), False, True),
    (re.compile(r'(?i)readOnly'),             True,   False),
    (re.compile(r'(?i)autoMount'),            False,  True),
    # Status / lifecycle
    (re.compile(r'(?i)Status$'),              "ACTIVE",    "INACTIVE"),
    (re.compile(r'(?i)State$'),               "RUNNING",   "STOPPED"),
    (re.compile(r'(?i)Phase$'),               "Running",   "Pending"),
    (re.compile(r'(?i)lifecycleState$'),      "AVAILABLE", "TERMINATED"),
    # Versioning / protocol
    (re.compile(r'(?i)(TlsVersion|tlsVersion|MinimalTls|minimalTls)'),
                                              "1.2",  "1.0"),
    (re.compile(r'(?i)(Version|version)$'),   "1.2",  "1.0"),
    (re.compile(r'(?i)Protocol$'),            "HTTPS","HTTP"),
    (re.compile(r'(?i)(Algorithm|Algo)$'),    "aws:kms", ""),
    # Access / security posture
    (re.compile(r'(?i)^access$'),             "Deny", "Allow"),   # Azure NSG `access`
    (re.compile(r'(?i)Prevention$'),          "enforced", "inherited"),
    (re.compile(r'(?i)(BucketPolicy|ResourcePolicy|AccessPolicy)'),
                                              '{"Version":"2012-10-17","Statement":[]}', None),
    # RBAC / K8s arrays
    (re.compile(r'(?i)^verbs$'),              ["get", "list"], ["*"]),
    (re.compile(r'(?i)^resources$'),          ["pods", "services"], ["*"]),
    (re.compile(r'(?i)^rules$'),              [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}], []),
    # Geography
    (re.compile(r'(?i)(Region|region)$'),     "us-east-1",    None),
    (re.compile(r'(?i)(Zone|zone)$'),         "us-central1-a", None),
    (re.compile(r'(?i)Location$'),            "eastus",       None),
    # Temporal
    (re.compile(r'(?i)(Date|date|Time|time)$'), "2025-01-01T00:00:00Z", None),
    (re.compile(r'(?i)(Age|Days|days)$'),     30,   120),
    # Numeric thresholds
    (re.compile(r'(?i)(Length|MinLength|MaxLength)'), 12, 4),
    (re.compile(r'(?i)(Retention|RetentionDays)'),  90,  0),
    (re.compile(r'(?i)(Count|count)$'),       2,    0),
    (re.compile(r'(?i)(Min|Max|Threshold)$'), 12,   4),
    # Identifiers
    (re.compile(r'(?i)(Id|ID)$'),             "example-id-abc123", None),
    (re.compile(r'(?i)(Name|name)$'),         "example-name",      None),
    (re.compile(r'(?i)Url$'),                 "https://example.com", None),
    # Network — absent public IP = PASS
    (re.compile(r'(?i)PublicIp'),             None, "54.100.200.1"),
    # Collections
    (re.compile(r'(?i)(Tags|tags)$'),         {"Environment": "production"}, {}),
    (re.compile(r'(?i)(Labels|labels)$'),     {"app": "production"},        {}),
    (re.compile(r'(?i)(Annotations|annotations)$'), {"example.io/key": "value"}, {}),
    (re.compile(r'(?i)(Config|config|Configuration|configuration)$'),
                                              {"example": "value"}, {}),
    (re.compile(r'(?i)(Type|type)$'),         "example-type", None),
    (re.compile(r'(?i)Block$'),               True, False),
    (re.compile(r'(?i)(Required|required)$'), True, False),
    (re.compile(r'(?i)Reuse'),                5,    0),   # PasswordReusePrevention
]

_DEFAULT_PASS  = "example-value"
_DEFAULT_FAIL  = None   # absent = FAIL for most `exists` checks


def _synthetic_value(field: str, pass_case: bool) -> Any:
    """Return a synthetic value for a field name — pass or fail case."""
    for pattern, p_val, f_val in _HEURISTICS:
        if pattern.search(field):
            return p_val if pass_case else f_val
    return _DEFAULT_PASS if pass_case else _DEFAULT_FAIL


def generate_fixture(fields: list[str], pass_case: bool) -> dict:
    """Generate a synthetic fixture dict from a list of field names."""
    result = {}
    for field in fields:
        val = _synthetic_value(field, pass_case)
        if val is not None:   # skip None (absent field → FAIL)
            result[field] = val
    return result


def _clean_part(part: str) -> str:
    """Strip [] and [N] array notation from a path segment."""
    return re.sub(r'\[.*?\]', '', part)


def _set_nested(d: dict, path: str, value: Any) -> None:
    """Set a value in a nested dict using a dot-path (strips 'item.' prefix).
    Array notation `containers[]` is treated as a single array with one element.
    Silently skips the assignment if an intermediate node is not a dict/list.
    """
    if path.startswith("item."):
        path = path[5:]

    parts = [_clean_part(p) for p in path.split(".") if _clean_part(p)]
    if not parts:
        return

    current: Any = d
    for i, part in enumerate(parts[:-1]):
        if not isinstance(current, (dict, list)):
            return  # can't traverse into a scalar — skip
        if isinstance(current, list):
            if not current:
                current.append({})
            current = current[0]
            if not isinstance(current, dict):
                return

        if part not in current:
            # Peek at next: does the next part or the value need a list?
            next_raw = path.split(".")[i + 1] if i + 1 < len(parts) else ""
            if "[]" in next_raw:
                current[part] = [{}]
            else:
                current[part] = {}

        child = current[part]
        if isinstance(child, list):
            if not child:
                child.append({})
            current = child[0]
        elif isinstance(child, dict):
            current = child
        else:
            # Already a scalar — convert to dict to allow deeper assignment
            current[part] = {}
            current = current[part]

    leaf = parts[-1]
    if isinstance(current, dict):
        current[leaf] = value
    elif isinstance(current, list):
        if current and isinstance(current[0], dict):
            current[0][leaf] = value


def generate_fixture_from_vars(condition_vars: list[str], pass_case: bool) -> dict:
    """Build a synthetic fixture from check condition `var` paths.
    Used when emit.fields is empty (K8s full-object resources).
    """
    result: dict = {}
    for var in condition_vars:
        # Get just the leaf field name for heuristic value generation
        leaf = var.split(".")[-1].replace("[]", "").split("[")[0]
        val  = _synthetic_value(leaf, pass_case)
        if val is None and pass_case:
            val = "example-value"
        if val is not None:
            _set_nested(result, var, val)
    return result


# ══════════════════════════════════════════════════════════════════════════════
# Capture-script generator
# ══════════════════════════════════════════════════════════════════════════════

_CLI_TEMPLATES = {
    "aws" : "aws {svc} {op} --output json > {out}",
    "azure": "az {svc} {op} -o json > {out}",
    "gcp" : "gcloud {svc} {op} --format=json > {out}",
    "oci" : "oci {svc} {op} --output json > {out}",
    "k8s" : "kubectl get {op} -o json > {out}",
    "alicloud": "aliyun {svc} {op} > {out}",
}


def generate_capture_script(ops: dict[str, dict], out_path: Path) -> None:
    lines = [
        "#!/usr/bin/env bash",
        "# capture_fixtures.sh — Phase 2: capture real CSP API responses",
        "# Run this against a sandbox account, then place output under",
        "# fixtures/{csp}/{service}/{op_leaf}.json",
        "# Generated by build_fixture_index.py",
        "",
        'set -euo pipefail',
        'FIXTURES_DIR="$(dirname "$0")/fixtures"',
        "",
    ]

    for csp in CSP_LIST:
        csp_ops = [(op, meta) for op, meta in ops.items()
                   if meta.get("csp") == csp]
        if not csp_ops:
            continue

        lines += [f"", f"# {'─' * 60}", f"# {csp.upper()}", f"# {'─' * 60}"]

        for op, meta in sorted(csp_ops):
            # op = "aws.s3.get_bucket_encryption"
            parts     = op.split(".")
            svc       = parts[1] if len(parts) > 1 else "unknown"
            op_name   = ".".join(parts[2:]) if len(parts) > 2 else op
            op_leaf   = parts[-1] if parts else op
            out_rel   = f'$FIXTURES_DIR/{csp}/{svc}/{op_leaf}.json'

            tmpl = _CLI_TEMPLATES.get(csp, "# {csp} {op} > {out}")
            cmd  = tmpl.format(svc=svc, op=op_name, out=out_rel, csp=csp)
            lines.append(f'mkdir -p "$FIXTURES_DIR/{csp}/{svc}"')
            lines.append(f'{cmd}   # {op}  (used by {len(meta["rules"])} rules)')

    out_path.write_text("\n".join(lines) + "\n")
    out_path.chmod(0o755)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csp",      default=None, help="Limit to one CSP")
    parser.add_argument("--dry-run",  action="store_true", help="Print counts, don't write files")
    parser.add_argument("--no-fixtures", action="store_true", help="Skip writing fixture JSON files")
    args = parser.parse_args()

    print("Phase 2 — Fixture Library Builder")
    print(f"{'─' * 60}")

    print("[1/4] Scanning discovery YAMLs …", end=" ", flush=True)
    disco = parse_discovery_yamls()
    print(f"{len(disco)} discovery ops indexed")

    print("[2/4] Scanning check rule YAMLs …", end=" ", flush=True)
    ops = parse_check_yamls()
    # Fallback: add all discovery ops for CSPs with no check YAMLs yet
    fallback = parse_fallback_ops(disco)
    added = 0
    for op, meta in fallback.items():
        if op not in ops:
            ops[op] = meta
            added += 1
    if args.csp:
        ops = {k: v for k, v in ops.items() if v.get("csp") == args.csp}
    print(f"{len(ops)} unique for_each ops found  (+{added} from fallback CSPs)")

    # Match ops to discovery schemas
    matched   = {k: v for k, v in ops.items() if k in disco}
    unmatched = {k: v for k, v in ops.items() if k not in disco}
    print(f"  → matched to discovery schema: {len(matched)}")
    print(f"  → no discovery schema found:   {len(unmatched)}")

    if args.dry_run:
        print("\n[dry-run] Would generate fixtures for:")
        for csp in CSP_LIST:
            csp_ops = [(k, v) for k, v in matched.items() if v.get("csp") == csp]
            print(f"  {csp}: {len(csp_ops)} ops")
        return

    print(f"[3/4] Generating fixture files …")
    fixture_index: dict[str, dict] = {}
    written = skipped = 0

    FIXTURE_DIR.mkdir(exist_ok=True)

    for op, meta in matched.items():
        d = disco[op]
        csp     = d.get("csp") or meta.get("csp") or "unknown"
        service = d.get("service") or op.split(".")[1] if "." in op else "unknown"
        op_leaf = op.split(".")[-1]

        svc_dir = FIXTURE_DIR / csp / service
        if not args.no_fixtures:
            svc_dir.mkdir(parents=True, exist_ok=True)

        fields   = d.get("fields", [])
        cond_vars = meta.get("vars", [])

        if fields:
            fix_pass = generate_fixture(fields, pass_case=True)
            fix_fail = generate_fixture(fields, pass_case=False)
        elif cond_vars:
            # No emit schema (e.g. K8s full-object resources) — build from condition vars
            fix_pass = generate_fixture_from_vars(cond_vars, pass_case=True)
            fix_fail = generate_fixture_from_vars(cond_vars, pass_case=False)
        else:
            skipped += 1
            continue

        pass_path = svc_dir / f"{op_leaf}.json"
        fail_path = svc_dir / f"{op_leaf}_fail.json"

        if not args.no_fixtures:
            pass_path.write_text(json.dumps(fix_pass, indent=2, default=str))
            # Only write fail fixture if it differs from pass
            if fix_fail != fix_pass and fix_fail:
                fail_path.write_text(json.dumps(fix_fail, indent=2, default=str))

        fixture_index[op] = {
            "csp"          : csp,
            "service"      : service,
            "fields"       : fields,
            "condition_vars": meta.get("vars", []),
            "rule_count"   : len(meta.get("rules", [])),
            "fixture_pass" : str(pass_path.relative_to(BASE)),
            "fixture_fail" : str(fail_path.relative_to(BASE)) if (fix_fail != fix_pass and fix_fail) else None,
        }
        written += 1

    # Also record unmatched ops (no discovery schema)
    for op, meta in unmatched.items():
        fixture_index[op] = {
            "csp"          : meta.get("csp", ""),
            "service"      : op.split(".")[1] if "." in op else "",
            "fields"       : [],
            "condition_vars": meta.get("vars", []),
            "rule_count"   : len(meta.get("rules", [])),
            "fixture_pass" : None,
            "fixture_fail" : None,
            "no_schema"    : True,
        }

    print(f"  → {written} fixtures written, {skipped} skipped (no fields)")

    print("[4/4] Writing index + capture script …", end=" ", flush=True)
    index_path = BASE / "fixtures" / "index.json"
    index_path.parent.mkdir(exist_ok=True)
    index_path.write_text(json.dumps(fixture_index, indent=2, sort_keys=True))

    script_path = BASE / "fixtures" / "capture_fixtures.sh"
    generate_capture_script(ops, script_path)
    print("done")

    # Summary
    print(f"\n{'═' * 60}")
    print("  Summary by CSP")
    print(f"{'─' * 60}")
    for csp in CSP_LIST:
        c_ops = [op for op, v in fixture_index.items() if v.get("csp") == csp]
        c_fix = sum(1 for op in c_ops if fixture_index[op].get("fixture_pass"))
        print(f"  {csp:12s}  {len(c_ops):4d} ops  |  {c_fix:4d} fixtures generated")

    total_ops = len(fixture_index)
    total_fix = sum(1 for v in fixture_index.values() if v.get("fixture_pass"))
    print(f"{'─' * 60}")
    print(f"  {'TOTAL':12s}  {total_ops:4d} ops  |  {total_fix:4d} fixtures generated")
    print(f"{'═' * 60}")
    print(f"\nIndex: {index_path}")
    print(f"Script: {script_path}")
    print()


if __name__ == "__main__":
    main()
