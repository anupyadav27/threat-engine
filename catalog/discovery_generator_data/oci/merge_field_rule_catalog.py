#!/usr/bin/env python3
"""
Merge OCI field catalog + check rules → single unified field_rule_catalog.csv

Schema (18 existing + 7 new columns):
  [field columns]  csp, service, field_path, item_var_path, field_type, is_id,
                   producing_op, op_kind, is_independent, root_op, chain_ops,
                   chain_length, hop_distance, chain_ops_with_fields,
                   operators, operators_no_value, python_call, http_path
  [rule columns]   check_rule_id, check_for_each, check_var,
                   check_condition_op, check_condition_value,
                   check_severity, check_frameworks

Row semantics:
  check_rule_id == ""  →  pure field/discovery row (no rule attached)
  check_rule_id != ""  →  rule row (field data + rule definition merged)

One rule per row. If two rules check the same field, that field appears in two rows.

Output:
  catalog/discovery_generator/oci/oci_field_rule_catalog.csv

Usage:
  python3 merge_field_rule_catalog.py

Derived artifacts from this single CSV:
  1. Discovery YAML  = DISTINCT producing_op, chain_ops WHERE service=X
  2. Check YAML      = rows WHERE check_rule_id != "" AND service=X
  3. User new rule   = INSERT row with field cols + check cols
"""

from __future__ import annotations
import csv, json, re, yaml
from collections import defaultdict
from pathlib import Path

BASE_OCI     = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
MASTER_CSV   = BASE_OCI / "oci_master_field_catalog.csv"
RULES_BASE   = Path("/Users/apple/Desktop/threat-engine/catalog/rule/oci_rule_check")
OUTPUT_CSV   = BASE_OCI / "oci_field_rule_catalog.csv"

FIELD_COLS = [
    "csp", "service", "field_path", "item_var_path", "field_type", "is_id",
    "producing_op", "op_kind", "is_independent", "root_op", "chain_ops",
    "chain_length", "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value", "python_call", "http_path",
    # ── identifier / dependency link columns (new) ──
    "resource_type",       # e.g. 'bucket', 'autonomous_database'
    "resource_id_field",   # field from root_op that is the resource key (always 'ocid' for OCI)
    "resource_id_param",   # SDK param name for the get_ op (e.g. 'autonomous_database_id')
]
RULE_COLS = [
    "check_rule_id",
    "check_for_each",
    "check_var",
    "check_condition_op",
    "check_condition_value",
    "check_condition",         # ← combined JSON {"var":..,"op":..,"value":..} — engine-ready
    "check_conditions_json",   # JSONB for multi-condition AND/OR rules (future)
    "check_severity",
    "check_frameworks",
    "check_description",
    "is_system_rule",
    "is_active",
    "needs_review",
    "review_reason",
]
ALL_COLS = FIELD_COLS + RULE_COLS

# ── Resource identifier map: service → {get_op_bare → resource_id_param} ─────

ROOT_PARAMS = {
    "compartmentId", "CompartmentId", "compartment_id",
    "tenancyId", "TenancyId", "tenancy_id",
    "regionId", "RegionId", "region_id",
    "namespaceName", "NamespaceName", "Namespace", "namespace",
}


def pascal_to_snake(name: str) -> str:
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def load_resource_id_params() -> dict[str, dict[str, str]]:
    """
    Returns: service → { get_op_bare → resource_id_param_snake }
    e.g. {'database': {'get_autonomous_database': 'autonomous_database_id'}}

    For OCI, every get_ op has exactly one non-root required param ending in Id.
    The param snake_case name is passed as: {param}: '{{ item.ocid }}'
    """
    result: dict[str, dict[str, str]] = defaultdict(dict)
    for s2_path in sorted(BASE_OCI.rglob("step2_read_operation_registry.json")):
        svc = s2_path.parent.name
        try:
            ops = json.loads(s2_path.read_text()).get("operations", {})
        except Exception:
            continue
        for op, meta in ops.items():
            if meta.get("kind") != "read_get":
                continue
            non_root = [p for p in meta.get("required_params", []) if p not in ROOT_PARAMS]
            if non_root:
                result[svc][op] = pascal_to_snake(non_root[0])
    return result


# ── Extract resource_type from field_path ─────────────────────────────────────

def resource_type_from_field(field_path: str) -> str:
    """
    'bucket.kms_key_id'        → 'bucket'
    'autonomous_database.name' → 'autonomous_database'
    'ocid'                     → ''   (root-level field, no resource prefix)
    """
    return field_path.split(".")[0] if "." in field_path else ""


# ── Default severity from rule_id keyword ────────────────────────────────────

def _severity(rule_id: str) -> str:
    low = rule_id.lower()
    if any(k in low for k in ["mfa", "kms", "cmek", "encryption", "public", "admin"]):
        return "HIGH"
    if any(k in low for k in ["backup", "logging", "audit", "monitoring", "ssl"]):
        return "MEDIUM"
    return "MEDIUM"


# ── Load master field catalog ─────────────────────────────────────────────────

def load_field_catalog(
    id_param_map: dict[str, dict[str, str]],
) -> tuple[list[dict], dict[str, dict]]:
    """
    Returns:
      rows          : all field rows as list of dicts (with new identifier cols)
      var_path_idx  : item_var_path → row  (for matching check var fields)
    """
    rows = []
    var_path_idx: dict[str, dict] = {}

    for r in csv.DictReader(open(MASTER_CSV)):
        # Populate the 3 new identifier columns
        prod_bare = r.get("producing_op", "").split(".")[-1]
        svc       = r.get("service", "")

        r["resource_type"]     = resource_type_from_field(r.get("field_path", ""))
        r["resource_id_field"] = "ocid"   # OCI universal: OCID is always the identifier
        r["resource_id_param"] = id_param_map.get(svc, {}).get(prod_bare, "")

        rows.append(r)
        vp = r.get("item_var_path", "")
        if vp:
            var_path_idx[vp] = r

    return rows, var_path_idx


# ── Load all check rules ──────────────────────────────────────────────────────

def load_check_rules() -> list[dict]:
    """Return flat list of check rule dicts."""
    rules = []
    for svc_dir in sorted(RULES_BASE.iterdir()):
        if not svc_dir.is_dir():
            continue
        chk_file = svc_dir / f"{svc_dir.name}.checks.yaml"
        if not chk_file.exists():
            continue
        data = yaml.safe_load(chk_file.read_text()) or {}
        for chk in data.get("checks", []):
            cond = chk.get("conditions") or {}
            # is_active: false if explicitly set, or if needs_review flag present
            chk_active = chk.get("is_active", True)
            if chk.get("needs_review"):
                chk_active = False
            rules.append({
                "service":      svc_dir.name,
                "rule_id":      chk.get("rule_id", ""),
                "for_each":     chk.get("for_each", ""),
                "var":          cond.get("var", ""),
                "op":           cond.get("op", "exists"),
                "value":        str(cond.get("value", "")) if cond.get("value") is not None else "",
                "is_active":    "true" if chk_active else "false",
                "needs_review": "true" if chk.get("needs_review") else "false",
                "review_reason": chk.get("review_reason", ""),
            })
    return rules


# ── Synthetic field row for unmatched vars ────────────────────────────────────

def synthetic_field_row(service: str, var: str, for_each: str, rule_id: str = "") -> dict:
    """
    Build a minimal field row for a var path not found in the master catalog.
    e.g. var = 'item.policy.is_mfa_required' → field_path = 'policy.is_mfa_required'
    """
    # Strip 'item.' prefix
    field_path = var[5:] if var.startswith("item.") else var

    # resource_type: from field_path prefix OR from rule_id (parts[2])
    rtype = resource_type_from_field(field_path)
    if not rtype and rule_id:
        parts = rule_id.split(".")
        rtype = parts[2] if len(parts) > 2 else ""

    # Infer field type from name
    low = field_path.lower().split(".")[-1]   # leaf name only
    if low.endswith("_id") or low == "ocid":
        ftype, is_id = "string", "Yes"
    elif low.startswith("is_") or low.endswith("_enabled") or low.endswith("_activated"):
        ftype, is_id = "boolean", "No"
    elif "tags" in low:
        ftype, is_id = "object", "No"
    elif "time" in low or "date" in low:
        ftype, is_id = "string", "No"
    else:
        ftype, is_id = "string", "No"

    prod_op  = for_each
    root_op  = for_each
    op_kind  = "read_list" if ".list_" in for_each else "read_get"
    is_indep = "Yes" if op_kind == "read_list" else "No"

    return {
        "csp":                   "oci",
        "service":               service,
        "field_path":            field_path,
        "item_var_path":         var,
        "field_type":            ftype,
        "is_id":                 is_id,
        "producing_op":          prod_op,
        "op_kind":               op_kind,
        "is_independent":        is_indep,
        "root_op":               root_op,
        "chain_ops":             prod_op,
        "chain_length":          "1",
        "hop_distance":          "0",
        "chain_ops_with_fields": prod_op,
        "operators":             "equals, exists, not_equals",
        "operators_no_value":    "exists",
        "python_call":           "",
        "http_path":             "",
        # identifier columns — always set for OCI
        "resource_type":         rtype,
        "resource_id_field":     "ocid",
        "resource_id_param":     "",    # list op — no parent ID param needed
    }


# ── Main merge ────────────────────────────────────────────────────────────────

def main():
    print("Loading resource identifier params...")
    id_param_map = load_resource_id_params()
    print(f"  {sum(len(v) for v in id_param_map.values())} get-op param mappings across {len(id_param_map)} services")

    print("Loading field catalog...")
    field_rows, var_idx = load_field_catalog(id_param_map)
    print(f"  {len(field_rows)} field rows  |  {len(var_idx)} indexed var paths")

    print("Loading check rules...")
    check_rules = load_check_rules()
    print(f"  {len(check_rules)} check rules across {len(set(r['service'] for r in check_rules))} services")

    # ── Build output rows ─────────────────────────────────────────────────────
    # Pass 1: all existing field rows (check cols = empty)
    out_rows: list[dict] = []
    for r in field_rows:
        row = dict(r)
        for c in RULE_COLS:
            row[c] = ""
        row["is_system_rule"] = ""
        row["is_active"]      = ""
        out_rows.append(row)

    synthetic_added: set[str] = set()

    # Pass 2: for each check rule, add a rule row (field cols + rule cols)
    matched = 0
    unmatched = 0
    svc_rule_counts: dict[str, int] = defaultdict(int)

    for rule in check_rules:
        svc      = rule["service"]
        rule_id  = rule["rule_id"]
        for_each = rule["for_each"]
        var      = rule["var"]
        op       = rule["op"]
        value    = rule["value"]

        # Find matching field row by item_var_path
        field_row = var_idx.get(var)

        if field_row is None:
            # Unmatched: create synthetic field row
            unmatched += 1
            if var not in synthetic_added:
                synthetic_added.add(var)
            field_row = synthetic_field_row(svc, var, for_each, rule_id=rule_id)
        else:
            matched += 1

        # Determine check_for_each: use rule's for_each (already correct from fixer)
        # Fallback: use root_op from field row
        check_fe = for_each or field_row.get("root_op", "")

        # Build combined condition JSON — engine-ready single object
        cond_obj = {"var": var, "op": op, "value": value if value else None}

        row = dict(field_row)
        # Ensure resource_id_field is always set (may be empty for root-level fields)
        if not row.get("resource_id_field"):
            row["resource_id_field"] = "ocid"

        row["check_rule_id"]         = rule_id
        row["check_for_each"]        = check_fe
        row["check_var"]             = var
        row["check_condition_op"]    = op
        row["check_condition_value"] = value
        row["check_condition"]       = json.dumps(cond_obj)   # ← combined condition JSON
        row["check_conditions_json"] = ""   # reserved for AND/OR multi-condition rules
        row["check_severity"]        = _severity(rule_id)
        row["check_frameworks"]      = ""   # enrich separately from compliance mapping
        row["check_description"]     = ""   # human-readable intent (fill from rule_id words)
        row["is_system_rule"]        = "true"
        row["is_active"]             = rule.get("is_active", "true")
        row["needs_review"]          = rule.get("needs_review", "false")
        row["review_reason"]         = rule.get("review_reason", "")

        # Ensure all cols present
        for c in RULE_COLS:
            if c not in row:
                row[c] = ""

        out_rows.append(row)
        svc_rule_counts[svc] += 1

    # ── Write output CSV ──────────────────────────────────────────────────────
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=ALL_COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(out_rows)

    print(f"\nOutput: {OUTPUT_CSV}")
    print(f"  Total rows     : {len(out_rows)}")
    print(f"  Field rows     : {len(field_rows)}")
    print(f"  Rule rows      : {len(check_rules)}")
    print(f"    matched       : {matched} ({100*matched//len(check_rules)}%)")
    print(f"    unmatched     : {unmatched} (synthetic field rows)")
    print(f"\nRules per service (check rule services):")
    for svc, cnt in sorted(svc_rule_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"  {svc:<30} {cnt}")

    # ── Show example rows ─────────────────────────────────────────────────────
    sample_rules = [r for r in out_rows if r["check_rule_id"]][:3]
    print(f"\nSample rule rows:")
    for r in sample_rules:
        print(f"  rule_id  : {r['check_rule_id']}")
        print(f"  field    : {r['field_path']}  ({r['field_type']})")
        print(f"  for_each : {r['check_for_each']}")
        print(f"  var      : {r['check_var']}")
        print(f"  cond     : {r['check_condition_op']} {r['check_condition_value'] or '(no value)'}")
        print()


# ── Derivation helpers (for downstream consumers) ─────────────────────────────

def load_unified_catalog(csv_path: Path = OUTPUT_CSV):
    """Load the unified catalog. Returns (field_rows, rule_rows)."""
    all_rows = list(csv.DictReader(open(csv_path)))
    field_rows = [r for r in all_rows if not r["check_rule_id"]]
    rule_rows  = [r for r in all_rows if r["check_rule_id"]]
    return field_rows, rule_rows


def generate_check_yaml(service: str, csv_path: Path = OUTPUT_CSV) -> str:
    """Generate {service}.checks.yaml content from unified catalog."""
    _, rule_rows = load_unified_catalog(csv_path)
    svc_rules = [r for r in rule_rows if r["service"] == service]
    if not svc_rules:
        return ""

    lines = [
        "version: '1.0'",
        f"provider: oci",
        f"service: {service}",
        "checks:",
    ]
    for r in svc_rules:
        val = r["check_condition_value"] or "null"
        # yaml null for empty
        if val in ("", "None", "null"):
            val = "null"
        elif val in ("true", "false"):
            pass
        else:
            val = f"'{val}'"

        lines.append(f"- rule_id: {r['check_rule_id']}")
        lines.append(f"  for_each: {r['check_for_each']}")
        lines.append(f"  conditions:")
        lines.append(f"    var: {r['check_var']}")
        lines.append(f"    op: {r['check_condition_op']}")
        lines.append(f"    value: {val}")
    return "\n".join(lines) + "\n"


def generate_discovery_yaml(service: str, csv_path: Path = OUTPUT_CSV) -> str:
    """
    Generate step6_{service}.discovery.yaml from unified catalog.
    Uses DISTINCT producing_op, grouped by chain_ops.
    """
    field_rows, _ = load_unified_catalog(csv_path)
    svc_rows = [r for r in field_rows if r["service"] == service]
    if not svc_rows:
        return ""

    # Collect ops
    ops: dict[str, dict] = {}   # op_bare → {is_independent, root_op, fields}
    for r in svc_rows:
        prod = r["producing_op"]
        bare = prod.split(".")[-1]
        if bare not in ops:
            ops[bare] = {
                "is_independent": r["is_independent"] == "Yes",
                "root_op":        r["root_op"].split(".")[-1],
                "fields":         [],
            }
        leaf = r["field_path"].split(".")[-1] if "." in r["field_path"] else r["field_path"]
        if leaf not in ops[bare]["fields"]:
            ops[bare]["fields"].append(leaf)

    # Sort: independent (list) first
    sorted_ops = sorted(ops.items(), key=lambda x: (0 if x[1]["is_independent"] else 1, x[0]))

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines = [
        f"# Discovery YAML — {service} (OCI)",
        f"# Generated from oci_field_rule_catalog.csv at {now}",
        "version: '1.0'",
        "provider: oci",
        f"service: {service}",
        "services:",
        f"  client: {service}",
        f"  module: oci.{service}",
        "discovery:",
    ]

    for op_bare, meta in sorted_ops:
        indep  = meta["is_independent"]
        root   = meta["root_op"]
        fields = meta["fields"]
        kind   = "independent" if indep else f"dependent → {root}"

        lines.append(f"  # ── {op_bare} [{kind}] ──")
        lines.append(f"  - discovery_id: oci.{service}.{op_bare}")
        if not indep and root != op_bare:
            lines.append(f"    for_each: oci.{service}.{root}")
        lines.append(f"    calls:")
        lines.append(f"      - action: {op_bare}")
        if not indep and root != op_bare:
            lines.append(f"        params:")
            lines.append(f"          {op_bare.replace('get_','').rstrip('s')}_id: '{{{{ item.ocid }}}}'")
        lines.append(f"        save_as: response")
        lines.append(f"        on_error: continue")
        lines.append(f"    emit:")
        lines.append(f"      as: item")
        if indep:
            lines.append(f"      items_for: '{{{{ response.data }}}}'")
        lines.append(f"      item:")
        for f in fields:
            ref = f"item.{f}" if indep else f"response.data.{f}"
            lines.append(f"        {f}: '{{{{ {ref} }}}}'")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
