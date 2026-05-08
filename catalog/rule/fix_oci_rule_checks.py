#!/usr/bin/env python3
"""
Fix OCI rule check YAMLs against the master field catalog.

For each service's checks.yaml:
  1. Validate for_each op exists in master catalog
  2. Validate var field is produced by that op
  3. Fix for_each → best list/get op for the resource
  4. Fix var field → semantically best field for the check intent
  5. Fix conditions.op + value to match field type

Output: overwrites each {service}/{service}.checks.yaml in-place.

Format reference: catalog/rule/oci_rule_check/ai_language/ai_language.checks.yaml
"""

from __future__ import annotations
import csv, re, yaml
from collections import defaultdict
from pathlib import Path

BASE_RULES = Path("/Users/apple/Desktop/threat-engine/catalog/rule/oci_rule_check")
BASE_DISC  = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
MASTER_CSV = BASE_DISC / "oci_master_field_catalog.csv"

# ── YAML dumper: keep None as null, no aliases ─────────────────────────────────
def _none_repr(dumper, _):
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")

yaml.add_representer(type(None), _none_repr)

class _NoAliasDumper(yaml.Dumper):
    def ignore_aliases(self, _): return True

_NoAliasDumper.add_representer(type(None), _none_repr)


# ── Build catalog index ───────────────────────────────────────────────────────
def build_catalog_index(csv_path: Path):
    """
    Returns:
      resource_idx: service → resource → {'list_ops': [], 'get_ops': [], 'fields': set()}
      op_fields:    service → op → set(field_paths)
    """
    resource_idx = defaultdict(lambda: defaultdict(
        lambda: {"list_ops": [], "get_ops": [], "fields": set()}
    ))
    op_fields: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    for r in csv.DictReader(open(csv_path)):
        svc      = r["service"]
        fp       = r["field_path"]
        raw_op   = r["producing_op"].split(".")[-1]   # strip 'oci.svc.'
        resource = fp.split(".")[0] if "." in fp else ""

        op_fields[svc][raw_op].add(fp)

        if not resource:
            continue
        entry = resource_idx[svc][resource]
        entry["fields"].add(fp)
        lst = entry["list_ops"] if raw_op.startswith("list_") else entry["get_ops"]
        if raw_op not in lst:
            lst.append(raw_op)

    return resource_idx, op_fields


# ── Semantic field selector ───────────────────────────────────────────────────

# Priority lists: for a given check keyword, which field suffixes to prefer
_KEYWORD_FIELDS: list[tuple[list[str], list[str]]] = [
    (["mfa"],                    ["is_mfa_activated"]),
    (["kms", "cmek", "cmk"],     ["kms_key_id", "vault_id", "encryption_key_id"]),
    (["encryption", "encrypt"],  ["kms_key_id", "encryption_key_id", "vault_id",
                                   "is_customer_managed_key"]),
    (["backup"],                 ["db_backup_config", "backup_enabled", "backup_config"]),
    (["audit", "logging", "log"],["audit_config", "is_audit_enabled", "logging_config",
                                   "log_group_id", "is_logging_enabled"]),
    (["ssl", "tls"],             ["ssl_configuration", "ssl_mode", "is_ssl_enabled",
                                   "ssl_secret_id"]),
    (["public"],                 ["public_access_type", "is_public",
                                   "is_internet_gateway_attached"]),
    (["private", "endpoint"],    ["private_endpoint_ip", "is_private",
                                   "private_subnet_id", "subnet_id"]),
    (["network", "vcn", "nsg"],  ["nsg_ids", "vcn_id", "subnet_id"]),
    (["versioning", "version"],  ["versioning", "is_versioning_enabled"]),
    (["rotation", "rotate"],     ["time_created", "time_of_expiry"]),
    (["replication"],            ["replication_sources", "is_replication_enabled"]),
    (["tag", "label"],           ["freeform_tags", "defined_tags"]),
    (["event", "notification"],  ["object_events_enabled", "is_event_enabled"]),
    (["firewall", "waf"],        ["web_app_firewall_id", "is_waf_enabled"]),
    (["access"],                 ["access_type", "public_access_type", "kms_key_id"]),
    (["key"],                    ["kms_key_id", "vault_id", "encryption_key_id"]),
    (["secret"],                 ["secret_id", "vault_id"]),
    (["storage"],                ["storage_tier", "object_storage_namespace"]),
    (["tier"],                   ["storage_tier"]),
]

# Fallback preference order for any check
_FALLBACK_FIELDS = [
    "status", "lifecycle_state", "name", "time_created",
    "freeform_tags", "defined_tags", "ocid", "compartment_id",
]

# Condition logic per field suffix
def _condition_for_field(field_path: str, check_name: str) -> tuple[str, object]:
    """
    Returns (op, value) appropriate for this field + check intent.
    """
    fp = field_path.lower()
    check = check_name.lower()

    # Boolean / is_* fields → check they are true
    if fp.endswith("_activated") or fp.endswith("_enabled") or fp.startswith("is_"):
        if "not" in check or "restrict" in check or "block" in check:
            return "equals", "false"
        return "equals", "true"

    # Key / ID fields → check they exist (not null)
    if fp.endswith("_key_id") or fp.endswith("_vault_id") or fp.endswith("_secret_id"):
        return "exists", None

    # Config / object fields → exists
    if fp.endswith("_config") or fp.endswith("_configuration") or fp.endswith("_tags"):
        return "not_empty", None

    # Status / lifecycle → active
    if fp in ("status", "lifecycle_state"):
        if "terminat" in check or "delet" in check or "stop" in check:
            return "not_equals", "TERMINATED"
        return "equals", "ACTIVE"

    # Public access type: should NOT be ObjectRead / NoAuthentication
    if "public_access_type" in fp:
        if "block" in check or "restrict" in check or "prevent" in check:
            return "not_equals", "ObjectRead"
        return "exists", None

    # Time fields → exists
    if "time" in fp or "date" in fp:
        return "exists", None

    # IDs → exists
    if fp.endswith("_id") or fp == "ocid":
        return "exists", None

    # Array-like
    if "ids" in fp or "list" in fp or fp.endswith("s"):
        return "not_empty", None

    return "exists", None


def best_field_for_check(
    check_name: str,
    available_fields: set[str],
    resource: str,
) -> str:
    """
    Pick the semantically best field for a given check_name from available_fields.
    Fields are in 'resource.field_name' format.
    Returns bare field_path (not item. prefixed).
    """
    check_low = check_name.lower()

    # Try keyword-driven priority
    for keywords, preferred in _KEYWORD_FIELDS:
        if any(kw in check_low for kw in keywords):
            for pref in preferred:
                # Exact suffix match
                full = f"{resource}.{pref}"
                if full in available_fields:
                    return full
                # Substring match in any available field
                for af in sorted(available_fields):
                    if pref in af:
                        return af

    # Fall back to field that shares a word with check_name
    check_words = set(re.split(r"[_\s]", check_low))
    for af in sorted(available_fields):
        af_words = set(re.split(r"[_\s.]", af.lower()))
        if check_words & af_words - {"enabled", "the", "is", "not", "a", "an"}:
            return af

    # Generic fallback by field priority
    for fb in _FALLBACK_FIELDS:
        full = f"{resource}.{fb}"
        if full in available_fields:
            return full
        for af in sorted(available_fields):
            if af.endswith(f".{fb}"):
                return af

    # Return any available field
    if available_fields:
        return sorted(available_fields)[0]

    return f"{resource}.status"


def best_op_for_resource(
    service: str,
    resource: str,
    resource_idx,
    catalog_services: set,
) -> str | None:
    """
    Return the best op name (bare, no oci.svc. prefix) for a resource.
    Prefer list_ ops (independent), fall back to get_.
    """
    if service not in catalog_services:
        return None
    entry = resource_idx[service].get(resource, {})
    if entry.get("list_ops"):
        return entry["list_ops"][0]
    if entry.get("get_ops"):
        return entry["get_ops"][0]

    # Fuzzy: try plural/singular variants
    for res_key in resource_idx[service]:
        if res_key.replace("_", "") == resource.replace("_", ""):
            e = resource_idx[service][res_key]
            if e.get("list_ops"):
                return e["list_ops"][0]
            if e.get("get_ops"):
                return e["get_ops"][0]

    return None


# ── Rule ID parser ────────────────────────────────────────────────────────────
def parse_rule_id(rule_id: str) -> tuple[str, str, str]:
    """
    oci.{service}.{resource}.{check_name}
    Returns (service, resource, check_name)
    """
    parts = rule_id.split(".")
    # parts[0]='oci', parts[1]=service, parts[2]=resource, parts[3:]=check_name
    if len(parts) < 4:
        return "", "", ""
    return parts[1], parts[2], ".".join(parts[3:])


# ── Fix a single check entry ──────────────────────────────────────────────────
def fix_check(
    check: dict,
    service: str,
    resource_idx,
    op_fields,
    catalog_services: set,
) -> dict:
    rule_id    = check.get("rule_id", "")
    for_each   = check.get("for_each", "")
    cond       = check.get("conditions", {}) or {}

    _, resource, check_name = parse_rule_id(rule_id)
    if not resource:
        return check

    # ── 1. Fix for_each ────────────────────────────────────────────────────
    current_op = for_each.split(".")[-1] if for_each else ""
    available_ops = op_fields.get(service, {})

    # The chosen op MUST produce fields for THIS resource (not another resource)
    def _op_covers_resource(op_name: str) -> bool:
        """True if this op produces at least one field for the target resource."""
        fields = op_fields.get(service, {}).get(op_name, set())
        return any(fp.startswith(f"{resource}.") or fp == resource
                   for fp in fields)

    if current_op in available_ops and _op_covers_resource(current_op):
        chosen_op = current_op
    else:
        # Find the canonical op for this resource
        chosen_op_bare = best_op_for_resource(
            service, resource, resource_idx, catalog_services
        )
        if chosen_op_bare:
            chosen_op = chosen_op_bare
        elif current_op:
            # Keep original even if not in catalog (unmapped service)
            chosen_op = current_op
        else:
            chosen_op = f"list_{resource}s"

    new_for_each = f"oci.{service}.{chosen_op}"

    # ── 2. Fix var field ───────────────────────────────────────────────────
    # Candidates = ALL fields for this resource across ALL ops in the service.
    # for_each iterates resource instances; var can reference any enriched field
    # (e.g. list_buckets iterates, but kms_key_id comes from get_bucket enrichment).
    # IMPORTANT: restrict to THIS resource's fields only — do not cross-contaminate
    # with fields from other resources that happen to share an op.
    resource_entry = resource_idx.get(service, {}).get(resource, {})
    all_resource_fields = resource_entry.get("fields", set())

    # Also include fields from the chosen op that belong to this resource
    fields_from_op = {f for f in op_fields.get(service, {}).get(chosen_op, set())
                      if f.startswith(f"{resource}.") or f == resource}
    candidate_fields = all_resource_fields | fields_from_op

    if candidate_fields:
        best = best_field_for_check(check_name, candidate_fields, resource)
        new_var = f"item.{best}"
        bare_field = best.split(".", 1)[1] if "." in best else best
        op_val, val = _condition_for_field(bare_field, check_name)
    else:
        # Service not in catalog or no fields — keep original or fallback
        orig_var = cond.get("var", f"item.{resource}.status") if isinstance(cond, dict) else f"item.{resource}.status"
        new_var  = orig_var if orig_var else f"item.{resource}.status"
        op_val   = cond.get("op", "exists") if isinstance(cond, dict) else "exists"
        val      = cond.get("value", None)  if isinstance(cond, dict) else None

    return {
        "rule_id":   rule_id,
        "for_each":  new_for_each,
        "conditions": {
            "var":   new_var,
            "op":    op_val,
            "value": val,
        },
    }


# ── Process one service YAML ──────────────────────────────────────────────────
def process_service(
    svc_dir: Path,
    resource_idx,
    op_fields,
    catalog_services: set,
) -> tuple[int, int, int]:
    service     = svc_dir.name
    checks_yaml = svc_dir / f"{service}.checks.yaml"
    if not checks_yaml.exists():
        return 0, 0, 0

    data = yaml.safe_load(checks_yaml.read_text()) or {}
    checks = data.get("checks", [])
    if not checks:
        return 0, 0, 0

    fixed = []
    changed = 0
    for chk in checks:
        orig_fe  = chk.get("for_each", "")
        orig_var = (chk.get("conditions") or {}).get("var", "")
        new_chk  = fix_check(chk, service, resource_idx, op_fields, catalog_services)
        if new_chk["for_each"] != orig_fe or new_chk["conditions"]["var"] != orig_var:
            changed += 1
        fixed.append(new_chk)

    out = {
        "version":  "1.0",
        "provider": "oci",
        "service":  service,
        "checks":   fixed,
    }

    # Dump with correct format
    yaml_str = yaml.dump(
        out,
        Dumper=_NoAliasDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    checks_yaml.write_text(yaml_str)
    return len(checks), changed, 1


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("Building catalog index...")
    resource_idx, op_fields = build_catalog_index(MASTER_CSV)
    catalog_services = set(resource_idx.keys())
    print(f"  {len(catalog_services)} services in catalog")

    svc_dirs = sorted(d for d in BASE_RULES.iterdir() if d.is_dir())
    print(f"  {len(svc_dirs)} service rule check dirs\n")

    total_checks = 0
    total_changed = 0
    total_files = 0

    for svc_dir in svc_dirs:
        n_checks, n_changed, n_files = process_service(
            svc_dir, resource_idx, op_fields, catalog_services
        )
        if n_files:
            total_checks  += n_checks
            total_changed += n_changed
            total_files   += n_files
            status = "✓" if n_changed == 0 else f"~{n_changed} fixed"
            in_cat = "✓" if svc_dir.name in catalog_services else "NOT IN CATALOG"
            print(f"  [{svc_dir.name}] {n_checks} checks  {status}  {in_cat}")

    print(f"\n{'='*65}")
    print(f"DONE")
    print(f"  Files processed : {total_files}")
    print(f"  Total checks    : {total_checks}")
    print(f"  Checks fixed    : {total_changed}")
    print(f"{'='*65}")


if __name__ == "__main__":
    main()
