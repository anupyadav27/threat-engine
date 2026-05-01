#!/usr/bin/env python3
"""
Generate OCI rule-check and metadata YAMLs from the legacy backup.

Field/for_each resolution priority:
  1. OCI step4_fields_produced_index.json  (items[].field → preferred list-op)
     → for_each: oci.{service}.{preferred_op}  var: item.{field}
  2. Backup rules/*.yaml discovery vars (resource_type → list-discovery → vars)
     → for_each: oci.{service}.{list_discovery_id}  var: item.{var}
  3. Generic fallback (status / ocid existence)

Output:
  catalog/rule/oci_rule_check/{service}/{service}.checks.yaml
  catalog/rule/oci_rule_metadata/{service}/{rule_id}.yaml
"""

from __future__ import annotations
import json, re, yaml
from collections import defaultdict
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE        = Path("/Users/apple/Desktop/threat-engine")
BACKUP_ROOT = BASE / "cspm-lgtech/engine_input/engine_check_oci/input/rule_db/default/services"
STEP4_ROOT  = BASE / "catalog/python_field_generator/oci"
CHECK_OUT   = BASE / "catalog/rule/oci_rule_check"
META_OUT    = BASE / "catalog/rule/oci_rule_metadata"

# ── Generic fields to skip when looking for security-relevant fields ───────────
GENERIC_FIELDS = {"compartment_id", "defined_tags", "freeform_tags", "name",
                  "ocid", "status", "time_created", "namespace"}

# ── Domain → provider_category ─────────────────────────────────────────────────
DOMAIN_MAP = {
    "identity_and_access_management":       "identity_and_access_management",
    "data_protection_and_privacy":          "data_protection",
    "network_security_and_connectivity":    "network_security",
    "logging_and_monitoring":               "logging_and_monitoring",
    "configuration_and_change_management":  "configuration_management",
    "compute_host_security":                "compute_host_security",
    "software_security":                    "software_security",
    "supply_chain_security":                "supply_chain_security",
    "incident_response":                    "incident_response",
    "encryption_and_key_management":        "encryption_and_key_management",
    "backup_and_recovery":                  "backup_and_recovery",
    "storage_and_database_security":        "storage_and_database_security",
}

# ── YAML helpers ───────────────────────────────────────────────────────────────
def _none_repr(dumper, _):
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")
yaml.add_representer(type(None), _none_repr)

def resource_class(resource: str) -> str:
    return "".join(w.title() for w in resource.split("_"))


# ══════════════════════════════════════════════════════════════════════════════
# Index builders
# ══════════════════════════════════════════════════════════════════════════════

def build_step4_index(service: str) -> dict[str, str]:
    """
    Return {field_name: preferred_list_op} from step4_fields_produced_index.json.
    Only includes items[].* fields (i.e. produced by list operations).
    """
    path = STEP4_ROOT / service / "step4_fields_produced_index.json"
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    index: dict[str, str] = {}
    for field_path, info in data.get("fields", {}).items():
        if not field_path.startswith("items[]."):
            continue
        field_name = field_path[len("items[]."):]
        preferred_op = info.get("preferred", {}).get("op", "")
        if preferred_op:
            index[field_name] = preferred_op
    return index


def build_backup_resource_index(service: str) -> dict[str, dict[str, list[str]]]:
    """
    Return {resource_type: {discovery_id: [var, …]}} from backup rules/*.yaml.
    Separates list_* from get_* so we can prefer list discoveries.
    """
    rules_dir = BACKUP_ROOT / service / "rules"
    if not rules_dir.exists():
        return {}

    result: dict[str, dict] = defaultdict(lambda: defaultdict(list))
    for rules_file in rules_dir.glob("*.yaml"):
        raw = yaml.safe_load(rules_file.read_text()) or {}
        for top_val in raw.values():
            if not isinstance(top_val, dict):
                continue
            for disc in top_val.get("discovery", []):
                disc_id  = disc.get("discovery_id", "")
                res_type = disc.get("resource_type", "")
                if not disc_id or not res_type:
                    continue
                vars_list = [
                    f.get("var", "")
                    for call in disc.get("calls", [])
                    for f in call.get("fields", [])
                    if f.get("var")
                ]
                result[res_type][disc_id] = vars_list

    return {rt: dict(discs) for rt, discs in result.items()}


# ══════════════════════════════════════════════════════════════════════════════
# for_each resolution
# ══════════════════════════════════════════════════════════════════════════════

def _list_discoveries(disc_map: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return only list_* (independent) discoveries from a resource's disc_map."""
    return {did: vars_ for did, vars_ in disc_map.items()
            if did.startswith("list_")}


def best_list_op_for_resource(
        service: str,
        resource_type: str,
        backup_index: dict[str, dict[str, list[str]]],
) -> tuple[str, list[str]]:
    """
    Pick the best list_* discovery for (service, resource_type) from backup index.
    Returns (discovery_id, [vars]).
    """
    res_discs = backup_index.get(resource_type, {})
    list_discs = _list_discoveries(res_discs)

    if list_discs:
        # Prefer the one whose name most closely matches the resource_type
        def score(did: str) -> int:
            norm = resource_type.replace("_", "")
            return norm in did.replace("_", "")
        best = max(list_discs, key=score)
        return best, list_discs[best]

    # Try fuzzy match: find any resource type that overlaps
    res_norm = resource_type.replace("_", "").lower()
    for rt, discs in backup_index.items():
        if res_norm in rt.replace("_", "").lower() or rt.replace("_", "").lower() in res_norm:
            list_d = _list_discoveries(discs)
            if list_d:
                best = max(list_d, key=lambda d: len(d))
                return best, list_d[best]

    # Ultimate fallback
    return f"list_{resource_type}s", []


# ══════════════════════════════════════════════════════════════════════════════
# Condition derivation
# ══════════════════════════════════════════════════════════════════════════════

# Security keyword groups for semantic matching
_BOOL_TRUE_TOKENS  = {"enabled", "activated", "protected", "active", "immutable",
                       "required", "enforced", "configured", "attached"}
_BOOL_FALSE_TOKENS = {"disabled", "deactivated", "unrestricted"}
_EXISTS_TOKENS     = {"exists", "set", "defined", "assigned", "registered",
                       "present", "established"}
_ENCRYPTED_TOKENS  = {"encrypted", "encryption", "cmek", "kms", "cmk", "vault",
                       "key_id", "managed"}
_RESTRICTED_TOKENS = {"restricted", "private", "private_endpoint", "isolated",
                       "no_public", "blocked", "selected", "allowlisted",
                       "whitelisted", "vcn"}
_LOGGING_TOKENS    = {"logging", "audit", "auditing", "log", "cloudwatch",
                       "monitoring", "events"}
_BACKUP_TOKENS     = {"backup", "recovery", "snapshot", "retention", "worm"}
_ROTATION_TOKENS   = {"rotated", "rotation", "rotate", "expiry", "expire", "age"}
_TAG_TOKENS        = {"tag", "tagged", "tags"}
_PUBLIC_TOKENS     = {"public"}
_MFA_TOKENS        = {"mfa", "2fa", "multi_factor", "totp"}


def _token_overlap(tokens_a: set[str], tokens_b: set[str]) -> int:
    return len(tokens_a & tokens_b)


def _best_var_for_tokens(check_tokens: set[str], vars_list: list[str]) -> str | None:
    """Find the var whose name has the highest token overlap with check_tokens."""
    if not vars_list:
        return None
    scored = []
    for v in vars_list:
        v_tokens = set(v.lower().split("_"))
        scored.append((_token_overlap(check_tokens, v_tokens), v))
    scored.sort(key=lambda x: -x[0])
    best_score, best_var = scored[0]
    return best_var if best_score > 0 else None


def derive_condition(check_name: str, available_vars: list[str]) -> dict:
    """
    Build a condition dict given the check name and available vars from
    the chosen discovery.
    """
    tokens = set(check_name.lower().split("_"))

    # ── MFA ───────────────────────────────────────────────────────────────────
    if tokens & _MFA_TOKENS:
        v = _best_var_for_tokens(tokens | _MFA_TOKENS, available_vars)
        field = f"item.{v}" if v else "item.is_mfa_activated"
        return {"var": field, "op": "equals", "value": True}

    # ── Encryption / KMS / CMEK ───────────────────────────────────────────────
    if tokens & _ENCRYPTED_TOKENS:
        v = _best_var_for_tokens(tokens | _ENCRYPTED_TOKENS, available_vars)
        field = f"item.{v}" if v else "item.kms_key_id"
        return {"var": field, "op": "exists", "value": None}

    # ── Public access ─────────────────────────────────────────────────────────
    if tokens & _PUBLIC_TOKENS:
        v = _best_var_for_tokens({"public"}, available_vars)
        if v:
            if "type" in v.lower():
                return {"var": f"item.{v}", "op": "not_equals", "value": "ObjectRead"}
            return {"var": f"item.{v}", "op": "equals", "value": False}
        return {"var": "item.public_access_type", "op": "not_equals", "value": "ObjectRead"}

    # ── Restricted / private / VCN ───────────────────────────────────────────
    if tokens & _RESTRICTED_TOKENS:
        v = _best_var_for_tokens(tokens | _RESTRICTED_TOKENS, available_vars)
        if v:
            return {"var": f"item.{v}", "op": "not_empty", "value": None}
        return {"var": "item", "op": "exists", "value": None}

    # ── Backup / recovery / retention / WORM ─────────────────────────────────
    if tokens & _BACKUP_TOKENS:
        v = _best_var_for_tokens(tokens | _BACKUP_TOKENS, available_vars)
        if v:
            if "config" in v.lower() or "policy" in v.lower():
                return {"var": f"item.{v}", "op": "exists", "value": None}
            if "days" in v.lower() or "period" in v.lower():
                return {"var": f"item.{v}", "op": "gte", "value": 90}
            return {"var": f"item.{v}", "op": "equals", "value": True}
        return {"var": "item.db_backup_config", "op": "exists", "value": None}

    # ── Logging / audit / monitoring ──────────────────────────────────────────
    if tokens & _LOGGING_TOKENS:
        v = _best_var_for_tokens(tokens | _LOGGING_TOKENS, available_vars)
        field = f"item.{v}" if v else "item.audit_config"
        return {"var": field, "op": "exists", "value": None}

    # ── Rotation / expiry ─────────────────────────────────────────────────────
    if tokens & _ROTATION_TOKENS:
        v = _best_var_for_tokens(tokens | _ROTATION_TOKENS, available_vars)
        field = f"item.{v}" if v else "item.time_created"
        return {"var": field, "op": "exists", "value": None}

    # ── Tags ──────────────────────────────────────────────────────────────────
    if tokens & _TAG_TOKENS:
        return {"var": "item.freeform_tags", "op": "not_empty", "value": None}

    # ── Boolean-true (enabled, active, …) ────────────────────────────────────
    if tokens & _BOOL_TRUE_TOKENS:
        v = _best_var_for_tokens(tokens, available_vars)
        if v:
            return {"var": f"item.{v}", "op": "equals", "value": True}
        # Try constructed name: is_<check_name>
        guesses = [f"is_{check_name}", check_name]
        for g in guesses:
            if g in available_vars:
                return {"var": f"item.{g}", "op": "equals", "value": True}
        return {"var": "item.status", "op": "equals", "value": "ACTIVE"}

    # ── Boolean-false (disabled, …) ───────────────────────────────────────────
    if tokens & _BOOL_FALSE_TOKENS:
        v = _best_var_for_tokens(tokens, available_vars)
        field = f"item.{v}" if v else "item.status"
        return {"var": field, "op": "equals", "value": False}

    # ── Exists / configured / attached ────────────────────────────────────────
    if tokens & _EXISTS_TOKENS:
        v = _best_var_for_tokens(tokens, available_vars)
        field = f"item.{v}" if v else "item.status"
        return {"var": field, "op": "exists", "value": None}

    # ── Token-overlap fallback ────────────────────────────────────────────────
    v = _best_var_for_tokens(tokens, available_vars)
    if v and v not in GENERIC_FIELDS:
        return {"var": f"item.{v}", "op": "exists", "value": None}

    # ── Generic final fallback ────────────────────────────────────────────────
    return {"var": "item.status", "op": "exists", "value": None}


# ══════════════════════════════════════════════════════════════════════════════
# Main resolution per rule
# ══════════════════════════════════════════════════════════════════════════════

def resolve_check(
        rule_id:      str,
        service:      str,
        resource:     str,
        check_name:   str,
        step4_index:  dict[str, str],          # field → preferred_list_op
        backup_index: dict[str, dict[str, list[str]]],  # resource→disc_id→vars
) -> tuple[str, dict]:
    """
    Returns (for_each, condition_dict).

    Priority:
      1. step4 has a security field that matches check_name → use it
      2. backup list discovery vars for the resource → use them
      3. generic status/exists fallback
    """
    check_tokens = set(check_name.lower().split("_"))

    # ── Priority 1: step4 field match ────────────────────────────────────────
    # Only non-generic fields are interesting
    security_fields = {f: op for f, op in step4_index.items()
                       if f not in GENERIC_FIELDS}
    if security_fields:
        # Score each security field by token overlap with check_name
        scored = []
        for field, op in security_fields.items():
            f_tokens = set(field.lower().split("_"))
            overlap = _token_overlap(check_tokens, f_tokens)
            scored.append((overlap, field, op))
        scored.sort(key=lambda x: -x[0])
        best_overlap, best_field, best_op = scored[0]
        if best_overlap >= 1:
            for_each  = f"oci.{service}.{best_op}"
            condition = derive_condition(check_name, list(security_fields.keys()))
            return for_each, condition

    # ── Priority 2: backup vars ───────────────────────────────────────────────
    list_disc_id, list_vars = best_list_op_for_resource(service, resource, backup_index)
    # Exclude generic vars from condition derivation (keep security-specific ones)
    sec_vars = [v for v in list_vars if v not in GENERIC_FIELDS] or list_vars
    for_each  = f"oci.{service}.{list_disc_id}"
    condition = derive_condition(check_name, sec_vars)
    return for_each, condition


# ══════════════════════════════════════════════════════════════════════════════
# Metadata builder
# ══════════════════════════════════════════════════════════════════════════════

def build_metadata(raw: dict) -> dict:
    domain      = raw.get("domain", "")
    subcategory = raw.get("subcategory", "")
    service     = raw.get("service", "")
    resource    = raw.get("resource", "")
    rule_id     = raw.get("rule_id", "")
    check_name  = rule_id.split(".")[-1] if rule_id else ""
    prov_cat    = DOMAIN_MAP.get(domain, subcategory or domain)
    return {
        "assertion_id":      f"{subcategory}.{check_name}" if subcategory else check_name,
        "domain":            domain,
        "program":           f"{service}.security.{resource}.{check_name}",
        "provider_category": prov_cat,
        "resource_class":    resource_class(resource),
        "rule_id":           rule_id,
        "scope":             raw.get("scope", f"{service}.{resource}"),
        "severity":          raw.get("severity", "medium"),
        "source":            "compliance_database",
        "title":             raw.get("title", ""),
        "description":       raw.get("description", ""),
        "rationale":         raw.get("rationale", ""),
        "references":        raw.get("references", []),
        "requirement":       raw.get("requirement", ""),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    services = sorted(p.name for p in BACKUP_ROOT.iterdir() if p.is_dir())
    print(f"Processing {len(services)} OCI services\n")

    total_checks = total_meta = 0
    skipped: list[tuple[str, str, str]] = []
    step4_hits = step4_misses = 0

    for service in services:
        meta_dir = BACKUP_ROOT / service / "metadata"
        if not meta_dir.exists() or not any(meta_dir.glob("*.yaml")):
            print(f"  [{service}] SKIP — no metadata")
            continue

        # Build lookup indexes
        step4_idx    = build_step4_index(service)
        backup_idx   = build_backup_resource_index(service)
        sec_fields   = {f for f in step4_idx if f not in GENERIC_FIELDS}

        meta_files = sorted(meta_dir.glob("*.yaml"))
        all_checks: list[dict] = []
        all_meta:   list[tuple[str, dict]] = []

        for mf in meta_files:
            raw = yaml.safe_load(mf.read_text()) or {}
            rule_id    = raw.get("rule_id", "")
            resource   = raw.get("resource", "")
            check_name = rule_id.split(".")[-1] if rule_id else ""

            if not rule_id or not resource:
                skipped.append((service, mf.name, "missing rule_id or resource"))
                continue

            for_each, condition = resolve_check(
                rule_id, service, resource, check_name,
                step4_idx, backup_idx,
            )

            # Track step4 vs fallback
            if sec_fields and any(
                f in condition.get("var", "") for f in sec_fields
            ):
                step4_hits += 1
            else:
                step4_misses += 1

            all_checks.append({
                "rule_id":    rule_id,
                "for_each":   for_each,
                "conditions": condition,
            })
            all_meta.append((rule_id, build_metadata(raw)))

        # ── Write checks YAML ────────────────────────────────────────────────
        out_check = CHECK_OUT / service
        out_check.mkdir(parents=True, exist_ok=True)
        doc = {"version": "1.0", "provider": "oci",
               "service": service, "checks": all_checks}
        (out_check / f"{service}.checks.yaml").write_text(
            yaml.dump(doc, default_flow_style=False,
                      sort_keys=False, allow_unicode=True)
        )
        total_checks += len(all_checks)

        # ── Write metadata YAMLs ─────────────────────────────────────────────
        out_meta = META_OUT / service
        out_meta.mkdir(parents=True, exist_ok=True)
        for rule_id, meta_entry in all_meta:
            (out_meta / f"{rule_id}.yaml").write_text(
                yaml.dump(meta_entry, default_flow_style=False,
                          sort_keys=False, allow_unicode=True)
            )
        total_meta += len(all_meta)

        print(f"  [{service}] {len(all_checks)} checks, "
              f"{len(sec_fields)} step4-security-fields available")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("OCI RULE GENERATION COMPLETE")
    print("=" * 70)
    print(f"  Services processed      : {len(services)}")
    print(f"  Check entries written   : {total_checks}")
    print(f"  Metadata files written  : {total_meta}")
    print(f"  Step4 field hits        : {step4_hits}")
    print(f"  Backup-var fallbacks    : {step4_misses}")

    if skipped:
        print(f"\n  Skipped ({len(skipped)}):")
        for svc, fname, reason in skipped:
            print(f"    [{svc}] {fname} — {reason}")


if __name__ == "__main__":
    main()
