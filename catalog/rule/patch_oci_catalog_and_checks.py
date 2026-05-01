#!/usr/bin/env python3
"""
Two-part patch:

Part 1 — Add real missing OCI SDK ops to catalog source files
  (step2_read_operation_registry.json, adjacency.json, direct_vars.json)
  Services: key_management, mysql, ons, queue, streaming, certificates,
            load_balancer, dns

Part 2 — Fix garbage/wrong ops in rule check YAMLs
  Replace invented ops (list_ebss, list_cis_*, list_passwords, etc.)
  with correct OCI SDK ops, then re-run fix_oci_rule_checks.py logic.
"""

from __future__ import annotations
import json, re, yaml
from pathlib import Path

BASE_DISC  = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
BASE_RULES = Path("/Users/apple/Desktop/threat-engine/catalog/rule/oci_rule_check")

# ── YAML dumper ────────────────────────────────────────────────────────────────
def _none_repr(dumper, _):
    return dumper.represent_scalar("tag:yaml.org,2002:null", "null")

class _Dumper(yaml.Dumper):
    def ignore_aliases(self, _): return True

_Dumper.add_representer(type(None), _none_repr)


# ═══════════════════════════════════════════════════════════════════════════════
# PART 1 — Catalog source file patches
# ═══════════════════════════════════════════════════════════════════════════════

def _std_output_fields(service: str, resource: str, extra: dict | None = None) -> dict:
    """Standard output_fields block for a list_ op."""
    fields = {
        "ocid":         {"type": "string", "path": f"_{resource}s[].id",
                         "entity": "oci.ocid"},
        "compartment_id": {"type": "string", "path": f"_{resource}s[].compartment_id",
                           "entity": "oci.compartment_id"},
        "name":         {"type": "string", "path": f"_{resource}s[].display_name",
                         "entity": f"oci.{service}.{resource}.name"},
        "status":       {"type": "string", "path": f"_{resource}s[].lifecycle_state",
                         "entity": f"oci.{service}.{resource}.status"},
        "time_created": {"type": "string", "path": f"_{resource}s[].time_created",
                         "entity": f"oci.{service}.{resource}.time_created"},
        "freeform_tags":{"type": "string", "path": f"_{resource}s[].freeform_tags",
                         "entity": f"oci.{service}.{resource}.freeform_tags"},
        "defined_tags": {"type": "string", "path": f"_{resource}s[].defined_tags",
                         "entity": f"oci.{service}.{resource}.defined_tags"},
    }
    if extra:
        fields.update(extra)
    return fields


def _std_op_entry(service: str, op: str, resource: str,
                  extra_fields: dict | None = None) -> dict:
    return {
        "operation":       op,
        "service":         service,
        "csp":             "oci",
        "kind":            "read_list",
        "independent":     False,
        "python_method":   op,
        "yaml_action":     op,
        "required_params": ["compartmentId"],
        "optional_params": [],
        "output_fields":   _std_output_fields(service, resource, extra_fields),
    }


def _std_entities(service: str, resource: str, extra: list | None = None) -> list:
    base = [
        "oci.ocid",
        "oci.compartment_id",
        f"oci.{service}.{resource}.name",
        f"oci.{service}.{resource}.status",
        f"oci.{service}.{resource}.time_created",
        f"oci.{service}.{resource}.freeform_tags",
        f"oci.{service}.{resource}.defined_tags",
    ]
    return base + (extra or [])


def _std_dv_fields(service: str, resource: str,
                   extra: dict | None = None) -> dict:
    fields = {
        f"{resource}.name":         {"type": "string"},
        f"{resource}.status":       {"type": "string"},
        f"{resource}.time_created": {"type": "string"},
        f"{resource}.freeform_tags":{"type": "object"},
        f"{resource}.defined_tags": {"type": "object"},
    }
    if extra:
        fields.update(extra)
    return fields


# ── Per-service patch specs ───────────────────────────────────────────────────

PATCHES: list[dict] = [

    # key_management — add list_keys
    {
        "service":  "key_management",
        "op":       "list_keys",
        "resource": "key",
        "extra_s2": {
            "algorithm":           {"type": "string",
                                    "path": "_keys[].algorithm",
                                    "entity": "oci.key_management.key.algorithm"},
            "current_key_version": {"type": "string",
                                    "path": "_keys[].current_key_version",
                                    "entity": "oci.key_management.key.current_key_version"},
            "protection_mode":     {"type": "string",
                                    "path": "_keys[].protection_mode",
                                    "entity": "oci.key_management.key.protection_mode"},
        },
        "extra_ent": [
            "oci.key_management.key.algorithm",
            "oci.key_management.key.current_key_version",
            "oci.key_management.key.protection_mode",
        ],
        "extra_dv": {
            "key.algorithm":           {"type": "string"},
            "key.current_key_version": {"type": "string"},
            "key.protection_mode":     {"type": "string"},
        },
    },

    # mysql — add list_db_systems
    {
        "service":  "mysql",
        "op":       "list_db_systems",
        "resource": "db_system",
        "extra_s2": {
            "mysql_version":       {"type": "string",
                                    "path": "_db_systems[].mysql_version",
                                    "entity": "oci.mysql.db_system.mysql_version"},
            "is_highly_available": {"type": "boolean",
                                    "path": "_db_systems[].is_highly_available",
                                    "entity": "oci.mysql.db_system.is_highly_available"},
            "backup_policy":       {"type": "object",
                                    "path": "_db_systems[].backup_policy",
                                    "entity": "oci.mysql.db_system.backup_policy"},
            "deletion_policy":     {"type": "object",
                                    "path": "_db_systems[].deletion_policy",
                                    "entity": "oci.mysql.db_system.deletion_policy"},
        },
        "extra_ent": [
            "oci.mysql.db_system.mysql_version",
            "oci.mysql.db_system.is_highly_available",
            "oci.mysql.db_system.backup_policy",
            "oci.mysql.db_system.deletion_policy",
        ],
        "extra_dv": {
            "db_system.mysql_version":       {"type": "string"},
            "db_system.is_highly_available": {"type": "boolean"},
            "db_system.backup_policy":       {"type": "object"},
            "db_system.deletion_policy":     {"type": "object"},
        },
    },

    # ons — add list_topics
    {
        "service":  "ons",
        "op":       "list_topics",
        "resource": "topic",
        "extra_s2": {
            "topic_id": {"type": "string", "path": "_topics[].topic_id",
                         "entity": "oci.ons.topic.topic_id"},
        },
        "extra_ent": ["oci.ons.topic.topic_id"],
        "extra_dv":  {"topic.topic_id": {"type": "string"}},
    },

    # queue — add list_queues
    {
        "service":  "queue",
        "op":       "list_queues",
        "resource": "queue",
        "extra_s2": {
            "dead_letter_queue_delivery_count": {
                "type": "integer",
                "path": "_queues[].dead_letter_queue_delivery_count",
                "entity": "oci.queue.queue.dead_letter_queue_delivery_count",
            },
            "visibility_in_seconds": {
                "type": "integer",
                "path": "_queues[].visibility_in_seconds",
                "entity": "oci.queue.queue.visibility_in_seconds",
            },
        },
        "extra_ent": [
            "oci.queue.queue.dead_letter_queue_delivery_count",
            "oci.queue.queue.visibility_in_seconds",
        ],
        "extra_dv": {
            "queue.dead_letter_queue_delivery_count": {"type": "integer"},
            "queue.visibility_in_seconds":            {"type": "integer"},
        },
    },

    # streaming — add list_streams
    {
        "service":  "streaming",
        "op":       "list_streams",
        "resource": "stream",
        "extra_s2": {
            "partitions":          {"type": "integer",
                                    "path": "_streams[].partitions",
                                    "entity": "oci.streaming.stream.partitions"},
            "retention_in_hours":  {"type": "integer",
                                    "path": "_streams[].retention_in_hours",
                                    "entity": "oci.streaming.stream.retention_in_hours"},
        },
        "extra_ent": [
            "oci.streaming.stream.partitions",
            "oci.streaming.stream.retention_in_hours",
        ],
        "extra_dv": {
            "stream.partitions":         {"type": "integer"},
            "stream.retention_in_hours": {"type": "integer"},
        },
    },

    # certificates — add list_certificates
    {
        "service":  "certificates",
        "op":       "list_certificates",
        "resource": "certificate",
        "extra_s2": {
            "time_of_expiry": {"type": "string",
                               "path": "_certificates[].time_of_expiry",
                               "entity": "oci.certificates.certificate.time_of_expiry"},
            "issuer_ca_id":   {"type": "string",
                               "path": "_certificates[].issuer_ca_id",
                               "entity": "oci.certificates.certificate.issuer_ca_id"},
        },
        "extra_ent": [
            "oci.certificates.certificate.time_of_expiry",
            "oci.certificates.certificate.issuer_ca_id",
        ],
        "extra_dv": {
            "certificate.time_of_expiry": {"type": "string"},
            "certificate.issuer_ca_id":   {"type": "string"},
        },
    },

    # certificates — add list_certificate_authorities
    {
        "service":  "certificates",
        "op":       "list_certificate_authorities",
        "resource": "certificate_authority",
        "extra_s2": {
            "time_of_expiry":        {"type": "string",
                                      "path": "_certificate_authorities[].time_of_expiry",
                                      "entity": "oci.certificates.certificate_authority.time_of_expiry"},
            "config_type":           {"type": "string",
                                      "path": "_certificate_authorities[].config_type",
                                      "entity": "oci.certificates.certificate_authority.config_type"},
        },
        "extra_ent": [
            "oci.certificates.certificate_authority.time_of_expiry",
            "oci.certificates.certificate_authority.config_type",
        ],
        "extra_dv": {
            "certificate_authority.time_of_expiry": {"type": "string"},
            "certificate_authority.config_type":    {"type": "string"},
        },
    },

    # load_balancer — add list_load_balancers
    {
        "service":  "load_balancer",
        "op":       "list_load_balancers",
        "resource": "load_balancer",
        "extra_s2": {
            "ip_addresses":          {"type": "array",
                                      "path": "_load_balancers[].ip_addresses",
                                      "entity": "oci.load_balancer.load_balancer.ip_addresses"},
            "is_private":            {"type": "boolean",
                                      "path": "_load_balancers[].is_private",
                                      "entity": "oci.load_balancer.load_balancer.is_private"},
            "shape_name":            {"type": "string",
                                      "path": "_load_balancers[].shape_name",
                                      "entity": "oci.load_balancer.load_balancer.shape_name"},
        },
        "extra_ent": [
            "oci.load_balancer.load_balancer.ip_addresses",
            "oci.load_balancer.load_balancer.is_private",
            "oci.load_balancer.load_balancer.shape_name",
        ],
        "extra_dv": {
            "load_balancer.ip_addresses": {"type": "array"},
            "load_balancer.is_private":   {"type": "boolean"},
            "load_balancer.shape_name":   {"type": "string"},
        },
    },

    # dns — add list_zones (list_records needs zone_id, use list_zones as independent)
    {
        "service":  "dns",
        "op":       "list_zones",
        "resource": "zone",
        "extra_s2": {
            "zone_type":    {"type": "string",
                             "path": "_zones[].zone_type",
                             "entity": "oci.dns.zone.zone_type"},
            "is_protected": {"type": "boolean",
                             "path": "_zones[].is_protected",
                             "entity": "oci.dns.zone.is_protected"},
        },
        "extra_ent": [
            "oci.dns.zone.zone_type",
            "oci.dns.zone.is_protected",
        ],
        "extra_dv": {
            "zone.zone_type":    {"type": "string"},
            "zone.is_protected": {"type": "boolean"},
        },
    },

    # dns — add list_records (needs zone_id, so it's a 2-hop op)
    {
        "service":  "dns",
        "op":       "list_records",
        "resource": "record",
        "required_params": ["zoneNameOrId"],  # override — needs zone
        "extra_s2": {
            "rtype":       {"type": "string", "path": "_records[].rtype",
                            "entity": "oci.dns.record.rtype"},
            "rdata":       {"type": "string", "path": "_records[].rdata",
                            "entity": "oci.dns.record.rdata"},
            "domain":      {"type": "string", "path": "_records[].domain",
                            "entity": "oci.dns.record.domain"},
        },
        "extra_ent": [
            "oci.dns.record.rtype",
            "oci.dns.record.rdata",
            "oci.dns.record.domain",
        ],
        "extra_dv": {
            "record.rtype":  {"type": "string"},
            "record.rdata":  {"type": "string"},
            "record.domain": {"type": "string"},
        },
    },
]


def patch_catalog(patch: dict) -> None:
    service  = patch["service"]
    op       = patch["op"]
    resource = patch["resource"]
    svc_dir  = BASE_DISC / service

    req_params = patch.get("required_params", ["compartmentId"])

    # ── step2_read_operation_registry.json ─────────────────────────────────
    step2_path = svc_dir / "step2_read_operation_registry.json"
    step2 = json.loads(step2_path.read_text()) if step2_path.exists() else {"operations": {}}
    ops = step2.setdefault("operations", {})

    if op not in ops:
        entry = _std_op_entry(service, op, resource, patch.get("extra_s2"))
        entry["required_params"] = req_params
        ops[op] = entry
        step2_path.write_text(json.dumps(step2, indent=2))
        print(f"    step2: added {op}")
    else:
        print(f"    step2: {op} already present")

    # ── adjacency.json ──────────────────────────────────────────────────────
    adj_path = svc_dir / "adjacency.json"
    adj = json.loads(adj_path.read_text()) if adj_path.exists() else {}
    op_prod = adj.setdefault("op_produces", {})
    op_cons = adj.setdefault("op_consumes", {})

    if op not in op_prod:
        op_prod[op] = _std_entities(service, resource, patch.get("extra_ent"))
        # consumes: compartment for independent ops, zone for list_records
        if req_params == ["compartmentId"]:
            op_cons[op] = ["oci.compartment_id"]
        else:
            rp_snake = [re.sub(r'(?<!^)(?=[A-Z])', '_', p).lower() for p in req_params]
            op_cons[op] = [f"oci.{service}.{p}" for p in rp_snake]
        adj_path.write_text(json.dumps(adj, indent=2))
        print(f"    adj:   added {op}")
    else:
        print(f"    adj:   {op} already present")

    # ── direct_vars.json ────────────────────────────────────────────────────
    dv_path = svc_dir / "direct_vars.json"
    dv = json.loads(dv_path.read_text()) if dv_path.exists() else {"service": service, "fields": {}}
    dv_fields = dv.setdefault("fields", {})

    new_fields = _std_dv_fields(service, resource, patch.get("extra_dv"))
    added = 0
    for fname, finfo in new_fields.items():
        if fname not in dv_fields:
            dv_fields[fname] = finfo
            added += 1
    if added:
        dv_path.write_text(json.dumps(dv, indent=2))
        print(f"    dv:    added {added} fields for resource '{resource}'")
    else:
        print(f"    dv:    fields already present")


# ═══════════════════════════════════════════════════════════════════════════════
# PART 2 — Fix garbage ops in rule check YAMLs
# ═══════════════════════════════════════════════════════════════════════════════

# Map: service → { bad_op → good_op }
# good_op must be a valid OCI SDK operation (existing or newly added)
OP_FIXES: dict[str, dict[str, str]] = {
    "certificates": {
        "list_certificatess":          "list_certificates",      # double-s typo
        "list_certificate_authoritys": "list_certificate_authorities",
    },
    "compute": {
        "list_cis_3_1_1_needs_developments": "list_instances",
        "list_cis_3_2_11_needs_developments": "list_instances",
        "list_ebss":                  "list_volumes",            # EBS = OCI block volume
        "list_managements":           "list_instances",
        "list_networkacls":           "list_security_lists",     # OCI equiv of network ACLs
    },
    "container_engine": {
        "list_cis_2_3_2_needs_developments":         "list_clusters",
        "list_cis_3_2_10_needs_developments":        "list_clusters",
        "list_cis_3_2_2_needs_developments":         "list_clusters",
        "list_cis_5_4_4_needs_developments":         "list_clusters",
        "list_k8s_apiserver_admission_psa_enforce_modes": "list_clusters",
        "list_k8s_apiserver_tls_min_version_1_2s":   "list_clusters",
        "list_k8s_rbac_wildcard_verbs_disalloweds":  "list_clusters",
    },
    "database": {
        "list_clusters":  "list_autonomous_container_databases",
        "list_instances": "list_db_nodes",
    },
    "identity": {
        "list_passwords": "list_users",
    },
    "load_balancer": {
        "list_balancers": "list_load_balancers",
        "list_listeners": "list_load_balancers",     # listeners need lb_id; use list_load_balancers
    },
    "monitoring": {
        "list_logs": "list_alarms",
    },
    "object_storage": {
        "list_storages": "list_buckets",
    },
    "dns": {
        "list_records": "list_zones",     # list_records needs zone_id; use list_zones as independent
    },
}

# Also fix var fields when the resource changes (e.g. ebs→volume, record→zone)
RESOURCE_REMAP: dict[str, dict[str, str]] = {
    "compute": {
        "ebs":                   "volume",
        "management":            "instance",
        "networkacl":            "security_list",
        "cis_3_1_1_needs_development": "instance",
        "cis_3_2_11_needs_development": "instance",
    },
    "container_engine": {
        "cis_2_3_2_needs_development": "cluster",
        "cis_3_2_10_needs_development": "cluster",
        "cis_3_2_2_needs_development": "cluster",
        "cis_5_4_4_needs_development": "cluster",
        "k8s_apiserver_admission_psa_enforce_mode": "cluster",
        "k8s_apiserver_tls_min_version_1_2": "cluster",
        "k8s_rbac_wildcard_verbs_disallowed": "cluster",
    },
    "database": {
        "cluster":  "autonomous_container_database",
        "instance": "db_node",
    },
    "identity": {
        "password": "user",
    },
    "load_balancer": {
        "balancer": "load_balancer",
        "listener": "load_balancer",
    },
    "monitoring": {
        "log": "alarm",
    },
    "object_storage": {
        "storage": "bucket",
    },
    "dns": {
        "record": "zone",
    },
}


def fix_rule_checks() -> int:
    total_fixed = 0
    for svc_dir in sorted(BASE_RULES.iterdir()):
        if not svc_dir.is_dir(): continue
        service = svc_dir.name
        if service not in OP_FIXES:
            continue
        checks_yaml = svc_dir / f"{service}.checks.yaml"
        if not checks_yaml.exists():
            continue

        data = yaml.safe_load(checks_yaml.read_text()) or {}
        checks = data.get("checks", [])
        fixed = 0

        op_map  = OP_FIXES[service]
        res_map = RESOURCE_REMAP.get(service, {})

        new_checks = []
        for chk in checks:
            fe_op = chk.get("for_each", "").split(".")[-1]
            if fe_op in op_map:
                good_op = op_map[fe_op]
                chk["for_each"] = f"oci.{service}.{good_op}"

                # Fix the var field if resource changed
                cond = chk.get("conditions", {}) or {}
                var  = cond.get("var", "")
                # Extract old resource from rule_id: oci.svc.old_resource.check
                parts = chk.get("rule_id", "").split(".")
                old_resource = parts[2] if len(parts) > 2 else ""
                new_resource = res_map.get(old_resource, "")
                if new_resource and var.startswith(f"item.{old_resource}."):
                    cond["var"] = var.replace(
                        f"item.{old_resource}.", f"item.{new_resource}."
                    )
                    chk["conditions"] = cond
                fixed += 1
            new_checks.append(chk)

        if fixed:
            data["checks"] = new_checks
            yaml_str = yaml.dump(data, Dumper=_Dumper, default_flow_style=False,
                                  sort_keys=False, allow_unicode=True)
            checks_yaml.write_text(yaml_str)
            print(f"  [{service}] fixed {fixed} garbage ops")
            total_fixed += fixed

    return total_fixed


# ═══════════════════════════════════════════════════════════════════════════════
# PART 3 — Regenerate CSVs and master catalog
# ═══════════════════════════════════════════════════════════════════════════════

def regenerate_catalogs() -> None:
    """Re-run both CSV generators for affected services."""
    import subprocess, sys
    gen_csv    = BASE_DISC / "generate_oci_field_csv.py"
    gen_master = BASE_DISC / "generate_oci_master_catalog.py"

    print("\nRegenerating field CSVs...")
    r1 = subprocess.run([sys.executable, str(gen_csv)], capture_output=True, text=True)
    if r1.returncode != 0:
        print("  ERROR:", r1.stderr[-300:])
    else:
        lines = [l for l in r1.stdout.splitlines() if "DONE" in l or "field rows" in l.lower()]
        print("  " + (lines[-1] if lines else "done"))

    print("Regenerating master catalog...")
    r2 = subprocess.run([sys.executable, str(gen_master)], capture_output=True, text=True)
    if r2.returncode != 0:
        print("  ERROR:", r2.stderr[-300:])
    else:
        for line in r2.stdout.splitlines():
            if any(x in line for x in ["DONE", "Total", "Services", "Independent", "Chain"]):
                print("  " + line.strip())


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    print("=" * 65)
    print("PART 1 — Patching catalog source files")
    print("=" * 65)
    for patch in PATCHES:
        print(f"\n[{patch['service']}] {patch['op']}")
        patch_catalog(patch)

    print("\n" + "=" * 65)
    print("PART 2 — Fixing garbage ops in rule check YAMLs")
    print("=" * 65)
    total = fix_rule_checks()
    print(f"\n  Total garbage ops fixed: {total}")

    print("\n" + "=" * 65)
    print("PART 3 — Regenerating catalogs")
    print("=" * 65)
    regenerate_catalogs()

    print("\n" + "=" * 65)
    print("PART 4 — Re-running rule check fixer with updated catalog")
    print("=" * 65)
    import subprocess, sys
    fixer = BASE_RULES.parent / "fix_oci_rule_checks.py"
    r = subprocess.run([sys.executable, str(fixer)], capture_output=True, text=True)
    if r.returncode != 0:
        print("  ERROR:", r.stderr[-400:])
    else:
        for line in r.stdout.splitlines():
            if any(x in line for x in ["DONE", "Total", "fixed", "processed"]):
                print("  " + line.strip())

    print("\nAll done.")


if __name__ == "__main__":
    main()
