#!/usr/bin/env python3
"""
Rebuild AliCloud catalog step files from real configscan discovery data.

Sources:
  - engine_configscan_alicloud rules/*.yaml  → real API actions, response paths, fields
  - existing step2_read (resolvable chains)  → dependency chain data

Outputs per service (where real data exists):
  - step2_read_operation_registry.json  (real ops + fields)
  - step2_write_operation_registry.json (unchanged)
  - step1_api_driven_registry.json      (combined from real read + existing write)
  - step4_fields_produced_index.json    (from real fields)
  - step5_resource_catalog_inventory_enrich.json  (real resource types)
  - step6_{svc}.discovery.yaml          (real format: proper items_for, real fields)
  - step3_read_operation_dependency_chain.json  (all services)
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
    import yaml

CATALOG = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud")
CONFIGSCAN_BASE = Path(
    "/Users/apple/Desktop/threat-engine/engine_input"
    "/engine_configscan_alicloud/input/rule_db/default/services"
)
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ──────────────────────────────────────────────────────────────────────────────
# Configscan service name → catalog service name mapping
# ──────────────────────────────────────────────────────────────────────────────
CONFIGSCAN_TO_CATALOG: dict[str, str] = {
    "accessanalyzer": "accessanalyzer",   # not in catalog but keep
    "ack":            "ack",
    "actiontrail":    "actiontrail",
    "alb":            "alb",
    "analyticdb":     "analyticdb",
    "api":            "apigateway",       # AliCloud API Gateway maps to apigateway
    "apigateway":     "apigateway",
    "apikeys":        "apigateway",       # API keys are part of apigateway
    "apsaradb":       "rds",              # ApsaraDB = RDS
    "apsaramq":       "alikafka",         # ApsaraMQ = kafka/messaging
    "apsaravideo":    "vod",              # ApsaraVideo = VOD
    "arms":           "arms",
    "artifacts":      "cr",              # Container Registry artifacts
    "asr":            "hbr",             # Auto Storage Rescue → hbr backup
    "auto":           "ess",             # Auto Scaling = ESS
    "bss":            "bss",
    "cas":            "cas",
    "cdn":            "cdn",
    "cen":            "cbn",             # Cloud Enterprise Network = CBN
    "cfw":            "cloudfw",
    "cloudfw":        "cloudfw",
    "cloudmonitor":   "cms",             # CloudMonitor = CMS
    "cms":            "cms",
    "config":         "config",
    "cr":             "cr",
    "data":           "dms",             # Data Lake Formation → DMS
    "datahub":        "alikafka",        # DataHub is messaging
    "dataworks":      "dms",             # DataWorks is data management
    "ddos":           "ddos",
    "dedicated":      "dedicated",
    "devops":         "codepipeline",    # DevOps = code pipeline
    "dlf":            "dms",             # Data Lake Formation
    "dms":            "dms",
    "dns":            "alidns",
    "dts":            "dts",
    "ecs":            "ecs",
    "efs":            "nas",             # EFS-like = NAS
    "eip":            "vpc",             # EIP is part of VPC
    "elasticsearch":  "elasticsearch",
    "emas":           "emas",
    "emr":            "emr",
    "ess":            "ess",
    "eventbridge":    "eventbridge",
    "expressconnect": "vpc",             # Express Connect is VPC-related
    "fc":             "fc",
    "flink":          "emr",             # Flink = realtime compute (EMR-like)
    "fnf":            "fnf",
    "function":       "fc",              # Function Compute
    "general":        None,              # Skip - general rules, no specific service
    "gtm":            "alidnsgtm",
    "hbr":            "hbr",
    "hologres":       "hitsdb",          # Hologres = HiTSDB (time series)
    "ims":            "ims",
}

# Services to skip entirely (general rules, no specific catalog mapping)
SKIP_SERVICES = {"general"}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def fix_items_for(raw: str) -> str:
    """Convert single-brace items_for to double-brace Jinja2."""
    # '{ response.Resources.Resource }' → '{{ response.Resources.Resource }}'
    fixed = re.sub(r"'\{\s*(.+?)\s*\}'", r"'{{ \1 }}'", raw)
    return fixed


def extract_list_field(items_for: str) -> str:
    """Extract 'Resources.Resource' from items_for path."""
    m = re.search(r"\w+_response\.(.+?)(?:\s*\}|$)", items_for)
    return m.group(1) if m else "data"


def parse_configscan_yaml(svc_name: str) -> list[dict] | None:
    """
    Parse a configscan rules/{svc}.yaml and return list of discovery entries.
    Returns None if file not found.
    """
    rules_yaml = CONFIGSCAN_BASE / svc_name / "rules" / f"{svc_name}.yaml"
    if not rules_yaml.exists():
        return None

    try:
        data = yaml.safe_load(rules_yaml.read_text())
    except Exception as e:
        print(f"  [WARN] Failed to parse {rules_yaml}: {e}")
        return None

    return data.get("discovery", [])


def discovery_to_step6_entry(entry: dict, catalog_svc: str) -> dict | None:
    """Convert a configscan discovery entry to our step6 format dict."""
    disc_id = entry.get("discovery_id", "")
    calls = entry.get("calls", [])
    emit = entry.get("emit", {})

    if not calls or not disc_id:
        return None

    call = calls[0]
    action = call.get("action", "")
    save_as = call.get("save_as", "response")
    params = call.get("params", {}) or {}

    # items_for: after yaml.safe_load(), value is a plain string like: { ami_response.Amis.Ami }
    # We need to produce: '{{ response.Amis.Ami }}'
    items_for_raw = emit.get("items_for", "")
    if items_for_raw:
        inner = str(items_for_raw).strip()
        # Remove surrounding braces if present (single-brace configscan format)
        if inner.startswith("{") and inner.endswith("}"):
            inner = inner[1:-1].strip()
        # Replace save_as-based prefix (ami_response., disk_response., etc.) → response.
        inner = re.sub(r"^\w+_response\.", "response.", inner)
        # Wrap in Jinja2 double-brace format with surrounding single quotes for YAML
        items_for_fixed = f"'{{{{ {inner} }}}}'"
    else:
        items_for_fixed = None

    # Field mappings: convert '{{ r.Field }}' → '{{ item.Field }}'
    item_fields = emit.get("item", {})
    fixed_fields: dict[str, str] = {}
    for key, val in item_fields.items():
        if isinstance(val, str):
            fixed = re.sub(r"\{\{\s*r\.(\w+)\s*\}\}", r"{{ item.\1 }}", val)
            # Also handle region placeholder
            fixed = re.sub(r"\{\{\s*region\s*\}\}", "{{ region }}", fixed)
            fixed_fields[key] = fixed
        else:
            fixed_fields[key] = val

    # Rebuild discovery_id: alicloud.{catalog_svc}.{resource_type}
    # Extract resource_type from original discovery_id
    parts = disc_id.split(".")
    resource_type = parts[-1] if len(parts) >= 3 else "resource"
    new_disc_id = f"alicloud.{catalog_svc}.{resource_type}"

    result: dict = {
        "discovery_id": new_disc_id,
        "action": action,
        "save_as": "response",
        "items_for": items_for_fixed,
        "required_params": list(params.keys()) if params else [],
        "fields": fixed_fields,
        "resource_type": resource_type,
        "list_field": extract_list_field(items_for_raw) if items_for_raw else "data",
    }
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Step2 read generator
# ──────────────────────────────────────────────────────────────────────────────

def build_step2_read(catalog_svc: str, entries: list[dict]) -> dict:
    """Build step2_read_operation_registry.json from parsed entries."""
    operations: dict[str, dict] = {}
    seen_actions: set[str] = set()

    for entry in entries:
        action = entry["action"]
        if not action or action in seen_actions:
            continue
        seen_actions.add(action)

        # Build output_fields from the emitted fields
        output_fields: dict[str, dict] = {}
        for field_key, field_val in entry["fields"].items():
            # Extract the API path from '{{ item.FieldName }}'
            m = re.search(r"\{\{\s*item\.(\w+)\s*\}\}", str(field_val))
            if m:
                path = m.group(1)
                output_fields[field_key] = {
                    "type": "string",
                    "path": path,
                    "entity": f"{catalog_svc}.{field_key}",
                }

        is_independent = not entry["required_params"]
        operations[action] = {
            "operation": action,
            "service": catalog_svc,
            "csp": "alicloud",
            "kind": "read_list",
            "independent": is_independent,
            "python_method": action,
            "yaml_action": action,
            "required_params": entry["required_params"],
            "optional_params": [],
            "output_fields": output_fields,
            "resource_type": entry["resource_type"],
            "list_field": entry["list_field"],
        }

    indep = [v for v in operations.values() if v["independent"]]
    dep = [v for v in operations.values() if not v["independent"]]

    return {
        "service": catalog_svc,
        "csp": "alicloud",
        "generated_at": NOW,
        "total_operations": len(operations),
        "independent_count": len(indep),
        "dependent_count": len(dep),
        "operations": operations,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step1 generator (combine read + write)
# ──────────────────────────────────────────────────────────────────────────────

def build_step1(catalog_svc: str, read_ops: dict, write_ops: dict | None) -> dict:
    independent: list[dict] = []
    dependent: list[dict] = []

    for op_name, op in read_ops.get("operations", {}).items():
        req = op.get("required_params", [])
        entry = {
            "operation": op_name,
            "python_method": op.get("python_method", op_name),
            "yaml_action": op.get("yaml_action", op_name),
            "kind": op.get("kind", "read_list"),
            "side_effect": False,
            "required_params": req,
            "optional_params": op.get("optional_params", []),
            "output_fields": op.get("output_fields", {}),
        }
        (dependent if req else independent).append(entry)

    for op_name, op in (write_ops or {}).get("operations", {}).items():
        req = op.get("required_params", [])
        entry = {
            "operation": op_name,
            "python_method": op.get("python_method", op_name),
            "yaml_action": op.get("yaml_action", op_name),
            "kind": op.get("kind", "write_create"),
            "side_effect": True,
            "required_params": req,
            "optional_params": op.get("optional_params", []),
            "output_fields": op.get("output_fields", {}),
        }
        (dependent if req else independent).append(entry)

    return {
        "service": catalog_svc,
        "csp": "alicloud",
        "generated_at": NOW,
        "total_operations": len(independent) + len(dependent),
        "independent_count": len(independent),
        "dependent_count": len(dependent),
        "independent": independent,
        "dependent": dependent,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step4 generator
# ──────────────────────────────────────────────────────────────────────────────

def build_step4(catalog_svc: str, read_ops: dict) -> dict:
    fields: dict[str, dict] = {}
    for op_name, op in read_ops.get("operations", {}).items():
        is_indep = not bool(op.get("required_params"))
        for field_name, field_info in op.get("output_fields", {}).items():
            if field_name not in fields:
                fields[field_name] = {"field_path": field_name, "producers": [], "preferred": None}
            fields[field_name]["producers"].append({
                "op": op_name,
                "kind": op.get("kind", "read_list"),
                "independent": is_indep,
                "produces_type": field_info.get("type", "string"),
                "is_id": "id" in field_name.lower(),
            })

    for fd in fields.values():
        prods = fd["producers"]
        indep = [p for p in prods if p["independent"]]
        chosen = (indep or prods)[0]
        fd["preferred"] = {"strategy": "independent" if indep else "any", "op": chosen["op"]}

    return {
        "csp": "alicloud",
        "service": catalog_svc,
        "generated_at": NOW,
        "total_fields": len(fields),
        "fields": fields,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step5 generator
# ──────────────────────────────────────────────────────────────────────────────

def build_step5(catalog_svc: str, entries: list[dict]) -> dict:
    resources: dict[str, dict] = {}
    svc_upper = catalog_svc.upper()

    for entry in entries:
        rtype = entry["resource_type"]
        if rtype in resources:
            continue
        resources[rtype] = {
            "resource_type": rtype,
            "classification": "PRIMARY_RESOURCE",
            "has_identifier": True,
            "identifier_type": "arn",
            "identifier_pattern": (
                f"acs:{catalog_svc}:{{region}}:{{account-id}}:{svc_upper}/{{resource-id}}"
            ),
            "identifier": {
                "primary_param": entry["fields"].get("id", f"{svc_upper}Id"),
                "identifier_type": "arn",
            },
            "inventory": {
                "ops": [{
                    "operation": entry["action"],
                    "kind": "read_list",
                    "independent": not bool(entry["required_params"]),
                    "python_method": entry["action"],
                }]
            },
            "inventory_enrich": {"ops": []},
        }

    return {
        "service": catalog_svc,
        "csp": "alicloud",
        "generated_at": NOW,
        "total_resources": len(resources),
        "resources": resources,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step6 YAML builder
# ──────────────────────────────────────────────────────────────────────────────

def build_step6_yaml(catalog_svc: str, entries: list[dict]) -> str:
    lines = [
        f"# Discovery YAML — {catalog_svc} (AliCloud)",
        f"# Generated: {NOW}",
        "version: '1.0'",
        f"provider: alicloud",
        f"service: {catalog_svc}",
        "services:",
        f"  client: {catalog_svc}",
        f"  module: alibabacloud_python_sdk.{catalog_svc}",
        "discovery:",
    ]

    if not entries:
        lines.append("  []  # No operations available")
        return "\n".join(lines) + "\n"

    seen_disc_ids: set[str] = set()

    for entry in entries:
        disc_id = entry["discovery_id"]
        if disc_id in seen_disc_ids:
            continue
        seen_disc_ids.add(disc_id)

        action = entry["action"]
        items_for = entry.get("items_for")
        req_params = entry.get("required_params", [])
        fields = entry.get("fields", {})

        dep_label = " [dependent]" if req_params else ""
        lines.append(f"  # ── {disc_id}{dep_label} ──")
        lines.append(f"  - discovery_id: {disc_id}")
        lines.append(f"    calls:")
        lines.append(f"      - action: {action}")
        lines.append(f"        save_as: response")
        lines.append(f"        on_error: continue")

        if req_params:
            params_str = ", ".join(f"'{p}'" for p in req_params)
            lines.append(f"    # required_params: [{params_str}]")

        lines.append(f"    emit:")
        lines.append(f"      as: item")

        if items_for:
            lines.append(f"      items_for: {items_for}")

        lines.append(f"      item:")
        if fields:
            for field_key, field_val in fields.items():
                lines.append(f"        {field_key}: '{field_val}'")
        else:
            lines.append(f"        # No output fields defined")

    return "\n".join(lines) + "\n"


# ──────────────────────────────────────────────────────────────────────────────
# Step3 dependency chain builder
# ──────────────────────────────────────────────────────────────────────────────

def build_step3(catalog_svc: str, read_ops: dict) -> dict:
    """Build step3_read_operation_dependency_chain.json."""
    ops = read_ops.get("operations", {})

    # Collect fields produced by independent ops
    indep_fields: dict[str, list[str]] = {}  # field → list of ops that produce it
    for op_name, op in ops.items():
        if op.get("independent", False) or not op.get("required_params"):
            for field_name in op.get("output_fields", {}):
                indep_fields.setdefault(field_name, []).append(op_name)

    # Find root (independent) ops
    roots = []
    for op_name, op in ops.items():
        if not op.get("required_params"):
            produced = list(op.get("output_fields", {}).keys())
            roots.append({
                "op": op_name,
                "kind": op.get("kind", "read_list"),
                "produces": [f"{catalog_svc}.{f}" for f in produced],
            })

    # Build entity paths: which ops provide each entity
    entity_paths: dict[str, list[dict]] = {}
    for op_name, op in ops.items():
        req = op.get("required_params", [])
        for field_name in op.get("output_fields", {}):
            entity = f"{catalog_svc}.{field_name}"
            entity_paths.setdefault(entity, [])
            # Check if chain is resolvable
            can_resolve = all(p in indep_fields for p in req)
            entry = {
                "operations": [op_name],
                "resolvable": can_resolve,
                "requires": req,
            }
            if req and can_resolve:
                # Add the ops that provide the required params
                entry["provided_by"] = {
                    param: indep_fields.get(param, []) for param in req
                }
            entity_paths[entity].append(entry)

    # Build resolvable chains (dependent ops whose params are all available)
    chains = []
    for op_name, op in ops.items():
        req = op.get("required_params", [])
        if not req:
            continue
        can_resolve = all(p in indep_fields for p in req)
        if can_resolve:
            chains.append({
                "dependent_op": op_name,
                "required_params": req,
                "param_sources": {
                    param: indep_fields.get(param, []) for param in req
                },
                "status": "RESOLVABLE",
            })
        else:
            missing = [p for p in req if p not in indep_fields]
            chains.append({
                "dependent_op": op_name,
                "required_params": req,
                "missing_params": missing,
                "status": "BROKEN",
            })

    return {
        "service": catalog_svc,
        "csp": "alicloud",
        "generated_at": NOW,
        "read_only": True,
        "roots": roots,
        "entity_paths": entity_paths,
        "dependency_chains": chains,
        "resolvable_count": sum(1 for c in chains if c["status"] == "RESOLVABLE"),
        "broken_count": sum(1 for c in chains if c["status"] == "BROKEN"),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Wire dependency chains in step6
# ──────────────────────────────────────────────────────────────────────────────

def inject_for_each_in_yaml(step6_path: Path, step3: dict) -> bool:
    """
    Add for_each + params to resolvable dependent operations in step6 YAML.
    Returns True if file was modified.
    """
    resolvable = {
        c["dependent_op"]: c for c in step3.get("dependency_chains", [])
        if c["status"] == "RESOLVABLE"
    }
    if not resolvable:
        return False

    content = step6_path.read_text()
    original = content

    for dep_op, chain in resolvable.items():
        # Find the block for this dependent op
        # Pattern: "- discovery_id: alicloud.{svc}.{resource}" followed by "action: dep_op"
        # We need to add:
        #   for_each: alicloud.{svc}.{parent_resource}
        #   and params: block under the action

        param_sources = chain.get("param_sources", {})
        if not param_sources:
            continue

        # For each required param, find what op produces it and what its resource_type is
        # (simplified: take first producing op's resource_type)
        for param, providing_ops in param_sources.items():
            if not providing_ops:
                continue
            parent_op = providing_ops[0]

            # Find the parent's discovery_id (service.resource_type)
            # We search the content for the action: parent_op line in a discovery block
            parent_disc_match = re.search(
                rf"- discovery_id: (alicloud\.\w+\.\w+).*?action: {re.escape(parent_op)}",
                content,
                re.DOTALL,
            )
            if not parent_disc_match:
                continue
            parent_disc_id = parent_disc_match.group(1)

            # Find the dependent op's block and inject for_each + params
            dep_action_pattern = re.compile(
                rf"(  - discovery_id: alicloud\.\w+\.\w+(?:\s+# .*)?)"
                rf"(.*?action: {re.escape(dep_op)}\s*\n)",
                re.DOTALL,
            )
            def inject(m: re.Match) -> str:
                block_start = m.group(1)
                before_save = m.group(2)
                # Add for_each after discovery_id line
                disc_id_line = block_start.split("\n")[0]
                for_each_line = f"\n    for_each: {parent_disc_id}"
                injected_start = block_start.replace(
                    disc_id_line,
                    disc_id_line + for_each_line,
                    1,
                )
                # Add params under action
                params_block = (
                    f"        params:\n"
                    f"          {param}: '{{{{ item.{param} }}}}'\n"
                )
                before_save_with_params = before_save.rstrip("\n") + "\n" + params_block
                return injected_start + before_save_with_params

            content = dep_action_pattern.sub(inject, content, count=1)

    if content != original:
        step6_path.write_text(content)
        return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Main processing
# ──────────────────────────────────────────────────────────────────────────────

def process_service(configscan_svc: str, catalog_svc: str) -> dict[str, str]:
    results: dict[str, str] = {}
    svc_dir = CATALOG / catalog_svc

    if not svc_dir.exists():
        svc_dir.mkdir(parents=True, exist_ok=True)

    # 1. Parse configscan YAML
    raw_entries = parse_configscan_yaml(configscan_svc)
    if raw_entries is None:
        return {"status": "NO_CONFIGSCAN_DATA"}

    # 2. Convert entries to our format
    entries = [
        e for raw in raw_entries
        if (e := discovery_to_step6_entry(raw, catalog_svc)) is not None
    ]
    if not entries:
        return {"status": "EMPTY_ENTRIES"}

    print(f"  {configscan_svc} → {catalog_svc}: {len(entries)} real discovery entries")

    # 3. Build and save step2_read
    existing_write = load_json(svc_dir / "step2_write_operation_registry.json")
    new_step2_read = build_step2_read(catalog_svc, entries)
    save_json(svc_dir / "step2_read_operation_registry.json", new_step2_read)
    results["step2_read"] = f"REBUILT ({len(new_step2_read['operations'])} ops)"

    # 4. Build and save step1
    new_step1 = build_step1(catalog_svc, new_step2_read, existing_write)
    save_json(svc_dir / "step1_api_driven_registry.json", new_step1)
    results["step1"] = f"REBUILT ({new_step1['total_operations']} ops)"

    # 5. Build and save step4
    new_step4 = build_step4(catalog_svc, new_step2_read)
    save_json(svc_dir / "step4_fields_produced_index.json", new_step4)
    results["step4"] = f"REBUILT ({new_step4['total_fields']} fields)"

    # 6. Build and save step5
    new_step5 = build_step5(catalog_svc, entries)
    save_json(svc_dir / "step5_resource_catalog_inventory_enrich.json", new_step5)
    results["step5"] = f"REBUILT ({new_step5['total_resources']} resources)"

    # 7. Build and save step6
    step6_path = svc_dir / f"step6_{catalog_svc}.discovery.yaml"
    yaml_content = build_step6_yaml(catalog_svc, entries)
    step6_path.write_text(yaml_content)
    results["step6"] = f"REBUILT ({len(entries)} discoveries)"

    # 8. Build step3
    new_step3 = build_step3(catalog_svc, new_step2_read)
    save_json(svc_dir / "step3_read_operation_dependency_chain.json", new_step3)
    results["step3"] = (
        f"BUILT ({new_step3['resolvable_count']} resolvable, "
        f"{new_step3['broken_count']} broken)"
    )

    return results


def process_step3_only(catalog_svc: str) -> dict[str, str]:
    """Build step3 for services without configscan data (from existing step2_read)."""
    svc_dir = CATALOG / catalog_svc
    step2_read = load_json(svc_dir / "step2_read_operation_registry.json")
    if not step2_read:
        return {"step3": "SKIP (no step2_read)"}

    step3 = build_step3(catalog_svc, step2_read)
    save_json(svc_dir / "step3_read_operation_dependency_chain.json", step3)
    return {
        "step3": (
            f"BUILT ({step3['resolvable_count']} resolvable, "
            f"{step3['broken_count']} broken)"
        )
    }


def main() -> None:
    print(f"\n{'='*70}")
    print("AliCloud Catalog Rebuild from Real Configscan Data")
    print(f"{'='*70}\n")

    # Phase 1: Process services with real configscan data
    print("─── Phase 1: Rebuild from configscan real data ───\n")
    phase1_results: dict[str, dict] = {}
    processed_catalog_svcs: set[str] = set()

    for cs_svc, cat_svc in sorted(CONFIGSCAN_TO_CATALOG.items()):
        if cs_svc in SKIP_SERVICES or cat_svc is None:
            continue

        result = process_service(cs_svc, cat_svc)
        if result.get("status") not in ("NO_CONFIGSCAN_DATA", "EMPTY_ENTRIES"):
            processed_catalog_svcs.add(cat_svc)
        phase1_results[f"{cs_svc}→{cat_svc}"] = result

    # Phase 2: Build step3 for all remaining catalog services
    print(f"\n─── Phase 2: Build step3 for remaining {138 - len(processed_catalog_svcs)} services ───\n")
    all_svcs = sorted(
        d.name for d in CATALOG.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )
    step3_built = 0
    for svc in all_svcs:
        if svc in processed_catalog_svcs:
            continue
        result = process_step3_only(svc)
        if "BUILT" in result.get("step3", ""):
            step3_built += 1

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")

    rebuilt = sum(1 for r in phase1_results.values() if "REBUILT" in str(r))
    print(f"\nServices rebuilt from real data : {rebuilt}")
    print(f"Step3 built for other services  : {step3_built}")
    print(f"\nDetailed results:")
    for svc_pair, result in phase1_results.items():
        if result.get("status") not in ("NO_CONFIGSCAN_DATA", "EMPTY_ENTRIES"):
            print(f"  {svc_pair}:")
            for step, status in result.items():
                print(f"    {step:12s}: {status}")

    print(f"\nDone.\n")


if __name__ == "__main__":
    main()
