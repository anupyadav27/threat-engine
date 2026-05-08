#!/usr/bin/env python3
"""
Fix AliCloud catalog step files (step1–step6) for all 138 services.

Issues addressed:
  1. Generate missing step1_api_driven_registry.json  (~113 services)
  2. Generate missing step4_fields_produced_index.json (~113 services)
  3. Generate missing step5_resource_catalog_inventory_enrich.json (~113 services)
  4. Fix step6 discovery YAML field references:
       - Group A (have step1): {{ response.snake_case }} → {{ response.PascalCase }}
       - Group B (no step1) : {{ item.snake_case }}     → {{ item.PascalCase }}
  5. Generate empty step6 for 'tools' service (only one missing step6)
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CATALOG = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud")
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    print(f"  [WROTE] {path.name}")


def derive_resource_type(op_name: str) -> str:
    """DescribeInstances → instances, ListBuckets → buckets."""
    stripped = re.sub(r'^(Describe|List|Get|Query|Fetch)', '', op_name)
    return stripped.lower() if stripped else op_name.lower()


def field_path_map(operations: dict) -> dict[str, str]:
    """Build {snake_field: PascalPath} from all output_fields across operations."""
    mapping: dict[str, str] = {}
    for op in operations.values():
        for field_name, field_info in op.get("output_fields", {}).items():
            path = field_info.get("path", "")
            if path and field_name not in mapping:
                mapping[field_name] = path
    return mapping


# ──────────────────────────────────────────────────────────────────────────────
# Step 1 generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_step1(svc: str, read_ops: dict | None, write_ops: dict | None) -> dict:
    """Combine read + write ops into step1_api_driven_registry.json format."""
    independent: list[dict] = []
    dependent: list[dict] = []

    for source in [read_ops, write_ops]:
        if source is None:
            continue
        for op_name, op in source.get("operations", {}).items():
            req = op.get("required_params", [])
            entry = {
                "operation": op_name,
                "python_method": op.get("python_method", op_name),
                "yaml_action": op.get("yaml_action", op_name),
                "kind": op.get("kind", "read_list"),
                "side_effect": source is write_ops,
                "required_params": req,
                "optional_params": op.get("optional_params", []),
                "output_fields": op.get("output_fields", {}),
            }
            (dependent if req else independent).append(entry)

    return {
        "service": svc,
        "csp": "alicloud",
        "generated_at": NOW,
        "total_operations": len(independent) + len(dependent),
        "independent_count": len(independent),
        "dependent_count": len(dependent),
        "independent": independent,
        "dependent": dependent,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step 4 generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_step4(svc: str, read_ops: dict | None) -> dict:
    """Build step4_fields_produced_index.json from read operations."""
    fields: dict[str, dict] = {}

    for op_name, op in (read_ops or {}).get("operations", {}).items():
        is_indep = not bool(op.get("required_params"))
        for field_name, field_info in op.get("output_fields", {}).items():
            if field_name not in fields:
                fields[field_name] = {
                    "field_path": field_name,
                    "producers": [],
                    "preferred": None,
                }
            fields[field_name]["producers"].append({
                "op": op_name,
                "kind": op.get("kind", "read_list"),
                "independent": is_indep,
                "produces_type": field_info.get("type", "string"),
                "is_id": "id" in field_name.lower(),
            })

    # Choose preferred producer (independent preferred over dependent)
    for field_data in fields.values():
        prods = field_data["producers"]
        indep = [p for p in prods if p["independent"]]
        chosen = (indep or prods)[0]
        field_data["preferred"] = {
            "strategy": "independent" if indep else "any",
            "op": chosen["op"],
        }

    return {
        "csp": "alicloud",
        "service": svc,
        "generated_at": NOW,
        "total_fields": len(fields),
        "fields": fields,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step 5 generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_step5(svc: str, read_ops: dict | None) -> dict:
    """Build step5_resource_catalog_inventory_enrich.json from read operations."""
    resources: dict[str, dict] = {}
    svc_upper = svc.upper()

    seen: set[str] = set()
    for op_name, op in (read_ops or {}).get("operations", {}).items():
        rtype = derive_resource_type(op_name)
        is_indep = not bool(op.get("required_params"))
        inv_op = {
            "operation": op_name,
            "kind": op.get("kind", "read_list"),
            "independent": is_indep,
            "python_method": op.get("python_method", op_name),
        }
        if rtype not in resources:
            resources[rtype] = {
                "resource_type": rtype,
                "classification": "PRIMARY_RESOURCE",
                "has_identifier": True,
                "identifier_type": "arn",
                "identifier_pattern": (
                    f"acs:{svc}:{{region}}:{{account-id}}:{svc_upper}/{{resource-id}}"
                ),
                "identifier": {
                    "primary_param": f"{svc_upper}Id",
                    "identifier_type": "arn",
                },
                "inventory": {"ops": [inv_op]},
                "inventory_enrich": {"ops": []},
            }
        else:
            # Append op to existing resource type
            resources[rtype]["inventory"]["ops"].append(inv_op)

    return {
        "service": svc,
        "csp": "alicloud",
        "generated_at": NOW,
        "total_resources": len(resources),
        "resources": resources,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Step 6 fixer / generator
# ──────────────────────────────────────────────────────────────────────────────

def build_step6_yaml(svc: str, read_ops: dict | None) -> str:
    """
    Regenerate step6 discovery YAML from read operations with correct field refs.

    Rules:
    - Independent operations (no required_params): plain entry, no params comment.
    - Dependent operations (has required_params): include with commented params hint.
    - read_list → items_for: '{{ response.data }}' + item.PascalCase refs.
    - read_get  → no items_for + response.PascalCase refs.
    - Field template: left=snake_case key, right={{ item/response.Path }}.
    """
    lines: list[str] = [
        f"# Discovery YAML — {svc} (AliCloud)",
        f"# Generated: {NOW}",
        "version: '1.0'",
        f"provider: alicloud",
        f"service: {svc}",
        "services:",
        f"  client: {svc}",
        f"  module: alibabacloud_python_sdk.{svc}",
        "discovery:",
    ]

    ops = (read_ops or {}).get("operations", {})
    if not ops:
        lines.append("  []  # No operations available")
        return "\n".join(lines) + "\n"

    for op_name, op in ops.items():
        req_params = op.get("required_params", [])
        kind = op.get("kind", "read_list")
        is_list = kind in ("read_list", "read_describe")
        dep_label = " [dependent]" if req_params else ""

        lines.append(f"  # ── {op_name}{dep_label} ──")
        lines.append(f"  - discovery_id: alicloud.{svc}.{op_name}")
        lines.append(f"    calls:")
        lines.append(f"      - action: {op_name}")
        lines.append(f"        save_as: response")
        lines.append(f"        on_error: continue")

        if req_params:
            # Add commented params block for chaining reference
            params_str = ", ".join(f"'{p}'" for p in req_params)
            lines.append(f"    # required_params: [{params_str}]")

        lines.append(f"    emit:")
        lines.append(f"      as: item")

        if is_list:
            lines.append(f"      items_for: '{{{{ response.data }}}}'")

        # Build field refs using PascalCase paths from output_fields
        lines.append(f"      item:")
        out_fields = op.get("output_fields", {})
        if out_fields:
            for field_name, field_info in out_fields.items():
                path = field_info.get("path", "")
                if not path:
                    # Fallback: PascalCase the snake_case field name
                    path = "".join(w.capitalize() for w in field_name.split("_"))
                ref_src = "item" if is_list else "response"
                lines.append(f"        {field_name}: '{{{{ {ref_src}.{path} }}}}'")
        else:
            lines.append(f"        # No output fields defined")

    return "\n".join(lines) + "\n"


def fix_step6_yaml(svc: str, existing_yaml: str, read_ops: dict | None) -> str:
    """
    Fix an existing step6 YAML in-place:
    - Replace {{ response.snake_case }} with {{ response.PascalPath }}
    - Replace {{ item.snake_case }} with {{ item.PascalPath }}
    - Add items_for line when missing for read_list operations.

    Uses output_fields path mapping from read_ops for accurate substitution.
    Falls back to manual PascalCase conversion when field not found in mapping.
    """
    if not read_ops:
        return existing_yaml

    # Build field → path mapping across all operations
    fmap = field_path_map(read_ops.get("operations", {}))

    def replace_template(match: re.Match) -> str:
        prefix = match.group(1)   # 'response' or 'item'
        field = match.group(2)    # field name (may already be PascalCase)

        # Skip if already PascalCase (starts with uppercase) — idempotent
        if field and field[0].isupper():
            return match.group(0)

        # Look up PascalCase path from output_fields mapping
        if field in fmap:
            pascal = fmap[field]
        else:
            # Fallback: convert snake_case → PascalCase
            parts = field.split("_")
            pascal = "".join(w[0].upper() + w[1:] if w else "" for w in parts)

        return f"{{{{ {prefix}.{pascal} }}}}"

    # Fix {{ response.snake_field }} and {{ item.snake_field }}
    fixed = re.sub(
        r"\{\{\s*(response|item)\.([\w]+)\s*\}\}",
        replace_template,
        existing_yaml,
    )

    # Add items_for for read_list operations that are missing it
    # Pattern: finds a discovery entry with read_list op name and no items_for
    ops = read_ops.get("operations", {})
    list_ops = {
        op_name for op_name, op in ops.items()
        if op.get("kind") in ("read_list", "read_describe")
    }

    def add_items_for(match: re.Match) -> str:
        """Insert items_for after 'emit:' block if op is a list op."""
        full = match.group(0)
        disc_id = match.group(1)
        op_name = disc_id.split(".")[-1]  # alicloud.svc.OpName → OpName
        if op_name in list_ops and "items_for:" not in full:
            # Insert items_for after 'as: item'
            return full.replace(
                "      as: item\n      item:",
                "      as: item\n      items_for: '{{ response.data }}'\n      item:",
            )
        return full

    # Apply items_for fix per discovery block
    fixed = re.sub(
        r"(- discovery_id: (alicloud\.[^.]+\.\S+).*?)(?=\n  - discovery_id:|\Z)",
        add_items_for,
        fixed,
        flags=re.DOTALL,
    )

    return fixed


# ──────────────────────────────────────────────────────────────────────────────
# Main loop
# ──────────────────────────────────────────────────────────────────────────────

def process_service(svc_dir: Path) -> dict[str, str]:
    svc = svc_dir.name
    results: dict[str, str] = {}

    # ── Load existing step2 files ──────────────────────────────────────────
    read_ops = load_json(svc_dir / "step2_read_operation_registry.json")
    write_ops = load_json(svc_dir / "step2_write_operation_registry.json")

    # ── Step 1 ────────────────────────────────────────────────────────────
    s1_path = svc_dir / "step1_api_driven_registry.json"
    if not s1_path.exists():
        if read_ops or write_ops:
            save_json(s1_path, generate_step1(svc, read_ops, write_ops))
            results["step1"] = "GENERATED"
        else:
            results["step1"] = "SKIP (no step2 data)"
    else:
        results["step1"] = "EXISTS"

    # ── Step 4 ────────────────────────────────────────────────────────────
    s4_path = svc_dir / "step4_fields_produced_index.json"
    if not s4_path.exists():
        if read_ops:
            save_json(s4_path, generate_step4(svc, read_ops))
            results["step4"] = "GENERATED"
        else:
            results["step4"] = "SKIP (no step2_read)"
    else:
        results["step4"] = "EXISTS"

    # ── Step 5 ────────────────────────────────────────────────────────────
    s5_path = svc_dir / "step5_resource_catalog_inventory_enrich.json"
    if not s5_path.exists():
        if read_ops:
            save_json(s5_path, generate_step5(svc, read_ops))
            results["step5"] = "GENERATED"
        else:
            results["step5"] = "SKIP (no step2_read)"
    else:
        results["step5"] = "EXISTS"

    # ── Step 6 ────────────────────────────────────────────────────────────
    s6_path = svc_dir / f"step6_{svc}.discovery.yaml"
    if not s6_path.exists():
        # Generate fresh step6
        yaml_content = build_step6_yaml(svc, read_ops)
        s6_path.write_text(yaml_content)
        print(f"  [GENERATED] {s6_path.name}")
        results["step6"] = "GENERATED"
    else:
        # Fix existing step6 in-place
        original = s6_path.read_text()
        fixed = fix_step6_yaml(svc, original, read_ops)
        if fixed != original:
            s6_path.write_text(fixed)
            print(f"  [FIXED] {s6_path.name}")
            results["step6"] = "FIXED"
        else:
            results["step6"] = "OK (no changes)"

    return results


def main() -> None:
    services = sorted(
        d for d in CATALOG.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )

    print(f"\n{'='*60}")
    print(f"AliCloud Catalog Fix — {len(services)} services")
    print(f"{'='*60}\n")

    summary: dict[str, dict] = {}
    for svc_dir in services:
        print(f"\n── {svc_dir.name} ──")
        summary[svc_dir.name] = process_service(svc_dir)

    # ── Print summary ──────────────────────────────────────────────────────
    print(f"\n\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")

    counts: dict[str, dict[str, int]] = {}
    for svc, res in summary.items():
        for step, status in res.items():
            counts.setdefault(step, {}).setdefault(status, 0)
            counts[step][status] += 1

    for step in ("step1", "step4", "step5", "step6"):
        if step in counts:
            print(f"\n{step}:")
            for status, n in sorted(counts[step].items()):
                print(f"  {status:40s}: {n}")

    generated = sum(
        1 for res in summary.values()
        for s in ("step1", "step4", "step5") if res.get(s) == "GENERATED"
    )
    fixed = sum(
        1 for res in summary.values() if res.get("step6") == "FIXED"
    )
    print(f"\nTotal files generated : {generated}")
    print(f"Total step6 fixed     : {fixed}")
    print(f"\nDone.\n")


if __name__ == "__main__":
    main()
