#!/usr/bin/env python3
"""
Rebuild step5_resource_catalog_inventory_enrich.json for ALL 446 AWS services.

Problem: current step5 is a single-resource stub. This rebuilds it as a full
multi-resource catalog aligned with the GCP model.

INPUT per service directory:
  step2_resource_operations_registry.json   → resource list + their op sets
  step2_read_operation_registry.json        → full read-op metadata
  resource_arn_mapping.json                 → ARN/ID entities per resource

OUTPUT per service directory:
  step5_resource_catalog_inventory_enrich.json  (overwritten)

SCHEMA:
{
  "service": "ec2",
  "csp": "aws",
  "generated_at": "<iso8601>",
  "total_resources": 254,
  "primary_resource_count": 63,
  "other_resource_count": 191,
  "resources": {
    "<resource_type>": {
      "resource_type": "<resource_type>",
      "classification": "PRIMARY_RESOURCE" | "OTHER_RESOURCE",
      "has_arn": true | false,
      "arn_entity": "<dotted entity name or null>",
      "can_inventory_from_roots": true | false,
      "should_inventory": true | false,
      "identifier": {
        "primary_param": "<IdParam>",
        "identifier_type": "arn" | "id" | "name" | "unknown",
        "arn_producing_ops": [...],
        "id_entities": [...]
      },
      "inventory": {
        "ops": [
          {
            "operation": "DescribeFoo",
            "kind": "read_describe",
            "independent": true,
            "python_method": "describe_foo",
            "yaml_action": "describeFoo",
            "required_params": [],
            "output_fields": {...}
          }
        ]
      },
      "inventory_enrich": {
        "ops": [...]   // dependent read ops in resource's 'other' list
      }
    }
  }
}
"""

import glob
import json
import re
from datetime import datetime, timezone
from pathlib import Path

AWS_ROOT = Path(__file__).parent.parent / "aws"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _infer_primary_param(resource_type: str, arn_entity: str | None) -> str:
    """Derive the likely identifier param name from the resource/ARN entity."""
    if arn_entity:
        # e.g. ec2.instance_instance_id → InstanceId
        last = arn_entity.split(".")[-1]          # instance_instance_id
        parts = last.split("_")
        # Convert snake_case to PascalCase
        return "".join(p.capitalize() for p in parts)
    # Fall back to resource_type → FooId
    clean = re.sub(r"[^a-z0-9]", "_", resource_type.lower()).strip("_")
    parts = [p for p in clean.split("_") if p]
    return "".join(p.capitalize() for p in parts) + "Id"


def _infer_identifier_type(res: dict, arn_map_res: dict) -> str:
    if res.get("has_arn"):
        return "arn"
    if arn_map_res.get("id_entities"):
        return "id"
    return "name"


def build_catalog(svc_dir: Path) -> dict | None:
    step2_path = svc_dir / "step2_resource_operations_registry.json"
    read2_path = svc_dir / "step2_read_operation_registry.json"
    arn_path   = svc_dir / "resource_arn_mapping.json"

    if not step2_path.exists() or not read2_path.exists():
        return None

    step2 = json.loads(step2_path.read_text())
    read2 = json.loads(read2_path.read_text())
    arn_data: dict = {}
    if arn_path.exists():
        raw = json.loads(arn_path.read_text())
        arn_data = raw.get("analysis", {}).get("resources", {})

    service = step2.get("service", svc_dir.name)
    read_ops: dict = read2.get("operations", {})   # op_name → metadata

    primary_resources = step2.get("primary_resources", [])
    other_resources   = step2.get("other_resources",   [])

    resources_out: dict = {}

    def _process_resource(res: dict, classification: str):
        rtype = res.get("resource_type", "")
        ops_info = res.get("operations", {})

        independent_ops  = ops_info.get("independent", [])
        other_ops        = ops_info.get("other", [])
        yaml_disc_ops    = ops_info.get("yaml_discovery", [])

        # Use all read ops that appear in independent OR yaml_discovery as inventory ops
        inventory_op_names = list(dict.fromkeys(independent_ops + yaml_disc_ops))
        # Other ops that are read-type go to enrich
        enrich_op_names = [o for o in other_ops if o not in inventory_op_names]

        def _enrich_op(name: str) -> dict:
            meta = read_ops.get(name, {})
            return {
                "operation":     name,
                "kind":          meta.get("kind", "read_other"),
                "independent":   meta.get("independent", False),
                "python_method": meta.get("python_method", ""),
                "yaml_action":   meta.get("yaml_action", ""),
                "required_params": meta.get("required_params", []),
            }

        inventory_ops_list  = [_enrich_op(n) for n in inventory_op_names]
        enrich_ops_list     = [_enrich_op(n) for n in enrich_op_names
                                if n in read_ops]  # only read ops

        # Identifier info
        arn_map_res  = arn_data.get(rtype, {})
        arn_entity   = res.get("arn_entity") or arn_map_res.get("arn_entity")
        id_entities  = arn_map_res.get("id_entities", [])
        arn_prod_ops = arn_map_res.get("arn_producing_operations", [])

        primary_param = _infer_primary_param(rtype, arn_entity)
        id_type       = _infer_identifier_type(res, arn_map_res)

        resources_out[rtype] = {
            "resource_type":           rtype,
            "classification":          classification,
            "has_arn":                 res.get("has_arn", False),
            "arn_entity":              arn_entity,
            "can_inventory_from_roots": res.get("can_get_from_root_ops", bool(independent_ops)),
            "should_inventory":        res.get("should_inventory", True),
            "identifier": {
                "primary_param":    primary_param,
                "identifier_type":  id_type,
                "arn_producing_ops": arn_prod_ops,
                "id_entities":       id_entities,
            },
            "inventory":        {"ops": inventory_ops_list},
            "inventory_enrich": {"ops": enrich_ops_list},
        }

    for res in primary_resources:
        _process_resource(res, "PRIMARY_RESOURCE")
    for res in other_resources:
        _process_resource(res, "OTHER_RESOURCE")

    return {
        "service":               service,
        "csp":                   "aws",
        "generated_at":          _now_iso(),
        "total_resources":       len(resources_out),
        "primary_resource_count": len(primary_resources),
        "other_resource_count":   len(other_resources),
        "resources":             resources_out,
    }


def main():
    svc_dirs = sorted(
        d for d in AWS_ROOT.iterdir()
        if d.is_dir()
        and (d / "step2_resource_operations_registry.json").exists()
    )
    print(f"Found {len(svc_dirs)} AWS services to process")

    ok = 0
    skipped = 0
    for svc_dir in svc_dirs:
        catalog = build_catalog(svc_dir)
        if catalog is None:
            skipped += 1
            continue
        out = svc_dir / "step5_resource_catalog_inventory_enrich.json"
        out.write_text(json.dumps(catalog, indent=2))
        n = catalog["total_resources"]
        p = catalog["primary_resource_count"]
        print(f"  {svc_dir.name:<40}  resources={n:>4}  (primary={p})")
        ok += 1

    print()
    print(f"Done: {ok} written, {skipped} skipped")


if __name__ == "__main__":
    main()
