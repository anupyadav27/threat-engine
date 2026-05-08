#!/usr/bin/env python3
"""step4_enhancer.py — Enhance step4_fields_produced_index.json with two new sections.

New sections added:
  1. param_source_map: maps API param name → {entity, emit_field, producing_op,
     discovery_id, items_path}
     Answers: "When a dependent op needs param X, which for_each op feeds it,
     and what field in the emitted item holds the value?"
     Example: Bucket → {emit_field: Name, producing_op: ListBuckets, ...}

  2. response_emit_map: maps operation → {emit_style, items_path | response_fields}
     Answers: "For op X, should we use items_for (list) or flat emit, and what path?"
     Example: GetPublicAccessBlock → {emit_style: flat, ...}
              GetBucketAcl         → {emit_style: list, items_path: response.Grants}

Algorithm (fully derived from step1 + step3 + existing step4.fields):
  param_source_map:
    - step4.fields gives: field_name → entity
    - step3 entity_paths gives: entity → consuming ops + their consumed entities
    - step1 required_params: for each consumer, what params it needs
    - new_param = consumer.required_params − producer.required_params
    - items_path = the list-type output field of the producing op (from step1)

  response_emit_map:
    - step1 output_fields types: list → use items_for, structure/string → flat emit
    - For ops with single list field → items_path = response.<field>
    - For ops with multiple list fields → flag for manual review
    - For ops with no list fields → flat emit

Usage:
    python3 step4_enhancer.py           # preview (prints JSON diff)
    python3 step4_enhancer.py --write   # update step4 in place
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
from collections import Counter

BASE = Path(__file__).parent
WRITE = "--write" in sys.argv

# ── Load inputs ──────────────────────────────────────────────────────────────
step1_raw = json.loads((BASE / "step1_api_driven_registry.json").read_text())
service_key = next(iter(step1_raw))          # e.g. "s3"
step1 = step1_raw[service_key]
provider = "aws"                             # adjust for non-AWS
service = step1["service"]

step3 = json.loads((BASE / "step3_read_operation_dependency_chain.json").read_text())
step4 = json.loads((BASE / "step4_fields_produced_index.json").read_text())

# ── Build op lookup ───────────────────────────────────────────────────────────
all_ops: list[dict] = step1.get("independent", []) + step1.get("dependent", [])
op_by_name: dict[str, dict] = {op["operation"]: op for op in all_ops}

def discovery_id(op_name: str) -> str:
    """Convert PascalCase op name to snake_case discovery_id."""
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", op_name).lower()
    return f"{provider}.{service}.{snake}"


_SKIP_LIST_FIELDS = {"CommonPrefixes", "DeleteMarkers", "ContinuationToken",
                     "NextContinuationToken", "NextMarker"}

def primary_list_field(op_name: str) -> str | None:
    """Return the primary list-type output field for op_name (items_path candidate)."""
    op = op_by_name.get(op_name, {})
    candidates = [k for k, v in op.get("output_fields", {}).items()
                  if v.get("type") == "list" and k not in _SKIP_LIST_FIELDS]
    return candidates[0] if candidates else None


# ══════════════════════════════════════════════════════════════════════════════
# Section 1 — param_source_map
# ══════════════════════════════════════════════════════════════════════════════

def build_param_source_map() -> dict:
    """Derive: api_param_name → {entity, emit_field, producing_op, discovery_id, items_path}"""

    # ── Algorithm ───────────────────────────────────────────────────────────
    # For each entity E → field F (from step4.fields):
    #
    # Step A — find param name:
    #   If any dependent op has F in its required_params → param = F (same name)
    #   Else → name mismatch (e.g. Name→Bucket): pick the most-common required_param
    #   across all ops that output F (excluding F itself from ops that both output and require it)
    #
    # Step B — find producing op:
    #   Among ops that output F, pick List ops that do NOT require F as a param
    #   (i.e. they produce F, not consume it). Sort by fewest required_params first.

    # ── Service-specific overrides ──────────────────────────────────────────
    # Cases where the field name in the emitted item differs from the API param
    # name, or where auto-selection picks the wrong producing op.
    # Format: field_name → (param_name, preferred_producing_op | None)
    FIELD_OVERRIDES: dict[str, tuple[str, str | None]] = {
        # S3: bucket identifier is called 'Name' in ListBuckets output
        #     but 'Bucket' in all dependent API calls.
        "Name":     ("Bucket",   "ListBuckets"),
        # S3: object Key is produced by multiple List ops; ListObjectsV2 is
        #     the canonical modern op (not ListMultipartUploads which also has Key).
        "Key":      ("Key",      "ListObjectsV2"),
        # S3: UploadId is produced by ListMultipartUploads; ListParts requires it
        #     but ListParts is not in ops_with_field so Case 1 misses it.
        "UploadId": ("UploadId", "ListMultipartUploads"),
    }

    param_source: dict[str, dict] = {}

    all_field_items = list(step4.get("fields", {}).items())
    # Process override fields first so they claim their params before auto-detection
    override_fields = [i for i in all_field_items if i[0] in FIELD_OVERRIDES]
    other_fields    = [i for i in all_field_items if i[0] not in FIELD_OVERRIDES]

    for field_name, fdata in override_fields + other_fields:
        entity = fdata.get("dependency_index_entity")
        if not entity:
            continue

        ops_with_field = fdata.get("operations", [])
        if not ops_with_field:
            continue

        # ── Step A: derive param name ───────────────────────────────────────
        # Check override first
        override = FIELD_OVERRIDES.get(field_name)
        if override:
            param, forced_producer = override
        else:
            forced_producer = None
            # Case 1: field name IS the param name
            direct_consumers = [
                n for n in ops_with_field
                if field_name in op_by_name.get(n, {}).get("required_params", [])
            ]
            if direct_consumers:
                param = field_name
            else:
                # Case 2: name mismatch — count required_params across all ops
                # that output this field (they all need the same "parent" param)
                counter: Counter = Counter()
                for op_name in ops_with_field:
                    for p in op_by_name.get(op_name, {}).get("required_params", []):
                        counter[p] += 1
                if not counter:
                    continue
                param = counter.most_common(1)[0][0]

        # ── Step B: find best producing op ─────────────────────────────────
        if forced_producer:
            best_producer = forced_producer
        else:
            # Producer = List op that outputs F but does NOT require F as a param
            producers = [
                n for n in ops_with_field
                if n.startswith("List")
                and field_name not in op_by_name.get(n, {}).get("required_params", [])
            ]
            if not producers:
                continue
            # Sort by fewest required_params (most independent first)
            producers.sort(key=lambda n: len(op_by_name.get(n, {}).get("required_params", [])))
            best_producer = producers[0]

        # Skip if this param was already claimed by an earlier (override) entry
        if param in param_source:
            continue

        list_field = primary_list_field(best_producer)
        items_path = f"response.{list_field}" if list_field else None

        param_source[param] = {
            "entity":       entity,
            "emit_field":   field_name,
            "producing_op": best_producer,
            "discovery_id": discovery_id(best_producer),
            "items_path":   items_path,
            "note": (
                f"When dependent op needs '{param}' param, "
                f"use for_each={discovery_id(best_producer)} "
                f"and set {param}='{{{{ item.{field_name} }}}}'"
            ),
        }

    return dict(sorted(param_source.items()))


# ══════════════════════════════════════════════════════════════════════════════
# Section 2 — response_emit_map
# ══════════════════════════════════════════════════════════════════════════════

def build_response_emit_map() -> dict:
    """Derive: op_name → {emit_style, items_path | response_fields, field_types}"""

    emit_map: dict[str, dict] = {}

    skip_fields = {"ResponseMetadata", "ContinuationToken", "IsTruncated",
                   "NextContinuationToken", "NextMarker", "NextKeyMarker",
                   "NextVersionIdMarker", "NextUploadIdMarker", "MaxUploads",
                   "MaxKeys", "MaxParts", "Delimiter", "EncodingType",
                   "KeyCount", "Prefix", "Bucket", "Name", "Marker",
                   "VersionIdMarker", "UploadIdMarker",
                   # Pagination/noise list fields from multi-response ops
                   "CommonPrefixes", "DeleteMarkers"}

    read_ops = step1.get("independent", []) + [
        op for op in step1.get("dependent", [])
        if op.get("read_only", True)
    ]

    for op in read_ops:
        op_name = op["operation"]
        # Only include read ops (Get*, List*, Describe*)
        if not any(op_name.startswith(p) for p in ("Get", "List", "Describe")):
            continue

        out_fields = op.get("output_fields", {})
        if not out_fields:
            continue

        list_fields = {k: v for k, v in out_fields.items()
                       if v.get("type") == "list" and k not in skip_fields}
        struct_fields = {k: v for k, v in out_fields.items()
                        if v.get("type") == "structure" and k not in skip_fields}
        scalar_fields = {k: v for k, v in out_fields.items()
                        if v.get("type") in ("string", "boolean", "integer", "long",
                                             "timestamp", "double")
                        and k not in skip_fields}

        if len(list_fields) == 1:
            lf = next(iter(list_fields))
            emit_map[op_name] = {
                "emit_style": "list",
                "items_path": f"response.{lf}",
                "list_field": lf,
            }
        elif len(list_fields) > 1:
            emit_map[op_name] = {
                "emit_style": "multi_list",
                "list_fields": list(list_fields.keys()),
                "note": "Multiple list fields — pick primary or emit one per field",
            }
        elif struct_fields:
            # Structure response: flat emit — emit from response.<struct_field>.*
            primary = next(iter(struct_fields))
            emit_map[op_name] = {
                "emit_style": "flat",
                "response_field": primary,
                "field_type": "structure",
                "note": f"Flat emit — do NOT use items_for, access via response.{primary}.*",
            }
        elif scalar_fields:
            emit_map[op_name] = {
                "emit_style": "flat",
                "response_fields": list(scalar_fields.keys()),
                "field_type": "scalar",
                "note": "Flat emit — access top-level response fields directly",
            }

    return dict(sorted(emit_map.items()))


# ── Main ──────────────────────────────────────────────────────────────────────
param_source_map = build_param_source_map()
response_emit_map = build_response_emit_map()

print(f"\n=== param_source_map ({len(param_source_map)} entries) ===")
for param, info in param_source_map.items():
    print(f"  {param:15s} ← emit_field={info['emit_field']!r:12s} "
          f"from {info['producing_op']} via {info['items_path']}")

print(f"\n=== response_emit_map ({len(response_emit_map)} entries) ===")
for op_name, info in response_emit_map.items():
    style = info["emit_style"]
    path  = info.get("items_path") or info.get("response_field") or info.get("response_fields")
    print(f"  {op_name:50s} → {style:12s}  {path}")

if not WRITE:
    print("\n[DRY RUN] Pass --write to update step4_fields_produced_index.json in place.")
    sys.exit(0)

# Write enhanced step4
step4["param_source_map"]   = param_source_map
step4["response_emit_map"]  = response_emit_map
out_path = BASE / "step4_fields_produced_index.json"
out_path.write_text(json.dumps(step4, indent=2))
print(f"\nUpdated: {out_path}")
