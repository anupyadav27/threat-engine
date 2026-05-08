#!/usr/bin/env python3
"""step6_patch_all.py — Fix items_for type bugs in all AWS step6 discovery YAMLs.

Root cause: the step6 generator used items_for on structure/scalar/map/blob fields,
which are not iterable. Only list-type output fields are valid for items_for.

Fixes applied per op:
  1. items_for on a structure field → remove items_for, fix {{ item.X }} → {{ response.F.X }}
  2. items_for on a wrong list field → update items_for to the correct path
  3. items_for on scalar/map/blob → remove items_for, fix templates → {{ response.X }}
  4. items_for on UNKNOWN field (not in step1) → use response_emit_map to determine action

Preserves:
  - All correct ops (list-type items_for pointing to the right field)
  - Existing for_each / params assignments (generally correct)
  - Existing emit.item sub-field lists (correct sub-fields, wrong template prefix)
  - YAML file header/metadata

Output format matches catalog/aws/s3/step6_s3.discovery.yaml (yaml.safe_dump).

Usage:
    python3 step6_patch_all.py           # dry-run: show what would change
    python3 step6_patch_all.py --write   # apply fixes to all step6 files
    python3 step6_patch_all.py --write --service ec2   # single service
    python3 step6_patch_all.py --service ec2           # dry-run single service
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
from collections import Counter

import yaml

WRITE   = "--write"   in sys.argv
CATALOG = Path(__file__).parent

_svc_flag: str | None = None
if "--service" in sys.argv:
    idx = sys.argv.index("--service")
    if idx + 1 < len(sys.argv):
        _svc_flag = sys.argv[idx + 1]

# ── Skip fields (pagination / metadata noise) ─────────────────────────────────
_SKIP_EMIT_FIELDS = {
    "ResponseMetadata", "ContinuationToken", "IsTruncated",
    "NextContinuationToken", "NextMarker", "NextKeyMarker",
    "NextVersionIdMarker", "NextUploadIdMarker", "MaxUploads",
    "MaxKeys", "MaxParts", "Delimiter", "EncodingType",
    "KeyCount", "Prefix", "Bucket", "Name", "Marker",
    "VersionIdMarker", "UploadIdMarker",
    "CommonPrefixes", "DeleteMarkers",
}

_SKIP_LIST_FIELDS = _SKIP_EMIT_FIELDS


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_op_lookup(op_by_name: dict) -> dict:
    """
    Build a normalised lookup: lowercase_no_underscores → PascalCase op name.

    boto3 snake_case and PascalCase don't round-trip cleanly for acronyms
    (ListOpenIDConnectProviders ↔ list_open_id_connect_providers), so we
    match by stripping underscores + lowercasing both sides.
    """
    return {k.lower().replace("_", ""): k for k in op_by_name}


def _lookup_op(method_snake: str, op_lookup: dict) -> str | None:
    """list_open_id_connect_providers → 'ListOpenIDConnectProviders' (via normalised lookup)."""
    key = method_snake.lower().replace("_", "")
    return op_lookup.get(key)


def _disc_method(disc_id: str) -> str:
    """aws.s3.get_bucket_acl → get_bucket_acl"""
    return disc_id.split(".")[-1]


def _extract_response_field(template: str) -> str | None:
    """'{{ response.Grants }}' → 'Grants'"""
    m = re.match(r"\{\{\s*response\.(\w+)\s*\}\}", str(template))
    return m.group(1) if m else None


def _fix_item_templates_to_flat(
    item: dict,
    struct_field: str | None,
) -> dict:
    """
    Convert emit.item templates from items_for ({{ item.X }}) style to flat style.

    If struct_field is given:  {{ item.X }} → {{ response.StructField.X }}
    If struct_field is None:   {{ item.X }} → {{ response.X }}   (scalar / top-level)
    """
    fixed = {}
    for k, v in item.items():
        v_str = str(v)
        if struct_field:
            # Replacement string for re.sub (NOT an f-string after concatenation):
            # "{{ response.Field.\1 }}" — braces here are literal regex replacement chars
            repl = "{{{{ response.{}.".format(struct_field) + r"\1 }}"
            new_v = re.sub(r"\{\{\s*item\.(\w+)\s*\}\}", repl, v_str)
        else:
            new_v = re.sub(
                r"\{\{\s*item\.(\w+)\s*\}\}",
                r"{{ response.\1 }}",
                v_str,
            )
        fixed[k] = new_v
    return fixed


def _build_response_emit_map(step1: dict) -> dict:
    """Compute response_emit_map inline from step1 (same logic as step4_enhance_all.py)."""
    emit_map: dict = {}

    read_ops = step1.get("independent", []) + [
        op for op in step1.get("dependent", [])
        if op.get("read_only", True)
    ]

    for op in read_ops:
        op_name = op["operation"]
        if not any(op_name.startswith(p) for p in ("Get", "List", "Describe")):
            continue
        out_fields = op.get("output_fields", {})
        if not out_fields:
            continue

        list_fields = {
            k: v for k, v in out_fields.items()
            if v.get("type") == "list" and k not in _SKIP_LIST_FIELDS
        }
        struct_fields = {
            k: v for k, v in out_fields.items()
            if v.get("type") == "structure" and k not in _SKIP_EMIT_FIELDS
        }
        scalar_fields = {
            k: v for k, v in out_fields.items()
            if v.get("type") in (
                "string", "boolean", "integer", "long",
                "timestamp", "double",
            )
            and k not in _SKIP_EMIT_FIELDS
        }

        if len(list_fields) == 1:
            lf = next(iter(list_fields))
            emit_map[op_name] = {
                "emit_style": "list",
                "items_path": f"response.{lf}",
                "list_field": lf,
            }
        elif len(list_fields) > 1:
            # Pick first non-skip list field as primary
            primary_lf = next(iter(list_fields))
            emit_map[op_name] = {
                "emit_style": "multi_list",
                "list_fields": list(list_fields.keys()),
                "primary_list_field": primary_lf,
            }
        elif struct_fields:
            primary = next(iter(struct_fields))
            emit_map[op_name] = {
                "emit_style": "flat",
                "response_field": primary,
                "field_type": "structure",
            }
        elif scalar_fields:
            emit_map[op_name] = {
                "emit_style": "flat",
                "response_fields": list(scalar_fields.keys()),
                "field_type": "scalar",
            }

    return emit_map


# ── Core fix function ─────────────────────────────────────────────────────────

def fix_op(op: dict, op_by_name: dict, emit_map: dict, op_lookup: dict | None = None) -> tuple[dict, str]:
    """
    Fix one discovery op's emit section.

    Returns (fixed_op, change_label) where change_label is '' if no change.
    """
    emit = op.get("emit")
    if not isinstance(emit, dict):
        return op, ""

    items_for = emit.get("items_for")
    if not items_for:
        return op, ""

    current_field = _extract_response_field(str(items_for))
    if not current_field:
        return op, ""

    # Resolve discovery_id method to the exact step1 API op name (handles acronyms)
    method_snake = _disc_method(op.get("discovery_id", ""))
    pascal_name  = _lookup_op(method_snake, op_lookup) if op_lookup else None

    # Look up step1 type for current_field in this op's output
    step1_op   = op_by_name.get(pascal_name, {}) if pascal_name else {}
    out_fields = step1_op.get("output_fields", {})
    field_type = out_fields.get(current_field, {}).get("type", "UNKNOWN")

    # Get the authoritative emit info
    emit_info  = emit_map.get(pascal_name, {}) if pascal_name else {}
    emit_style = emit_info.get("emit_style", "")

    # ── Case 1: field IS a list ───────────────────────────────────────────────
    if field_type == "list":
        expected_path  = emit_info.get("items_path", "")
        if expected_path:
            expected_field = expected_path.rsplit(".", 1)[-1]
            if expected_field != current_field:
                # Correct list op, wrong field name → update items_for
                new_emit = {**emit, "items_for": f"{{{{ response.{expected_field} }}}}"}
                op = {**op, "emit": new_emit}
                return op, f"list field corrected: {current_field}→{expected_field}"
        return op, ""   # correct — no change

    # ── Case 2: field is a structure ──────────────────────────────────────────
    if field_type == "structure":
        # The actual struct field in step1 for this op
        actual_struct = (
            emit_info.get("response_field")
            or next((k for k, v in out_fields.items() if v.get("type") == "structure"), None)
        )
        new_emit = {k: v for k, v in emit.items() if k != "items_for"}
        item     = emit.get("item") or {}

        if isinstance(item, dict) and current_field == actual_struct:
            # items_for used same structure field → just fix templates
            new_emit["item"] = _fix_item_templates_to_flat(item, current_field)
            label = f"structure flat: removed items_for, fixed templates (response.{current_field}.*)"
        elif actual_struct:
            # items_for used wrong field → emit whole structure
            new_emit["item"] = _fix_item_templates_to_flat(item, actual_struct)
            label = (
                f"structure flat: wrong field {current_field}→{actual_struct}, "
                f"fixed templates"
            )
        else:
            # Can't determine structure field — just remove items_for + fix item.X → response.X
            if isinstance(item, dict):
                new_emit["item"] = _fix_item_templates_to_flat(item, None)
            label = f"structure flat: removed items_for=response.{current_field}"

        op = {**op, "emit": new_emit}
        return op, label

    # ── Case 3: field is a scalar/map/blob ────────────────────────────────────
    if field_type in ("string", "boolean", "integer", "long",
                      "timestamp", "double", "map", "blob"):
        new_emit = {k: v for k, v in emit.items() if k != "items_for"}
        item = emit.get("item") or {}
        if isinstance(item, dict):
            new_emit["item"] = _fix_item_templates_to_flat(item, None)
        op = {**op, "emit": new_emit}
        return op, f"scalar/map/blob flat: removed items_for=response.{current_field}"

    # ── Case 4: UNKNOWN field (not in step1.output_fields for this op) ───────
    # The step6 generator assigned a field from another op — use emit_map
    if emit_style == "list":
        expected_path  = emit_info.get("items_path", "")
        if expected_path:
            expected_field = expected_path.rsplit(".", 1)[-1]
            if expected_field != current_field:
                new_emit = {**emit, "items_for": f"{{{{ response.{expected_field} }}}}"}
                op = {**op, "emit": new_emit}
                return op, f"UNKNOWN→list: corrected items_for {current_field}→{expected_field}"
        return op, ""   # can't determine — leave as is

    if emit_style == "flat":
        response_field = emit_info.get("response_field")
        response_fields = emit_info.get("response_fields", [])
        new_emit = {k: v for k, v in emit.items() if k != "items_for"}
        item = emit.get("item") or {}

        if response_field and isinstance(item, dict):
            # Structure response — fix templates to use the correct field
            new_emit["item"] = _fix_item_templates_to_flat(item, response_field)
            label = (
                f"UNKNOWN→flat: removed items_for=response.{current_field}, "
                f"fixed to response.{response_field}.*"
            )
        elif response_fields and isinstance(item, dict):
            # Scalar fields — fix templates to direct response references
            new_emit["item"] = _fix_item_templates_to_flat(item, None)
            label = f"UNKNOWN→flat: removed items_for=response.{current_field}, scalar refs"
        else:
            if isinstance(item, dict):
                new_emit["item"] = _fix_item_templates_to_flat(item, None)
            label = f"UNKNOWN→flat: removed items_for=response.{current_field}"

        op = {**op, "emit": new_emit}
        return op, label

    # No emit_map entry and type is UNKNOWN — leave as is
    return op, ""


# ── Per-service patcher ───────────────────────────────────────────────────────

def patch_service(svc_dir: Path) -> tuple[str, int, int]:
    """
    Returns (status, n_ops_total, n_ops_fixed).
    """
    svc    = svc_dir.name
    step6  = svc_dir / f"step6_{svc}.discovery.yaml"
    step1f = svc_dir / "step1_api_driven_registry.json"

    if not step6.exists() or not step1f.exists():
        return "skipped", 0, 0

    try:
        raw       = step6.read_text()
        parsed    = yaml.safe_load(raw)
        disc_list = parsed.get("discovery") or []

        step1_raw  = json.loads(step1f.read_text())
        svc_key    = next(iter(step1_raw))
        step1      = step1_raw[svc_key]
        all_ops    = step1.get("independent", []) + step1.get("dependent", [])
        op_by_name = {op["operation"]: op for op in all_ops}
        op_lookup  = _build_op_lookup(op_by_name)

        emit_map = _build_response_emit_map(step1)

        fixed_list = []
        n_fixed    = 0
        for op in disc_list:
            if not isinstance(op, dict):
                fixed_list.append(op)
                continue
            new_op, change = fix_op(op, op_by_name, emit_map, op_lookup)
            if change:
                n_fixed += 1
                if not WRITE:
                    # Print first few changes per service
                    if n_fixed <= 3:
                        print(f"    [{op.get('discovery_id','?')}] {change}")
                    elif n_fixed == 4:
                        print(f"    ... (more)")
            fixed_list.append(new_op)

        if n_fixed > 0 and WRITE:
            new_parsed = {**parsed, "discovery": fixed_list}
            step6.write_text(
                yaml.safe_dump(
                    new_parsed,
                    default_flow_style=False,
                    allow_unicode=True,
                    sort_keys=False,
                )
            )

        return "ok", len(disc_list), n_fixed

    except Exception as e:
        return f"error: {e}", 0, 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    mode = "WRITE" if WRITE else "DRY RUN"
    print(f"step6_patch_all.py [{mode}]")
    if _svc_flag:
        print(f"  Single service: {_svc_flag}")
    print()

    counts     = dict(ok=0, no_change=0, skipped=0, error=0)
    total_ops  = 0
    total_fixed = 0
    errors: list[tuple[str, str]] = []

    for svc_dir in sorted(CATALOG.iterdir()):
        if not svc_dir.is_dir():
            continue
        svc = svc_dir.name
        if svc.endswith((".py", ".json", ".yaml", ".md", ".csv", ".txt")):
            continue
        if _svc_flag and svc != _svc_flag:
            continue

        status, n_ops, n_fixed = patch_service(svc_dir)

        if status == "ok":
            total_ops   += n_ops
            total_fixed += n_fixed
            if n_fixed > 0:
                counts["ok"] += 1
                print(f"  {svc:<40} {n_fixed:>3} fixes / {n_ops} ops  "
                      f"{'→ written' if WRITE else ''}")
            else:
                counts["no_change"] += 1
        elif status == "skipped":
            counts["skipped"] += 1
        else:
            counts["error"] += 1
            errors.append((svc, status))
            print(f"  {svc:<40} ERROR: {status}")

    print()
    print("=" * 65)
    print(f"  {counts['ok']:>4}  services patched  "
          f"({total_fixed} ops fixed out of {total_ops} total)")
    if counts["no_change"]:
        print(f"  {counts['no_change']:>4}  services already correct (no changes)")
    if counts["skipped"]:
        print(f"  {counts['skipped']:>4}  skipped (no step1 or step6)")
    if counts["error"]:
        print(f"  {counts['error']:>4}  errors")
        for svc, err in errors[:10]:
            print(f"       {svc}: {err}")

    if not WRITE:
        print()
        print("[DRY RUN] Pass --write to apply fixes to all step6 files.")


if __name__ == "__main__":
    main()
