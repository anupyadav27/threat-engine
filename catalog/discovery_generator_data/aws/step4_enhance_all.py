#!/usr/bin/env python3
"""step4_enhance_all.py — Batch enhance all AWS step4_fields_produced_index.json files.

Adds two new sections to every catalog/aws/{svc}/step4_fields_produced_index.json:
  - param_source_map: API param → {entity, emit_field, producing_op, discovery_id, items_path}
  - response_emit_map: op_name → {emit_style, items_path | response_field | response_fields}

These are derived purely from step1 + step4.fields — no external input required.
The S3-specific FIELD_OVERRIDES from step4_enhancer.py are NOT applied here;
the generic algorithm handles the vast majority of services correctly.

Usage:
    python3 step4_enhance_all.py           # dry-run (shows counts per service)
    python3 step4_enhance_all.py --write   # update all step4 files in place
    python3 step4_enhance_all.py --write --service s3  # single service only
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
from collections import Counter

WRITE   = "--write"   in sys.argv
CATALOG = Path(__file__).parent          # catalog/aws/

# Single-service filter (--service <name>)
_svc_flag = None
if "--service" in sys.argv:
    idx = sys.argv.index("--service")
    if idx + 1 < len(sys.argv):
        _svc_flag = sys.argv[idx + 1]

# ── Constants ─────────────────────────────────────────────────────────────────

_SKIP_LIST_FIELDS = {
    "CommonPrefixes", "DeleteMarkers", "ContinuationToken",
    "NextContinuationToken", "NextMarker", "NextKeyMarker",
    "NextVersionIdMarker", "NextUploadIdMarker", "MaxUploads",
    "MaxKeys", "MaxParts", "Delimiter", "EncodingType",
    "KeyCount", "Prefix", "Bucket", "Name", "Marker",
    "VersionIdMarker", "UploadIdMarker",
}

_SKIP_EMIT_FIELDS = {
    "ResponseMetadata", "ContinuationToken", "IsTruncated",
    "NextContinuationToken", "NextMarker", "NextKeyMarker",
    "NextVersionIdMarker", "NextUploadIdMarker", "MaxUploads",
    "MaxKeys", "MaxParts", "Delimiter", "EncodingType",
    "KeyCount", "Prefix", "Bucket", "Name", "Marker",
    "VersionIdMarker", "UploadIdMarker",
    "CommonPrefixes", "DeleteMarkers",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _disc_id(op_name: str, provider: str, service: str) -> str:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", op_name).lower()
    return f"{provider}.{service}.{snake}"


def _primary_list_field(op_name: str, op_by_name: dict) -> str | None:
    op = op_by_name.get(op_name, {})
    candidates = [
        k for k, v in op.get("output_fields", {}).items()
        if v.get("type") == "list" and k not in _SKIP_LIST_FIELDS
    ]
    return candidates[0] if candidates else None


# ── Section 1: param_source_map ───────────────────────────────────────────────

def build_param_source_map(
    step4: dict,
    op_by_name: dict,
    provider: str,
    service: str,
) -> dict:
    """
    Maps API param name → {entity, emit_field, producing_op, discovery_id, items_path}.

    Algorithm:
      For each field_name in step4.fields that has a dependency_index_entity:
        Step A: find the API param name
          - Case 1: field_name IS in a consumer's required_params → param = field_name
          - Case 2: name mismatch → count required_params across all ops that output
                    this field; the most common is the "parent" param name
        Step B: find the best producing op
          - List ops that output this field but do NOT require it as a param
          - Sort by fewest required_params (most independent first)
      Override: skip param if already claimed by an earlier field.
    """
    param_source: dict = {}

    for field_name, fdata in step4.get("fields", {}).items():
        entity = fdata.get("dependency_index_entity")
        if not entity:
            continue
        ops_with_field = fdata.get("operations", [])
        if not ops_with_field:
            continue

        # ── Step A: derive param name ─────────────────────────────────────────
        direct_consumers = [
            n for n in ops_with_field
            if field_name in op_by_name.get(n, {}).get("required_params", [])
        ]
        if direct_consumers:
            param = field_name
        else:
            counter: Counter = Counter()
            for op_name in ops_with_field:
                for p in op_by_name.get(op_name, {}).get("required_params", []):
                    counter[p] += 1
            if not counter:
                continue
            param = counter.most_common(1)[0][0]

        # ── Step B: find best producing op ───────────────────────────────────
        producers = [
            n for n in ops_with_field
            if n.startswith("List")
            and field_name not in op_by_name.get(n, {}).get("required_params", [])
        ]
        if not producers:
            continue
        producers.sort(
            key=lambda n: len(op_by_name.get(n, {}).get("required_params", []))
        )
        best_producer = producers[0]

        # Skip if param already claimed by an earlier field
        if param in param_source:
            continue

        list_field = _primary_list_field(best_producer, op_by_name)
        items_path = f"response.{list_field}" if list_field else None
        disc = _disc_id(best_producer, provider, service)

        param_source[param] = {
            "entity":       entity,
            "emit_field":   field_name,
            "producing_op": best_producer,
            "discovery_id": disc,
            "items_path":   items_path,
            "note": (
                f"When dependent op needs '{param}' param, "
                f"use for_each={disc} "
                f"and set {param}='{{{{ item.{field_name} }}}}'"
            ),
        }

    return dict(sorted(param_source.items()))


# ── Section 2: response_emit_map ──────────────────────────────────────────────

def build_response_emit_map(step1: dict) -> dict:
    """
    Maps op_name → {emit_style, items_path | response_field | response_fields}.

    Rules:
      - Single list output field  → emit_style: list,       items_path: response.<field>
      - Multiple list output fields→ emit_style: multi_list, list_fields: [...]
      - Structure output field    → emit_style: flat,       response_field: <field>
      - Scalar output fields      → emit_style: flat,       response_fields: [...]
    Only covers Get*/List*/Describe* ops (read-only).
    """
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
            if v.get("type") == "list" and k not in _SKIP_EMIT_FIELDS
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
            emit_map[op_name] = {
                "emit_style": "multi_list",
                "list_fields": list(list_fields.keys()),
                "note": "Multiple list fields — pick primary or emit one per field",
            }
        elif struct_fields:
            primary = next(iter(struct_fields))
            emit_map[op_name] = {
                "emit_style": "flat",
                "response_field": primary,
                "field_type": "structure",
                "note": (
                    f"Flat emit — do NOT use items_for, "
                    f"access via response.{primary}.*"
                ),
            }
        elif scalar_fields:
            emit_map[op_name] = {
                "emit_style": "flat",
                "response_fields": list(scalar_fields.keys()),
                "field_type": "scalar",
                "note": "Flat emit — access top-level response fields directly",
            }

    return dict(sorted(emit_map.items()))


# ── Per-service enhancer ──────────────────────────────────────────────────────

def enhance_service(svc_dir: Path) -> tuple[str, int, int]:
    """
    Returns (status, n_param_entries, n_emit_entries).
    status: 'ok' | 'skipped' | 'error: ...' | 'already_done'
    """
    step1_path = svc_dir / "step1_api_driven_registry.json"
    step4_path = svc_dir / "step4_fields_produced_index.json"

    if not step1_path.exists() or not step4_path.exists():
        return "skipped", 0, 0

    try:
        step1_raw = json.loads(step1_path.read_text())
        svc_key   = next(iter(step1_raw))
        step1     = step1_raw[svc_key]
        provider  = "aws"
        service   = step1.get("service", svc_dir.name)

        step4 = json.loads(step4_path.read_text())

        all_ops    = step1.get("independent", []) + step1.get("dependent", [])
        op_by_name = {op["operation"]: op for op in all_ops}

        param_source_map = build_param_source_map(step4, op_by_name, provider, service)
        response_emit_map = build_response_emit_map(step1)

        step4["param_source_map"]  = param_source_map
        step4["response_emit_map"] = response_emit_map

        if WRITE:
            step4_path.write_text(json.dumps(step4, indent=2))

        return "ok", len(param_source_map), len(response_emit_map)

    except Exception as e:
        return f"error: {e}", 0, 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    mode = "WRITE" if WRITE else "DRY RUN"
    print(f"step4_enhance_all.py [{mode}]")
    if _svc_flag:
        print(f"  Single service filter: {_svc_flag}")
    print()

    counts = dict(ok=0, already_done=0, skipped=0, error=0)
    total_params = 0
    total_emit   = 0
    errors: list[tuple[str, str]] = []

    for svc_dir in sorted(CATALOG.iterdir()):
        if not svc_dir.is_dir():
            continue
        svc = svc_dir.name
        if svc.endswith((".py", ".json", ".yaml", ".md", ".csv", ".txt")):
            continue
        if _svc_flag and svc != _svc_flag:
            continue

        status, n_params, n_emit = enhance_service(svc_dir)

        if status == "ok":
            counts["ok"] += 1
            total_params += n_params
            total_emit   += n_emit
            if n_params > 0 or n_emit > 0:
                print(f"  {svc:<40} → {n_params:>3} params  {n_emit:>3} emit ops")
        elif status == "skipped":
            counts["skipped"] += 1
        elif status == "already_done":
            counts["already_done"] += 1
        else:
            counts["error"] += 1
            errors.append((svc, status))
            print(f"  {svc:<40} → {status}")

    print()
    print("=" * 65)
    print(f"  {counts['ok']:>4}  services enhanced  "
          f"({total_params} param mappings, {total_emit} emit mappings)")
    if counts["already_done"]:
        print(f"  {counts['already_done']:>4}  already had both sections (re-written)")
    if counts["skipped"]:
        print(f"  {counts['skipped']:>4}  skipped (no step1 or step4)")
    if counts["error"]:
        print(f"  {counts['error']:>4}  errors")
        for svc, err in errors[:10]:
            print(f"       {svc}: {err}")

    if not WRITE:
        print()
        print("[DRY RUN] Pass --write to update step4 files in place.")


if __name__ == "__main__":
    main()
