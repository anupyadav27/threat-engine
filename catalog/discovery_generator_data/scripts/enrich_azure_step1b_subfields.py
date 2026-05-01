#!/usr/bin/env python3
"""
enrich_azure_step1b_subfields.py — Add depth-1 and depth-2 sub-model fields to step1b.

For each Azure service with step1b_operation_registry.json:
  1. Import the service's azure.mgmt.{service}.operations + .models
  2. For each read_list and read_get op, extract the return model via type hints
  3. Enumerate model fields via _attribute_map (old SDK) or __annotations__ (new SDK)
  4. For complex-type fields (another model class), enumerate sub-model fields
  5. Add any missing value[].field and value[].field.sub_field entries to produces
  6. Write updated step1b back in-place

SDK format support:
  - Old SDK: _attribute_map on model class (most azure-mgmt-* packages)
  - New SDK: __annotations__ without _attribute_map (e.g. azure-mgmt-keyvault 14.x)
  - Parent class MRO merging: collects _attribute_map from all parent classes

Usage:
    python3 catalog/discovery_generator/scripts/enrich_azure_step1b_subfields.py
    python3 ...  --dry-run              # show what would change
    python3 ...  --service storage      # single service
    python3 ...  --depth 1              # only depth-1 (no sub-model recursion)
"""

from __future__ import annotations

import argparse
import importlib
import json
import typing
from collections import defaultdict
from pathlib import Path

# ── paths ──────────────────────────────────────────────────────────────────────

AZURE_ROOT = Path("catalog/discovery_generator/azure")
SKIP_DIRS  = {"tools", "__pycache__", "temp_code", ".git"}

# ── constants ──────────────────────────────────────────────────────────────────

# Primitive type strings in Azure SDK _attribute_map
_PRIMITIVE_TYPES = {
    "str", "bool", "int", "float", "long", "object",
    "iso-8601", "rfc-1123", "duration", "base64",
    "bytes", "bytearray", "dict", "list", "None",
}

# These types are dicts/lists of primitives — not sub-models
_CONTAINER_PREFIXES = ("{", "[")

# Op kinds to enrich
_ENRICH_KINDS = {"read_list", "read_get"}


def _is_complex_type(type_str: str) -> bool:
    """Return True if type_str refers to a model class (not a primitive/container)."""
    if not type_str:
        return False
    if type_str in _PRIMITIVE_TYPES:
        return False
    if type_str.startswith(_CONTAINER_PREFIXES):
        return False
    # Azure SDK: model names are CamelCase, start with uppercase
    return type_str[0].isupper()


def _is_model_class(cls) -> bool:
    """Return True if cls is an Azure SDK model class.

    Handles both old SDK (_attribute_map) and new SDK (__annotations__).
    """
    if cls is None or not isinstance(cls, type):
        return False
    # Old SDK: has _attribute_map anywhere in MRO
    for c in cls.__mro__:
        if c is object:
            continue
        if c.__dict__.get("_attribute_map"):
            return True
    # New SDK: has non-private __annotations__ and is from azure namespace
    ann = getattr(cls, "__annotations__", {})
    module = getattr(cls, "__module__", "") or ""
    if ann and "azure" in module and any(not k.startswith("_") for k in ann):
        return True
    return False


def _extract_type_name(annotation) -> str:
    """Extract a simple type name string from a Python annotation.

    Handles:
      - str forward references: '_models.VaultProperties' → 'VaultProperties'
      - Optional[X]            → type name of X
      - List[X]                → type name of X (for list fields)
      - Plain class            → class __name__
    """
    if annotation is None:
        return ""

    if isinstance(annotation, str):
        name = annotation.strip("'\"")
        # Strip module prefix: '_models.Foo' → 'Foo'
        if "." in name:
            name = name.rsplit(".", 1)[-1]
        # Strip Optional wrapper written as string
        if name.startswith("Optional[") and name.endswith("]"):
            name = name[9:-1]
        return name

    # typing.Union / Optional[X, None]
    origin = getattr(annotation, "__origin__", None)
    if origin is typing.Union:
        args = typing.get_args(annotation)
        non_none = [a for a in args if a is not type(None)]
        if non_none:
            return _extract_type_name(non_none[0])
        return ""

    # List-like: List[X], list[X]
    if origin in (list,) or (
        origin is not None
        and getattr(origin, "__name__", "") in ("list", "List")
    ):
        args = typing.get_args(annotation)
        if args:
            return _extract_type_name(args[0])
        return ""
    # typing.List without origin
    if hasattr(annotation, "__args__") and getattr(annotation, "__origin__", None) is None:
        pass  # fall through to __name__

    if hasattr(annotation, "__name__"):
        return annotation.__name__

    return ""


def _get_model_fields(model_cls) -> dict[str, str]:
    """Return {field_name: type_str} for a model class.

    Collects fields via:
    1. _attribute_map from ALL classes in MRO (handles parent class fields)
    2. __annotations__ from ALL classes in MRO (for new-SDK models without _attribute_map)

    Returns dict ordered: child-class fields first, parent fields after.
    """
    fields: dict[str, str] = {}
    has_attr_map = False

    # Strategy 1: walk MRO and collect every _attribute_map entry
    for cls in model_cls.__mro__:
        if cls is object:
            continue
        attr_map = cls.__dict__.get("_attribute_map", {})
        if attr_map:
            has_attr_map = True
        for field_name, attr_info in attr_map.items():
            if field_name not in fields:
                if isinstance(attr_info, dict):
                    fields[field_name] = attr_info.get("type", "")
                else:
                    fields[field_name] = str(attr_info)

    # Strategy 2: __annotations__ from MRO (new SDK format, no _attribute_map)
    if not has_attr_map:
        for cls in model_cls.__mro__:
            if cls is object:
                continue
            ann = cls.__dict__.get("__annotations__", {})
            for field_name, annotation in ann.items():
                if field_name.startswith("_"):
                    continue
                if field_name not in fields:
                    fields[field_name] = _extract_type_name(annotation)

    return fields


import re as _re


def _unwrap_list_model(model_cls, models_module) -> type:
    """
    If model_cls is a page-wrapper (has value: [ItemModel]), return ItemModel.
    E.g. AccountList → Account.  Otherwise returns model_cls unchanged.
    """
    fields = _get_model_fields(model_cls)
    value_type = fields.get("value", "")

    # Old SDK: type string is '[ModelName]'
    if value_type.startswith("[") and value_type.endswith("]"):
        inner_name = value_type[1:-1]
        inner_cls  = getattr(models_module, inner_name, None)
        if inner_cls is not None and _is_model_class(inner_cls):
            return inner_cls

    return model_cls


def _model_from_docstring(method, models_module) -> typing.Optional[type]:
    """
    Parse ':rtype: ~...ItemPaged[~...models.SomeModel]' from docstring.
    Returns the model class or None.
    """
    doc = method.__doc__ or ""
    # Match ItemPaged[...models.ModelName] or just ...models.ModelName
    m = _re.search(r"ItemPaged\[~[\w.]+models\.([\w]+)\]", doc)
    if not m:
        m = _re.search(r":rtype:.*~[\w.]+models\.([\w]+)", doc)
    if m:
        name = m.group(1)
        cls  = getattr(models_module, name, None)
        if cls is not None and _is_model_class(cls):
            return cls
    return None


def _model_from_class_name(class_name: str, models_module) -> typing.Optional[type]:
    """
    Heuristic: AccountsOperations → try 'Account', 'Accounts'.
    """
    # Strip 'Operations' suffix
    base = class_name.replace("Operations", "").rstrip("s")
    for name in (base, base + "s", base.rstrip("s")):
        cls = getattr(models_module, name, None)
        if cls is not None and _is_model_class(cls):
            # Reject if it looks like a *List wrapper itself
            if not name.endswith("List"):
                return cls
    return None


def _get_return_model(
    ops_module,
    models_module,
    class_name: str,
    operation: str,
) -> typing.Optional[type]:
    """
    Get the item-level return model class for an operation method.
    Handles:
      - ItemPaged[ItemModel]          — type-hint path
      - ItemPaged[ItemListModel]      — unwraps value:[ItemModel]
      - No annotations → docstring   — parses :rtype: line
      - Still nothing → class name   — heuristic fallback
    """
    cls = getattr(ops_module, class_name, None)
    if cls is None:
        return None

    method = getattr(cls, operation, None)
    if method is None:
        return None

    model_cls = None

    # ── Strategy 1: type hints ───────────────────────────────────────────────
    try:
        hints = typing.get_type_hints(method)
        ret_type = hints.get("return")
        if ret_type is not None:
            args = typing.get_args(ret_type)
            candidate = args[0] if args else ret_type
            if _is_model_class(candidate):
                model_cls = candidate
    except Exception:
        pass

    # ── Strategy 2: docstring :rtype: ───────────────────────────────────────
    if model_cls is None:
        model_cls = _model_from_docstring(method, models_module)

    # ── Strategy 3: class-name heuristic ────────────────────────────────────
    if model_cls is None:
        model_cls = _model_from_class_name(class_name, models_module)

    if model_cls is None:
        return None

    # ── Unwrap page-wrapper (*List models) ───────────────────────────────────
    model_cls = _unwrap_list_model(model_cls, models_module)

    return model_cls


def _build_new_produces(
    op: dict,
    models_module,
    ops_module,
    max_depth: int = 2,
) -> list[dict]:
    """
    Return a list of new produce entries to add to op['produces'].
    Does not modify op in place.
    """
    class_name = op.get("class_name", "")
    operation  = op.get("operation", "")
    kind       = op.get("kind", "")
    op_id      = op.get("operation_id", "")
    service    = op_id.split(".")[1] if op_id.count(".") >= 2 else ""

    if kind not in _ENRICH_KINDS:
        return []

    model_cls = _get_return_model(ops_module, models_module, class_name, operation)
    if model_cls is None:
        return []

    # Determine path prefix
    # read_list → "value[]", read_get → "value"
    prefix = "value[]" if kind == "read_list" else "value"

    # Build set of existing paths
    existing_paths: set[str] = {
        p["path"]
        for p in op.get("produces", [])
        if isinstance(p, dict) and p.get("path")
    }

    new_entries: list[dict] = []

    # Get all fields using combined _attribute_map / __annotations__ approach
    model_fields = _get_model_fields(model_cls)

    for attr_name, field_type in model_fields.items():
        depth1_path = f"{prefix}.{attr_name}"

        # ── depth-1 ──────────────────────────────────────────────────────────
        if depth1_path not in existing_paths:
            entity = f"{service}.value_{attr_name}"
            new_entries.append({
                "entity": entity,
                "source": "item",
                "path":   depth1_path,
            })
            existing_paths.add(depth1_path)

        # ── depth-2 ──────────────────────────────────────────────────────────
        if max_depth >= 2 and _is_complex_type(field_type):
            sub_cls = getattr(models_module, field_type, None)
            if sub_cls is None or not _is_model_class(sub_cls):
                continue

            sub_fields = _get_model_fields(sub_cls)
            for sub_attr_name in sub_fields:
                depth2_path = f"{depth1_path}.{sub_attr_name}"
                if depth2_path not in existing_paths:
                    entity = f"{service}.value_{attr_name}_{sub_attr_name}"
                    new_entries.append({
                        "entity": entity,
                        "source": "item",
                        "path":   depth2_path,
                    })
                    existing_paths.add(depth2_path)

    return new_entries


# ── service enricher ───────────────────────────────────────────────────────────

def enrich_service(
    svc_dir: Path,
    *,
    dry_run: bool = False,
    max_depth: int = 2,
) -> dict:
    """Enrich one service's step1b. Returns stats dict."""
    service = svc_dir.name
    step1b_path = svc_dir / "step1b_operation_registry.json"

    stats: dict = {
        "service":       service,
        "status":        "ok",
        "ops_enriched":  0,
        "fields_added":  0,
        "import_error":  "",
    }

    if not step1b_path.exists():
        stats["status"] = "no_step1b"
        return stats

    with open(step1b_path) as f:
        data = json.load(f)

    module_name = data.get("module", f"azure.mgmt.{service}")
    ops_mod_name = f"{module_name}.operations"
    mdl_mod_name = f"{module_name}.models"

    try:
        ops_module = importlib.import_module(ops_mod_name)
        mdl_module = importlib.import_module(mdl_mod_name)
    except ImportError as e:
        stats["status"] = "import_error"
        stats["import_error"] = str(e)
        return stats

    operations = data.get("operations", {})
    modified = False

    for op_id, op in operations.items():
        if not isinstance(op, dict):
            continue
        if op.get("kind") not in _ENRICH_KINDS:
            continue

        new_entries = _build_new_produces(op, mdl_module, ops_module, max_depth)
        if new_entries:
            if not dry_run:
                op.setdefault("produces", []).extend(new_entries)
            stats["ops_enriched"] += 1
            stats["fields_added"] += len(new_entries)
            modified = True

    if modified and not dry_run:
        with open(step1b_path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")

    return stats


# ── main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich step1b with sub-model field paths")
    parser.add_argument("--dry-run",  action="store_true", help="Show changes without writing")
    parser.add_argument("--service",  help="Comma-separated service names to limit scope")
    parser.add_argument("--depth",    type=int, default=2, choices=[1, 2],
                        help="Max recursion depth (default: 2)")
    args = parser.parse_args()

    service_filter = None
    if args.service:
        service_filter = {s.strip() for s in args.service.split(",")}

    # Collect service dirs
    svc_dirs = sorted(
        d for d in AZURE_ROOT.iterdir()
        if d.is_dir() and d.name not in SKIP_DIRS and not d.name.startswith(".")
    )
    if service_filter:
        svc_dirs = [d for d in svc_dirs if d.name in service_filter]

    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"Enriching {len(svc_dirs)} service dirs (depth={args.depth}, {mode})")
    print("=" * 70)

    totals = defaultdict(int)
    errors: list[str] = []

    for svc_dir in svc_dirs:
        stats = enrich_service(svc_dir, dry_run=args.dry_run, max_depth=args.depth)
        status = stats["status"]

        if status == "no_step1b":
            totals["no_step1b"] += 1
            continue
        if status == "import_error":
            totals["import_error"] += 1
            errors.append(f"{svc_dir.name}: {stats['import_error']}")
            continue

        totals["processed"] += 1
        totals["ops_enriched"] += stats["ops_enriched"]
        totals["fields_added"] += stats["fields_added"]

        if stats["ops_enriched"] > 0:
            print(f"  {svc_dir.name:<40}  ops={stats['ops_enriched']:>3}  "
                  f"fields_added={stats['fields_added']:>5}")

    print("=" * 70)
    print(f"Processed:    {totals['processed']}")
    print(f"No step1b:    {totals['no_step1b']}")
    print(f"Import error: {totals['import_error']}")
    print(f"Ops enriched: {totals['ops_enriched']}")
    print(f"Fields added: {totals['fields_added']}")

    if errors:
        print(f"\nImport errors ({len(errors)}):")
        for e in errors[:20]:
            print(f"  {e}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more")

    if args.dry_run:
        print("\n[DRY RUN] No files written.")
    else:
        print(f"\nRun generate_azure_master_field_catalog.py to rebuild the CSV.")


if __name__ == "__main__":
    main()
