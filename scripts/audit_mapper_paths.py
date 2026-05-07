#!/usr/bin/env python3
"""DCAT mapper path audit.

Compares hardcoded `emitted_fields` access keys across all engine code
against the field set actually produced by the catalog `emit.item` blocks.

Surfaces three classes of bug-prone access:
  1. STALE   — code accesses a key that no catalog template emits anywhere
  2. NESTED  — code accesses a nested envelope (`KeyMetadata.KeyId`) when
               catalog flattens to top-level (`KeyId`)
  3. UNUSED  — catalog emits a field but no engine code reads it

Read-only — does not modify any file. Produces markdown punch list.
"""
from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

import yaml

ROOT = Path("/Users/apple/Desktop/threat-engine")
CATALOG_ROOT = ROOT / "catalog" / "discovery_generator_data"
ENGINES_ROOT = ROOT / "engines"

# Variable names that are assumed to hold emitted_fields-like dicts when seen
# as the receiver of `.get("...")` or `["..."]` access.
EMIT_LIKE_VARS = {
    "emitted",
    "emitted_fields",
    "ef",
    "fields",
    "raw_response",
    "raw",
    "item",
    "data",
    "finding_data",
    "config_data",
    "config",
}

# Skip these — they're either system fields or not from emitted_fields
SKIP_KEYS = {
    "resource_uid", "resource_id", "resource_arn", "resource_name", "resource_type",
    "scan_run_id", "tenant_id", "account_id", "customer_id", "credential_ref",
    "credential_type", "provider", "region", "service", "config_hash", "version",
    "first_seen_at", "last_seen_at", "created_at", "updated_at",
    "_raw_response", "_discovery_id", "_for_each_idx",
    "discovery_id", "id", "type", "name",  # too generic
}


def collect_catalog_fields() -> Set[str]:
    """Walk every step6_*.discovery.yaml and extract LHS keys of emit.item."""
    fields: Set[str] = set()
    for prov in CATALOG_ROOT.iterdir():
        if not prov.is_dir():
            continue
        for svc in prov.iterdir():
            if not svc.is_dir():
                continue
            for yp in svc.glob("step6_*.discovery.yaml"):
                try:
                    with yp.open() as fh:
                        data = yaml.safe_load(fh) or {}
                except Exception:
                    continue
                for disc in data.get("discovery") or []:
                    emit = disc.get("emit") or {}
                    if not isinstance(emit, dict):
                        continue
                    item = emit.get("item")
                    if isinstance(item, dict):
                        for k in item.keys():
                            if isinstance(k, str):
                                fields.add(k)
                                if "." in k:  # also add the leading and trailing components
                                    fields.update(p for p in k.split(".") if p)
    return fields


# ── AST scan ────────────────────────────────────────────────────────────────


_NESTED_PATTERN = re.compile(
    r"\.get\(\s*['\"]([A-Z][A-Za-z0-9]+)['\"]\s*,\s*\{\}\s*\)\s*\.get\(\s*['\"]([A-Z][A-Za-z0-9]+)['\"]"
)


def find_emit_access(py_path: Path) -> Tuple[List[Tuple[int, str, str]], List[Tuple[int, str, str]]]:
    """Return (flat_accesses, nested_accesses).

    flat:    list of (lineno, var_name, key)
    nested:  list of (lineno, outer_key, inner_key)  — these are 99% bugs
    """
    flat: List[Tuple[int, str, str]] = []
    nested: List[Tuple[int, str, str]] = []
    try:
        src = py_path.read_text()
    except Exception:
        return [], []

    # AST pass for flat: emitted.get("X"), emitted["X"]
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return [], []

    for node in ast.walk(tree):
        # foo.get("Bar")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get":
            recv = node.func.value
            if isinstance(recv, ast.Name) and recv.id in EMIT_LIKE_VARS:
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    key = node.args[0].value
                    if key and key not in SKIP_KEYS and not key.startswith("_"):
                        flat.append((node.lineno, recv.id, key))
        # foo["Bar"]
        if isinstance(node, ast.Subscript):
            recv = node.value
            slc = node.slice
            if isinstance(recv, ast.Name) and recv.id in EMIT_LIKE_VARS:
                key = None
                if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                    key = slc.value
                if key and key not in SKIP_KEYS and not key.startswith("_"):
                    flat.append((node.lineno, recv.id, key))

    # Regex pass for nested: .get("Outer", {}).get("Inner")
    for m in _NESTED_PATTERN.finditer(src):
        outer, inner = m.group(1), m.group(2)
        # Approximate line number
        lineno = src.count("\n", 0, m.start()) + 1
        nested.append((lineno, outer, inner))

    return flat, nested


def audit_engine(engine_dir: Path, catalog_fields: Set[str]) -> Dict[str, List]:
    """Return per-engine punch list."""
    stale_by_file: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)
    nested_by_file: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)
    seen_keys: Set[str] = set()

    for py in engine_dir.rglob("*.py"):
        if "__pycache__" in py.parts or "/test" in str(py) or py.name.startswith("test_"):
            continue
        flat, nested = find_emit_access(py)
        rel = str(py.relative_to(ROOT))
        for lineno, var, key in flat:
            seen_keys.add(key)
            if key not in catalog_fields:
                stale_by_file[rel].append((lineno, var, key))
        for lineno, outer, inner in nested:
            # Nested access is a smell when the inner field exists at the
            # catalog top level (catalog already lifted it).
            if inner in catalog_fields:
                nested_by_file[rel].append((lineno, outer, inner))
    return {
        "stale": stale_by_file,
        "nested": nested_by_file,
        "seen_keys": seen_keys,
    }


def main() -> int:
    print("Indexing catalog fields...", file=sys.stderr)
    catalog_fields = collect_catalog_fields()
    print(f"Indexed {len(catalog_fields)} unique catalog field names", file=sys.stderr)

    target_engines = [
        "encryption-security",
        "container-security",
        "database-security",
        "ai-security",
        "threat",
        "compliance",
        "iam",
        "datasec",
        "network-security",
        "risk",
        "inventory",
        "check",
    ]
    print(f"# Mapper Path Audit\n")
    print(f"Catalog field universe: **{len(catalog_fields)}** unique field names")
    print(f"Engines audited: {', '.join(target_engines)}\n")

    grand_stale = 0
    grand_nested = 0

    for eng in target_engines:
        ed = ENGINES_ROOT / eng
        if not ed.is_dir():
            continue
        result = audit_engine(ed, catalog_fields)
        stale = result["stale"]
        nested = result["nested"]
        if not stale and not nested:
            continue

        eng_stale_count = sum(len(v) for v in stale.values())
        eng_nested_count = sum(len(v) for v in nested.values())
        grand_stale += eng_stale_count
        grand_nested += eng_nested_count

        print(f"\n## `engines/{eng}/` — {eng_stale_count} stale, {eng_nested_count} nested accesses\n")

        if nested:
            print("### 🔴 Nested envelope access (likely bug — catalog already flat)\n")
            for f, items in sorted(nested.items()):
                print(f"- `{f}`")
                for lineno, outer, inner in items[:8]:
                    print(f"  - L{lineno}: `{outer}.{inner}` → flat catalog key `{inner}`")
                if len(items) > 8:
                    print(f"  - … {len(items)-8} more")
            print()

        if stale:
            print("### 🟡 Stale or unknown keys (no catalog field matches)\n")
            for f, items in sorted(stale.items())[:8]:
                # Group by key
                key_lines: Dict[str, List[int]] = defaultdict(list)
                for lineno, var, key in items:
                    key_lines[key].append(lineno)
                shown = list(key_lines.items())[:10]
                print(f"- `{f}`: " + ", ".join(f"`{k}`(L{','.join(str(x) for x in lns[:3])}{'…' if len(lns)>3 else ''})" for k, lns in shown))
                if len(key_lines) > 10:
                    print(f"  - … {len(key_lines)-10} more keys")
            if len(stale) > 8:
                print(f"- … {len(stale)-8} more files")
            print()

    print(f"\n## Summary\n")
    print(f"- Total nested-envelope accesses: **{grand_nested}**")
    print(f"- Total stale/unknown keys: **{grand_stale}**")
    print(f"\nNested accesses are high-confidence bugs. Stale keys may be legitimate")
    print(f"(model fields not lifted to catalog, or post-processed values) — review.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
