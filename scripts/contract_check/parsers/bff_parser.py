"""
BFF Parser — extracts returned field keys from Python BFF view handlers.

Handles:
  - Top-level dict keys in return {...} statements
  - Nested dict keys one level deep (e.g. "pulse_stats": {"critical_count": ...})
  - Pydantic model field names declared in the handler file
  - List of engine endpoints the handler calls (for cross-referencing)
"""

from __future__ import annotations
import os
import re

REPO_ROOT = "/Users/apple/Desktop/threat-engine"
BFF_DIR = os.path.join(REPO_ROOT, "shared/api_gateway/bff")

# Map BFF view name → handler file name(s) (without .py, relative to BFF_DIR)
_VIEW_HANDLER_MAP: dict[str, list[str]] = {
    "threat-command-room": ["threat_command_room"],
    "threats":             ["threats"],
    "threats-graph":       ["threat_graph"],
    "compliance":          ["compliance"],
    "risk":                ["risk"],
    "network-security":    ["network_security"],
    "iam":                 ["iam"],
    "datasec":             ["datasec"],
    "vulnerability":       ["vulnerability"],
    "ciem":                ["ciem"],
    "secops":              ["secops"],
    "billing":             ["billing"],
    "admin-billing":       ["platform_admin"],
    "inventory":           ["inventory"],
    "scan-status":         ["scan_status"],
    "scans":               ["scans"],
    # Additional views
    "findings":            ["views/finding_detail"],
    "onboarding":          ["onboarding_cloud_accounts"],
    "policies":            ["policies"],
    "rules":               ["rules"],
    "reports":             ["reports"],
    "ai-security":         ["ai_security"],
    "container-security":  ["container_security"],
    "database-security":   ["database_security"],
    "encryption":          ["encryption"],
    "cnapp":               ["cnapp"],
    "cwpp":                ["cwpp"],
}


# Map view name → the specific async function name in its BFF handler file.
# When a handler file contains multiple view functions, this pins parsing to
# the right one so fields from sibling functions don't bleed in.
_VIEW_FUNCTION_MAP: dict[str, str] = {
    "admin-billing":   "view_admin_billing",
    "platform-admin":  "view_platform_admin",
    "billing":         "view_billing",
}


def _handler_path(name: str) -> str:
    return os.path.join(BFF_DIR, f"{name}.py")


def _scope_to_function(content: str, fn_name: str) -> str:
    """
    Extract only the body of `async def fn_name(...)` from content.
    Falls back to full content if the function isn't found.
    """
    pattern = re.compile(
        r'(?:async\s+)?def\s+' + re.escape(fn_name) + r'\s*\(',
        re.MULTILINE,
    )
    m = pattern.search(content)
    if not m:
        return content

    start = m.start()
    # Find the next top-level def/async def after this one
    next_fn = re.compile(r'^(?:async\s+)?def\s+\w+', re.MULTILINE)
    next_m = next_fn.search(content, m.end())
    end = next_m.start() if next_m else len(content)
    return content[start:end]


def _extract_top_level_keys(content: str) -> set[str]:
    """Extract string keys from return {...} blocks."""
    keys: set[str] = set()

    # Match "key": value  or  "key": {  patterns inside return blocks
    for m in re.finditer(r'["\'](\w+)["\']\s*:', content):
        key = m.group(1)
        if key and re.match(r'^[a-z_]\w*$', key):   # snake_case keys only
            keys.add(key)

    # Also catch bare-word keys in dict literals:  key=value  or  key: value
    for m in re.finditer(r'^\s{4,}(\w+)\s*:', content, re.MULTILINE):
        key = m.group(1)
        if key and re.match(r'^[a-z_]\w*$', key) and key not in {
            'if', 'else', 'for', 'while', 'try', 'except', 'with', 'return',
            'import', 'from', 'class', 'def', 'async', 'await', 'raise', 'pass',
        }:
            keys.add(key)

    return keys


def _extract_nested_keys(content: str) -> set[str]:
    """
    Extract one-level-deep nested keys.
    Pattern:  "parent": {  ... "child": ...  }
    Returns 'parent.child' paths.
    """
    nested: set[str] = set()

    # Find all "parent": { ... } blocks
    for m in re.finditer(
        r'["\'](\w+)["\']\s*:\s*\{([^{}]{0,800})\}',
        content,
        re.DOTALL,
    ):
        parent = m.group(1)
        inner = m.group(2)
        for child_m in re.finditer(r'["\'](\w+)["\']\s*:', inner):
            child = child_m.group(1)
            if re.match(r'^[a-z_]\w*$', child):
                nested.add(f"{parent}.{child}")

    return nested


def _extract_pydantic_fields(content: str) -> set[str]:
    """
    Extract field names from Pydantic BaseModel subclasses defined in the handler.
    """
    fields: set[str] = set()
    in_class = False
    for line in content.splitlines():
        if re.match(r'^class \w+\(.*BaseModel.*\)', line):
            in_class = True
            continue
        if in_class:
            if re.match(r'^class ', line):   # new class started
                in_class = False
            field_m = re.match(r'^\s{4}(\w+)\s*:', line)
            if field_m:
                fname = field_m.group(1)
                if not fname.startswith('_') and fname != 'model_config':
                    fields.add(fname)
    return fields


def _extract_get_keys(content: str) -> set[str]:
    """
    Extract keys from .get("field") / .get('field') calls in BFF handlers.
    These cover fields the BFF reads from engine responses via dict.get().
    """
    keys: set[str] = set()
    for m in re.finditer(r'\.get\(["\'](\w+)["\']', content):
        key = m.group(1)
        if re.match(r'^[a-z_]\w*$', key) and key not in {
            'status', 'error', 'detail', 'message',   # too generic
        }:
            keys.add(key)
    return keys


def _extract_engine_calls(content: str) -> list[str]:
    """
    Extract engine endpoint paths the handler calls.
    Looks for patterns like: fetch_one("/api/v1/risk/...")
    """
    return re.findall(r'["\'](/api/v\d/[^"\']+)["\']', content)


def extract_bff_fields(view_name: str) -> dict:
    """
    Parse BFF handler(s) for `view_name` and return all field keys.

    Returns:
        {
          "fields": ["pulse_stats", "pulse_stats.critical_count", ...],
          "engine_calls": ["/api/v1/threat/ui-data", ...],
          "source_files": [...],
          "notes": [...]
        }
    """
    handler_names = _VIEW_HANDLER_MAP.get(view_name, [view_name.replace("-", "_")])
    notes: list[str] = []
    all_fields: set[str] = set()
    all_engine_calls: list[str] = []
    source_files: list[str] = []

    for name in handler_names:
        path = _handler_path(name)
        if not os.path.isfile(path):
            notes.append(f"BFF handler not found: {path}")
            continue

        source_files.append(path)
        content = open(path, encoding="utf-8").read()

        # Narrow to the specific view function if known, to avoid bleeding
        # fields from sibling functions in the same handler file.
        fn_name = _VIEW_FUNCTION_MAP.get(view_name)
        if fn_name:
            content = _scope_to_function(content, fn_name)

        all_fields |= _extract_top_level_keys(content)
        all_fields |= _extract_nested_keys(content)
        all_fields |= _extract_get_keys(content)
        all_fields |= _extract_pydantic_fields(content)
        all_engine_calls += _extract_engine_calls(content)

    # Pull fields from _common_schemas.py only when we're NOT scoped to a
    # specific function (scoped views have precise enough data already).
    if not _VIEW_FUNCTION_MAP.get(view_name):
        common_path = os.path.join(BFF_DIR, "_common_schemas.py")
        if os.path.isfile(common_path):
            common_content = open(common_path, encoding="utf-8").read()
            all_fields |= _extract_pydantic_fields(common_content)

    return {
        "fields": sorted(all_fields),
        "engine_calls": list(dict.fromkeys(all_engine_calls)),   # dedupe, preserve order
        "source_files": source_files,
        "notes": notes,
    }
