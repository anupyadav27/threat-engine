"""
Engine Parser — extracts declared fields from FastAPI engine Pydantic response models.

Strategy:
  1. Find all `response_model=XxxResponse` declarations in api_server.py
  2. Resolve each model class → extract its field names + types
  3. Also capture `extra = "allow"` flag (signals pass-through risk)
"""

from __future__ import annotations
import os
import re

REPO_ROOT = "/Users/apple/Desktop/threat-engine"
ENGINES_ROOT = os.path.join(REPO_ROOT, "engines")

# Map engine name → api_server.py path(s) (relative to REPO_ROOT)
_ENGINE_API_MAP: dict[str, list[str]] = {
    "threat":            ["engines/threat/threat_engine/api_server.py"],
    "risk":              ["engines/risk/api_server.py"],
    "compliance":        ["engines/compliance/compliance_engine/api_server.py"],
    "iam":               ["engines/iam/iam_engine/api_server.py"],
    "network-security":  ["engines/network-security/network_security_engine/api_server.py"],
    "datasec":           ["engines/datasec/datasec_engine/api_server.py"],
    "vulnerability":     ["engines/vulnerability/vulnerability_engine/api_server.py"],
    "ciem":              ["engines/ciem/ciem_engine/api_server.py"],
    "secops":            ["engines/secops/sast_engine/api_server.py"],
    "inventory":         ["engines/inventory/inventory_engine/api_server.py"],
    "discoveries":       ["engines/discoveries/common/api_server.py"],
    "billing":           [
        "engines/billing/main.py",
        "engines/billing/models.py",
        "engines/billing/_schemas.py",
        "engines/billing/routers/subscriptions.py",
        "engines/billing/routers/plans.py",
        "engines/billing/routers/invoices.py",
        "engines/billing/routers/usage.py",
        "engines/billing/routers/checkout.py",
    ],
    "platform-admin":    ["engines/platform-admin/main.py", "engines/platform-admin/routers/billing.py"],
    "check":             ["engines/check/check_engine/api_server.py"],
    "container-security":["engines/container-security/container_security_engine/api_server.py"],
    "encryption":        ["engines/encryption/encryption_engine/api_server.py"],
    "dbsec":             ["engines/dbsec/dbsec_engine/api_server.py"],
    "ai-security":       ["engines/ai-security/ai_security_engine/api_server.py"],
}


def _find_api_server(engine_name: str) -> list[str]:
    paths = []
    for rel in _ENGINE_API_MAP.get(engine_name, []):
        abs_path = os.path.join(REPO_ROOT, rel)
        if os.path.isfile(abs_path):
            paths.append(abs_path)
    if not paths:
        # Fallback: glob search
        for dirpath, _, filenames in os.walk(os.path.join(ENGINES_ROOT, engine_name)):
            if "api_server.py" in filenames:
                paths.append(os.path.join(dirpath, "api_server.py"))
    return paths


def _parse_model_fields(content: str, model_name: str) -> dict:
    """
    Extract fields from a Pydantic BaseModel class by name.
    Returns {"fields": [...], "has_extra_allow": bool}
    """
    fields: list[str] = []
    has_extra_allow = False
    in_class = False
    brace_depth = 0

    for line in content.splitlines():
        # Detect class start
        if re.match(rf'^class {re.escape(model_name)}\s*\(', line):
            in_class = True
            brace_depth = 0
            continue

        if not in_class:
            continue

        # Stop at next top-level class definition
        if re.match(r'^class \w+', line) and brace_depth == 0:
            break

        # Track indented block depth (rough)
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        # extra = "allow" detection
        if 'extra' in stripped and '"allow"' in stripped:
            has_extra_allow = True

        # Field declaration: field_name: type  or  field_name: type = default
        field_m = re.match(r'^\s{4}(\w+)\s*:\s*(.+?)(?:\s*=.*)?$', line)
        if field_m:
            fname = field_m.group(1)
            ftype = field_m.group(2).strip()
            if (
                not fname.startswith('_')
                and fname not in {
                    'model_config', 'class', 'def',
                    # Python typing / standard names that are never data fields
                    'Optional', 'Required', 'Union', 'List', 'Dict', 'Set',
                    'Tuple', 'Any', 'Type', 'Literal', 'ClassVar', 'Final',
                    'Annotated', 'Field', 'validator', 'root_validator',
                }
                and not ftype.startswith('ClassVar')
                and not fname[0].isupper()   # PascalCase = type alias, not a field
            ):
                fields.append(fname)

    return {"fields": fields, "has_extra_allow": has_extra_allow}


def _extract_response_models(content: str) -> list[str]:
    """Return all model names used as response_model= on endpoints."""
    return re.findall(r'response_model\s*=\s*(\w+)', content)


def _extract_dict_return_keys(content: str) -> set[str]:
    """
    Extract string keys from dict return statements and .get() calls in engine router files.
    Covers cases where the engine returns raw dicts (e.g. BillingLenientResponse).
    """
    keys: set[str] = set()
    # "key": value  in a dict literal
    for m in re.finditer(r'["\']([a-z][a-z0-9_]+)["\']\s*:', content):
        k = m.group(1)
        if re.match(r'^[a-z][a-z0-9_]+$', k) and k not in {
            'status', 'detail', 'message', 'error', 'type', 'id',
        }:
            keys.add(k)
    # .get("key") or .get('key')
    for m in re.finditer(r'\.get\(["\']([a-z][a-z0-9_]+)["\']', content):
        k = m.group(1)
        if re.match(r'^[a-z][a-z0-9_]+$', k):
            keys.add(k)
    return keys


def _extract_all_model_names(content: str) -> list[str]:
    """Return all BaseModel subclass names defined in the file."""
    return re.findall(r'^class (\w+)\s*\(.*BaseModel.*\)', content, re.MULTILINE)


def extract_engine_fields(engine_name: str) -> dict:
    """
    Parse engine API server(s) for `engine_name`.

    Returns:
        {
          "fields": ["risk_score", "scenarios", ...],          # all declared fields
          "response_models": {"RiskUiDataResponse": [...], ...},
          "has_extra_allow": bool,                             # any model uses extra="allow"
          "source_files": [...],
          "notes": [...]
        }
    """
    paths = _find_api_server(engine_name)
    notes: list[str] = []
    all_fields: set[str] = set()
    response_models: dict[str, list[str]] = {}
    any_extra_allow = False

    if not paths:
        notes.append(f"No api_server.py found for engine '{engine_name}'")
        return {
            "fields": [],
            "response_models": {},
            "has_extra_allow": False,
            "source_files": [],
            "notes": notes,
        }

    for path in paths:
        content = open(path, encoding="utf-8").read()

        used_model_names = _extract_response_models(content)
        all_model_names = _extract_all_model_names(content)

        # Parse every model class in the file
        for model_name in all_model_names:
            result = _parse_model_fields(content, model_name)
            if result["fields"]:
                response_models[model_name] = result["fields"]
                all_fields.update(result["fields"])
            if result["has_extra_allow"]:
                any_extra_allow = True

        if not used_model_names and not all_model_names:
            notes.append(f"No Pydantic models found in {path}")
            # Fall back to dict-key extraction (handles lenient response models)
            all_fields.update(_extract_dict_return_keys(content))
        elif any_extra_allow:
            # Engine uses extra="allow" — also harvest dict keys as additional coverage
            all_fields.update(_extract_dict_return_keys(content))

    return {
        "fields": sorted(all_fields),
        "response_models": response_models,
        "has_extra_allow": any_extra_allow,
        "source_files": paths,
        "notes": notes,
    }
