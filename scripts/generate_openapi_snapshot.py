#!/usr/bin/env python3
"""Generate bff.openapi.snapshot.json from the API gateway FastAPI app.

This script is called:
  - Manually by developers when BFF Pydantic models change
  - By CI to diff against the committed snapshot (Layer 4 of the contract pipeline)

Usage:
    python scripts/generate_openapi_snapshot.py

Output:
    bff.openapi.snapshot.json  (at repo root)

CI diff check (in .github/workflows/contract.yml):
    python scripts/generate_openapi_snapshot.py --check
    # Exit 1 if snapshot differs from current state; exit 0 if identical.

Notes:
  - The script imports the FastAPI app and uses app.openapi() to generate the spec.
  - It only captures schemas from BFF route response_models (not engine routes).
  - Field ADDITIONS are OK. Field removals or renames fail the check.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO_ROOT / "bff.openapi.snapshot.json"

# Make repo importable.
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "shared"))

# In Docker: shared/common → ./engine_common, shared/auth → ./engine_auth.
# Locally we add the parent dirs to the path and then inject aliases so
# `import engine_common` resolves to the shared/common package, and
# `import engine_auth` resolves to the shared/auth package.
import importlib.util as _ilu
import types as _types


def _alias(real_path: Path, alias: str) -> None:
    """Make ``import alias`` resolve to the package at ``real_path``."""
    if alias in sys.modules:
        return
    spec = _ilu.spec_from_file_location(alias, real_path / "__init__.py")
    if spec is None:
        # No __init__.py — create a namespace package alias.
        mod = _types.ModuleType(alias)
        mod.__path__ = [str(real_path)]  # type: ignore[attr-defined]
        mod.__package__ = alias
        sys.modules[alias] = mod
        return
    mod = _ilu.module_from_spec(spec)  # type: ignore[arg-type]
    mod.__package__ = alias
    sys.modules[alias] = mod
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        pass  # partial load is fine — just needs to be importable


_alias(REPO_ROOT / "shared" / "common", "engine_common")
_alias(REPO_ROOT / "shared" / "auth", "engine_auth")


def _collect_bff_only(openapi_spec: Dict[str, Any]) -> Dict[str, Any]:
    """Strip non-BFF routes and return a pruned spec.

    Only keeps routes under /api/v1/views/ so engine proxy routes don't
    pollute the snapshot.
    """
    paths = openapi_spec.get("paths", {})
    bff_paths = {p: v for p, v in paths.items() if "/views/" in p or "/gateway/" in p}
    return {
        "openapi": openapi_spec.get("openapi"),
        "info": openapi_spec.get("info"),
        "paths": bff_paths,
        "components": openapi_spec.get("components", {}),
    }


def _schema_field_names(spec: Dict[str, Any]) -> Set[str]:
    """Return all property names declared in the spec's component schemas."""
    names: Set[str] = set()
    for schema in spec.get("components", {}).get("schemas", {}).values():
        if isinstance(schema, dict):
            for prop in (schema.get("properties") or {}).keys():
                names.add(prop)
    return names


def generate_snapshot() -> Dict[str, Any]:
    """Import the gateway app and return the pruned BFF OpenAPI spec."""
    # Stub out heavy middleware that requires a running cluster.
    _stub_imports()

    try:
        from shared.api_gateway.main import app  # type: ignore[import]
    except Exception as exc:
        print(f"[snapshot] Could not import gateway app: {exc}", file=sys.stderr)
        print("[snapshot] Generating minimal schema-only snapshot from BFF schemas package.", file=sys.stderr)
        return _minimal_schema_snapshot()

    spec = app.openapi()
    return _collect_bff_only(spec)


def _stub_imports() -> None:
    """Patch env vars and modules that are unavailable outside the cluster."""
    required_vars = {
        "THREAT_ENGINE_URL":      "http://engine-threat",
        "CHECK_ENGINE_URL":       "http://engine-check",
        "DISCOVERIES_ENGINE_URL": "http://engine-discoveries",
        "COMPLIANCE_ENGINE_URL":  "http://engine-compliance",
        "INVENTORY_ENGINE_URL":   "http://engine-inventory",
        "IAM_ENGINE_URL":         "http://engine-iam",
        "RISK_ENGINE_URL":        "http://engine-risk",
        "DATASEC_ENGINE_URL":     "http://engine-datasec",
        "NETWORK_ENGINE_URL":     "http://engine-network",
        "ENCRYPTION_ENGINE_URL":  "http://engine-encryption",
        "VULNERABILITY_ENGINE_URL": "http://engine-vulnerability",
        "SECOPS_ENGINE_URL":      "http://engine-secops",
        "CIEM_ENGINE_URL":        "http://engine-ciem",
        "PLATFORM_BACKEND_URL":   "http://engine-platform",
        "BILLING_ENGINE_URL":     "http://engine-billing",
        "PLATFORM_ADMIN_URL":     "http://engine-platform-admin",
        "CONTAINER_SEC_ENGINE_URL": "http://engine-container-sec",
        "AI_SECURITY_ENGINE_URL": "http://engine-ai-security",
        "DBSEC_ENGINE_URL":       "http://engine-dbsec",
        "CNAPP_ENGINE_URL":       "http://engine-cnapp",
        "CWPP_ENGINE_URL":        "http://engine-cwpp",
    }
    for k, v in required_vars.items():
        os.environ.setdefault(k, v)


def _minimal_schema_snapshot() -> Dict[str, Any]:
    """Fallback: load schema models without triggering bff/__init__.py router imports.

    Strategy:
      1. Register stub parent packages (shared, shared.api_gateway, shared.api_gateway.bff,
         shared.api_gateway.bff.schemas, shared.api_gateway.bff.views) so relative imports
         resolve correctly.
      2. Load _common_schemas.py and views/_schemas.py directly — these only depend on pydantic.
      3. Load schemas/_common.py and schemas/findings.py once stubs are in place.
    """
    import importlib.util as ilu
    from pydantic import BaseModel

    bff_dir = REPO_ROOT / "shared" / "api_gateway" / "bff"

    def _load_direct(path: Path, pkg_name: str, mod_name: str) -> Any:
        """Load a Python file as module ``mod_name`` in package ``pkg_name``."""
        spec = ilu.spec_from_file_location(mod_name, path)
        if spec is None:
            return None
        mod = ilu.module_from_spec(spec)  # type: ignore[arg-type]
        mod.__package__ = pkg_name
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception as exc:
            print(f"[snapshot] Warning loading {path.name}: {exc}", file=sys.stderr)
        return mod

    # ── Step 1: register stub parent packages ────────────────────────────────
    for pkg in [
        "shared",
        "shared.api_gateway",
        "shared.api_gateway.bff",
        "shared.api_gateway.bff.schemas",
        "shared.api_gateway.bff.views",
    ]:
        if pkg not in sys.modules:
            stub = _types.ModuleType(pkg)
            stub.__path__ = []  # type: ignore[attr-defined]
            stub.__package__ = pkg
            sys.modules[pkg] = stub

    # Point package paths at the real directories so file discovery works.
    sys.modules["shared.api_gateway.bff"].__path__ = [str(bff_dir)]  # type: ignore[attr-defined]
    sys.modules["shared.api_gateway.bff.schemas"].__path__ = [str(bff_dir / "schemas")]  # type: ignore[attr-defined]
    sys.modules["shared.api_gateway.bff.views"].__path__ = [str(bff_dir / "views")]  # type: ignore[attr-defined]

    # ── Step 2: load leaf modules that have no relative imports ───────────────
    _load_direct(
        bff_dir / "_common_schemas.py",
        pkg_name="shared.api_gateway.bff",
        mod_name="shared.api_gateway.bff._common_schemas",
    )
    _load_direct(
        bff_dir / "views" / "_schemas.py",
        pkg_name="shared.api_gateway.bff.views",
        mod_name="shared.api_gateway.bff.views._schemas",
    )

    # ── Step 3: load new schema files (they use relative imports) ─────────────
    schema_modules: list[Any] = []
    for fname, pkg, mod_name in [
        ("_common.py",   "shared.api_gateway.bff.schemas", "shared.api_gateway.bff.schemas._common"),
        ("findings.py",  "shared.api_gateway.bff.schemas", "shared.api_gateway.bff.schemas.findings"),
    ]:
        mod = _load_direct(bff_dir / "schemas" / fname, pkg, mod_name)
        if mod is not None:
            schema_modules.append(mod)

    # ── Step 4: collect Pydantic model schemas ────────────────────────────────
    schemas_dict: Dict[str, Any] = {}
    for mod in schema_modules:
        for name in getattr(mod, "__all__", []):
            obj = getattr(mod, name, None)
            if obj is None:
                continue
            try:
                if isinstance(obj, type) and issubclass(obj, BaseModel):
                    schemas_dict[name] = obj.model_json_schema()
            except Exception:
                pass

    return {
        "openapi": "3.1.0",
        "info": {"title": "BFF Contract Snapshot (phase0)", "version": "phase0"},
        "paths": {},
        "components": {"schemas": schemas_dict},
    }


def _diff_snapshots(old: Dict[str, Any], new: Dict[str, Any]) -> list[str]:
    """Return a list of breaking changes (removals / renames).

    Field additions are non-breaking and not reported.
    """
    breaking: list[str] = []
    old_fields = _schema_field_names(old)
    new_fields = _schema_field_names(new)
    removed = old_fields - new_fields
    for field in sorted(removed):
        breaking.append(f"REMOVED field: '{field}'")
    # Path-level removals.
    old_paths = set(old.get("paths", {}).keys())
    new_paths = set(new.get("paths", {}).keys())
    for path in sorted(old_paths - new_paths):
        breaking.append(f"REMOVED endpoint: '{path}'")
    return breaking


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate BFF OpenAPI snapshot")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Diff current spec against committed snapshot; exit 1 on breaking changes.",
    )
    parser.add_argument(
        "--output",
        default=str(SNAPSHOT_PATH),
        help="Output file path (default: bff.openapi.snapshot.json at repo root)",
    )
    args = parser.parse_args()

    current = generate_snapshot()

    if args.check:
        if not SNAPSHOT_PATH.exists():
            print(
                f"[snapshot] ERROR: {SNAPSHOT_PATH} does not exist. "
                "Run 'python scripts/generate_openapi_snapshot.py' to create it.",
                file=sys.stderr,
            )
            sys.exit(1)
        with SNAPSHOT_PATH.open() as f:
            committed = json.load(f)
        breaking = _diff_snapshots(committed, current)
        if breaking:
            print("[snapshot] BREAKING CHANGES detected:", file=sys.stderr)
            for b in breaking:
                print(f"  - {b}", file=sys.stderr)
            print(
                "\nTo accept intentional breaking changes, regenerate the snapshot:\n"
                "  python scripts/generate_openapi_snapshot.py\n"
                "  git add bff.openapi.snapshot.json",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[snapshot] OK — no breaking changes vs {SNAPSHOT_PATH.name}")
    else:
        out_path = Path(args.output)
        with out_path.open("w") as f:
            json.dump(current, f, indent=2, default=str)
        field_count = len(_schema_field_names(current))
        print(
            f"[snapshot] Written to {out_path}  "
            f"({len(current.get('paths', {}))} BFF paths, {field_count} schema fields)"
        )


if __name__ == "__main__":
    main()
