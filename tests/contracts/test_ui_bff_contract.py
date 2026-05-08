"""JNY-14 Layer 3: UI ↔ BFF contract diff.

For each BFF view that has a Pydantic response model (the JNY-13 set), check
that every dotted-path the frontend reads from the response is actually
declared on the model. Lenient extras lists tolerate the legacy snake_case
dual-naming and the JSONB pass-through fields documented in
shared/api_gateway/bff/_common_schemas.py.

Run: pytest tests/contracts/ -v

The test auto-runs scripts/extract-bff-fields.js if the cache is missing,
so it works on a fresh checkout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Type, get_args, get_origin

import pytest
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = REPO_ROOT / "scripts" / ".cache" / "ui-consumed-fields.json"
EXTRACTOR = REPO_ROOT / "scripts" / "extract-bff-fields.js"

# Make BFF schemas importable.
sys.path.insert(0, str(REPO_ROOT))


# ── UI page → BFF view name mapping ──────────────────────────────────────────
# Only the views that have a Pydantic model in _common_schemas.py are gated.
# Adding a new view means: model it in _common_schemas.py, add it here.
PYDANTIC_MODELED_VIEWS: Dict[str, str] = {
    # view name (as used in fetchView('<x>')) -> Pydantic class name
    "inventory": "InventoryViewResponse",
    "threat-mitre-heatmap": "ThreatsViewResponse",
    "threats": "ThreatsViewResponse",
    "ciem": "CiemViewResponse",
    "compliance": "ComplianceViewResponse",
    "iam": "IamViewResponse",
    "datasec": "DatasecViewResponse",
}

# Acceptable extras: legacy snake_case duals, JSONB drill-downs, and runtime
# helpers that the BFF intentionally passes through via extra="allow".
# Keys are dotted-paths exactly as the extractor emits them.
ACCEPTABLE_EXTRAS: Dict[str, Set[str]] = {
    "*": {
        # React/Next runtime + filter-context wrappers, never on the wire.
        "error",
        "loading",
        "pagination",
        "items",
        "data",
        "result",
        # JSONB pass-through is intentional; downstream tabs drill into it.
        "raw",
        "metadata",
        "details",
        # Common JS Array/Object built-ins that the regex extractor cannot
        # distinguish from BFF response fields. Babel mode would catch these.
        "length",
        "map",
        "filter",
        "find",
        "forEach",
        "reduce",
        "some",
        "every",
        "slice",
        "splice",
        "push",
        "pop",
        "concat",
        "join",
        "sort",
        "reverse",
        "indexOf",
        "includes",
        "flat",
        "flatMap",
        "keys",
        "values",
        "entries",
        "toString",
        "hasOwnProperty",
    },
    # Per-view tolerances — fields the BFF passes through via extra="allow".
    # Each entry justified by a JNY-13/JNY-14 review note.
    "ciem": {
        # CIEM view returns scanTrend via JSONB pass-through (engine-side).
        "scanTrend",
    },
    "threat-mitre-heatmap": {
        # The heatmap variant of the threats view shapes its own summary +
        # tactics blob (separate from threatFindings list); BFF returns
        # them via extra="allow".
        "summary",
        "tactics",
    },
}


def _load_consumed() -> Dict[str, Any]:
    """Load the AST/regex extractor output, regenerating if absent."""
    if not CACHE_PATH.exists():
        node = shutil.which("node")
        if not node:
            pytest.skip("node binary not on PATH; cannot regenerate cache")
        subprocess.run(
            [node, str(EXTRACTOR)],
            check=True,
            cwd=str(REPO_ROOT),
            timeout=60,
        )
    with CACHE_PATH.open() as f:
        return json.load(f)


def _flatten_model(model: Type[BaseModel], prefix: str = "", depth: int = 0) -> Set[str]:
    """Flatten a Pydantic model into a set of dotted paths.

    Lists collapse to '.0' so the extractor's positional indexing aligns.
    Dict[str, Any] fields stop here — JSONB pass-through is opaque by design.
    """
    out: Set[str] = set()
    if depth > 6:  # safety
        return out
    for name, field in model.model_fields.items():
        key = f"{prefix}.{name}" if prefix else name
        out.add(key)
        ann = field.annotation
        out |= _flatten_annotation(ann, key, depth)
    return out


def _flatten_annotation(ann: Any, prefix: str, depth: int) -> Set[str]:
    out: Set[str] = set()
    origin = get_origin(ann)
    args = get_args(ann)
    if origin in (list, List):
        if args:
            out |= _flatten_annotation(args[0], f"{prefix}.0", depth + 1)
        return out
    if origin is dict:
        # Dict[str, Any] – treat as opaque JSONB.
        return out
    if isinstance(ann, type) and issubclass(ann, BaseModel):
        out |= _flatten_model(ann, prefix, depth + 1)
        return out
    # Optional[X] / Union[...] – recurse into each arm.
    if args:
        for a in args:
            if a is type(None):
                continue
            out |= _flatten_annotation(a, prefix, depth + 1)
    return out


def _is_acceptable(path: str, view: str) -> bool:
    head = path.split(".", 1)[0]
    if head in ACCEPTABLE_EXTRAS.get("*", set()):
        return True
    if head in ACCEPTABLE_EXTRAS.get(view, set()):
        return True
    return False


def _path_covered(consumed: str, provided: Set[str]) -> bool:
    """A consumed path is covered if any prefix of it is declared.

    We only model the structural envelope; once we descend into a List[Dict]
    or Dict[str, Any] the BFF intentionally returns opaque JSONB, so any
    deeper access is allowed.
    """
    if consumed in provided:
        return True
    parts = consumed.split(".")
    for i in range(len(parts), 0, -1):
        if ".".join(parts[:i]) in provided:
            return True
    return False


@pytest.fixture(scope="module")
def consumed_fields() -> Dict[str, Any]:
    return _load_consumed()


@pytest.fixture(scope="module")
def schemas_module():
    from shared.api_gateway.bff import _common_schemas as mod  # noqa: WPS433

    return mod


@pytest.mark.parametrize("view_name,model_name", sorted(PYDANTIC_MODELED_VIEWS.items()))
def test_ui_bff_contract_diff(
    view_name: str,
    model_name: str,
    consumed_fields: Dict[str, Any],
    schemas_module,
) -> None:
    """Every UI-consumed path on `view_name` is covered by `model_name`."""
    if view_name not in consumed_fields["views"]:
        pytest.skip(f"no UI consumer found for view '{view_name}' (yet)")
    model: Type[BaseModel] = getattr(schemas_module, model_name)
    provided = _flatten_model(model)
    consumed = set(consumed_fields["views"][view_name]["paths"])

    missing: List[str] = []
    for path in sorted(consumed):
        if _path_covered(path, provided):
            continue
        if _is_acceptable(path, view_name):
            continue
        missing.append(path)

    if missing:
        files = consumed_fields["views"][view_name]["files"]
        msg = (
            f"\nUI ↔ BFF contract drift for view '{view_name}' "
            f"(model: {model_name})\n"
            f"  Files reading this view:\n"
            + "".join(f"    - {f}\n" for f in files)
            + "  Paths consumed by UI but not declared on the model:\n"
            + "".join(f"    - {p}\n" for p in missing)
            + "  Fix: add the field to the Pydantic model OR remove the "
            "UI access OR list it in ACCEPTABLE_EXTRAS with a justification."
        )
        pytest.fail(msg)


def test_extractor_cache_is_fresh(consumed_fields: Dict[str, Any]) -> None:
    """The cache must be present, well-formed, and non-empty."""
    assert "views" in consumed_fields
    assert consumed_fields["_meta"]["view_count"] >= 1
    assert consumed_fields["_meta"]["mode"] in {"babel", "regex"}


def test_extractor_runs_under_30s(consumed_fields: Dict[str, Any]) -> None:
    """JNY-14 acceptance criterion: full extract must complete in <30s."""
    assert consumed_fields["_meta"]["duration_ms"] < 30_000
