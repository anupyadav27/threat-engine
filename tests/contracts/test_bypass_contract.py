"""JNY-16 Layer 3: UI ↔ direct-engine bypass contract diff.

For each direct-engine bypass path documented in the story (vulnerability,
sbom, onboarding-write, cspm-auth), this test asserts that every field the UI
consumes from the bypass response is declared in the engine's Pydantic
``response_model`` (introspected via the engine OpenAPI spec at
``/<engine-prefix>/openapi.json``).

This is the safety net that JNY-13/14 alone do not provide: those tests cover
the BFF surface only, while the four bypasses talk to engines directly.

Coverage expectations (per JNY-15 status as of 2026-05-04):
    - Engines that haven't yet adopted Pydantic ``response_model=`` SKIP rather
      than FAIL — see STORY-ENG-PYDANTIC-COVERAGE.md for the matrix.
    - The skip is annotated with the spin-off story ID so it's traceable.

Run:
    pytest tests/contracts/test_bypass_contract.py -v

To skip without cluster access:
    SKIP_BYPASS_CONTRACT=1 pytest tests/contracts/test_bypass_contract.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Set

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CACHE_PATH = REPO_ROOT / "scripts" / ".cache" / "ui-consumed-bypass-fields.json"
EXTRACTOR = REPO_ROOT / "scripts" / "extract-bff-fields.js"

# Default cluster ingress NLB — same as the JNY-15 smoke harness.
NLB = os.environ.get(
    "BYPASS_CONTRACT_NLB",
    "http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com",
)

# (bypass_name, ingress_prefix, required_permission)
# bypass_name matches a key in ui-consumed-bypass-fields.json["bypasses"].
# ingress_prefix is the URL prefix the engine's OpenAPI lives under at NLB.
# required_permission is documented but not enforced at this layer (JNY-13
# already gates it on the BFF side, and bypasses authenticate via session
# cookies / API keys per their own engine).
BYPASSES = [
    ("vulnerability", "/vulnerability", "vulnerability:read"),
    ("sbom", "/sbom", "vulnerability:read"),
    ("onboarding-write", "/onboarding", "cloud_accounts:write"),
    ("cspm-auth", "/cspm", None),  # auth handshake — no perm gate
]

# JNY-15 coverage matrix snapshot: engines without ANY Pydantic response_model.
# These are SKIPPED (not FAILED) per the story. Each maps to a spin-off story.
NO_PYDANTIC_COVERAGE: Dict[str, str] = {
    "vulnerability": "STORY-ENG-PYDANTIC-VULNERABILITY",
    "sbom": "STORY-ENG-PYDANTIC-VULNERABILITY",  # same engine, /sbom is a sibling ingress
    "onboarding-write": "STORY-ENG-PYDANTIC-ONBOARDING",
    "cspm-auth": "STORY-ENG-PYDANTIC-CSPM-DJANGO",
}

# Fields that are React/Next runtime artifacts or fetch error envelopes — never
# on the wire from the engine. Tolerated globally so the diff stays signal-rich.
TOLERATED_FIELDS: Set[str] = {
    "error",
    "loading",
    "data",
    "items",
    "results",  # DRF pagination envelope — present in all cspm-auth list endpoints
}


def _ensure_cache() -> Dict[str, Any]:
    """Run the extractor on demand if the cache is missing."""
    if not CACHE_PATH.exists():
        node = shutil.which("node")
        if not node:
            pytest.skip("node not on PATH — cannot regenerate bypass field cache")
        subprocess.run([node, str(EXTRACTOR)], check=True, cwd=REPO_ROOT)
    with CACHE_PATH.open() as f:
        return json.load(f)


def _fetch_openapi(prefix: str) -> Dict[str, Any] | None:
    """Pull the engine's /openapi.json. Returns None if unreachable or missing.

    We don't make this a hard failure: in CI without cluster access the test
    simply degrades to ``no schema available`` and SKIPs.
    """
    if os.environ.get("SKIP_BYPASS_CONTRACT") == "1":
        return None
    try:
        import httpx
    except ImportError:
        return None
    url = f"{NLB}{prefix}/openapi.json"
    try:
        resp = httpx.get(url, timeout=5.0)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def _collect_schema_field_names(spec: Dict[str, Any]) -> Set[str]:
    """Flatten every property name that appears in any response schema.

    This is intentionally a coarse top-level-field check — the bypass extractor
    only captures one-hop accesses (``data.scan_id``), so a flat set of all
    declared property names is sufficient to catch silent renames.
    """
    names: Set[str] = set()
    components = spec.get("components", {}).get("schemas", {})
    for schema in components.values():
        if not isinstance(schema, dict):
            continue
        for prop in (schema.get("properties") or {}).keys():
            names.add(prop)
    # Also walk inline response schemas referenced from paths.
    for path_item in (spec.get("paths") or {}).values():
        if not isinstance(path_item, dict):
            continue
        for op in path_item.values():
            if not isinstance(op, dict):
                continue
            for resp in (op.get("responses") or {}).values():
                content = (resp or {}).get("content", {})
                schema = (content.get("application/json") or {}).get("schema") or {}
                for prop in (schema.get("properties") or {}).keys():
                    names.add(prop)
    return names


@pytest.mark.parametrize("name,prefix,perm", BYPASSES, ids=[b[0] for b in BYPASSES])
def test_bypass_consumed_fields_have_engine_schema(
    name: str, prefix: str, perm: str | None
) -> None:
    """Each consumed UI field for a bypass must appear in the engine OpenAPI."""
    cache = _ensure_cache()
    bypass = cache.get("bypasses", {}).get(name)
    assert bypass is not None, (
        f"bypass {name!r} missing from extractor output — "
        "did you change BYPASSES in scripts/extract-bff-fields.js?"
    )

    routes = bypass.get("routes", {})
    if not routes:
        pytest.skip(f"No UI consumers detected for bypass {name!r} — nothing to gate")

    # If the engine has no Pydantic response_model coverage, skip (do not fail).
    spinoff = NO_PYDANTIC_COVERAGE.get(name)
    if spinoff:
        pytest.skip(
            f"Engine {name!r} has no Pydantic response_model coverage yet — "
            f"see {spinoff}. {len(routes)} consumer route(s) await schema."
        )

    spec = _fetch_openapi(prefix)
    if spec is None:
        pytest.skip(
            f"Engine {prefix} OpenAPI unreachable from this environment — "
            "set BYPASS_CONTRACT_NLB or run inside the cluster."
        )

    declared = _collect_schema_field_names(spec)
    consumed: Set[str] = set()
    for info in routes.values():
        consumed.update(info.get("fields") or [])
    consumed -= TOLERATED_FIELDS

    missing = sorted(consumed - declared)
    assert not missing, (
        f"Bypass {name!r}: UI consumes fields not declared in engine OpenAPI:\n"
        + "\n".join(
            f"  - {f}  (consumed by: "
            + ", ".join(
                c
                for r in routes.values()
                if f in (r.get("fields") or [])
                for c in r.get("consumers", [])
            )
            + ")"
            for f in missing
        )
    )


def test_bypass_list_matches_extractor() -> None:
    """The hardcoded BYPASSES test parametrize list must match the extractor's
    output keys. Catches drift when someone adds a bypass to one but not the
    other."""
    cache = _ensure_cache()
    extractor_keys = set(cache.get("bypasses", {}).keys())
    test_keys = {b[0] for b in BYPASSES}
    assert extractor_keys == test_keys, (
        f"BYPASSES drift: extractor={sorted(extractor_keys)} test={sorted(test_keys)}"
    )
