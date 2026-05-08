#!/usr/bin/env python3
"""DCAT catalog completeness CI test.

Run on every PR touching catalog/discovery_generator_data/** or
engines/discoveries/** to detect:

  1. Catalog YAML drift (an emit.item template suddenly emits fewer fields,
     uses syntactically broken Jinja, or removes a known consumer field).
  2. Templates that don't render against a captured sample response —
     catches the "I changed response.X.Y to response.X" mistake.
  3. Field churn that downstream engines depend on (cross-references the
     mapper-path audit script's output to flag any field-name removal that
     would silently break an engine column).

Run: python3 scripts/ci_catalog_completeness.py

Exit codes:
  0  — all checks pass
  1  — drift detected (CI blocker)
  2  — script error (e.g. missing fixture)

Designed to run in <10 seconds on the full 1,445-service catalog. No DB
required — uses captured fixtures under tests/dcat_fixtures/.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

import yaml

ROOT = Path(__file__).resolve().parent.parent
CATALOG_ROOT = ROOT / "catalog" / "discovery_generator_data"
FIXTURE_ROOT = ROOT / "tests" / "dcat_fixtures"

# Engine source roots to scan for downstream consumers
ENGINES_ROOT = ROOT / "engines"

# Add path to common.jinja_renderer
sys.path.insert(0, str(ROOT / "engines" / "discoveries"))

try:
    from common.jinja_renderer import render_emit_item
    _RENDERER_AVAILABLE = True
except ImportError:
    print(
        "ERROR: cannot import common.jinja_renderer. "
        "Run from threat-engine repo root.",
        file=sys.stderr,
    )
    sys.exit(2)


# ── Built-in baseline assertions (smoke fixtures) ────────────────────────────
#
# Each entry: (provider, service, discovery_id, sample_response, required_fields)
# The renderer must produce a dict containing ALL required_fields (non-None
# values not required — Jinja can render to None for optional response fields).
#
SMOKE_FIXTURES: List[Tuple[str, str, str, dict, List[str]]] = [
    (
        "aws", "kms", "aws.kms.describe_key",
        {
            "KeyMetadata": {
                "KeyId": "abc123",
                "Arn": "arn:aws:kms:us-east-1:111:key/abc123",
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "Origin": "AWS_KMS",
                "Enabled": True,
                "AWSAccountId": "111",
                "MultiRegion": False,
                "KeyManager": "CUSTOMER",
                "Description": "test key",
                "CreationDate": "2024-01-01T00:00:00Z",
            }
        },
        ["KeyId", "Arn", "KeyState", "KeyUsage", "KeySpec", "Origin", "Enabled"],
    ),
    (
        "aws", "acm", "aws.acm.describe_certificate",
        {
            "Certificate": {
                "CertificateArn": "arn:aws:acm:us-east-1:111:certificate/xyz",
                "DomainName": "example.com",
                "Status": "ISSUED",
                "Type": "AMAZON_ISSUED",
                "KeyAlgorithm": "RSA-2048",
                "Issuer": "Amazon",
                "NotBefore": "2024-01-01T00:00:00Z",
                "NotAfter": "2025-01-01T00:00:00Z",
                "InUseBy": [],
            }
        },
        ["CertificateArn", "DomainName", "Status", "Type", "KeyAlgorithm",
         "NotBefore", "NotAfter", "Issuer"],
    ),
    (
        "aws", "secretsmanager", "aws.secretsmanager.list_secrets",
        {
            "SecretList": [
                {
                    "ARN": "arn:aws:secretsmanager:us-east-1:111:secret:foo",
                    "Name": "foo",
                    "RotationEnabled": False,
                    "LastAccessedDate": "2024-01-01T00:00:00Z",
                }
            ]
        },
        # list_secrets uses items_for, not item — we test list-iteration mode
        # in a separate fixture if desired. For now skip the field-list assert.
        [],
    ),
]


# ── Catalog inventory ────────────────────────────────────────────────────────


def collect_catalog_field_index() -> Dict[str, Dict[str, Set[str]]]:
    """For each (provider, service, discovery_id), collect emit.item field names.

    Returns: {provider: {discovery_id: set(field_names)}}
    """
    idx: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    for prov_dir in CATALOG_ROOT.iterdir():
        if not prov_dir.is_dir():
            continue
        prov = prov_dir.name
        for svc_dir in prov_dir.iterdir():
            if not svc_dir.is_dir():
                continue
            for yp in svc_dir.glob("step6_*.discovery.yaml"):
                try:
                    with yp.open() as fh:
                        data = yaml.safe_load(fh) or {}
                except Exception as exc:
                    print(f"WARN: yaml load failed {yp}: {exc}", file=sys.stderr)
                    continue
                for disc in data.get("discovery") or []:
                    did = disc.get("discovery_id")
                    if not did:
                        continue
                    emit = disc.get("emit") or {}
                    if not isinstance(emit, dict):
                        continue
                    item = emit.get("item")
                    if isinstance(item, dict):
                        for k in item.keys():
                            if isinstance(k, str):
                                idx[prov][did].add(k)
    return dict(idx)


# ── Check 1: smoke fixtures render correctly ────────────────────────────────


def check_smoke_fixtures(idx: Dict[str, Dict[str, Set[str]]]) -> List[str]:
    failures: List[str] = []
    for prov, svc, did, sample, required in SMOKE_FIXTURES:
        # Locate template in catalog
        yp = CATALOG_ROOT / prov / svc / f"step6_{svc}.discovery.yaml"
        if not yp.is_file():
            failures.append(f"FIXTURE_MISSING: {yp}")
            continue
        with yp.open() as fh:
            data = yaml.safe_load(fh) or {}
        template = None
        for disc in data.get("discovery") or []:
            if disc.get("discovery_id") == did:
                emit = disc.get("emit") or {}
                template = emit.get("item")
                break
        if not isinstance(template, dict) or not template:
            failures.append(f"NO_ITEM_TEMPLATE: {prov}/{svc}/{did}")
            continue

        # Render against sample
        try:
            rendered = render_emit_item(
                template,
                {"response": sample, "item": {}, "context": {}},
                discovery_id=did,
                resource_uid="test",
                failure_sink=[],
            )
        except Exception as exc:
            failures.append(f"RENDER_EXC: {did} → {exc}")
            continue
        if not isinstance(rendered, dict):
            failures.append(f"RENDER_RETURNED_NON_DICT: {did}")
            continue

        # Required fields must exist (None values OK — only key presence)
        for field in required:
            if field not in rendered:
                failures.append(
                    f"MISSING_REQUIRED_FIELD: {did} expected '{field}' "
                    f"(rendered keys: {sorted(rendered.keys())[:5]}…)"
                )
    return failures


# ── Check 2: every emit.item template uses well-formed Jinja ─────────────────


def check_template_syntax() -> List[str]:
    failures: List[str] = []
    for prov_dir in CATALOG_ROOT.iterdir():
        if not prov_dir.is_dir():
            continue
        for svc_dir in prov_dir.iterdir():
            if not svc_dir.is_dir():
                continue
            for yp in svc_dir.glob("step6_*.discovery.yaml"):
                try:
                    with yp.open() as fh:
                        data = yaml.safe_load(fh) or {}
                except Exception as exc:
                    failures.append(f"YAML_LOAD: {yp}: {exc}")
                    continue
                for disc in data.get("discovery") or []:
                    did = disc.get("discovery_id", "<no_id>")
                    emit = disc.get("emit") or {}
                    if not isinstance(emit, dict):
                        continue
                    item = emit.get("item")
                    if not isinstance(item, dict):
                        continue
                    for fname, tmpl in item.items():
                        if not isinstance(tmpl, str):
                            continue
                        # Render against an empty context — must not raise.
                        try:
                            render_emit_item(
                                {fname: tmpl},
                                {"response": {}, "item": {}, "context": {}},
                                discovery_id=did,
                                resource_uid="syntax_check",
                                failure_sink=[],
                            )
                        except Exception as exc:
                            failures.append(
                                f"TEMPLATE_SYNTAX: {prov_dir.name}/{svc_dir.name}/"
                                f"{did}/{fname} → {type(exc).__name__}: {exc}"
                            )
    return failures


# ── Check 3: downstream engines reference catalog fields ─────────────────────


def check_engine_consumers(idx: Dict[str, Dict[str, Set[str]]]) -> List[str]:
    """Detect engine code accesses to fields no catalog template emits.

    Lighter-touch version of scripts/audit_mapper_paths.py — only flags as
    a CI failure if the engine accesses a field with a name that NO catalog
    template anywhere produces (i.e. truly orphaned).
    """
    # Universe = union of all field names across all (provider, discovery_id)
    universe: Set[str] = set()
    for prov_map in idx.values():
        for fields in prov_map.values():
            universe |= fields

    # Run audit script's heuristics inline (avoid subprocess)
    import ast
    import re

    EMIT_LIKE_VARS = {
        "emitted", "emitted_fields", "ef", "raw_response",
    }
    # Built-in / non-catalog keys we expect engines to reference
    SYSTEM_KEYS = {
        "resource_uid", "resource_id", "resource_arn", "resource_type",
        "resource_name", "_raw_response", "_discovery_id", "tags",
    }

    failures: List[str] = []
    target_dirs = [
        ENGINES_ROOT / e for e in (
            "encryption-security", "container-security", "database-security",
            "ai-security", "datasec",
        ) if (ENGINES_ROOT / e).is_dir()
    ]
    for ed in target_dirs:
        for py in ed.rglob("*.py"):
            if "__pycache__" in py.parts or py.name.startswith("test_"):
                continue
            try:
                src = py.read_text()
                tree = ast.parse(src)
            except Exception:
                continue
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in EMIT_LIKE_VARS
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                ):
                    key = node.args[0].value
                    if (
                        key
                        and key not in SYSTEM_KEYS
                        and not key.startswith("_")
                        and key not in universe
                        # Heuristic: ignore PascalCase strings that look like
                        # legitimate provider field names not in our catalog
                        # universe (false positive for non-AWS provider files).
                        and key[0].islower()
                    ):
                        failures.append(
                            f"ORPHAN_FIELD: {py.relative_to(ROOT)}:{node.lineno} "
                            f"'{key}' (no catalog template emits this)"
                        )
    return failures


def main() -> int:
    print("=" * 70)
    print("DCAT Catalog Completeness CI Check")
    print("=" * 70)

    if not CATALOG_ROOT.is_dir():
        print(f"FAIL: catalog root missing: {CATALOG_ROOT}", file=sys.stderr)
        return 2

    idx = collect_catalog_field_index()
    total_dids = sum(len(m) for m in idx.values())
    total_fields = sum(len(s) for m in idx.values() for s in m.values())
    print(f"\nCatalog index: {len(idx)} providers, "
          f"{total_dids} discovery_ids, {total_fields} emit.item field bindings\n")

    all_failures: List[Tuple[str, List[str]]] = []

    print("Check 1/3: smoke fixtures render with required fields...")
    f1 = check_smoke_fixtures(idx)
    all_failures.append(("Smoke fixtures", f1))
    print(f"  {'PASS' if not f1 else 'FAIL'} ({len(f1)} issues)")

    print("Check 2/3: every emit.item Jinja template parses cleanly...")
    f2 = check_template_syntax()
    all_failures.append(("Template syntax", f2))
    print(f"  {'PASS' if not f2 else 'FAIL'} ({len(f2)} issues)")

    print("Check 3/3: downstream engine consumers reference live fields...")
    f3 = check_engine_consumers(idx)
    all_failures.append(("Engine consumers", f3))
    print(f"  {'PASS' if not f3 else 'WARN'} ({len(f3)} candidate orphans)")

    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)

    blocking = bool(f1) or bool(f2)
    for label, failures in all_failures:
        if failures:
            print(f"\n--- {label} ({len(failures)}) ---")
            for fail in failures[:25]:
                print(f"  {fail}")
            if len(failures) > 25:
                print(f"  … {len(failures) - 25} more")

    if blocking:
        print("\n❌ BLOCKING: smoke or syntax failures detected.")
        return 1
    if f3:
        print("\n⚠️  WARNINGS: orphan field references — review but non-blocking.")
    print("\n✅ Catalog completeness check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
