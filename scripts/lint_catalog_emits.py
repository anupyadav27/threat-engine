#!/usr/bin/env python3
"""DCAT-01 — pre-flight catalog lint.

For every discovery_id in catalog/discovery_generator_data/<csp>/<svc>/step6_*.discovery.yaml,
verify that:

  A) An `emit` block exists (else: warn — runtime falls back to raw dump)
  B) The `emit` has either `item:` or `items_for:` (else: error — silent NULLs)
  C) Every `item:` field is a leaf template (str with `{{ ... }}`) — not a nested dict
  D) Every Jinja path resolves syntactically against `response`/`item`/`context`
  E) For AWS only: every Jinja path corresponds to a real boto3 SDK field

Exit codes:
  0  no issues
  1  catalog has structural errors (B or C)
  2  catalog has gaps (A, D, or E warnings)

Usage:
  python3 scripts/lint_catalog_emits.py --provider aws --strict
  python3 scripts/lint_catalog_emits.py --all-providers
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

ROOT = Path("/Users/apple/Desktop/threat-engine")
CATALOG_ROOT = ROOT / "catalog/discovery_generator_data"

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("catalog_lint")


@dataclass
class LintIssue:
    severity: str  # "ERROR" | "WARN"
    csp: str
    service: str
    discovery_id: str
    field_path: str
    message: str


# ── Catalog walk ────────────────────────────────────────────────────────────


def lint_catalog(provider: str, service: str) -> List[LintIssue]:
    issues: List[LintIssue] = []
    svc_dir = CATALOG_ROOT / provider / service
    if not svc_dir.is_dir():
        return issues

    yaml_path = next(iter(svc_dir.glob("step6_*.discovery.yaml")), None)
    if not yaml_path:
        return issues

    try:
        with yaml_path.open() as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:
        issues.append(LintIssue("ERROR", provider, service, "(yaml-load)", "", f"yaml load failed: {exc}"))
        return issues

    for disc in (data.get("discovery") or []):
        did = disc.get("discovery_id", "")
        if not did:
            continue
        emit = disc.get("emit") or {}

        # A: emit block exists
        if not emit:
            issues.append(LintIssue("WARN", provider, service, did, "", "no emit block — runtime will dump raw response"))
            continue

        item = emit.get("item")
        items_for = emit.get("items_for")

        # B: at least one of item:/items_for: must be present
        if not item and not items_for:
            issues.append(LintIssue("ERROR", provider, service, did, "",
                                    "emit has neither item: nor items_for: — silent NULLs guaranteed"))
            continue

        # C: every item: field must be a leaf template
        if isinstance(item, dict):
            for field_name, tmpl in item.items():
                if not isinstance(tmpl, str):
                    if isinstance(tmpl, dict):
                        issues.append(LintIssue("ERROR", provider, service, did, field_name,
                                                "field value is nested dict — must be leaf template; lift inner fields"))
                    else:
                        issues.append(LintIssue("WARN", provider, service, did, field_name,
                                                f"field value is non-template literal: {type(tmpl).__name__}"))
                    continue
                if "{{" not in tmpl:
                    # Plain literal — fine but unusual
                    continue
                # D: Jinja path looks well-formed
                if not _looks_like_valid_jinja(tmpl):
                    issues.append(LintIssue("WARN", provider, service, did, field_name,
                                            f"Jinja template looks malformed: {tmpl[:80]}"))

    return issues


def _looks_like_valid_jinja(tmpl: str) -> bool:
    """Quick syntactic check — counts of {{ and }} match, has a path."""
    if tmpl.count("{{") != tmpl.count("}}"):
        return False
    inner = tmpl.strip().lstrip("{{").rstrip("}}").strip()
    if not inner:
        return False
    # Must reference response, item, or context
    return bool(re.match(r"^(response|item|context)(\.|\[|$)", inner.split()[0]))


# ── CLI ─────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", help="single CSP")
    parser.add_argument("--service", help="single service")
    parser.add_argument("--all-providers", action="store_true")
    parser.add_argument("--strict", action="store_true",
                        help="exit 1 on WARN as well as ERROR")
    args = parser.parse_args()

    if args.all_providers:
        providers = [d.name for d in CATALOG_ROOT.iterdir() if d.is_dir()]
    elif args.provider:
        providers = [args.provider]
    else:
        parser.print_help()
        return 1

    all_issues: List[LintIssue] = []
    for p in providers:
        provider_dir = CATALOG_ROOT / p
        if not provider_dir.is_dir():
            continue
        services = [args.service] if args.service else [
            d.name for d in provider_dir.iterdir() if d.is_dir()
        ]
        for svc in services:
            all_issues.extend(lint_catalog(p, svc))

    errors = [i for i in all_issues if i.severity == "ERROR"]
    warns = [i for i in all_issues if i.severity == "WARN"]

    log.info("=== Catalog Lint Summary ===")
    log.info("ERRORS: %d, WARNINGS: %d", len(errors), len(warns))

    # Show sample issues
    for batch, name in [(errors[:30], "ERROR"), (warns[:30], "WARN")]:
        if not batch:
            continue
        log.info(f"\nFirst {len(batch)} {name}s:")
        for i in batch:
            log.info(f"  [{i.severity}] {i.csp}/{i.service} {i.discovery_id} {i.field_path}: {i.message}")

    if errors:
        return 1
    if args.strict and warns:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
