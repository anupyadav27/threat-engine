#!/usr/bin/env python3
"""
CI linter — rejects compiled Cypher that contains string-interpolated values.

Enforces CP1-01: all runtime values from pattern YAML must be $param bindings.
Run by CI gate before any pattern PR merges.

Usage:
    python cypher_parameterization_linter.py [--yaml-dir <path>]

Exit codes:
    0 — all patterns compiled safely
    1 — one or more patterns have unsafe Cypher (interpolated values)
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Add engine root to path for local imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from threat_v1.patterns.compiler import PatternCompiler
from threat_v1.patterns.registry import PatternRegistry

_SENTINEL_TENANT = "lint-tenant-00000000"

# Patterns that indicate runtime values were interpolated into Cypher strings.
# These would never appear in safe parameterized Cypher.
_UNSAFE_PATTERNS = [
    # Python f-string artifacts
    re.compile(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}"),  # {variable}
    # Hardcoded resource type names that should be params
    re.compile(r"resource_type\s*=\s*['\"][A-Z][a-zA-Z]+['\"]"),
    # Hardcoded rule IDs
    re.compile(r"rule_id\s*=\s*['\"][a-z][a-z0-9\-]+['\"]"),
    # Hardcoded tenant values
    re.compile(r"tenant_id\s*=\s*['\"][a-zA-Z0-9\-]+['\"]"),
]

# Every compiled query MUST contain a $tid or $tenant_id parameter reference
_REQUIRED_TENANT_PARAM = re.compile(r"\$(tid|tenant_id)\b")


def lint_pattern(pattern, compiler: PatternCompiler) -> list[str]:
    """Lint a single pattern. Returns list of violation messages (empty = safe)."""
    violations: list[str] = []

    try:
        cypher, params = compiler.compile(pattern, _SENTINEL_TENANT)
    except Exception as exc:
        violations.append(f"compile() raised exception: {exc}")
        return violations

    # Check 1: no unsafe interpolation artifacts in the Cypher string
    for unsafe_re in _UNSAFE_PATTERNS:
        match = unsafe_re.search(cypher)
        if match:
            violations.append(
                f"Unsafe interpolation detected in compiled Cypher: '{match.group()}'"
            )

    # Check 2: tenant filter must be present
    if not _REQUIRED_TENANT_PARAM.search(cypher):
        violations.append(
            "Compiled Cypher missing $tid / $tenant_id parameter — "
            "tenant isolation not enforced"
        )

    # Check 3: the sentinel tenant value must not appear literally in the query
    if _SENTINEL_TENANT in cypher:
        violations.append(
            f"Sentinel tenant '{_SENTINEL_TENANT}' found literally in Cypher — "
            "tenant_id was interpolated instead of parameterized"
        )

    # Check 4: pattern id must appear in params (as $pattern_id), not in Cypher string
    if pattern.id in cypher and "$pattern_id" not in cypher:
        violations.append(
            f"pattern.id '{pattern.id}' appears literally in Cypher — "
            "must be passed as $pattern_id param"
        )

    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Cypher parameterization linter")
    parser.add_argument(
        "--yaml-dir",
        default="catalog/threat_patterns",
        help="Path to the threat_patterns catalog directory",
    )
    args = parser.parse_args()

    yaml_dir = Path(args.yaml_dir)
    if not yaml_dir.exists():
        print(f"ERROR: yaml_dir '{yaml_dir}' does not exist", file=sys.stderr)
        return 1

    patterns = PatternRegistry.load_from_yaml_dir(str(yaml_dir))
    if not patterns:
        print("WARNING: no patterns found in yaml_dir", file=sys.stderr)
        return 0

    compiler = PatternCompiler()
    total = 0
    failed = 0

    for pattern in patterns:
        total += 1
        violations = lint_pattern(pattern, compiler)
        if violations:
            failed += 1
            print(f"FAIL {pattern.id}:")
            for v in violations:
                print(f"  - {v}")
        else:
            print(f"OK   {pattern.id}")

    print(f"\n{total - failed}/{total} patterns passed linting.")
    if failed:
        print(f"{failed} pattern(s) FAILED — fix before merge.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
