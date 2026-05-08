#!/usr/bin/env python3
"""
YAML validator for CIS Technology compliance rule files.

Scans all generated rule output directories for a given category/tech and
validates each YAML file against 8 schema checks.  Exits 0 when zero findings
are produced; exits 1 otherwise.

Usage::

    python3 catalog/rule/validate_tech_rules.py \\
        [--category <category>]     # optional; limit scan to one category
        [--tech <subcategory>]      # optional; limit scan to one tech
        [--output <path>]           # optional; override default report path
        [--fail-fast]               # optional; stop after first failure file

Output:
    JSON report written to <output> (default: catalog/rule/tech_validation_report.json)

Exit code:
    0 — zero findings (passed=true)
    1 — one or more findings (passed=false)
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "pyyaml is required.  Install it: pip install pyyaml"
    ) from exc

# ─── Repository root ─────────────────────────────────────────────────────────

_BASE = Path("/Users/apple/Desktop/threat-engine")

# ─── Known tech categories (non-cloud only) ──────────────────────────────────

TECH_CATEGORIES: set[str] = {
    "linux",
    "database",
    "networking",
    "web_server",
    "container",
    "virtualization",
    "cloud_saas",
    "devops",
    "data",
}

# Cloud CSP categories to skip
_CLOUD_CATEGORIES: set[str] = {
    "aws",
    "azure",
    "gcp",
    "oci",
    "ibm",
    "alicloud",
    "k8s",
}

# Known benchmark_subcategory values produced by the tech pipeline
TECH_SUBCATEGORIES: set[str] = {
    "ubuntu",
    "rhel",
    "debian",
    "centos",
    "suse",
    "postgresql",
    "mysql",
    "oracle_db",
    "sql_server",
    "mariadb",
    "ibm_db2",
    "mongodb",
    "cassandra",
    "docker",
    "vmware_esxi",
    "cisco_ios_xe",
    "cisco_asa",
    "cisco_nxos",
    "cisco_ios_xr",
    "cisco_firewall",
    "palo_alto",
    "fortigate",
    "check_point",
    "apache_http",
    "nginx",
    "iis",
    "tomcat",
    "websphere",
    "microsoft_365",
    "google_workspace",
    "sharepoint",
    "dynamics_365",
    "gitlab",
    "snowflake",
}

# ─── Validation constants ─────────────────────────────────────────────────────

VALID_SEVERITIES: set[str] = {
    "critical",
    "high",
    "medium",
    "low",
    "informational",
}

# V2: check rule_id pattern
_CHECK_RULE_ID_RE = re.compile(
    r"^[a-z0-9_]+\.cis\.[0-9_]+\.[a-z0-9_]+$"
)

# V3: CIEM rule_id pattern
_CIEM_RULE_ID_RE = re.compile(
    r"^tciem\.[a-z0-9_]+\.[a-z0-9_]+$"
)

# V4: MITRE technique pattern
_MITRE_TECHNIQUE_RE = re.compile(
    r"^T\d{4}(\.\d{3})?$"
)

# Default report output path (relative to repo root)
_DEFAULT_REPORT_PATH = _BASE / "catalog" / "rule" / "tech_validation_report.json"


# ─── Finding helpers ──────────────────────────────────────────────────────────


def _finding(
    file: str,
    check: str,
    message: str,
    rule_id: str | None = None,
    severity: str = "error",
) -> dict[str, Any]:
    """Construct a validation finding dict.

    Args:
        file: Repo-relative path string of the scanned file.
        check: Validation check identifier, e.g. ``"V2"``.
        message: Human-readable description of the failure.
        rule_id: Optional rule_id of the affected rule (None for file-level checks).
        severity: ``"error"`` or ``"warning"``.

    Returns:
        A finding dict.
    """
    return {
        "file": file,
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "message": message,
    }


# ─── File classification ──────────────────────────────────────────────────────


def _is_tech_generated_file(path: Path, data: Any) -> bool:
    """Return True if *path* should be validated as a tech-generated file.

    A file is tech-generated when:
    - It contains ``tech_type`` at the top level, OR
    - Its parent directory name is in ``TECH_SUBCATEGORIES`` AND the path
      contains ``_rule_check/``, ``_rule_ciem/``, or ``_rule_metadata/``.

    Args:
        path: Absolute path to the YAML file.
        data: Parsed YAML data (top-level).

    Returns:
        True when the file should be validated.
    """
    if not isinstance(data, dict):
        return False

    # Key check: top-level tech_type
    if "tech_type" in data:
        return True

    # Path-based check: directory name in known tech subcategories
    parent_name = path.parent.name
    path_str = str(path)
    if parent_name in TECH_SUBCATEGORIES and (
        "_rule_check/" in path_str
        or "_rule_ciem/" in path_str
        or "_rule_metadata/" in path_str
        or ".discovery.yaml" in path_str
    ):
        return True

    return False


def _is_cloud_path(path: Path) -> bool:
    """Return True when the path's category directory is a cloud CSP.

    Checks whether any path component matches a known cloud category prefix.

    Args:
        path: Absolute file path to check.

    Returns:
        True when the file belongs to a cloud CSP category.
    """
    for part in path.parts:
        # Match directory names like "aws_rule_check", "azure_rule_ciem", etc.
        for cloud_cat in _CLOUD_CATEGORIES:
            if part.startswith(cloud_cat + "_rule") or part == cloud_cat:
                return True
    return False


# ─── Rule-level validation checks ────────────────────────────────────────────


def validate_v2_check_rule_id(rule: dict, file: str) -> list[dict]:
    """V2: Check rule_id format for files in *_rule_check/ paths.

    Args:
        rule: A single rule dict from the ``rules:`` list.
        file: Repo-relative path string.

    Returns:
        List of findings (empty when check passes).
    """
    rule_id = str(rule.get("rule_id", ""))
    if not _CHECK_RULE_ID_RE.match(rule_id):
        return [
            _finding(
                file=file,
                check="V2",
                rule_id=rule_id or None,
                message=(
                    f"rule_id {rule_id!r} does not match pattern "
                    r"^[a-z0-9_]+\.cis\.[0-9_]+\.[a-z0-9_]+$"
                ),
            )
        ]
    return []


def validate_v3_ciem_rule_id(rule: dict, file: str) -> list[dict]:
    """V3: CIEM rule_id format for files in *_rule_ciem/ paths.

    Args:
        rule: A single rule dict from the ``rules:`` list.
        file: Repo-relative path string.

    Returns:
        List of findings (empty when check passes).
    """
    rule_id = str(rule.get("rule_id", ""))
    if not _CIEM_RULE_ID_RE.match(rule_id):
        return [
            _finding(
                file=file,
                check="V3",
                rule_id=rule_id or None,
                message=(
                    f"CIEM rule_id {rule_id!r} does not match pattern "
                    r"^tciem\.[a-z0-9_]+\.[a-z0-9_]+$"
                ),
            )
        ]
    return []


def validate_v4_mitre_technique(rule: dict, file: str) -> list[dict]:
    """V4: CIEM rules must have a valid mitre_technique.

    Args:
        rule: A single CIEM rule dict.
        file: Repo-relative path string.

    Returns:
        List of findings (empty when check passes).
    """
    rule_id = str(rule.get("rule_id", "")) or None
    technique = rule.get("mitre_technique", None)
    if not technique:
        return [
            _finding(
                file=file,
                check="V4",
                rule_id=rule_id,
                message="CIEM rule is missing mitre_technique field",
            )
        ]
    technique_str = str(technique)
    if not _MITRE_TECHNIQUE_RE.match(technique_str):
        return [
            _finding(
                file=file,
                check="V4",
                rule_id=rule_id,
                message=(
                    f"mitre_technique {technique_str!r} does not match pattern "
                    r"^T\d{4}(\.\d{3})?$"
                ),
            )
        ]
    return []


def validate_v6_severity(rule: dict, file: str) -> list[dict]:
    """V6: Severity must be in the allowed set (after lowercasing).

    Args:
        rule: A single rule dict.
        file: Repo-relative path string.

    Returns:
        List of findings (empty when check passes).
    """
    rule_id = str(rule.get("rule_id", "")) or None
    raw = rule.get("severity", None)
    if raw is None:
        return [
            _finding(
                file=file,
                check="V6",
                rule_id=rule_id,
                message="rule is missing severity field",
            )
        ]
    lower = str(raw).lower().strip()
    if lower not in VALID_SEVERITIES:
        return [
            _finding(
                file=file,
                check="V6",
                rule_id=rule_id,
                message=(
                    f"severity {raw!r} (lowercased: {lower!r}) is not in "
                    f"{sorted(VALID_SEVERITIES)}"
                ),
            )
        ]
    return []


def validate_v7_automated_assertion(rule: dict, file: str) -> list[dict]:
    """V7: Automated check rules must have a valid assertion block.

    Applies only when automation_type is NOT ``manual`` and there is no
    ``manual_procedure`` key.  The assertion block must be a dict with non-empty
    ``field``, ``operator``, and ``expected`` keys.

    Args:
        rule: A single check rule dict.
        file: Repo-relative path string.

    Returns:
        List of findings (empty when check passes).
    """
    rule_id = str(rule.get("rule_id", "")) or None
    auto_type = str(rule.get("automation_type", "")).lower().strip()

    # Skip manual rules — those are validated by V8
    if auto_type == "manual":
        return []

    # Also skip if a manual_procedure key is present (treated as manual)
    if "manual_procedure" in rule:
        return []

    assertion = rule.get("assertion", None)
    if assertion is None:
        return [
            _finding(
                file=file,
                check="V7",
                rule_id=rule_id,
                message=(
                    "automated check rule has no assertion block and no "
                    "manual_procedure — add an assertion with field/operator/expected"
                ),
            )
        ]

    if not isinstance(assertion, dict):
        return [
            _finding(
                file=file,
                check="V7",
                rule_id=rule_id,
                message=f"assertion must be a dict, got {type(assertion).__name__}",
            )
        ]

    findings: list[dict] = []
    for key in ("field", "operator"):
        val = assertion.get(key, "")
        if not val or not str(val).strip():
            findings.append(
                _finding(
                    file=file,
                    check="V7",
                    rule_id=rule_id,
                    message=f"assertion.{key} is missing or empty",
                )
            )

    # expected can be the string "false", "0", etc. — check key presence only
    if "expected" not in assertion:
        findings.append(
            _finding(
                file=file,
                check="V7",
                rule_id=rule_id,
                message="assertion.expected key is missing",
            )
        )

    return findings


def validate_v8_manual_procedure(rule: dict, file: str) -> list[dict]:
    """V8: Manual check rules must have a non-empty manual_procedure.

    Args:
        rule: A single check rule dict.
        file: Repo-relative path string.

    Returns:
        List of findings (empty when check passes).
    """
    rule_id = str(rule.get("rule_id", "")) or None
    auto_type = str(rule.get("automation_type", "")).lower().strip()

    if auto_type != "manual":
        return []

    proc = rule.get("manual_procedure", None)
    if not proc or not str(proc).strip():
        return [
            _finding(
                file=file,
                check="V8",
                rule_id=rule_id,
                message="manual rule is missing a non-empty manual_procedure field",
            )
        ]

    return []


# ─── File-level V5 duplicate detection ───────────────────────────────────────


def check_v5_duplicates(
    rule_ids: list[str],
    file: str,
) -> list[dict]:
    """V5: Detect duplicate rule_id values across a list of rule IDs.

    Args:
        rule_ids: All rule_id strings collected for one tech directory.
        file: Path string used in findings (can be a synthetic label).

    Returns:
        One finding per duplicate rule_id found.
    """
    seen: dict[str, int] = {}
    for rid in rule_ids:
        seen[rid] = seen.get(rid, 0) + 1

    findings: list[dict] = []
    for rid, count in seen.items():
        if count > 1:
            findings.append(
                _finding(
                    file=file,
                    check="V5",
                    rule_id=rid,
                    message=f"rule_id {rid!r} appears {count} times in this tech directory",
                )
            )
    return findings


# ─── Per-file validation ──────────────────────────────────────────────────────


def validate_file(
    path: Path,
    is_check: bool,
    is_ciem: bool,
    is_discovery: bool,
) -> tuple[list[dict], int]:
    """Validate a single YAML file and return findings + rule count.

    Applies V1 (parse), then per-rule checks V2-V8 as appropriate.  V5
    (duplicate rule_id) is computed at the tech-directory level by the caller.

    Args:
        path: Absolute path to the YAML file.
        is_check: True when the file is in a *_rule_check/ directory.
        is_ciem: True when the file is in a *_rule_ciem/ directory.
        is_discovery: True when the file is a discovery YAML.

    Returns:
        Tuple of (findings_list, rule_count).  rule_count is 0 when V1 fails.
    """
    # Make paths repo-relative for reporting
    try:
        rel = str(path.relative_to(_BASE))
    except ValueError:
        rel = str(path)

    # V1: YAML parse
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return (
            [
                _finding(
                    file=rel,
                    check="V1",
                    message=f"YAML parse error: {exc}",
                )
            ],
            0,
        )

    if not isinstance(data, dict):
        return (
            [
                _finding(
                    file=rel,
                    check="V1",
                    message="Top-level YAML is not a mapping (dict)",
                )
            ],
            0,
        )

    # Determine which top-level list key to use
    list_key = "discovery" if is_discovery else "rules"
    rules_list = data.get(list_key, None)

    if rules_list is None or not isinstance(rules_list, list):
        # Not a generated tech file with the expected list — skip
        return [], 0

    findings: list[dict] = []
    rule_count = len(rules_list)

    for rule in rules_list:
        if not isinstance(rule, dict):
            continue

        # V6: severity applies to check, ciem, and metadata rules — NOT discovery items
        if not is_discovery:
            findings.extend(validate_v6_severity(rule, rel))

        if is_check:
            # V2: check rule_id format
            findings.extend(validate_v2_check_rule_id(rule, rel))
            # V7: automated assertion present
            findings.extend(validate_v7_automated_assertion(rule, rel))
            # V8: manual procedure present
            findings.extend(validate_v8_manual_procedure(rule, rel))

        if is_ciem:
            # V3: CIEM rule_id format
            findings.extend(validate_v3_ciem_rule_id(rule, rel))
            # V4: MITRE technique
            findings.extend(validate_v4_mitre_technique(rule, rel))

    return findings, rule_count


# ─── Tech directory scanner ───────────────────────────────────────────────────


def _collect_yaml_files(
    catalog_root: Path,
    category_filter: str | None,
    tech_filter: str | None,
) -> list[tuple[Path, str, str]]:
    """Collect all candidate YAML file paths for validation.

    Returns a list of ``(absolute_path, file_kind, tech_dir)`` tuples where
    ``file_kind`` is one of: ``"check"``, ``"ciem"``, ``"metadata"``,
    ``"discovery"``.

    Skips files whose category is a cloud CSP (``_CLOUD_CATEGORIES``).

    Args:
        catalog_root: Absolute path to the ``catalog/`` directory.
        category_filter: Optional benchmark_category string to limit scope.
        tech_filter: Optional benchmark_subcategory string to limit scope.

    Returns:
        List of (path, kind, tech_dir) tuples.
    """
    candidates: list[tuple[Path, str, str]] = []

    rule_root = catalog_root / "rule"
    discovery_root = catalog_root / "discovery_generator_data"

    def _accept_category(dir_name: str, kind_suffix: str) -> str | None:
        """Extract and validate the category from a directory name.

        Args:
            dir_name: Directory name, e.g. ``"database_rule_check"``.
            kind_suffix: The suffix to strip, e.g. ``"_rule_check"``.

        Returns:
            Category string if accepted, None if rejected.
        """
        if not dir_name.endswith(kind_suffix):
            return None
        cat = dir_name[: -len(kind_suffix)]
        if cat in _CLOUD_CATEGORIES:
            return None
        if category_filter and cat != category_filter:
            return None
        return cat

    # --- *_rule_check/
    for cat_dir in rule_root.iterdir():
        if not cat_dir.is_dir():
            continue
        cat = _accept_category(cat_dir.name, "_rule_check")
        if cat is None:
            continue
        for tech_dir in cat_dir.iterdir():
            if not tech_dir.is_dir():
                continue
            if tech_filter and tech_dir.name != tech_filter:
                continue
            for f in tech_dir.glob("*.yaml"):
                candidates.append((f, "check", tech_dir.name))

    # --- *_rule_ciem/
    for cat_dir in rule_root.iterdir():
        if not cat_dir.is_dir():
            continue
        cat = _accept_category(cat_dir.name, "_rule_ciem")
        if cat is None:
            continue
        for tech_dir in cat_dir.iterdir():
            if not tech_dir.is_dir():
                continue
            if tech_filter and tech_dir.name != tech_filter:
                continue
            for f in tech_dir.glob("*.yaml"):
                candidates.append((f, "ciem", tech_dir.name))

    # --- *_rule_metadata/
    for cat_dir in rule_root.iterdir():
        if not cat_dir.is_dir():
            continue
        cat = _accept_category(cat_dir.name, "_rule_metadata")
        if cat is None:
            continue
        for tech_dir in cat_dir.iterdir():
            if not tech_dir.is_dir():
                continue
            if tech_filter and tech_dir.name != tech_filter:
                continue
            for f in tech_dir.glob("*.yaml"):
                candidates.append((f, "metadata", tech_dir.name))

    # --- discovery_generator_data/<category>/<tech>/*.discovery.yaml
    if discovery_root.exists():
        for cat_dir in discovery_root.iterdir():
            if not cat_dir.is_dir():
                continue
            if cat_dir.name in _CLOUD_CATEGORIES:
                continue
            if category_filter and cat_dir.name != category_filter:
                continue
            for tech_dir in cat_dir.iterdir():
                if not tech_dir.is_dir():
                    continue
                if tech_filter and tech_dir.name != tech_filter:
                    continue
                for f in tech_dir.glob("*.discovery.yaml"):
                    candidates.append((f, "discovery", tech_dir.name))

    return candidates


# ─── Main validation run ──────────────────────────────────────────────────────


def run_validation(
    catalog_root: Path,
    category_filter: str | None,
    tech_filter: str | None,
    fail_fast: bool,
) -> dict[str, Any]:
    """Run the full validation scan and return the report dict.

    Args:
        catalog_root: Absolute path to the ``catalog/`` directory.
        category_filter: Optional category filter (None = all).
        tech_filter: Optional tech filter (None = all).
        fail_fast: When True, stop after the first file with failures.

    Returns:
        Report dict with keys: generated_at, files_scanned, files_skipped,
        total_rules_checked, total_findings, passed, techs_scanned, findings.
    """
    candidates = _collect_yaml_files(catalog_root, category_filter, tech_filter)

    files_scanned = 0
    files_skipped = 0
    total_rules = 0
    all_findings: list[dict] = []
    techs_seen: set[str] = set()

    # Collect rule_ids per (kind, tech_dir) for V5 duplicate detection.
    # V5 checks for duplicates within a single directory type + tech combination
    # (e.g. all check files in database_rule_check/postgresql/).
    # Key: (kind, tech_dir) → (list of rule_ids, list of file rel-paths)
    dir_rule_ids: dict[tuple[str, str], list[str]] = {}
    dir_files: dict[tuple[str, str], list[str]] = {}

    abort = False

    for path, kind, tech_dir in sorted(candidates, key=lambda x: str(x[0])):
        if abort:
            break

        # Quick check: is this a generated file?
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            data = None
        except OSError:
            data = None

        # Determine is_check/is_ciem/is_discovery flags
        is_check = kind == "check"
        is_ciem = kind == "ciem"
        is_discovery = kind == "discovery"

        # Skip non-tech-generated files
        if data is not None and not _is_tech_generated_file(path, data):
            try:
                rel = str(path.relative_to(_BASE))
            except ValueError:
                rel = str(path)
            print(f"[SKIP]  {rel} (not a tech-generated file)")
            files_skipped += 1
            continue

        # Validate
        findings, rule_count = validate_file(path, is_check, is_ciem, is_discovery)
        total_rules += rule_count

        try:
            rel = str(path.relative_to(_BASE))
        except ValueError:
            rel = str(path)

        # Collect rule_ids for V5 check (not discovery files)
        # Scope is (kind, tech_dir) so check/ciem/metadata are tracked separately
        if not is_discovery and data and isinstance(data, dict):
            rules_list = data.get("rules", [])
            if isinstance(rules_list, list):
                scope_key = (kind, tech_dir)
                if scope_key not in dir_rule_ids:
                    dir_rule_ids[scope_key] = []
                    dir_files[scope_key] = []
                for rule in rules_list:
                    if isinstance(rule, dict):
                        rid = str(rule.get("rule_id", ""))
                        if rid:
                            dir_rule_ids[scope_key].append(rid)
                dir_files[scope_key].append(rel)

        files_scanned += 1
        techs_seen.add(tech_dir)

        if findings:
            all_findings.extend(findings)
            print(f"[FAIL]  {rel} ({len(findings)} errors)")
            if fail_fast:
                abort = True
        else:
            print(f"[OK]    {rel} ({rule_count} rules)")

    # V5: duplicate rule_id check per (kind, tech_dir)
    for scope_key, rule_ids in dir_rule_ids.items():
        # Use the first file in the scope as the finding location
        scope_files = dir_files[scope_key]
        tech_label = scope_files[0] if scope_files else str(scope_key)
        v5_findings = check_v5_duplicates(rule_ids, tech_label)
        if v5_findings:
            all_findings.extend(v5_findings)
            # Print inline with file label
            print(
                f"[FAIL]  {tech_label} (V5: {len(v5_findings)} duplicate rule_id(s))"
            )

    passed = len(all_findings) == 0

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "total_rules_checked": total_rules,
        "total_findings": len(all_findings),
        "passed": passed,
        "techs_scanned": sorted(techs_seen),
        "findings": all_findings,
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="validate_tech_rules",
        description="Validate CIS Technology compliance YAML rule files.",
    )
    parser.add_argument(
        "--category",
        default=None,
        metavar="CATEGORY",
        help="Limit scan to one benchmark_category (e.g. database, linux).",
    )
    parser.add_argument(
        "--tech",
        default=None,
        metavar="TECH",
        help="Limit scan to one benchmark_subcategory within the category.",
    )
    parser.add_argument(
        "--output",
        default=str(_DEFAULT_REPORT_PATH),
        metavar="PATH",
        help=f"Output path for the JSON report (default: {_DEFAULT_REPORT_PATH}).",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        default=False,
        help="Stop scanning after the first file with failures.",
    )
    return parser


def main() -> None:
    """Entry point for the tech rule validator.

    Raises:
        SystemExit(0): When validation passes (zero findings).
        SystemExit(1): When validation fails (one or more findings).
    """
    parser = _build_parser()
    args = parser.parse_args()

    catalog_root = _BASE / "catalog"
    if not catalog_root.exists():
        print(f"[ERROR] catalog root not found: {catalog_root}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning catalog: {catalog_root}")
    if args.category:
        print(f"Category filter : {args.category}")
    if args.tech:
        print(f"Tech filter     : {args.tech}")
    print()

    report = run_validation(
        catalog_root=catalog_root,
        category_filter=args.category,
        tech_filter=args.tech,
        fail_fast=args.fail_fast,
    )

    # Write report
    report_path = Path(args.output)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Summary line
    print()
    print(
        f"Validation complete. "
        f"Scanned: {report['files_scanned']} files | "
        f"Skipped: {report['files_skipped']} | "
        f"Rules checked: {report['total_rules_checked']} | "
        f"Errors: {report['total_findings']}"
    )
    print(f"Report written to: {report_path}")

    sys.exit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
