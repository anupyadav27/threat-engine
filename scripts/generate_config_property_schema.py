#!/usr/bin/env python3
"""
Parses all check rule YAMLs and extracts var path references from conditions.

Output: config_property_schema.json — keyed by resource_type (derived from for_each),
each resource_type mapping to a dict of sanitized property_name → metadata.

Used by GRAPH-S1-03 to expand native security-relevant properties onto Neo4j Resource nodes.

Usage:
    python3 scripts/generate_config_property_schema.py

Output:
    engines/threat/threat_engine/graph/config_property_schema.json
"""
import glob
import json
import re
import sys
from pathlib import Path

import yaml

# Run from repo root; paths are relative to repo root
RULE_DIR = "catalog/rule/aws_rule_check/"
OUT = "engines/threat/threat_engine/graph/config_property_schema.json"

# Property name allowlist: only alphanum + underscore, max 64 chars, must start with letter
SAFE_PROP = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _sanitize_var(raw_var: str) -> str:
    """Convert a var path like 'Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm'
    to a safe property name: strip array markers, replace dots with underscores, lowercase.

    Args:
        raw_var: The raw var path after stripping 'item.' prefix.

    Returns:
        Sanitized property name string.
    """
    # Remove [] array access markers (e.g. Rules[].Status → Rules.Status)
    cleaned = raw_var.replace("[]", "")
    # Replace dots with underscores
    cleaned = cleaned.replace(".", "_")
    # Lowercase
    cleaned = cleaned.lower()
    # Strip leading/trailing underscores that can appear after stripping item prefix
    cleaned = cleaned.strip("_")
    return cleaned


def extract_var_paths(conditions: object) -> set:
    """Recursively walk a conditions dict/list to extract all var: item.X paths.

    Only extracts vars that start with 'item.' — ignores field-based conditions
    (activity log style) and bare item references.

    Args:
        conditions: The conditions field from a rule check (dict, list, or None).

    Returns:
        Set of raw var path strings (with 'item.' prefix already stripped).
    """
    paths: set = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            # Check if this dict node is a condition with var
            if "var" in node and isinstance(node["var"], str):
                v = node["var"]
                if v.startswith("item."):
                    # Strip 'item.' prefix — but keep the rest (may include nested paths)
                    paths.add(v[5:])  # e.g. 'Rules[].ApplyServerSideEncryptionByDefault.SSEAlgorithm'
                elif v == "item":
                    # Bare 'item' reference — not useful as a named property, skip
                    pass
            # Recurse into all dict values (handles all/any/nested conditions)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(conditions)
    return paths


def derive_resource_type(for_each: str) -> str:
    """Convert a for_each discovery ID to a resource_type key.

    Examples:
        aws.s3.get_bucket_encryption → aws_s3_get_bucket_encryption
        aws.rds.describe_db_clusters → aws_rds_describe_db_clusters
        aws.kms.list_aliases → aws_kms_list_aliases

    Args:
        for_each: The for_each field value from a check rule.

    Returns:
        Underscore-separated resource type string.
    """
    return for_each.replace(".", "_")


def process_yaml_file(path: str, schema: dict) -> tuple:
    """Parse one YAML file and merge its extracted properties into schema.

    Args:
        path: Absolute or relative path to the YAML file.
        schema: The running schema dict to merge into (mutated in place).

    Returns:
        Tuple of (checks_processed, properties_added) counts.
    """
    checks_processed = 0
    properties_added = 0

    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"  WARN: YAML parse error in {path}: {e}", file=sys.stderr)
        return 0, 0
    except OSError as e:
        print(f"  WARN: Cannot read {path}: {e}", file=sys.stderr)
        return 0, 0

    if not isinstance(doc, dict):
        return 0, 0

    # All YAML files in this catalog use a top-level 'checks' list
    checks = doc.get("checks", [])
    if not isinstance(checks, list):
        return 0, 0

    for check in checks:
        if not isinstance(check, dict):
            continue

        for_each = check.get("for_each", "")
        if not for_each or not isinstance(for_each, str):
            # Skip activity-log style checks with no for_each
            continue

        conditions = check.get("conditions")
        if not conditions:
            continue

        rt = derive_resource_type(for_each)
        var_paths = extract_var_paths(conditions)
        checks_processed += 1

        for raw_path in sorted(var_paths):
            prop_name = _sanitize_var(raw_path)
            if not prop_name:
                continue
            if not SAFE_PROP.match(prop_name):
                # Log skipped unsafe names for transparency
                print(
                    f"  SKIP unsafe prop '{prop_name}' (from var '{raw_path}') in {path}",
                    file=sys.stderr,
                )
                continue

            if rt not in schema:
                schema[rt] = {}

            if prop_name not in schema[rt]:
                schema[rt][prop_name] = {
                    "emitted_field_path": raw_path,
                }
                properties_added += 1
            # If already present from a prior file, keep the first occurrence (idempotent)

    return checks_processed, properties_added


def main() -> int:
    """Run the schema generator.

    Returns:
        Exit code (0 = success, 1 = failure).
    """
    yaml_files = sorted(glob.glob(f"{RULE_DIR}**/*.yaml", recursive=True))
    if not yaml_files:
        print(f"ERROR: No YAML files found under {RULE_DIR}", file=sys.stderr)
        return 1

    print(f"Scanning {len(yaml_files)} YAML files in {RULE_DIR}...")

    schema: dict = {}
    total_checks = 0
    total_props = 0

    for path in yaml_files:
        checks_n, props_n = process_yaml_file(path, schema)
        total_checks += checks_n
        total_props += props_n

    # Ensure output directory exists
    out_path = Path(OUT)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2, sort_keys=True)
        f.write("\n")  # trailing newline for POSIX compliance

    resource_type_count = len(schema)
    total_property_count = sum(len(v) for v in schema.values())

    print(
        f"Generated schema: {resource_type_count} resource types, "
        f"{total_property_count} total properties "
        f"({total_checks} checks scanned across {len(yaml_files)} files)"
    )
    print(f"Output: {OUT}")

    if resource_type_count < 30:
        print(
            f"ERROR: Only {resource_type_count} resource types found — expected ≥ 30. "
            "Check YAML parsing logic.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
