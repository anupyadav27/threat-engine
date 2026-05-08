"""
DB Parser — extracts column names from PostgreSQL schema SQL files.

Handles:
  - CREATE TABLE statements
  - Inline column definitions: col_name TYPE [constraints]
  - JSONB columns (flagged separately — they hold arbitrary nested data)
  - Standard columns (finding_id, scan_run_id, tenant_id, ...) always present
"""

from __future__ import annotations
import os
import re

REPO_ROOT = "/Users/apple/Desktop/threat-engine"
SCHEMA_DIR = os.path.join(REPO_ROOT, "shared/database/schemas")
# Some engine schemas live in the nested database/database/schemas/ directory
SCHEMA_DIR_ALT = os.path.join(REPO_ROOT, "shared/database/database/schemas")

# Standard columns present on every engine findings table (from CLAUDE.md constitution)
STANDARD_COLUMNS = {
    "finding_id", "scan_run_id", "tenant_id", "account_id",
    "credential_ref", "credential_type", "provider", "region",
    "resource_uid", "resource_type", "severity", "status",
    "first_seen_at", "last_seen_at",
}

# Map engine/view name → schema file name(s) (without .sql)
_ENGINE_SCHEMA_MAP: dict[str, list[str]] = {
    "threat":            ["threat_mitre_reference_schema"],
    "threats-graph":     ["threat_mitre_reference_schema"],
    "risk":              ["risk_schema"],
    "compliance":        ["compliance_data_schema"],
    "network-security":  ["network_schema"],
    "datasec":           ["datasec_schema", "datasec_enhanced_schema"],
    "ciem":              ["ciem_schema"],
    "billing":           ["billing_schema"],
    "iam":               ["iam_policy_statements"],
    "check":             ["check_schema"],   # lives in SCHEMA_DIR_ALT
    "container-security":["container_security_schema", "container_schema"],
    "encryption":        ["encryption_schema"],
    "dbsec":             ["database_security_schema"],
    "ai-security":       ["ai_security_schema"],
    "inventory":         ["api_schema"],
    "vulnerability":     ["supplychain_schema"],
    "secops":            ["api_schema"],
    "threat-command-room": ["threat_mitre_reference_schema", "risk_schema"],
}


def _schema_path(name: str) -> str:
    primary = os.path.join(SCHEMA_DIR, f"{name}.sql")
    if os.path.isfile(primary):
        return primary
    # Fallback to alternate schema directory
    return os.path.join(SCHEMA_DIR_ALT, f"{name}.sql")


def _parse_columns(sql: str) -> tuple[set[str], set[str]]:
    """
    Parse CREATE TABLE blocks and return (regular_columns, jsonb_columns).
    Uses paren-depth tracking so multi-line GENERATED ALWAYS AS expressions
    (which end with ') STORED,') don't prematurely close the table block.
    """
    regular: set[str] = set()
    jsonb: set[str] = set()

    in_table = False
    paren_depth = 0

    for line in sql.splitlines():
        stripped = line.strip()

        if re.match(r'CREATE TABLE\b', stripped, re.IGNORECASE):
            in_table = True
            paren_depth = 1   # the opening '(' that follows on this line or next
            continue

        if not in_table:
            continue

        # Track paren depth to correctly identify table block end
        paren_depth += stripped.count('(') - stripped.count(')')

        # Table block ends when paren depth returns to 0 (outer closing paren)
        if paren_depth <= 0:
            in_table = False
            paren_depth = 0
            continue

        # Skip constraints, primary key lines, comments, GENERATED expressions
        if re.match(r'(CONSTRAINT|PRIMARY KEY|UNIQUE|CHECK\s*\(|FOREIGN KEY|--|/\*|GENERATED)', stripped, re.IGNORECASE):
            continue
        # Skip lines that are continuations of GENERATED expressions
        if re.match(r'(substring|encode|sha256|STORED)', stripped, re.IGNORECASE):
            continue

        # Column line: col_name TYPE ...
        col_m = re.match(r'^(\w+)\s+(\S+)', stripped)
        if col_m:
            col_name = col_m.group(1).lower()
            col_type = col_m.group(2).upper()
            if col_name in {'id'} and col_type in {'BIGSERIAL', 'SERIAL', 'UUID'}:
                regular.add(col_name)
                continue
            if 'JSONB' in col_type or 'JSON' in col_type:
                jsonb.add(col_name)
            else:
                regular.add(col_name)

    return regular, jsonb


def extract_db_columns(engine_name: str) -> dict:
    """
    Parse SQL schema file(s) for `engine_name`.

    Returns:
        {
          "columns": ["scan_run_id", "tenant_id", ...],
          "jsonb_columns": ["rule_metadata", "signal_types", ...],  # hold nested data
          "standard_columns_present": bool,
          "source_files": [...],
          "notes": [...]
        }
    """
    schema_names = _ENGINE_SCHEMA_MAP.get(engine_name, [])
    if not schema_names:
        # Fallback: try engine_name as schema file name directly
        schema_names = [engine_name.replace("-", "_") + "_schema"]

    notes: list[str] = []
    all_regular: set[str] = set()
    all_jsonb: set[str] = set()
    source_files: list[str] = []

    for name in schema_names:
        path = _schema_path(name)
        if not os.path.isfile(path):
            notes.append(f"Schema file not found: {path}")
            continue

        source_files.append(path)
        sql = open(path, encoding="utf-8").read()
        regular, jsonb = _parse_columns(sql)
        all_regular |= regular
        all_jsonb |= jsonb

    # Always inject standard columns (they are constitutional)
    all_regular |= STANDARD_COLUMNS

    standard_present = STANDARD_COLUMNS.issubset(all_regular)

    return {
        "columns": sorted(all_regular),
        "jsonb_columns": sorted(all_jsonb),
        "standard_columns_present": standard_present,
        "source_files": source_files,
        "notes": notes,
    }
