#!/usr/bin/env python3
"""
Upload Compliance CSV Data to RDS

Reads compliance CSV files from complaince_csv/ directory, inserts rows into
compliance_data and compliance_rule_data_mapping tables in the compliance DB.

Usage:
    python upload_compliance_data.py [--host HOST] [--port PORT] [--db DB] [--user USER] [--password PASSWORD]

The script:
  1. Creates tables if they don't exist (from compliance_data_schema.sql)
  2. Reads all 5 CSP CSV files
  3. Inserts into compliance_data (unique_compliance_id is PK, ON CONFLICT UPDATE)
  4. Explodes mapped_rules into compliance_rule_data_mapping
"""

import argparse
import csv
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import execute_values


# ── CSV file config ──────────────────────────────────────────────────────────
# Each entry: (filename, csp, mapped_rules_column)
CSV_FILES = [
    ("aws_consolidated_rules_with_final_checks.csv", "aws", "final_aws_check"),
    ("azure_consolidated_rules_with_mapping.csv", "azure", "mapped_rule"),
    ("gcp_consolidated_rules_cleaned.csv", "gcp", "mapped_rule_id"),
    ("ibm_consolidated_rules_cleaned.csv", "ibm", "ibm_checks"),
    ("k8s_consolidated_rules_cleaned.csv", "k8s", "mapped_rule_ids"),
]


def create_tables(conn) -> None:
    """Create compliance_data and compliance_rule_data_mapping tables."""
    schema_path = Path(__file__).parent.parent / "schemas" / "compliance_data_schema.sql"
    if schema_path.exists():
        sql = schema_path.read_text()
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        print(f"✓ Tables created/verified from {schema_path.name}")
    else:
        # Inline fallback
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS compliance_data (
                    unique_compliance_id    VARCHAR(255)    PRIMARY KEY,
                    technology              VARCHAR(50),
                    compliance_framework    VARCHAR(100)    NOT NULL,
                    framework_id            VARCHAR(100)    NOT NULL,
                    framework_version       VARCHAR(50),
                    requirement_id          VARCHAR(100)    NOT NULL,
                    requirement_name        TEXT            NOT NULL,
                    requirement_description TEXT,
                    section                 VARCHAR(255),
                    service                 VARCHAR(100),
                    total_checks            INTEGER         DEFAULT 0,
                    automation_type         VARCHAR(50),
                    confidence_score        VARCHAR(50),
                    "references"            TEXT,
                    source_file             VARCHAR(255),
                    csp                     VARCHAR(20)     NOT NULL DEFAULT 'aws',
                    mapped_rules            TEXT,
                    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS compliance_rule_data_mapping (
                    id                      SERIAL          PRIMARY KEY,
                    rule_id                 VARCHAR(255)    NOT NULL,
                    unique_compliance_id    VARCHAR(255)    NOT NULL REFERENCES compliance_data(unique_compliance_id),
                    framework_id            VARCHAR(100)    NOT NULL,
                    compliance_framework    VARCHAR(100)    NOT NULL,
                    csp                     VARCHAR(20)     NOT NULL DEFAULT 'aws',
                    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
                    UNIQUE (rule_id, unique_compliance_id)
                );
                CREATE INDEX IF NOT EXISTS idx_crdm_rule_id ON compliance_rule_data_mapping(rule_id);
                CREATE INDEX IF NOT EXISTS idx_crdm_framework_id ON compliance_rule_data_mapping(framework_id);
                CREATE INDEX IF NOT EXISTS idx_crdm_compliance_fw ON compliance_rule_data_mapping(compliance_framework);
                CREATE INDEX IF NOT EXISTS idx_crdm_rule_framework ON compliance_rule_data_mapping(rule_id, framework_id);
            """)
        conn.commit()
        print("✓ Tables created (inline SQL)")


def parse_mapped_rules(raw: str) -> List[str]:
    """Parse semicolon-separated rule_ids, stripping whitespace."""
    if not raw or not raw.strip():
        return []
    return [r.strip() for r in raw.split(";") if r.strip()]


def load_csv(
    csv_path: str,
    csp: str,
    mapped_rules_col: str,
) -> Tuple[List[tuple], List[tuple]]:
    """Load a CSV file and return (data_rows, mapping_rows).

    Args:
        csv_path: Path to the CSV file.
        csp: Cloud service provider name.
        mapped_rules_col: Column name containing the mapped rule_ids.

    Returns:
        (data_rows, mapping_rows) tuples ready for execute_values.
    """
    data_rows = []
    mapping_rows = []

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            uid = row.get("unique_compliance_id", "").strip()
            if not uid:
                continue

            compliance_framework = row.get("compliance_framework", "").strip()
            framework_id = row.get("framework_id", "").strip()
            requirement_id = row.get("requirement_id", "").strip()
            requirement_name = row.get("requirement_name", "").strip()

            if not compliance_framework or not requirement_id:
                continue

            # Get mapped rules from the CSP-specific column
            mapped_rules_raw = row.get(mapped_rules_col, "").strip()
            mapped_rules = parse_mapped_rules(mapped_rules_raw)
            mapped_rules_str = ";".join(mapped_rules) if mapped_rules else ""

            # Parse total_checks
            tc = row.get("total_checks", "0").strip()
            try:
                total_checks = int(tc) if tc else 0
            except ValueError:
                total_checks = 0

            data_rows.append((
                uid,
                row.get("technology", "").strip() or None,
                compliance_framework,
                framework_id or compliance_framework.lower(),
                row.get("framework_version", "").strip() or None,
                requirement_id,
                requirement_name or requirement_id,
                row.get("requirement_description", "").strip() or None,
                row.get("section", "").strip() or None,
                row.get("service", "").strip() or None,
                total_checks,
                row.get("automation_type", "").strip() or None,
                row.get("confidence_score", "").strip() or None,
                row.get("references", "").strip() or None,
                row.get("source_file", "").strip() or None,
                csp,
                mapped_rules_str or None,
            ))

            # Explode rule mappings
            for rule_id in mapped_rules:
                if rule_id:
                    mapping_rows.append((
                        rule_id,
                        uid,
                        framework_id or compliance_framework.lower(),
                        compliance_framework,
                        csp,
                    ))

    return data_rows, mapping_rows


def upload_data(
    conn,
    data_rows: List[tuple],
    mapping_rows: List[tuple],
    csp: str,
) -> Tuple[int, int]:
    """Insert data and mapping rows into the database.

    Returns:
        (data_count, mapping_count) of rows upserted.
    """
    with conn.cursor() as cur:
        # Upsert compliance_data
        if data_rows:
            execute_values(
                cur,
                """
                INSERT INTO compliance_data (
                    unique_compliance_id, technology, compliance_framework,
                    framework_id, framework_version, requirement_id,
                    requirement_name, requirement_description, section,
                    service, total_checks, automation_type, confidence_score,
                    "references", source_file, csp, mapped_rules
                ) VALUES %s
                ON CONFLICT (unique_compliance_id) DO UPDATE SET
                    technology = EXCLUDED.technology,
                    compliance_framework = EXCLUDED.compliance_framework,
                    framework_id = EXCLUDED.framework_id,
                    framework_version = EXCLUDED.framework_version,
                    requirement_id = EXCLUDED.requirement_id,
                    requirement_name = EXCLUDED.requirement_name,
                    requirement_description = EXCLUDED.requirement_description,
                    section = EXCLUDED.section,
                    service = EXCLUDED.service,
                    total_checks = EXCLUDED.total_checks,
                    automation_type = EXCLUDED.automation_type,
                    confidence_score = EXCLUDED.confidence_score,
                    "references" = EXCLUDED."references",
                    source_file = EXCLUDED.source_file,
                    csp = EXCLUDED.csp,
                    mapped_rules = EXCLUDED.mapped_rules
                """,
                data_rows,
                page_size=500,
            )

        # Upsert compliance_rule_data_mapping
        if mapping_rows:
            execute_values(
                cur,
                """
                INSERT INTO compliance_rule_data_mapping (
                    rule_id, unique_compliance_id, framework_id,
                    compliance_framework, csp
                ) VALUES %s
                ON CONFLICT (rule_id, unique_compliance_id) DO UPDATE SET
                    framework_id = EXCLUDED.framework_id,
                    compliance_framework = EXCLUDED.compliance_framework,
                    csp = EXCLUDED.csp
                """,
                mapping_rows,
                page_size=500,
            )

    conn.commit()
    return len(data_rows), len(mapping_rows)


def main():
    parser = argparse.ArgumentParser(description="Upload compliance CSV data to RDS")
    parser.add_argument("--host", default=os.getenv("COMPLIANCE_DB_HOST", "localhost"))
    parser.add_argument("--port", type=int, default=int(os.getenv("COMPLIANCE_DB_PORT", "5432")))
    parser.add_argument("--db", default=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"))
    parser.add_argument("--user", default=os.getenv("COMPLIANCE_DB_USER", "postgres"))
    parser.add_argument("--password", default=os.getenv("COMPLIANCE_DB_PASSWORD", ""))
    parser.add_argument("--csv-dir", default=None, help="Path to CSV directory")
    args = parser.parse_args()

    # Find CSV directory
    csv_dir = args.csv_dir
    if not csv_dir:
        # Try relative to repo root
        repo_root = Path(__file__).parent.parent.parent.parent
        csv_dir = str(repo_root / "complaince_csv")

    if not Path(csv_dir).is_dir():
        print(f"ERROR: CSV directory not found: {csv_dir}")
        sys.exit(1)

    print(f"Connecting to {args.host}:{args.port}/{args.db} as {args.user}")
    conn = psycopg2.connect(
        host=args.host,
        port=args.port,
        dbname=args.db,
        user=args.user,
        password=args.password,
    )

    # 1. Create tables
    create_tables(conn)

    # 2. Process each CSV
    total_data = 0
    total_mappings = 0

    for filename, csp, rules_col in CSV_FILES:
        csv_path = os.path.join(csv_dir, filename)
        if not os.path.exists(csv_path):
            print(f"  ⚠ Skipping {filename} (not found)")
            continue

        data_rows, mapping_rows = load_csv(csv_path, csp, rules_col)
        d_cnt, m_cnt = upload_data(conn, data_rows, mapping_rows, csp)
        total_data += d_cnt
        total_mappings += m_cnt
        print(f"  ✓ {csp:6s}: {d_cnt:5d} controls, {m_cnt:5d} rule mappings ({filename})")

    print(f"\n{'='*60}")
    print(f"TOTAL: {total_data} controls, {total_mappings} rule mappings uploaded")

    # 3. Print summary
    with conn.cursor() as cur:
        cur.execute("SELECT csp, COUNT(*) FROM compliance_data GROUP BY csp ORDER BY csp")
        print("\nCompliance_data per CSP:")
        for row in cur.fetchall():
            print(f"  {row[0]:8s}: {row[1]:5d}")

        cur.execute("SELECT compliance_framework, COUNT(*) FROM compliance_data GROUP BY compliance_framework ORDER BY compliance_framework")
        print("\nCompliance_data per framework:")
        for row in cur.fetchall():
            print(f"  {row[0]:20s}: {row[1]:5d}")

        cur.execute("SELECT COUNT(DISTINCT rule_id) FROM compliance_rule_data_mapping")
        print(f"\nUnique rule_ids in mapping: {cur.fetchone()[0]}")

    conn.close()
    print("\n✓ Done!")


if __name__ == "__main__":
    main()
