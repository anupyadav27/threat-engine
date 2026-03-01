#!/usr/bin/env python3
"""
Upload AWS compliance CSV to compliance DB table compliance_control_mappings.
Reference: consolidated_services/database/migrations/006_compliance_control_mappings.sql
Source: data_compliance/aws/aws_consolidated_rules_with_final_checks.csv
"""
import os
import sys
import csv

# Project root
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import psycopg2
from pathlib import Path

DEFAULT_CSV = os.path.join(ROOT, "data_compliance", "aws", "aws_consolidated_rules_with_final_checks.csv")


def get_compliance_config():
    """Read config from env (COMPLIANCE_DB_*) so script runs without asyncpg/consolidated_services."""
    return {
        "host": os.getenv("COMPLIANCE_DB_HOST", "localhost"),
        "port": int(os.getenv("COMPLIANCE_DB_PORT", "5432")),
        "database": os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
        "user": os.getenv("COMPLIANCE_DB_USER", "compliance_user"),
        "password": os.getenv("COMPLIANCE_DB_PASSWORD", "compliance_password"),
    }


def upload_compliance(csv_path: str = None, truncate_first: bool = False):
    csv_path = csv_path or DEFAULT_CSV
    path = Path(csv_path)
    if not path.is_file():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    config = get_compliance_config()
    conn = psycopg2.connect(**config)
    cur = conn.cursor()

    if truncate_first:
        cur.execute("TRUNCATE TABLE compliance_control_mappings RESTART IDENTITY;")
        conn.commit()

    # Columns in 006: unique_compliance_id, technology, compliance_framework, framework_id, framework_version,
    # requirement_id, requirement_name, requirement_description, section, service, total_checks,
    # automation_type, confidence_score, "references", source_file, aws_checks, final_aws_check, rule_ids
    # CSV: unique_compliance_id, technology, compliance_framework, framework_id, framework_version,
    # requirement_id, requirement_name, requirement_description, section, service, total_checks,
    # automation_type, confidence_score, references, source_file, aws_checks, final_aws_check
    sql = """
    INSERT INTO compliance_control_mappings (
        unique_compliance_id, technology, compliance_framework, framework_id, framework_version,
        requirement_id, requirement_name, requirement_description, section, service, total_checks,
        automation_type, confidence_score, "references", source_file, aws_checks, final_aws_check, rule_ids
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    )
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
        aws_checks = EXCLUDED.aws_checks,
        final_aws_check = EXCLUDED.final_aws_check,
        rule_ids = EXCLUDED.rule_ids,
        updated_at = NOW();
    """

    count = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            uid = row.get("unique_compliance_id", "").strip()
            if not uid:
                continue
            final_check = (row.get("final_aws_check") or "").strip()
            rule_ids = [r.strip() for r in final_check.split(";") if r.strip()] if final_check else []
            total = row.get("total_checks", "0").strip()
            try:
                total_checks = int(total) if total.isdigit() else 0
            except ValueError:
                total_checks = 0
            try:
                cur.execute(sql, (
                    uid,
                    (row.get("technology") or "").strip() or None,
                    (row.get("compliance_framework") or "").strip(),
                    (row.get("framework_id") or "").strip() or None,
                    (row.get("framework_version") or "").strip() or None,
                    (row.get("requirement_id") or "").strip(),
                    (row.get("requirement_name") or "").strip() or None,
                    (row.get("requirement_description") or "").strip() or None,
                    (row.get("section") or "").strip() or None,
                    (row.get("service") or "").strip() or None,
                    total_checks,
                    (row.get("automation_type") or "").strip() or None,
                    (row.get("confidence_score") or "").strip() or None,
                    (row.get("references") or "").strip() or None,
                    (row.get("source_file") or "").strip() or None,
                    (row.get("aws_checks") or "").strip() or None,
                    final_check or None,
                    rule_ids,
                ))
                count += 1
            except Exception as e:
                conn.rollback()
                raise RuntimeError(f"Insert failed row {uid}: {e}") from e

    conn.commit()
    cur.close()
    conn.close()
    return count


def main():
    import argparse
    p = argparse.ArgumentParser(description="Upload AWS compliance CSV to compliance_control_mappings")
    p.add_argument("--csv", default=DEFAULT_CSV, help="Path to aws_consolidated_rules_with_final_checks.csv")
    p.add_argument("--truncate", action="store_true", help="Truncate table before insert")
    args = p.parse_args()
    n = upload_compliance(csv_path=args.csv, truncate_first=args.truncate)
    print(f"Done. Uploaded {n} compliance row(s).")


if __name__ == "__main__":
    main()
