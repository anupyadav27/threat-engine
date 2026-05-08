#!/usr/bin/env python3
"""
sync_compliance_to_db.py
=========================
Reads the `compliance` field from every rule metadata YAML and updates
ONLY the `compliance_frameworks` column in the rule_metadata DB table.

Targeted update — does not touch any other columns, avoiding schema mismatches.

Usage:
    python sync_compliance_to_db.py                   # all CSPs
    python sync_compliance_to_db.py --csp gcp k8s     # specific CSPs
    python sync_compliance_to_db.py --dry-run         # print counts only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import execute_values
import yaml

ROOT     = Path(__file__).resolve().parents[2]
RULE_DIR = ROOT / "catalog" / "rule"

CSPS = ["aws", "azure", "gcp", "oci", "ibm", "alicloud", "k8s"]


def get_db_conn():
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "postgres"),
        password=os.getenv("CHECK_DB_PASSWORD", ""),
    )


def load_compliance_from_yaml(path: Path) -> Optional[List[str]]:
    """Return the compliance list from a metadata YAML, or None if empty/missing."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    val = data.get("compliance_frameworks") or data.get("compliance")
    if not val:
        return None
    if isinstance(val, dict):
        val = val.get("frameworks", [])
    if isinstance(val, list) and val:
        return [str(v) for v in val]
    return None


def collect_updates(csps: List[str]) -> List[Tuple[str, str]]:
    """Return list of (rule_id, compliance_json) for all YAMLs with compliance data."""
    rows: List[Tuple[str, str]] = []
    for csp in csps:
        meta_dir = RULE_DIR / f"{csp}_rule_metadata"
        if not meta_dir.exists():
            print(f"  [{csp}] metadata dir not found — skipping")
            continue
        count = 0
        for yaml_file in meta_dir.rglob("*.yaml"):
            rule_id = yaml_file.stem
            compliance = load_compliance_from_yaml(yaml_file)
            if compliance:
                # Store as {"frameworks": [...]} to match existing DB format
                compliance_json = json.dumps({"frameworks": compliance})
                rows.append((rule_id, compliance_json))
                count += 1
        print(f"  [{csp}] {count} rules with compliance data")
    return rows


def update_db(rows: List[Tuple[str, str]], dry_run: bool) -> int:
    """Upsert compliance_frameworks into rule_metadata. Returns updated count."""
    if not rows:
        return 0
    if dry_run:
        print(f"\n[dry-run] Would update {len(rows)} rule_metadata rows")
        return len(rows)

    conn = get_db_conn()
    updated = 0
    try:
        with conn.cursor() as cur:
            # Batch update in chunks of 500
            for i in range(0, len(rows), 500):
                chunk = rows[i:i+500]
                execute_values(cur, """
                    UPDATE rule_metadata AS rm
                    SET compliance_frameworks = data.cf::jsonb,
                        updated_at = NOW()
                    FROM (VALUES %s) AS data(rule_id, cf)
                    WHERE rm.rule_id = data.rule_id
                """, chunk)
                updated += cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return updated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--csp", nargs="+", choices=CSPS, default=CSPS)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print(f"Collecting compliance data from metadata YAMLs...")
    rows = collect_updates(args.csp)
    print(f"\nTotal rules with compliance mappings: {len(rows)}")

    updated = update_db(rows, args.dry_run)

    if not args.dry_run:
        print(f"Updated {updated} rows in rule_metadata.compliance_frameworks")
        print("\nNext: the compliance engine will pick up the new mappings on the next scan.")
    else:
        print("\nDry run complete. Remove --dry-run to apply.")


if __name__ == "__main__":
    main()
