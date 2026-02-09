#!/usr/bin/env python3
"""
Seed mitre_technique_reference from mitre_attack_iaas_matrix.json

Reads the 114-technique IaaS matrix JSON and upserts every technique
(including sub-techniques) into the mitre_technique_reference table.

Usage:
    # Against RDS:
    THREAT_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com \
    THREAT_DB_USER=postgres THREAT_DB_PASSWORD=<pw> \
    python scripts/seed_mitre_reference.py

    # Against local:
    python scripts/seed_mitre_reference.py

    # Dry run (print SQL, don't execute):
    python scripts/seed_mitre_reference.py --dry-run
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _conn_str() -> str:
    host = os.getenv("THREAT_DB_HOST", "localhost")
    port = os.getenv("THREAT_DB_PORT", "5432")
    db = os.getenv("THREAT_DB_NAME", "threat_engine_threat")
    user = os.getenv("THREAT_DB_USER", "postgres")
    pwd = os.getenv("THREAT_DB_PASSWORD", "threat_password")
    return f"postgresql://{user}:{pwd}@{host}:{port}/{db}"


def parse_matrix(matrix_path: str) -> List[Dict[str, Any]]:
    """
    Parse the IaaS matrix JSON and flatten into rows for mitre_technique_reference.

    Each row represents one technique (or sub-technique). A parent technique
    appears in EVERY tactic it belongs to, so we merge tactics across appearances.
    """
    with open(matrix_path) as f:
        data = json.load(f)

    # technique_id -> row dict  (merge tactics across appearances)
    techniques: Dict[str, Dict[str, Any]] = {}

    for tactic_id, tactic_data in data.get("tactics", {}).items():
        tactic_name = tactic_data["name"]

        for tech in tactic_data.get("techniques", []):
            tech_id = tech["id"]

            # Upsert parent technique
            if tech_id not in techniques:
                techniques[tech_id] = {
                    "technique_id": tech_id,
                    "technique_name": tech.get("name", ""),
                    "tactics": [],
                    "description": tech.get("description", ""),
                    "aws_examples": tech.get("aws_examples", []),
                    "sub_techniques": [],
                    "platforms": ["IaaS", "AWS"],
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                }
            # Append tactic (deduplicated later)
            row = techniques[tech_id]
            if tactic_name not in row["tactics"]:
                row["tactics"].append(tactic_name)
            # Merge aws_examples from this tactic appearance
            for ex in tech.get("aws_examples", []):
                if ex not in row["aws_examples"]:
                    row["aws_examples"].append(ex)

            # Process sub-techniques
            for sub in tech.get("sub_techniques", []):
                sub_id = sub["id"]
                if sub_id not in techniques:
                    techniques[sub_id] = {
                        "technique_id": sub_id,
                        "technique_name": sub.get("name", ""),
                        "tactics": [],
                        "description": sub.get("description", ""),
                        "aws_examples": sub.get("aws_examples", []),
                        "sub_techniques": [],
                        "platforms": ["IaaS", "AWS"],
                        "url": f"https://attack.mitre.org/techniques/{sub_id.replace('.', '/')}/",
                    }
                sub_row = techniques[sub_id]
                if tactic_name not in sub_row["tactics"]:
                    sub_row["tactics"].append(tactic_name)
                for ex in sub.get("aws_examples", []):
                    if ex not in sub_row["aws_examples"]:
                        sub_row["aws_examples"].append(ex)

                # Link sub-technique to parent
                if sub_id not in row["sub_techniques"]:
                    row["sub_techniques"].append(sub_id)

    return sorted(techniques.values(), key=lambda r: r["technique_id"])


def seed_database(rows: List[Dict[str, Any]], dry_run: bool = False):
    """Upsert rows into mitre_technique_reference."""
    import psycopg2
    from psycopg2.extras import Json

    if dry_run:
        print(f"\n=== DRY RUN: {len(rows)} techniques to upsert ===\n")
        for r in rows:
            print(f"  {r['technique_id']:12s} | {r['technique_name']:50s} | tactics={r['tactics']}")
        return

    conn = psycopg2.connect(_conn_str())
    try:
        with conn.cursor() as cur:
            upsert_sql = """
                INSERT INTO mitre_technique_reference (
                    technique_id, technique_name, tactics,
                    sub_techniques, description, url,
                    platforms, aws_checks,
                    updated_at
                ) VALUES (
                    %(technique_id)s, %(technique_name)s, %(tactics)s,
                    %(sub_techniques)s, %(description)s, %(url)s,
                    %(platforms)s, %(aws_examples)s,
                    %(updated_at)s
                )
                ON CONFLICT (technique_id) DO UPDATE SET
                    technique_name = EXCLUDED.technique_name,
                    tactics = EXCLUDED.tactics,
                    sub_techniques = EXCLUDED.sub_techniques,
                    description = EXCLUDED.description,
                    url = EXCLUDED.url,
                    platforms = EXCLUDED.platforms,
                    aws_checks = EXCLUDED.aws_checks,
                    updated_at = EXCLUDED.updated_at
            """

            now = datetime.utcnow()
            inserted = 0
            for row in rows:
                params = {
                    "technique_id": row["technique_id"],
                    "technique_name": row["technique_name"],
                    "tactics": Json(row["tactics"]),
                    "sub_techniques": Json(row["sub_techniques"]),
                    "description": row["description"],
                    "url": row["url"],
                    "platforms": Json(row["platforms"]),
                    "aws_examples": Json(row["aws_examples"]),
                    "updated_at": now,
                }
                cur.execute(upsert_sql, params)
                inserted += 1

            conn.commit()
            print(f"\nSeeded {inserted} techniques into mitre_technique_reference")
            print(f"  Parent techniques: {sum(1 for r in rows if '.' not in r['technique_id'])}")
            print(f"  Sub-techniques:    {sum(1 for r in rows if '.' in r['technique_id'])}")

    finally:
        conn.close()


def main():
    dry_run = "--dry-run" in sys.argv

    # Find the JSON file
    script_dir = Path(__file__).resolve().parent
    # Check multiple locations
    candidates = [
        script_dir / "mitre_attack_iaas_matrix.json",
        script_dir.parent / "files" / "mitre_attack_iaas_matrix.json",
        Path("/Users/apple/Desktop/threat-engine/files/mitre_attack_iaas_matrix.json"),
        Path("mitre_attack_iaas_matrix.json"),
    ]

    matrix_path = None
    for p in candidates:
        if p.exists():
            matrix_path = str(p)
            break

    if not matrix_path:
        print("ERROR: mitre_attack_iaas_matrix.json not found. Searched:")
        for p in candidates:
            print(f"  {p}")
        sys.exit(1)

    print(f"Reading: {matrix_path}")
    rows = parse_matrix(matrix_path)
    print(f"Parsed {len(rows)} techniques from IaaS matrix (v18)")

    # Stats
    tactics_seen = set()
    for r in rows:
        tactics_seen.update(r["tactics"])
    print(f"Tactics covered: {len(tactics_seen)} — {sorted(tactics_seen)}")
    print(f"Parent techniques: {sum(1 for r in rows if '.' not in r['technique_id'])}")
    print(f"Sub-techniques:    {sum(1 for r in rows if '.' in r['technique_id'])}")

    seed_database(rows, dry_run=dry_run)


if __name__ == "__main__":
    main()
