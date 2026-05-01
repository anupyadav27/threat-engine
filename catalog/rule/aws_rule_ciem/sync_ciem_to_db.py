#!/usr/bin/env python3
"""
Sync CIEM rules from catalog/rule/aws_rule_ciem/ to the database:
  1. rule_checks (threat_engine_check) — the rule logic
  2. rule_metadata (threat_engine_check) — enriched metadata

Reads all *.yaml files under the catalog directory.
Uses ON CONFLICT DO UPDATE for both tables (idempotent).
"""
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import psycopg2
import psycopg2.extras
import yaml

CATALOG_DIR = Path(__file__).parent


def get_check_db():
    return psycopg2.connect(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        user=os.getenv("CHECK_DB_USER", "check_user"),
        password=os.getenv("CHECK_DB_PASSWORD", "check_password"),
    )


def load_rule_yamls(catalog_dir: Path) -> List[Dict]:
    """Load all CIEM rule YAMLs from catalog directory."""
    rules = []
    for yaml_path in sorted(catalog_dir.rglob("*.yaml")):
        if yaml_path.name.endswith((".py",)) or yaml_path.parent == catalog_dir:
            continue
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data or not isinstance(data, dict):
                continue
            rule_id = data.get("rule_id", "")
            if not rule_id.startswith("aws."):
                continue
            data["_path"] = str(yaml_path)
            rules.append(data)
        except Exception as e:
            print(f"  SKIP {yaml_path.name}: {e}")
    return rules


def sync_rule_checks(conn, rules: List[Dict]) -> int:
    """Upsert into rule_checks."""
    sql = """
        INSERT INTO rule_checks (rule_id, service, provider, check_type, check_config, is_active)
        VALUES %s
        ON CONFLICT (rule_id, customer_id, tenant_id) DO UPDATE SET
            service = EXCLUDED.service,
            provider = EXCLUDED.provider,
            check_type = EXCLUDED.check_type,
            check_config = EXCLUDED.check_config,
            is_active = EXCLUDED.is_active,
            updated_at = NOW()
    """
    values = []
    for r in rules:
        rule_id = r["rule_id"]
        service = r.get("service", "")
        provider = r.get("provider", "aws")
        check_type = r.get("check_type", "log")
        check_config = r.get("check_config", {})
        is_active = r.get("is_active", True)
        values.append((
            rule_id, service, provider, check_type,
            psycopg2.extras.Json(check_config),
            is_active,
        ))

    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, sql, values, page_size=200)
    conn.commit()
    return len(values)


def sync_rule_metadata(conn, rules: List[Dict]) -> int:
    """Upsert into rule_metadata."""
    sql = """
        INSERT INTO rule_metadata (
            rule_id, service, provider, resource, severity, title, description,
            threat_category, risk_score
        ) VALUES %s
        ON CONFLICT (rule_id) WHERE customer_id IS NULL AND tenant_id IS NULL DO UPDATE SET
            service = EXCLUDED.service,
            provider = EXCLUDED.provider,
            resource = EXCLUDED.resource,
            severity = EXCLUDED.severity,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            threat_category = EXCLUDED.threat_category,
            risk_score = EXCLUDED.risk_score,
            updated_at = NOW()
    """
    # Check if customer_id / tenant_id columns exist (partial index guard)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'rule_metadata'
            AND column_name IN ('customer_id', 'tenant_id')
        """)
        cols = {row[0] for row in cur.fetchall()}

    if "customer_id" not in cols or "tenant_id" not in cols:
        # Fallback: simple ON CONFLICT (rule_id)
        sql = sql.replace(
            "ON CONFLICT (rule_id) WHERE customer_id IS NULL AND tenant_id IS NULL",
            "ON CONFLICT (rule_id)"
        )

    values = []
    for r in rules:
        values.append((
            r["rule_id"],
            r.get("service", ""),
            r.get("provider", "aws"),
            r.get("resource", "aws_resource"),
            r.get("severity", "medium"),
            r.get("title", r["rule_id"]),
            r.get("description", ""),
            r.get("threat_category", ""),
            r.get("risk_score", 50),
        ))

    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, sql, values, page_size=200)
    conn.commit()
    return len(values)


def sync_threat_tags(conn, rules: List[Dict]) -> int:
    """Update threat_tags JSONB with mitre_tactics + mitre_techniques."""
    # Check if threat_tags column exists
    with conn.cursor() as cur:
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'rule_metadata'
            AND column_name = 'threat_tags'
        """)
        if not cur.fetchone():
            return 0

    updated = 0
    with conn.cursor() as cur:
        for r in rules:
            tags = {
                "mitre_tactics": r.get("mitre_tactics", []),
                "mitre_techniques": r.get("mitre_techniques", []),
            }
            cur.execute("""
                UPDATE rule_metadata SET threat_tags = %s, updated_at = NOW()
                WHERE rule_id = %s
            """, (psycopg2.extras.Json(tags), r["rule_id"]))
            updated += cur.rowcount
    conn.commit()
    return updated


def main():
    import argparse
    p = argparse.ArgumentParser(description="Sync CIEM rules to DB")
    p.add_argument("--metadata-only", action="store_true", help="Skip rule_checks sync")
    p.add_argument("--checks-only", action="store_true", help="Skip rule_metadata sync")
    p.add_argument("--dir", default=str(CATALOG_DIR), help="CIEM catalog directory")
    args = p.parse_args()

    catalog = Path(args.dir)
    rules = load_rule_yamls(catalog)
    print(f"Loaded {len(rules)} CIEM rules from {catalog}")

    conn = get_check_db()
    try:
        if not args.metadata_only:
            n = sync_rule_checks(conn, rules)
            print(f"  rule_checks: {n} rows upserted")

        if not args.checks_only:
            n = sync_rule_metadata(conn, rules)
            print(f"  rule_metadata: {n} rows upserted")
            n = sync_threat_tags(conn, rules)
            if n:
                print(f"  threat_tags: {n} rows updated")
    finally:
        conn.close()

    print("Done.")


if __name__ == "__main__":
    main()
