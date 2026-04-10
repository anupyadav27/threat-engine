#!/usr/bin/env python3
"""
Fix dependent discovery operations by adding for_each references.

Reads resource_inventory_identifier to find operations with required_params,
then updates rule_discoveries to add for_each that references the parent
operation's saved data.

Usage:
    python scripts/fix_dependent_for_each.py [--dry-run]
"""

import argparse
import json
import os
import re

import psycopg2
from psycopg2.extras import RealDictCursor


def get_conn(db_name):
    return psycopg2.connect(
        host=os.getenv("DB_HOST", os.getenv("INVENTORY_DB_HOST", "localhost")),
        port=int(os.getenv("DB_PORT", os.getenv("INVENTORY_DB_PORT", "5432"))),
        database=db_name,
        user=os.getenv("DB_USER", os.getenv("INVENTORY_DB_USER", "postgres")),
        password=os.getenv("DB_PASSWORD", os.getenv("INVENTORY_DB_PASSWORD", "")),
    )


def build_dependency_map():
    """Build map: dependent_operation → (parent_operation, required_param)."""
    conn = get_conn("threat_engine_inventory")
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT service, canonical_type, root_ops::text, enrich_ops::text
        FROM resource_inventory_identifier
        WHERE csp = 'aws' AND root_ops IS NOT NULL AND enrich_ops IS NOT NULL
    """)

    dep_map = {}  # method_name → { parent_method, required_param, service, resource_type }

    for row in cur.fetchall():
        service = row["service"]
        rt = row["canonical_type"]

        root_ops = json.loads(row["root_ops"]) if row["root_ops"] else []
        enrich_ops = json.loads(row["enrich_ops"]) if row["enrich_ops"] else []

        # Find the first independent root operation
        root_method = None
        for op in root_ops:
            if op.get("independent", True):
                root_method = op.get("python_method") or op.get("yaml_action") or ""
                break
        if not root_method:
            continue

        # Map each dependent operation to its root
        for op in enrich_ops:
            method = op.get("python_method") or op.get("yaml_action") or ""
            required = op.get("required_params", [])
            if method and required:
                dep_map[f"{service}.{method}"] = {
                    "parent_method": f"{service}.{root_method}",
                    "required_params": required,
                    "service": service,
                    "resource_type": rt,
                }

    conn.close()
    return dep_map


def fix_rule_discoveries(dep_map, dry_run=False):
    """Add for_each to dependent operations in rule_discoveries."""
    conn = get_conn("threat_engine_check")
    cur = conn.cursor()

    cur.execute("SELECT id, service, discoveries_data FROM rule_discoveries WHERE provider = 'aws' AND is_active = true")
    rows = cur.fetchall()

    total_fixed = 0
    for rid, svc, dd in rows:
        if not dd or not isinstance(dd, dict):
            continue
        discoveries = dd.get("discovery", [])
        changed = False

        for d in discoveries:
            if not d.get("enabled", True):
                continue
            if d.get("for_each"):
                continue  # Already has for_each

            calls = d.get("calls", [])
            if not calls:
                continue

            action = calls[0].get("action", "")
            key = f"{svc}.{action}"

            if key in dep_map:
                info = dep_map[key]
                parent = info["parent_method"]
                params = info["required_params"]
                # Reference parent's saved data
                parent_action = parent.split(".")[-1]
                d["for_each"] = f"{{{{ {parent_action}.response }}}}"
                # Also add required params to the call
                for param in params:
                    if param not in (calls[0].get("params") or {}):
                        calls[0].setdefault("params", {})[param] = f"{{{{ item.{param} }}}}"
                changed = True
                total_fixed += 1

        if changed and not dry_run:
            dd["discovery"] = discoveries
            cur.execute("UPDATE rule_discoveries SET discoveries_data = %s WHERE id = %s",
                        (json.dumps(dd), rid))

    if not dry_run:
        conn.commit()
    conn.close()
    return total_fixed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print("Building dependency map from identifier table...")
    dep_map = build_dependency_map()
    print(f"  Found {len(dep_map)} dependent operations with required_params")

    print("Fixing rule_discoveries...")
    fixed = fix_rule_discoveries(dep_map, dry_run=args.dry_run)
    print(f"  {'Would fix' if args.dry_run else 'Fixed'}: {fixed} operations")


if __name__ == "__main__":
    main()
