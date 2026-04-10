#!/usr/bin/env python3
"""
Fix dependent discovery operations in rule_discoveries table.

Reads resource_inventory_identifier (Step5 data) to find:
- Which operations are dependent (independent=false in enrich_ops)
- What required_params they need
- Which parent operation provides the data

Updates rule_discoveries.discoveries_data to add proper for_each
references so dependent operations iterate over parent results.

Usage:
    python scripts/fix_dependent_discoveries.py [--dry-run]
"""

import argparse
import json
import os
import re
import sys

import psycopg2
from psycopg2.extras import RealDictCursor


def get_conn(db_name):
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=db_name,
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )


def build_dependency_info():
    """Build: service → {dependent_method → {parent_method, required_params, parent_discovery_id}}"""
    conn = get_conn(os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"))
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT service, canonical_type, root_ops::text, enrich_ops::text
        FROM resource_inventory_identifier
        WHERE csp = 'aws'
        AND root_ops IS NOT NULL AND root_ops::text != '[]'
        AND enrich_ops IS NOT NULL AND enrich_ops::text != '[]'
    """)

    dep_info = {}  # service → method → info

    for row in cur.fetchall():
        service = row["service"]
        root_ops = json.loads(row["root_ops"]) if row["root_ops"] else []
        enrich_ops = json.loads(row["enrich_ops"]) if row["enrich_ops"] else []

        # Find the primary independent root operation
        root_method = None
        root_discovery_id = None
        for op in root_ops:
            if op.get("independent", True):
                root_method = op.get("python_method", "")
                root_discovery_id = op.get("yaml_action", root_method)
                break

        if not root_method:
            continue

        # Map each dependent operation
        for op in enrich_ops:
            method = op.get("python_method", "")
            required = op.get("required_params", [])
            if method and required:
                if service not in dep_info:
                    dep_info[service] = {}
                dep_info[service][method] = {
                    "parent_method": root_method,
                    "parent_discovery_id": f"aws.{service}.{root_discovery_id}",
                    "required_params": required,
                }

    conn.close()
    total = sum(len(v) for v in dep_info.values())
    print(f"Found {total} dependent operations across {len(dep_info)} services")
    return dep_info


def fix_rule_discoveries(dep_info, dry_run=False):
    """Update rule_discoveries to add for_each for dependent operations."""
    conn = get_conn(os.getenv("CHECK_DB_NAME", "threat_engine_check"))
    cur = conn.cursor()

    cur.execute("""
        SELECT id, service, discoveries_data
        FROM rule_discoveries
        WHERE provider = 'aws' AND is_active = true
    """)
    rows = cur.fetchall()

    total_fixed = 0
    services_fixed = set()

    for rid, service, dd in rows:
        if not dd or not isinstance(dd, dict):
            continue
        svc_deps = dep_info.get(service, {})
        if not svc_deps:
            continue

        discoveries = dd.get("discovery", [])
        changed = False

        # First pass: collect save_as mapping for independent operations
        save_as_map = {}  # discovery_id → save_as
        for d in discoveries:
            did = d.get("discovery_id", "")
            calls = d.get("calls", [])
            if calls:
                sa = calls[0].get("save_as", calls[0].get("action", "") + "_response")
                save_as_map[did] = sa

        # Second pass: fix dependent operations
        for d in discoveries:
            if not d.get("enabled", True):
                continue
            did = d.get("discovery_id", "")
            calls = d.get("calls", [])
            if not calls:
                continue

            action = calls[0].get("action", "")
            existing_for_each = d.get("for_each") or calls[0].get("for_each")

            # Skip if already has for_each
            if existing_for_each:
                continue

            # Check if this is a known dependent operation
            # Match camelCase YAML action → snake_case Step5 method
            action_snake = re.sub(r'([A-Z])', r'_\1', action).lower().lstrip('_')
            matched_action = action if action in svc_deps else (action_snake if action_snake in svc_deps else None)
            if matched_action and matched_action in svc_deps:
                info = svc_deps[matched_action]
                parent_did = info["parent_discovery_id"]
                parent_save_as = save_as_map.get(parent_did, "")

                if parent_save_as:
                    # Add for_each referencing parent's saved data
                    d["for_each"] = "{{ " + parent_save_as + " }}"

                    # Add required params to the call if missing
                    existing_params = calls[0].get("params", {})
                    for param in info["required_params"]:
                        if param not in existing_params:
                            calls[0].setdefault("params", {})[param] = "{{ item." + param + " }}"

                    changed = True
                    total_fixed += 1
                    services_fixed.add(service)

        if changed:
            dd["discovery"] = discoveries
            if not dry_run:
                cur.execute(
                    "UPDATE rule_discoveries SET discoveries_data = %s WHERE id = %s",
                    (json.dumps(dd), rid),
                )

    if not dry_run:
        conn.commit()
    conn.close()

    print(f"{'Would fix' if dry_run else 'Fixed'}: {total_fixed} dependent operations")
    print(f"Services affected: {sorted(services_fixed)}")
    return total_fixed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print("Building dependency info from Step5 catalog...")
    dep_info = build_dependency_info()

    print("\nFixing rule_discoveries...")
    fix_rule_discoveries(dep_info, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
