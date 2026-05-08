#!/usr/bin/env python3
"""
Reload Step5 catalog JSON files into resource_inventory_identifier table.

Reads all step5_resource_catalog_inventory_enrich.json files from catalog/<csp>/
and inserts clean rows into the DB, replacing corrupted data.

Handles different JSON structures per CSP:
  - AWS/OCI/AliCloud/IBM: nested {resources: {type: {...}}}
  - Azure: flat {service, resource, pattern, ...}
  - GCP: nested {services: {svc: {resources: {type: {...}}}}}

Usage:
    python scripts/reload_step5_to_db.py [--dry-run]
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_values

CATALOG_ROOT = Path(__file__).resolve().parent.parent / "catalog"
CSPS = ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]


def get_db_conn():
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
    )


def _make_row(csp, service, res, resource_type):
    """Build a DB row tuple from a Step5 resource entry."""
    classification = res.get("classification", "PRIMARY_RESOURCE")
    has_arn = res.get("has_arn", False)
    arn_entity = res.get("arn_entity") or ""
    should_inventory = res.get("should_inventory", True)
    can_inventory_from_roots = res.get("can_inventory_from_roots", False)
    identifier_pattern = res.get("identifier_pattern") or ""

    ident = res.get("identifier", {})
    primary_param = ident.get("primary_param", "")
    identifier_type = ident.get("identifier_type", ident.get("kind", ""))

    # Root ops
    inv_ops = res.get("inventory", {}).get("ops", [])
    root_ops = json.dumps(inv_ops) if inv_ops else "[]"

    # Enrich ops
    enrich_ops_list = res.get("inventory_enrich", {}).get("ops", [])
    enrich_ops = json.dumps(enrich_ops_list) if enrich_ops_list else "[]"

    parent_service = res.get("parent_service") or ""
    parent_resource_type = res.get("parent_resource_type") or ""
    raw_catalog = json.dumps(res)

    return (
        csp, service, resource_type, resource_type,
        classification, has_arn, arn_entity, identifier_type,
        primary_param, identifier_pattern,
        can_inventory_from_roots, should_inventory,
        root_ops, enrich_ops, raw_catalog,
        parent_service, parent_resource_type,
    )


def load_aws_style(csp, step5_file, data):
    """AWS/OCI/AliCloud/IBM: {resources: {type: {...}}}"""
    rows = []
    service = data.get("service", step5_file.parent.name)
    for rt_key, res in data.get("resources", {}).items():
        resource_type = res.get("resource_type", rt_key)
        rows.append(_make_row(csp, service, res, resource_type))
    return rows


def load_azure_style(csp, step5_file, data):
    """Azure: flat {service, resource, pattern, ...} per file."""
    service = data.get("service", step5_file.parent.name)
    resource = data.get("resource", "")
    resource_type = resource.split("/")[-1] if "/" in resource else resource

    pattern = data.get("pattern", "")
    should_inventory = data.get("should_inventory", False)
    independent = data.get("resource_independent_methods", [])
    dependent = data.get("resource_dependent_methods", [])

    # Build ops structures
    inv_ops = [{"operation": m, "independent": True} for m in independent]
    enrich_ops = [{"operation": m, "independent": False} for m in dependent]

    res = {
        "resource_type": resource_type,
        "classification": "PRIMARY_RESOURCE" if independent else "SUB_RESOURCE",
        "has_arn": False,
        "arn_entity": "",
        "should_inventory": should_inventory,
        "can_inventory_from_roots": bool(independent),
        "identifier_pattern": pattern,
        "identifier": {
            "primary_param": data.get("resource_identifiers", "").split(";")[0] if data.get("resource_identifiers") else "",
            "identifier_type": data.get("identifier_type", "id"),
        },
        "inventory": {"ops": inv_ops},
        "inventory_enrich": {"ops": enrich_ops},
    }
    return [_make_row(csp, service, res, resource_type)]


def load_gcp_style(csp, step5_file, data):
    """GCP: {services: {svc: {resources: {type: {...}}}}}"""
    rows = []
    for svc_name, svc_data in data.get("services", {}).items():
        for rt_key, res in svc_data.get("resources", {}).items():
            resource_type = res.get("resource_type", rt_key)

            # GCP uses different field names
            ident = res.get("identifier", {})
            full_id = ident.get("full_identifier", {})
            pattern = full_id.get("template", "")
            pattern_type = res.get("pattern_type", "")

            # Build compatible structure
            inv = res.get("inventory", {})
            inv_enrich = res.get("inventory_enrich", {})

            mapped = {
                "resource_type": resource_type,
                "classification": res.get("classification", "PRIMARY_RESOURCE"),
                "has_arn": False,
                "arn_entity": "",
                "should_inventory": res.get("should_inventory", True),
                "can_inventory_from_roots": res.get("can_inventory_from_roots", False),
                "identifier_pattern": pattern,
                "identifier": {
                    "primary_param": ident.get("primary_param", ""),
                    "identifier_type": ident.get("kind", "full_name"),
                },
                "inventory": inv if inv else {"ops": []},
                "inventory_enrich": inv_enrich if inv_enrich else {"ops": []},
                "parent_service": res.get("parent_service", ""),
                "parent_resource_type": res.get("parent_resource_type", ""),
            }
            rows.append(_make_row(csp, svc_name, mapped, resource_type))
    return rows


def detect_and_load(csp, step5_file):
    """Detect JSON format and load accordingly."""
    try:
        data = json.loads(step5_file.read_text())
    except (json.JSONDecodeError, OSError) as e:
        return []

    # Detect format
    if "services" in data and isinstance(data.get("services"), dict):
        # GCP style: {services: {svc: {resources: ...}}}
        first_svc = next(iter(data["services"].values()), {})
        if isinstance(first_svc, dict) and "resources" in first_svc:
            return load_gcp_style(csp, step5_file, data)

    if "resources" in data and isinstance(data.get("resources"), dict):
        # AWS/OCI/AliCloud/IBM style: {resources: {type: {...}}}
        return load_aws_style(csp, step5_file, data)

    if "resource" in data and "pattern" in data:
        # Azure style: flat per-file
        return load_azure_style(csp, step5_file, data)

    return []


def load_step5_files(csp):
    """Load all Step5 JSON files for a CSP."""
    csp_dir = CATALOG_ROOT / csp
    if not csp_dir.exists():
        return []

    rows = []

    # GCP has ONE big file per service group, not per-service
    # Check if there's a top-level step5 file
    top_step5 = csp_dir / "step5_resource_catalog_inventory_enrich.json"
    if top_step5.exists():
        rows.extend(detect_and_load(csp, top_step5))

    # Walk service directories
    for service_dir in sorted(csp_dir.iterdir()):
        if not service_dir.is_dir() or service_dir.name == "deprecated":
            continue

        step5_file = service_dir / "step5_resource_catalog_inventory_enrich.json"
        if step5_file.exists():
            rows.extend(detect_and_load(csp, step5_file))

    return rows


def reload_all(dry_run=False):
    all_rows = []
    for csp in CSPS:
        rows = load_step5_files(csp)
        print(f"{csp}: {len(rows)} resources from Step5 JSON")
        all_rows.extend(rows)

    print(f"\nTotal: {len(all_rows)} rows to load")

    if dry_run:
        print("[DRY RUN] No DB changes made.")
        return

    conn = get_db_conn()
    cur = conn.cursor()

    # Backup metadata
    print("\nBacking up metadata columns...")
    cur.execute("""
        SELECT csp, service, canonical_type,
               scope, category, subcategory, service_model,
               managed_by, access_pattern, encryption_scope,
               is_container, container_parent, diagram_priority,
               csp_category, asset_category
        FROM resource_inventory_identifier
        WHERE category IS NOT NULL AND category != ''
    """)
    metadata_backup = {}
    for row in cur.fetchall():
        key = (row[0], row[1], row[2])
        metadata_backup[key] = {
            "scope": row[3] or "",
            "category": row[4] or "",
            "subcategory": row[5] or "",
            "service_model": row[6] or "",
            "managed_by": row[7] or "",
            "access_pattern": row[8] or "",
            "encryption_scope": row[9] or "",
            "is_container": row[10] or False,
            "container_parent": row[11] or "",
            "diagram_priority": row[12] or 3,
            "csp_category": row[13] or "",
            "asset_category": row[14] or "",
        }
    print(f"  Backed up metadata for {len(metadata_backup)} entries")

    # Truncate and reload
    print("Truncating resource_inventory_identifier...")
    cur.execute("TRUNCATE resource_inventory_identifier RESTART IDENTITY")

    now = datetime.now(timezone.utc)
    insert_sql = """
        INSERT INTO resource_inventory_identifier (
            csp, service, resource_type, canonical_type,
            classification, has_arn, arn_entity, identifier_type,
            primary_param, identifier_pattern,
            can_inventory_from_roots, should_inventory,
            root_ops, enrich_ops, raw_catalog,
            parent_service, parent_resource_type,
            loaded_at, updated_at,
            scope, category, subcategory, service_model,
            managed_by, access_pattern, encryption_scope,
            is_container, container_parent, diagram_priority,
            csp_category, asset_category
        ) VALUES %s
    """

    values = []
    metadata_restored = 0
    for row in all_rows:
        csp, service, resource_type, canonical_type = row[0], row[1], row[2], row[3]
        meta = (
            metadata_backup.get((csp, service, canonical_type)) or
            metadata_backup.get((csp, service, resource_type)) or
            {}
        )
        if meta:
            metadata_restored += 1

        values.append((*row, now, now,
            meta.get("scope", ""),
            meta.get("category", ""),
            meta.get("subcategory", ""),
            meta.get("service_model", ""),
            meta.get("managed_by", ""),
            meta.get("access_pattern", ""),
            meta.get("encryption_scope", ""),
            meta.get("is_container", False),
            meta.get("container_parent", ""),
            meta.get("diagram_priority", 3),
            meta.get("csp_category", ""),
            meta.get("asset_category", ""),
        ))

    print(f"Inserting {len(values)} rows...")
    execute_values(cur, insert_sql, values, page_size=500)
    conn.commit()
    print(f"  Metadata restored for {metadata_restored} entries")

    # Verify
    cur.execute("SELECT csp, count(*) FROM resource_inventory_identifier GROUP BY csp ORDER BY csp")
    print("\nFinal counts:")
    total = 0
    for r in cur.fetchall():
        print(f"  {r[0]}: {r[1]}")
        total += r[1]
    print(f"  TOTAL: {total}")

    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    reload_all(dry_run=args.dry_run)
