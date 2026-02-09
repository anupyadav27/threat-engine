#!/usr/bin/env python3
"""
Populate threat_engine_pythonsdk DB tables from local data_pythonsdk files.

Reads from: /Users/apple/Desktop/threat-engine/engine_input/engine_check_aws/data_pythonsdk/{csp}/{service}/
Populates:  threat_engine_pythonsdk tables: operations, fields, resource_inventory, dependency_index, direct_vars

Tables already populated:
  - csp (7 rows)
  - services (991 rows) — but total_operations/discovery_operations need updating

Tables to populate:
  - operations       ← from boto3_dependencies_with_python_names_fully_enriched.json
  - fields            ← from field_operator_value_table.csv
  - resource_inventory ← from resource_inventory_report.json
  - dependency_index  ← from dependency_index.json
  - direct_vars       ← from direct_vars.json
  - enhancement_indexes ← from resource_arn_mapping.json (CSP-level aggregate)

Also updates:
  - services.total_operations, services.discovery_operations
  - csp.total_services
"""

import os
import sys
import json
import csv
import traceback
from pathlib import Path
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import execute_values, Json

# ─── Configuration ───────────────────────────────────────────────────────────
DB_HOST = "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DB_PORT = "5432"
DB_NAME = "threat_engine_pythonsdk"
DB_USER = "postgres"
DB_PASS = "jtv2BkJF8qoFtAKP"

DATA_ROOT = Path("/Users/apple/Desktop/threat-engine/engine_input/engine_check_aws/data_pythonsdk")

CSP_DIRS = {
    "aws":      DATA_ROOT / "aws",
    "azure":    DATA_ROOT / "azure",
    "gcp":      DATA_ROOT / "gcp",
    "alicloud": DATA_ROOT / "alicloud",
    "oci":      DATA_ROOT / "oci",
    "ibm":      DATA_ROOT / "ibm",
    "k8s":      DATA_ROOT / "k8s",
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_conn():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASS,
    )


def load_json(path: Path):
    """Load JSON file, return None on error."""
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        return None


def load_csv_rows(path: Path):
    """Load CSV file, return list of dicts."""
    try:
        with open(path, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception:
        return []


def list_service_dirs(csp_dir: Path):
    """List service directories (skip files, scripts, etc.)."""
    if not csp_dir.exists():
        return []
    services = []
    for entry in sorted(csp_dir.iterdir()):
        if entry.is_dir() and not entry.name.startswith(".") and entry.name != "backup" and entry.name != "__pycache__":
            services.append(entry)
    return services


# ─── Table Populators ────────────────────────────────────────────────────────

def populate_operations(conn, csp_id: str, service_id: str, service_dir: Path):
    """
    Populate operations table from boto3_dependencies_with_python_names_fully_enriched.json

    Structure: { "service_name": { "service": "...", "total_operations": N,
                   "independent": [...], "dependent": [...] } }
    Each operation: { "operation": "ListBuckets", "python_method": "list_buckets",
                      "required_params": [], "optional_params": [...], ... }
    """
    # Try CSP-specific dependency file names
    data = None
    for pattern in [
        "boto3_dependencies_with_python_names_fully_enriched.json",     # AWS
        "azure_dependencies_with_python_names_fully_enriched.json",     # Azure
        "gcp_dependencies_with_python_names_fully_enriched.json",       # GCP
        "alicloud_dependencies_with_python_names_fully_enriched.json",  # Alicloud
        "oci_dependencies_with_python_names_fully_enriched.json",       # OCI
        "ibm_dependencies_with_python_names_fully_enriched.json",       # IBM
        "k8s_dependencies_with_python_names_fully_enriched.json",       # K8s
    ]:
        fpath = service_dir / pattern
        data = load_json(fpath)
        if data:
            break
    if not data:
        return 0

    # The file is a dict with service name as key
    service_name = service_dir.name
    service_data = data.get(service_name) or data.get(list(data.keys())[0]) if data else None
    if not service_data:
        return 0

    # Also load minimal_operations_list for discovery info
    min_ops_path = service_dir / "minimal_operations_list.json"
    min_ops_data = load_json(min_ops_path) or {}
    root_ops_available = set(min_ops_data.get("root_operations_available", []))
    discovery_ops = set(min_ops_data.get("yaml_discovery_operations", []))

    def _make_row(op, op_type):
        operation_name = op.get("operation", "")
        if not operation_name:
            return None
        python_method = op.get("python_method", "")
        required_params = op.get("required_params", [])
        optional_params = op.get("optional_params", [])
        depends_on = op.get("depends_on", []) or op.get("dependencies", [])
        output_structure = op.get("output_fields", op.get("item_fields", {}))
        is_disc = operation_name in discovery_ops
        is_root = operation_name in root_ops_available or op_type == "independent"
        return (
            service_id, operation_name, python_method, op_type,
            is_disc, is_root,
            Json(required_params if isinstance(required_params, list) else []),
            Json(optional_params if isinstance(optional_params, list) else []),
            len(required_params) if isinstance(required_params, list) else 0,
            len(optional_params) if isinstance(optional_params, list) else 0,
            Json(depends_on if isinstance(depends_on, list) else []),
            len(depends_on) if isinstance(depends_on, list) else 0,
            "",  # main_output_field
            Json(output_structure if isinstance(output_structure, dict) else {}),
            op.get("description", ""),
            Json({}),
        )

    rows = []
    seen_ops = set()

    # Pattern 1: Top-level independent/dependent (AWS, Azure, IBM, K8s)
    for op_type in ["independent", "dependent"]:
        for op in service_data.get(op_type, []):
            row = _make_row(op, op_type)
            if row and row[1] not in seen_ops:
                seen_ops.add(row[1])
                rows.append(row)

    # Pattern 2: resources.{resource}.independent/dependent (GCP)
    if not rows and "resources" in service_data and isinstance(service_data["resources"], dict):
        for resource_name, resource_data in service_data["resources"].items():
            if not isinstance(resource_data, dict):
                continue
            for op_type in ["independent", "dependent"]:
                for op in resource_data.get(op_type, []):
                    row = _make_row(op, op_type)
                    if row and row[1] not in seen_ops:
                        seen_ops.add(row[1])
                        rows.append(row)

    # Pattern 3: flat operations[] list (Alicloud, OCI)
    if not rows and "operations" in service_data and isinstance(service_data["operations"], list):
        for op in service_data["operations"]:
            op_type = "independent"
            if op.get("depends_on") or op.get("dependencies"):
                op_type = "dependent"
            row = _make_row(op, op_type)
            if row and row[1] not in seen_ops:
                seen_ops.add(row[1])
                rows.append(row)

    if not rows:
        return 0

    cur = conn.cursor()
    try:
        # Delete existing operations for this service
        cur.execute("DELETE FROM operations WHERE service_id = %s", (service_id,))

        execute_values(cur, """
            INSERT INTO operations (
                service_id, operation_name, python_method, operation_type,
                is_discovery, is_root_operation,
                required_params, optional_params, total_required, total_optional,
                depends_on, dependency_count,
                main_output_field, output_structure, description, metadata
            ) VALUES %s
            ON CONFLICT (service_id, operation_name) DO UPDATE SET
                python_method = EXCLUDED.python_method,
                operation_type = EXCLUDED.operation_type,
                is_discovery = EXCLUDED.is_discovery,
                is_root_operation = EXCLUDED.is_root_operation,
                required_params = EXCLUDED.required_params,
                optional_params = EXCLUDED.optional_params,
                total_required = EXCLUDED.total_required,
                total_optional = EXCLUDED.total_optional,
                depends_on = EXCLUDED.depends_on,
                dependency_count = EXCLUDED.dependency_count,
                main_output_field = EXCLUDED.main_output_field,
                output_structure = EXCLUDED.output_structure,
                updated_at = now()
        """, rows)
        conn.commit()
        return len(rows)
    except Exception as e:
        conn.rollback()
        print(f"    ERROR operations {service_id}: {e}")
        return 0
    finally:
        cur.close()


def populate_fields(conn, csp_id: str, service_id: str, service_dir: Path):
    """
    Populate fields table from field_operator_value_table.csv

    CSV columns: service, field_name, field_type, is_enum, operators,
                 operators_no_value, operators_select_list, operators_manual_input,
                 value_requirement_type, possible_values, values_source, num_possible_values
    """
    fpath = service_dir / "field_operator_value_table.csv"
    csv_rows = load_csv_rows(fpath)
    if not csv_rows:
        return 0

    rows = []
    for row in csv_rows:
        field_name = row.get("field_name", "").strip()
        if not field_name:
            continue

        field_type = row.get("field_type", "string")
        is_enum = row.get("is_enum", "No").strip().lower() in ("yes", "true", "1")

        # Parse operators into JSON array
        operators_str = row.get("operators", "")
        operators = [o.strip() for o in operators_str.split(",") if o.strip()] if operators_str else []

        # Parse possible values
        pv_str = row.get("possible_values", "")
        possible_values = [v.strip() for v in pv_str.split(",") if v.strip()] if pv_str else []

        # Compliance/security categorization
        compliance_cat = row.get("compliance_category", "")
        security_impact = row.get("security_impact", "")
        target_cat = row.get("target_category", "properties")

        rows.append((
            service_id,
            "",  # operation_name (not in CSV, can be enriched later)
            field_name,
            f"{service_dir.name}.{field_name}",  # field_path
            field_type,
            compliance_cat,
            security_impact,
            Json([]),  # compliance_frameworks
            Json(operators),
            Json(possible_values),
            is_enum,
            target_cat,
            "",  # description
            Json({}),  # metadata
        ))

    if not rows:
        return 0

    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM fields WHERE service_id = %s", (service_id,))
        execute_values(cur, """
            INSERT INTO fields (
                service_id, operation_name, field_name, field_path,
                field_type, compliance_category, security_impact,
                compliance_frameworks, operators, possible_values,
                is_enum, target_category, description, metadata
            ) VALUES %s
        """, rows)
        conn.commit()
        return len(rows)
    except Exception as e:
        conn.rollback()
        print(f"    ERROR fields {service_id}: {e}")
        return 0
    finally:
        cur.close()


def populate_resource_inventory(conn, csp_id: str, service_id: str, service_dir: Path):
    """
    Populate resource_inventory table from resource_inventory_report.json

    Stores entire JSON as inventory_data JSONB, extracts counts.
    """
    fpath = service_dir / "resource_inventory_report.json"
    data = load_json(fpath)
    if not data:
        return 0

    resources = data.get("resources", [])
    total_resource_types = len(resources)

    # Count operations referenced
    all_ops = set()
    disc_ops = set()
    for res in resources:
        for op in res.get("all_operations", []):
            all_ops.add(op)
        for op in res.get("root_operations", []):
            disc_ops.add(op)
    total_operations = len(all_ops)
    discovery_operations = len(disc_ops)

    generated_at = data.get("generated_at")

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO resource_inventory (
                service_id, inventory_data, total_resource_types,
                total_operations, discovery_operations,
                version, generated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (service_id) DO UPDATE SET
                inventory_data = EXCLUDED.inventory_data,
                total_resource_types = EXCLUDED.total_resource_types,
                total_operations = EXCLUDED.total_operations,
                discovery_operations = EXCLUDED.discovery_operations,
                version = EXCLUDED.version,
                generated_at = EXCLUDED.generated_at,
                updated_at = now()
        """, (
            service_id,
            Json(data),
            total_resource_types,
            total_operations,
            discovery_operations,
            "1.0",
            generated_at,
        ))
        conn.commit()
        return 1
    except Exception as e:
        conn.rollback()
        print(f"    ERROR resource_inventory {service_id}: {e}")
        return 0
    finally:
        cur.close()


def populate_dependency_index(conn, csp_id: str, service_id: str, service_dir: Path):
    """
    Populate dependency_index table from dependency_index.json
    """
    fpath = service_dir / "dependency_index.json"
    data = load_json(fpath)
    if not data:
        return 0

    # Count functions
    roots = data.get("roots", [])
    entity_paths = data.get("entity_paths", {})

    independent_count = len(roots)
    # Count all unique operations across entity_paths
    all_ops = set()
    for entity, paths in entity_paths.items():
        for path in paths if isinstance(paths, list) else [paths]:
            if isinstance(path, dict):
                for op in path.get("operations", []):
                    all_ops.add(op)
    dependent_count = len(all_ops) - independent_count
    if dependent_count < 0:
        dependent_count = 0
    total_functions = independent_count + dependent_count

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO dependency_index (
                service_id, dependency_data,
                total_functions, independent_functions, dependent_functions,
                version, generated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (service_id) DO UPDATE SET
                dependency_data = EXCLUDED.dependency_data,
                total_functions = EXCLUDED.total_functions,
                independent_functions = EXCLUDED.independent_functions,
                dependent_functions = EXCLUDED.dependent_functions,
                updated_at = now()
        """, (
            service_id,
            Json(data),
            total_functions,
            independent_count,
            dependent_count,
            "1.0",
            None,
        ))
        conn.commit()
        return 1
    except Exception as e:
        conn.rollback()
        print(f"    ERROR dependency_index {service_id}: {e}")
        return 0
    finally:
        cur.close()


def populate_direct_vars(conn, csp_id: str, service_id: str, service_dir: Path):
    """
    Populate direct_vars table from direct_vars.json
    """
    fpath = service_dir / "direct_vars.json"
    data = load_json(fpath)
    if not data:
        return 0

    seed_from_list = data.get("seed_from_list", [])
    enriched_from_get = data.get("enriched_from_get_describe", [])
    total_fields = len(seed_from_list) + len(enriched_from_get)

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO direct_vars (
                service_id, direct_vars_data,
                total_fields, compliance_fields, security_fields,
                version, generated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (service_id) DO UPDATE SET
                direct_vars_data = EXCLUDED.direct_vars_data,
                total_fields = EXCLUDED.total_fields,
                updated_at = now()
        """, (
            service_id,
            Json(data),
            total_fields,
            0,  # compliance_fields — can be enriched later
            0,  # security_fields — can be enriched later
            "1.0",
            None,
        ))
        conn.commit()
        return 1
    except Exception as e:
        conn.rollback()
        print(f"    ERROR direct_vars {service_id}: {e}")
        return 0
    finally:
        cur.close()


def update_service_counts(conn, csp_id: str, service_id: str, ops_count: int, disc_count: int):
    """Update services table with operation counts."""
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE services SET
                total_operations = %s,
                discovery_operations = %s,
                last_updated = now()
            WHERE service_id = %s
        """, (ops_count, disc_count, service_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
    finally:
        cur.close()


def update_csp_counts(conn, csp_id: str):
    """Update csp table with total_services count."""
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE csp SET
                total_services = (SELECT COUNT(*) FROM services WHERE csp_id = %s),
                last_updated = now()
            WHERE csp_id = %s
        """, (csp_id, csp_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
    finally:
        cur.close()


def populate_enhancement_indexes(conn, csp_id: str, csp_dir: Path):
    """
    Populate enhancement_indexes with CSP-level aggregated data.
    Stores resource_arn_mapping as an enhancement index per service.
    """
    # Collect all resource_arn_mappings into one CSP-level index
    all_arn_mappings = {}
    for svc_dir in list_service_dirs(csp_dir):
        arn_path = svc_dir / "resource_arn_mapping.json"
        data = load_json(arn_path)
        if data and isinstance(data, dict):
            analysis = data.get("analysis", data)
            if isinstance(analysis, dict):
                svc_name = analysis.get("service", svc_dir.name)
                resources = analysis.get("resources", {})
                if resources:
                    all_arn_mappings[svc_name] = resources

    if not all_arn_mappings:
        return 0

    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO enhancement_indexes (
                index_type, csp_id, index_data,
                version, total_entries, generated_at
            ) VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (index_type, csp_id) DO UPDATE SET
                index_data = EXCLUDED.index_data,
                total_entries = EXCLUDED.total_entries,
                updated_at = now()
        """, (
            "resource_arn_mapping",
            csp_id,
            Json(all_arn_mappings),
            "1.0",
            len(all_arn_mappings),
            datetime.now(timezone.utc).isoformat(),
        ))
        conn.commit()
        return 1
    except Exception as e:
        conn.rollback()
        print(f"    ERROR enhancement_indexes {csp_id}: {e}")
        return 0
    finally:
        cur.close()


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Populate threat_engine_pythonsdk DB")
    parser.add_argument("--csp", type=str, default=None,
                        help="Only populate a specific CSP (aws, azure, gcp, alicloud, oci, ibm, k8s)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Count files only, don't write to DB")
    args = parser.parse_args()

    conn = get_conn()
    print(f"Connected to {DB_NAME} @ {DB_HOST}")
    print(f"Data root: {DATA_ROOT}")
    if args.csp:
        print(f"Filter: --csp {args.csp}")
    if args.dry_run:
        print("Mode: DRY RUN (no DB writes)")
    print()

    grand_totals = {
        "operations": 0,
        "fields": 0,
        "resource_inventory": 0,
        "dependency_index": 0,
        "direct_vars": 0,
        "enhancement_indexes": 0,
        "services_updated": 0,
    }

    for csp_id, csp_dir in CSP_DIRS.items():
        # Apply CSP filter
        if args.csp and csp_id != args.csp:
            continue

        if not csp_dir.exists():
            print(f"Skipping {csp_id}: directory not found")
            continue

        service_dirs = list_service_dirs(csp_dir)
        print(f"═══ {csp_id.upper()} ═══  ({len(service_dirs)} services)")

        csp_ops_total = 0
        csp_svc_processed = 0

        for svc_dir in service_dirs:
            service_name = svc_dir.name
            service_id = f"{csp_id}.{service_name}"

            # Check if service exists in DB
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM services WHERE service_id = %s", (service_id,))
            exists = cur.fetchone()
            cur.close()

            if not exists:
                # Service directory exists in local files but not in DB — insert it
                cur = conn.cursor()
                try:
                    cur.execute("""
                        INSERT INTO services (service_id, csp_id, service_name)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (service_id) DO NOTHING
                    """, (service_id, csp_id, service_name))
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    print(f"  ⚠ Cannot insert service {service_id}: {e}")
                    continue
                finally:
                    cur.close()

            # Populate each table
            ops_count = populate_operations(conn, csp_id, service_id, svc_dir)
            fields_count = populate_fields(conn, csp_id, service_id, svc_dir)
            ri_count = populate_resource_inventory(conn, csp_id, service_id, svc_dir)
            di_count = populate_dependency_index(conn, csp_id, service_id, svc_dir)
            dv_count = populate_direct_vars(conn, csp_id, service_id, svc_dir)

            # Calculate discovery operations from minimal_operations_list
            min_ops = load_json(svc_dir / "minimal_operations_list.json") or {}
            disc_ops = len(min_ops.get("yaml_discovery_operations", []))

            # Update service counts
            if ops_count > 0:
                update_service_counts(conn, csp_id, service_id, ops_count, disc_ops)
                grand_totals["services_updated"] += 1

            grand_totals["operations"] += ops_count
            grand_totals["fields"] += fields_count
            grand_totals["resource_inventory"] += ri_count
            grand_totals["dependency_index"] += di_count
            grand_totals["direct_vars"] += dv_count

            csp_ops_total += ops_count
            csp_svc_processed += 1

            # Progress indicator (every 50 services)
            if csp_svc_processed % 50 == 0:
                print(f"  ... processed {csp_svc_processed}/{len(service_dirs)} services")

        # Enhancement indexes (CSP-level)
        ei_count = populate_enhancement_indexes(conn, csp_id, csp_dir)
        grand_totals["enhancement_indexes"] += ei_count

        # Update CSP counts
        update_csp_counts(conn, csp_id)

        print(f"  Done: {csp_svc_processed} services, {csp_ops_total} operations")
        print()

    print("═══════════════════════════════════════════")
    print("POPULATION COMPLETE")
    print("═══════════════════════════════════════════")
    for table, count in grand_totals.items():
        print(f"  {table:25s}: {count:,}")

    # Final verification
    print("\n── Verification ──")
    cur = conn.cursor()
    for table in ["operations", "fields", "resource_inventory", "dependency_index", "direct_vars", "enhancement_indexes"]:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        count = cur.fetchone()[0]
        print(f"  {table:25s}: {count:,} rows in DB")

    cur.execute("SELECT csp_id, total_services FROM csp ORDER BY csp_id")
    for row in cur.fetchall():
        print(f"  csp {row[0]:12s}: {row[1]} services")

    cur.execute("SELECT csp_id, COUNT(*) as svcs, SUM(total_operations) as ops FROM services GROUP BY csp_id ORDER BY csp_id")
    for row in cur.fetchall():
        print(f"  services {row[0]:12s}: {row[1]} svcs, {row[2] or 0} total_ops")
    cur.close()

    conn.close()
    print("\nDone!")


if __name__ == "__main__":
    main()
