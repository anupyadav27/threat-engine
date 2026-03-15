#!/usr/bin/env python3
"""
Migrate scan_orchestration table from threat_engine_shared to threat_engine_onboarding.

This consolidates all orchestration logic under the onboarding engine, eliminating
the need for a separate shared database.

Steps:
1. Create scan_orchestration table in threat_engine_onboarding (if not exists)
2. Migrate all data from threat_engine_shared.scan_orchestration
3. Verify data integrity
4. Report migration results

Usage:
    export RDS_PASSWORD='your_password'  # or set PGPASSWORD
    python3 scripts/migrate_orchestration_to_onboarding.py --host your-rds-host --user postgres
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple


def run_psql(host: str, port: int, user: str, dbname: str, sql: str, sslmode: str = "require") -> str:
    """Execute SQL and return output"""
    env = os.environ.copy()
    if env.get("RDS_PASSWORD") and not env.get("PGPASSWORD"):
        env["PGPASSWORD"] = env["RDS_PASSWORD"]

    conninfo = f"host={host} port={port} user={user} dbname={dbname} sslmode={sslmode}"
    cmd = ["psql", conninfo, "-v", "ON_ERROR_STOP=1", "-At", "-c", sql]
    return subprocess.check_output(cmd, env=env, text=True)


def run_psql_no_output(host: str, port: int, user: str, dbname: str, sql: str, sslmode: str = "require") -> None:
    """Execute SQL without capturing output"""
    env = os.environ.copy()
    if env.get("RDS_PASSWORD") and not env.get("PGPASSWORD"):
        env["PGPASSWORD"] = env["RDS_PASSWORD"]

    conninfo = f"host={host} port={port} user={user} dbname={dbname} sslmode={sslmode}"
    cmd = ["psql", conninfo, "-v", "ON_ERROR_STOP=1", "-c", sql]
    subprocess.check_call(cmd, env=env, stdout=subprocess.DEVNULL)


def check_table_exists(host: str, port: int, user: str, dbname: str, table_name: str) -> bool:
    """Check if table exists in database"""
    try:
        sql = f"""
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'public' AND table_name = '{table_name}'
            LIMIT 1
        """
        result = run_psql(host, port, user, dbname, sql)
        return bool(result.strip())
    except subprocess.CalledProcessError:
        return False


def get_row_count(host: str, port: int, user: str, dbname: str, table_name: str) -> int:
    """Get row count for table"""
    try:
        sql = f"SELECT COUNT(*) FROM {table_name}"
        result = run_psql(host, port, user, dbname, sql)
        return int(result.strip())
    except subprocess.CalledProcessError:
        return 0


def create_orchestration_table(host: str, port: int, user: str, dbname: str) -> None:
    """Create scan_orchestration table in onboarding database"""
    print(f"Creating scan_orchestration table in {dbname}...")
    
    # Read the schema from the updated onboarding_schema.sql
    schema_file = Path(__file__).parent.parent / "consolidated_services/database/schemas/onboarding_schema.sql"
    
    if not schema_file.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_file}")
    
    # Extract just the scan_orchestration table creation from the schema
    with open(schema_file, 'r') as f:
        schema_content = f.read()
    
    # Find the scan_orchestration table definition
    lines = schema_content.split('\n')
    in_orchestration_section = False
    table_sql_lines = []
    
    for line in lines:
        if 'CREATE TABLE IF NOT EXISTS scan_orchestration' in line:
            in_orchestration_section = True
            table_sql_lines.append(line)
        elif in_orchestration_section:
            table_sql_lines.append(line)
            if line.strip() == ');':
                break
    
    if not table_sql_lines:
        raise ValueError("Could not find scan_orchestration table definition in schema file")
    
    table_sql = '\n'.join(table_sql_lines)
    
    # Remove foreign key constraints since base tables may not exist
    table_sql = table_sql.replace(
        "CONSTRAINT fk_tenant_orchestration FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "-- FK constraint removed: base tenants table may not exist"
    )
    
    # Also get the indexes
    index_lines = []
    for line in lines:
        if 'idx_orchestration_' in line and 'CREATE INDEX' in line:
            index_lines.append(line)
    
    full_sql = table_sql + '\n\n' + '\n'.join(index_lines)
    
    run_psql_no_output(host, port, user, dbname, full_sql)
    print("✓ scan_orchestration table created in onboarding database")


def migrate_data(host: str, port: int, user: str, source_db: str, target_db: str) -> Tuple[int, int]:
    """Migrate data from source to target database"""
    print(f"Migrating data from {source_db}.scan_orchestration to {target_db}.scan_orchestration...")
    
    # Get source data
    source_sql = """
        SELECT 
            orchestration_id, tenant_id, scan_name, scan_type, trigger_type,
            engines_requested, engines_completed, overall_status,
            started_at, completed_at, results_summary, error_details, created_at,
            execution_id, customer_id, provider, hierarchy_id, account_id,
            include_services, include_regions, discovery_scan_id, check_scan_id,
            inventory_scan_id, threat_scan_id, compliance_scan_id, iam_scan_id,
            datasec_scan_id, credential_type, credential_ref, exclude_services,
            exclude_regions, schedule_id
        FROM scan_orchestration
        ORDER BY created_at
    """
    
    source_count = get_row_count(host, port, user, source_db, "scan_orchestration")
    print(f"Source table has {source_count} rows")
    
    if source_count == 0:
        print("No data to migrate")
        return 0, 0
    
    # Export from source
    temp_file = f"/tmp/scan_orchestration_migration_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    env = os.environ.copy()
    if env.get("RDS_PASSWORD") and not env.get("PGPASSWORD"):
        env["PGPASSWORD"] = env["RDS_PASSWORD"]
    
    # Export to CSV
    export_sql = f"\\copy ({source_sql}) TO '{temp_file}' CSV HEADER"
    source_conninfo = f"host={host} port={port} user={user} dbname={source_db} sslmode=require"
    cmd = ["psql", source_conninfo, "-v", "ON_ERROR_STOP=1", "-c", export_sql]
    subprocess.check_call(cmd, env=env, stdout=subprocess.DEVNULL)
    
    print(f"✓ Exported {source_count} rows to {temp_file}")
    
    # Import to target
    import_sql = f"\\copy scan_orchestration FROM '{temp_file}' CSV HEADER"
    target_conninfo = f"host={host} port={port} user={user} dbname={target_db} sslmode=require"
    cmd = ["psql", target_conninfo, "-v", "ON_ERROR_STOP=1", "-c", import_sql]
    subprocess.check_call(cmd, env=env, stdout=subprocess.DEVNULL)
    
    target_count = get_row_count(host, port, user, target_db, "scan_orchestration")
    print(f"✓ Imported {target_count} rows to target database")
    
    # Cleanup temp file
    os.unlink(temp_file)
    
    return source_count, target_count


def verify_migration(host: str, port: int, user: str, source_db: str, target_db: str) -> bool:
    """Verify migration was successful"""
    print("Verifying migration...")
    
    source_count = get_row_count(host, port, user, source_db, "scan_orchestration")
    target_count = get_row_count(host, port, user, target_db, "scan_orchestration")
    
    print(f"Source: {source_count} rows, Target: {target_count} rows")
    
    if source_count != target_count:
        print("✗ Row count mismatch!")
        return False
    
    # Verify a few sample records
    sample_sql = """
        SELECT orchestration_id, tenant_id, provider, account_id, overall_status
        FROM scan_orchestration
        ORDER BY created_at DESC
        LIMIT 3
    """
    
    source_sample = run_psql(host, port, user, source_db, sample_sql)
    target_sample = run_psql(host, port, user, target_db, sample_sql)
    
    if source_sample.strip() != target_sample.strip():
        print("✗ Sample data mismatch!")
        print("Source sample:")
        print(source_sample)
        print("Target sample:")
        print(target_sample)
        return False
    
    print("✓ Migration verified successfully")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Migrate scan_orchestration table to onboarding database")
    parser.add_argument("--host", required=True, help="RDS host")
    parser.add_argument("--port", type=int, default=5432, help="RDS port")
    parser.add_argument("--user", required=True, help="RDS user")
    parser.add_argument("--sslmode", default="require", help="SSL mode")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    
    args = parser.parse_args()
    
    source_db = "threat_engine_shared"
    target_db = "threat_engine_onboarding"
    
    print("=" * 80)
    print("SCAN_ORCHESTRATION TABLE MIGRATION")
    print("=" * 80)
    print(f"Source: {source_db}")
    print(f"Target: {target_db}")
    print(f"Host: {args.host}")
    print()
    
    if not (os.environ.get("RDS_PASSWORD") or os.environ.get("PGPASSWORD")):
        print("Error: Set RDS_PASSWORD or PGPASSWORD environment variable")
        return 1
    
    try:
        # Check source table exists
        if not check_table_exists(args.host, args.port, args.user, source_db, "scan_orchestration"):
            print(f"✗ Source table {source_db}.scan_orchestration does not exist")
            return 1
        
        source_count = get_row_count(args.host, args.port, args.user, source_db, "scan_orchestration")
        print(f"Source table has {source_count} rows")
        
        # Check if target table already exists
        target_exists = check_table_exists(args.host, args.port, args.user, target_db, "scan_orchestration")
        if target_exists:
            target_count = get_row_count(args.host, args.port, args.user, target_db, "scan_orchestration")
            print(f"Target table already exists with {target_count} rows")
            
            if target_count > 0:
                print("Warning: Target table is not empty. Migration will append data.")
                response = input("Continue? (y/N): ").strip().lower()
                if response != 'y':
                    print("Migration cancelled")
                    return 0
        
        if args.dry_run:
            print("DRY RUN: Would migrate data but not executing")
            return 0
        
        # Create table if it doesn't exist
        if not target_exists:
            create_orchestration_table(args.host, args.port, args.user, target_db)
        
        # Migrate data
        if source_count > 0:
            migrated_source, migrated_target = migrate_data(
                args.host, args.port, args.user, source_db, target_db
            )
            
            # Verify migration
            if verify_migration(args.host, args.port, args.user, source_db, target_db):
                print()
                print("=" * 80)
                print("MIGRATION COMPLETED SUCCESSFULLY")
                print("=" * 80)
                print(f"Migrated {migrated_source} rows from {source_db} to {target_db}")
                print()
                print("Next steps:")
                print("1. Update engine orchestration clients to use threat_engine_onboarding")
                print("2. Test orchestration queries work from onboarding DB")
                print("3. Remove scan_orchestration from threat_engine_shared")
                print("4. Update deployment configs to remove shared DB references")
                return 0
            else:
                print("✗ Migration verification failed")
                return 1
        else:
            print("No data to migrate, but table structure is ready")
            return 0
            
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())