#!/usr/bin/env python3
"""
Run migration 002: Add resource_uid column
"""
import os
import sys
import psycopg2
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Database connection from environment or defaults
DB_HOST = os.getenv("CONFIGSCAN_DB_HOST", "localhost")
DB_PORT = int(os.getenv("CONFIGSCAN_DB_PORT", "5432"))
DB_NAME = os.getenv("CONFIGSCAN_DB_NAME", "threat_engine_configscan")
# Try to use table owner (apple) or fallback to configscan_user
DB_USER = os.getenv("CONFIGSCAN_DB_USER", os.getenv("USER", "configscan_user"))
DB_PASSWORD = os.getenv("CONFIGSCAN_DB_PASSWORD", "")

# Try DATABASE_URL if available
DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL:
    # Parse DATABASE_URL
    from urllib.parse import urlparse
    u = urlparse(DATABASE_URL)
    DB_HOST = u.hostname or DB_HOST
    DB_PORT = u.port or DB_PORT
    DB_NAME = (u.path or "").lstrip("/") or DB_NAME
    DB_USER = u.username or DB_USER
    DB_PASSWORD = u.password or DB_PASSWORD

def run_migration():
    """Run migration 002"""
    print("=" * 80)
    print("Migration 002: Add resource_uid column")
    print("=" * 80)
    print(f"Connecting to: {DB_USER}@{DB_HOST}:{DB_PORT}/{DB_NAME}")
    
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        conn.autocommit = False
        cur = conn.cursor()
        
        print("\n[1/7] Adding resource_uid column to discoveries table...")
        try:
            cur.execute("ALTER TABLE discoveries ADD COLUMN IF NOT EXISTS resource_uid TEXT;")
            print("  ✓ Column added")
        except psycopg2.errors.InsufficientPrivilege:
            # Try with current user privileges
            print("  ⚠ Insufficient privileges for ALTER TABLE, trying alternative...")
            try:
                cur.execute("""
                    DO $$ 
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns 
                            WHERE table_name = 'discoveries' AND column_name = 'resource_uid'
                        ) THEN
                            ALTER TABLE discoveries ADD COLUMN resource_uid TEXT;
                        END IF;
                    END $$;
                """)
                print("  ✓ Column added (using DO block)")
            except Exception as e2:
                print(f"  ✗ Failed: {e2}")
                print("  ⚠ You may need to run this migration as database owner")
                raise
        
        print("\n[2/7] Adding resource_uid column to check_results table...")
        cur.execute("ALTER TABLE check_results ADD COLUMN IF NOT EXISTS resource_uid TEXT;")
        print("  ✓ Column added")
        
        print("\n[3/7] Adding resource_uid column to discovery_history table...")
        try:
            cur.execute("ALTER TABLE discovery_history ADD COLUMN IF NOT EXISTS resource_uid TEXT;")
            print("  ✓ Column added")
        except psycopg2.errors.UndefinedTable:
            print("  ⚠ discovery_history table does not exist (skipping)")
        
        print("\n[4/7] Backfilling resource_uid from resource_arn...")
        cur.execute("""
            UPDATE discoveries 
            SET resource_uid = resource_arn 
            WHERE resource_uid IS NULL AND resource_arn IS NOT NULL
        """)
        discoveries_updated = cur.rowcount
        print(f"  ✓ Updated {discoveries_updated} records in discoveries")
        
        cur.execute("""
            UPDATE check_results 
            SET resource_uid = resource_arn 
            WHERE resource_uid IS NULL AND resource_arn IS NOT NULL
        """)
        checks_updated = cur.rowcount
        print(f"  ✓ Updated {checks_updated} records in check_results")
        
        try:
            cur.execute("""
                UPDATE discovery_history 
                SET resource_uid = resource_arn 
                WHERE resource_uid IS NULL AND resource_arn IS NOT NULL
            """)
            history_updated = cur.rowcount
            print(f"  ✓ Updated {history_updated} records in discovery_history")
        except psycopg2.errors.UndefinedTable:
            print("  ⚠ discovery_history table does not exist (skipping)")
        
        print("\n[5/7] Creating indexes on resource_uid...")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_discoveries_resource_uid ON discoveries(resource_uid);")
        print("  ✓ Index created: idx_discoveries_resource_uid")
        
        cur.execute("CREATE INDEX IF NOT EXISTS idx_check_results_resource_uid ON check_results(resource_uid);")
        print("  ✓ Index created: idx_check_results_resource_uid")
        
        try:
            cur.execute("CREATE INDEX IF NOT EXISTS idx_discovery_history_resource_uid ON discovery_history(resource_uid);")
            print("  ✓ Index created: idx_discovery_history_resource_uid")
        except psycopg2.errors.UndefinedTable:
            print("  ⚠ discovery_history table does not exist (skipping)")
        
        print("\n[6/7] Creating composite indexes...")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_discoveries_tenant_uid ON discoveries(tenant_id, resource_uid);")
        print("  ✓ Index created: idx_discoveries_tenant_uid")
        
        cur.execute("CREATE INDEX IF NOT EXISTS idx_check_results_tenant_uid ON check_results(tenant_id, resource_uid);")
        print("  ✓ Index created: idx_check_results_tenant_uid")
        
        print("\n[7/7] Adding column comments...")
        try:
            cur.execute("""
                COMMENT ON COLUMN discoveries.resource_uid IS 'Stable unique identifier (ARN for AWS, Resource ID for Azure, Resource Name for GCP)';
            """)
            cur.execute("""
                COMMENT ON COLUMN check_results.resource_uid IS 'Stable unique identifier (ARN for AWS, Resource ID for Azure, Resource Name for GCP)';
            """)
            print("  ✓ Comments added")
        except Exception as e:
            print(f"  ⚠ Could not add comments: {e}")
        
        conn.commit()
        print("\n" + "=" * 80)
        print("✓ Migration completed successfully!")
        print("=" * 80)
        print(f"\nSummary:")
        print(f"  - Discoveries updated: {discoveries_updated}")
        print(f"  - Check results updated: {checks_updated}")
        print(f"  - Indexes created: 5")
        
        # Verify migration
        print("\nVerifying migration...")
        cur.execute("SELECT COUNT(*) FROM discoveries WHERE resource_uid IS NOT NULL;")
        discoveries_with_uid = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM discoveries;")
        total_discoveries = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM check_results WHERE resource_uid IS NOT NULL;")
        checks_with_uid = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM check_results;")
        total_checks = cur.fetchone()[0]
        
        print(f"  Discoveries: {discoveries_with_uid}/{total_discoveries} have resource_uid")
        print(f"  Check results: {checks_with_uid}/{total_checks} have resource_uid")
        
        cur.close()
        conn.close()
        
    except psycopg2.OperationalError as e:
        print(f"\n✗ Connection failed: {e}")
        print("\nTroubleshooting:")
        print("  1. Check if PostgreSQL is running")
        print("  2. Verify connection details:")
        print(f"     Host: {DB_HOST}")
        print(f"     Port: {DB_PORT}")
        print(f"     Database: {DB_NAME}")
        print(f"     User: {DB_USER}")
        print("  3. Try setting DATABASE_URL environment variable")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    run_migration()
