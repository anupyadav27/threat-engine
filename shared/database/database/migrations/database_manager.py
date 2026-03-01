"""
Database Migration and Management Tool for Threat Engine
Provides unified database operations across all engines
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
from datetime import datetime
import hashlib

import asyncpg
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import argparse

# Add parent directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from consolidated_services.database.config.database_config import (
    get_database_config,
    ConsolidatedDatabaseSettings
)


class DatabaseManager:
    """Manages database operations across all engines"""
    
    def __init__(self):
        self.settings = ConsolidatedDatabaseSettings()
        self.engines = ["shared", "configscan", "compliance", "inventory", "threat"]
        self.schema_files = {
            "shared": "consolidated_services/database/schemas/shared_schema.sql",
            "configscan": "consolidated_services/database/schemas/configscan_schema.sql",
            "compliance": "consolidated_services/database/schemas/compliance_schema.sql",
            "inventory": "consolidated_services/database/schemas/inventory_schema.sql",
            "threat": "consolidated_services/database/schemas/threat_schema.sql",
        }
    
    def _get_sync_connection(self, engine: str):
        """Get synchronous connection for database operations"""
        config = get_database_config(engine)
        return psycopg2.connect(
            host=config.host,
            port=config.port,
            database=config.database,
            user=config.username,
            password=config.password
        )
    
    async def _get_async_connection(self, engine: str):
        """Get asynchronous connection for database operations"""
        config = get_database_config(engine)
        return await asyncpg.connect(
            host=config.host,
            port=config.port,
            database=config.database,
            user=config.username,
            password=config.password
        )
    
    def test_connection(self, engine: str) -> Tuple[bool, str]:
        """Test database connection for specific engine"""
        try:
            conn = self._get_sync_connection(engine)
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if result and result[0] == 1:
                return True, "Connection successful"
            else:
                return False, "Unexpected query result"
                
        except Exception as e:
            return False, f"Connection failed: {str(e)}"
    
    def test_all_connections(self) -> Dict[str, Tuple[bool, str]]:
        """Test connections for all engines"""
        results = {}
        for engine in self.engines:
            results[engine] = self.test_connection(engine)
        return results
    
    def get_table_count(self, engine: str) -> int:
        """Get number of tables in database"""
        try:
            conn = self._get_sync_connection(engine)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            """)
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return count
        except Exception:
            return 0
    
    def get_database_info(self, engine: str) -> Dict:
        """Get comprehensive database information"""
        try:
            conn = self._get_sync_connection(engine)
            cursor = conn.cursor()
            
            # Get table count
            cursor.execute("""
                SELECT COUNT(*) 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            """)
            table_count = cursor.fetchone()[0]
            
            # Get database size
            cursor.execute("""
                SELECT pg_size_pretty(pg_database_size(current_database()))
            """)
            db_size = cursor.fetchone()[0]
            
            # Get table names and row counts
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name
            """)
            tables = [row[0] for row in cursor.fetchall()]
            
            table_info = {}
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_count = cursor.fetchone()[0]
                table_info[table] = row_count
            
            cursor.close()
            conn.close()
            
            return {
                "engine": engine,
                "table_count": table_count,
                "database_size": db_size,
                "tables": table_info,
                "connection_status": "OK"
            }
            
        except Exception as e:
            return {
                "engine": engine,
                "error": str(e),
                "connection_status": "FAILED"
            }
    
    def apply_schema(self, engine: str, force: bool = False) -> Tuple[bool, str]:
        """Apply schema to specific engine database"""
        schema_file = self.schema_files.get(engine)
        if not schema_file:
            return False, f"No schema file defined for engine: {engine}"
        
        schema_path = Path(schema_file)
        if not schema_path.exists():
            return False, f"Schema file not found: {schema_file}"
        
        try:
            # Check if tables already exist
            table_count = self.get_table_count(engine)
            if table_count > 0 and not force:
                return False, f"Database already has {table_count} tables. Use --force to overwrite."
            
            # Read and execute schema
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
            
            conn = self._get_sync_connection(engine)
            cursor = conn.cursor()
            
            # Execute schema
            cursor.execute(schema_sql)
            conn.commit()
            
            cursor.close()
            conn.close()
            
            new_table_count = self.get_table_count(engine)
            return True, f"Schema applied successfully. Tables created: {new_table_count}"
            
        except Exception as e:
            return False, f"Schema application failed: {str(e)}"
    
    def apply_all_schemas(self, force: bool = False) -> Dict[str, Tuple[bool, str]]:
        """Apply schemas to all engine databases"""
        results = {}
        
        # Apply shared schema first (other schemas depend on it)
        results["shared"] = self.apply_schema("shared", force)
        
        # Apply other schemas
        for engine in ["configscan", "compliance", "inventory", "threat"]:
            results[engine] = self.apply_schema(engine, force)
        
        return results
    
    def backup_database(self, engine: str, backup_dir: str = "backups") -> Tuple[bool, str]:
        """Create database backup"""
        config = get_database_config(engine)
        
        # Create backup directory
        backup_path = Path(backup_dir)
        backup_path.mkdir(exist_ok=True)
        
        # Generate backup filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_path / f"{engine}_{config.database}_{timestamp}.sql"
        
        try:
            # Use pg_dump to create backup
            import subprocess
            
            env = os.environ.copy()
            env['PGPASSWORD'] = config.password
            
            cmd = [
                'pg_dump',
                '-h', config.host,
                '-p', str(config.port),
                '-U', config.username,
                '-d', config.database,
                '-f', str(backup_file),
                '--verbose'
            ]
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                file_size = backup_file.stat().st_size
                return True, f"Backup created: {backup_file} ({file_size} bytes)"
            else:
                return False, f"Backup failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Backup failed: {str(e)}"
    
    def restore_database(self, engine: str, backup_file: str) -> Tuple[bool, str]:
        """Restore database from backup"""
        config = get_database_config(engine)
        backup_path = Path(backup_file)
        
        if not backup_path.exists():
            return False, f"Backup file not found: {backup_file}"
        
        try:
            import subprocess
            
            env = os.environ.copy()
            env['PGPASSWORD'] = config.password
            
            cmd = [
                'psql',
                '-h', config.host,
                '-p', str(config.port),
                '-U', config.username,
                '-d', config.database,
                '-f', str(backup_path),
                '--verbose'
            ]
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                return True, f"Database restored from: {backup_file}"
            else:
                return False, f"Restore failed: {result.stderr}"
                
        except Exception as e:
            return False, f"Restore failed: {str(e)}"
    
    async def execute_query(self, engine: str, query: str) -> List[Dict]:
        """Execute query and return results"""
        try:
            conn = await self._get_async_connection(engine)
            rows = await conn.fetch(query)
            await conn.close()
            
            # Convert to list of dicts
            result = []
            for row in rows:
                result.append(dict(row))
            
            return result
            
        except Exception as e:
            raise Exception(f"Query execution failed: {str(e)}")
    
    def reset_database(self, engine: str) -> Tuple[bool, str]:
        """Reset database by dropping all tables"""
        try:
            conn = self._get_sync_connection(engine)
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            """)
            tables = [row[0] for row in cursor.fetchall()]
            
            if not tables:
                cursor.close()
                conn.close()
                return True, "No tables to drop"
            
            # Drop all tables with CASCADE
            for table in tables:
                cursor.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True, f"Dropped {len(tables)} tables"
            
        except Exception as e:
            return False, f"Reset failed: {str(e)}"


def main():
    """CLI interface for database management"""
    parser = argparse.ArgumentParser(description="Threat Engine Database Manager")
    parser.add_argument("command", choices=[
        "test", "info", "schema", "backup", "restore", "reset", "query"
    ], help="Command to execute")
    
    parser.add_argument("--engine", choices=[
        "shared", "configscan", "compliance", "inventory", "threat", "all"
    ], default="all", help="Target engine (default: all)")
    
    parser.add_argument("--force", action="store_true", 
                       help="Force operation (overwrite existing)")
    
    parser.add_argument("--backup-dir", default="backups",
                       help="Backup directory (default: backups)")
    
    parser.add_argument("--backup-file", 
                       help="Backup file for restore operation")
    
    parser.add_argument("--query-file", 
                       help="SQL file to execute")
    
    parser.add_argument("--query", 
                       help="SQL query to execute")
    
    args = parser.parse_args()
    
    manager = DatabaseManager()
    
    if args.command == "test":
        print("Testing database connections...")
        if args.engine == "all":
            results = manager.test_all_connections()
            for engine, (success, message) in results.items():
                status = "✓" if success else "✗"
                print(f"{status} {engine}: {message}")
        else:
            success, message = manager.test_connection(args.engine)
            status = "✓" if success else "✗"
            print(f"{status} {args.engine}: {message}")
    
    elif args.command == "info":
        print("Database information...")
        engines = [args.engine] if args.engine != "all" else manager.engines
        for engine in engines:
            info = manager.get_database_info(engine)
            print(f"\n{engine.upper()} Database:")
            print(f"  Status: {info.get('connection_status', 'UNKNOWN')}")
            if 'error' in info:
                print(f"  Error: {info['error']}")
            else:
                print(f"  Tables: {info['table_count']}")
                print(f"  Size: {info['database_size']}")
                if info['tables']:
                    print("  Table Details:")
                    for table, rows in info['tables'].items():
                        print(f"    {table}: {rows:,} rows")
    
    elif args.command == "schema":
        print("Applying database schemas...")
        if args.engine == "all":
            results = manager.apply_all_schemas(args.force)
            for engine, (success, message) in results.items():
                status = "✓" if success else "✗"
                print(f"{status} {engine}: {message}")
        else:
            success, message = manager.apply_schema(args.engine, args.force)
            status = "✓" if success else "✗"
            print(f"{status} {args.engine}: {message}")
    
    elif args.command == "backup":
        print("Creating database backups...")
        engines = [args.engine] if args.engine != "all" else manager.engines
        for engine in engines:
            success, message = manager.backup_database(engine, args.backup_dir)
            status = "✓" if success else "✗"
            print(f"{status} {engine}: {message}")
    
    elif args.command == "restore":
        if not args.backup_file:
            print("Error: --backup-file is required for restore")
            return
        
        if args.engine == "all":
            print("Error: Cannot restore all databases at once. Specify --engine")
            return
        
        print(f"Restoring {args.engine} database...")
        success, message = manager.restore_database(args.engine, args.backup_file)
        status = "✓" if success else "✗"
        print(f"{status} {message}")
    
    elif args.command == "reset":
        print("Resetting databases (dropping all tables)...")
        
        if args.engine == "all":
            confirm = input("This will DROP ALL TABLES in ALL databases. Continue? (y/N): ")
            if confirm.lower() != 'y':
                print("Cancelled")
                return
            engines = manager.engines
        else:
            confirm = input(f"This will DROP ALL TABLES in {args.engine} database. Continue? (y/N): ")
            if confirm.lower() != 'y':
                print("Cancelled")
                return
            engines = [args.engine]
        
        for engine in engines:
            success, message = manager.reset_database(engine)
            status = "✓" if success else "✗"
            print(f"{status} {engine}: {message}")
    
    elif args.command == "query":
        if args.engine == "all":
            print("Error: Cannot execute query on all databases. Specify --engine")
            return
        
        query = None
        if args.query:
            query = args.query
        elif args.query_file:
            with open(args.query_file, 'r') as f:
                query = f.read()
        else:
            print("Error: Either --query or --query-file is required")
            return
        
        try:
            results = asyncio.run(manager.execute_query(args.engine, query))
            print(f"Query executed successfully. Returned {len(results)} rows.")
            if results:
                print("\nResults:")
                for i, row in enumerate(results[:10]):  # Show first 10 rows
                    print(f"Row {i+1}: {row}")
                if len(results) > 10:
                    print(f"... and {len(results) - 10} more rows")
        except Exception as e:
            print(f"Query failed: {e}")


if __name__ == "__main__":
    main()