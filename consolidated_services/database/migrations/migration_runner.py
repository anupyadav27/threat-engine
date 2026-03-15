"""
Database Migration Runner
Handles database schema initialization and migrations
"""

import os
import sys
import asyncio
import argparse
from typing import List, Dict, Any
import logging

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from consolidated_services.database.connections import create_single_connection
from consolidated_services.database.config import get_database_config

logger = logging.getLogger(__name__)


class DatabaseMigrationRunner:
    """Handles database migrations and schema initialization"""
    
    def __init__(self):
        self.schemas_dir = os.path.join(os.path.dirname(__file__), "..", "schemas")
        self.engines = ["configscan", "compliance", "inventory", "threat", "shared"]
    
    async def initialize_engine_database(self, engine_name: str, force: bool = False) -> bool:
        """Initialize database for specific engine"""
        try:
            logger.info(f"Initializing {engine_name} database...")
            
            # Get schema file path
            schema_file = os.path.join(self.schemas_dir, f"{engine_name}_schema.sql")
            
            if not os.path.exists(schema_file):
                logger.error(f"Schema file not found: {schema_file}")
                return False
            
            # Create connection
            connection = await create_single_connection(engine_name)
            
            # Read schema file
            with open(schema_file, 'r') as f:
                schema_sql = f.read()
            
            # Split into statements and execute
            statements = self._split_sql_statements(schema_sql)
            
            for i, statement in enumerate(statements):
                if statement.strip():
                    try:
                        await connection.execute(statement)
                        logger.debug(f"Executed statement {i+1}/{len(statements)}")
                    except Exception as e:
                        logger.error(f"Failed to execute statement {i+1}: {e}")
                        if not force:
                            await connection.disconnect()
                            return False
            
            await connection.disconnect()
            logger.info(f"✅ {engine_name} database initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize {engine_name} database: {e}")
            return False
    
    async def initialize_all_databases(self, force: bool = False) -> Dict[str, bool]:
        """Initialize all engine databases"""
        logger.info("Initializing all engine databases...")
        results = {}
        
        for engine in self.engines:
            results[engine] = await self.initialize_engine_database(engine, force)
        
        # Summary
        successful = sum(1 for success in results.values() if success)
        total = len(results)
        
        logger.info(f"Database initialization complete: {successful}/{total} successful")
        return results
    
    async def check_database_connections(self) -> Dict[str, bool]:
        """Check connectivity to all engine databases"""
        logger.info("Checking database connections...")
        results = {}
        
        for engine in self.engines:
            try:
                connection = await create_single_connection(engine)
                health = await connection.health_check()
                await connection.disconnect()
                results[engine] = health
                logger.info(f"✅ {engine}: Connected" if health else f"❌ {engine}: Connection failed")
            except Exception as e:
                results[engine] = False
                logger.error(f"❌ {engine}: {e}")
        
        return results
    
    def _split_sql_statements(self, sql_content: str) -> List[str]:
        """Split SQL content into individual statements"""
        # Remove comments and split by semicolon
        lines = sql_content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Remove comments
            if '--' in line:
                line = line[:line.index('--')]
            line = line.strip()
            if line:
                cleaned_lines.append(line)
        
        # Join and split by semicolon
        full_sql = ' '.join(cleaned_lines)
        statements = [stmt.strip() for stmt in full_sql.split(';') if stmt.strip()]
        
        return statements
    
    async def get_migration_status(self, engine_name: str) -> Dict[str, Any]:
        """Get migration status for specific engine"""
        try:
            connection = await create_single_connection(engine_name)
            
            # Check if basic tables exist
            table_check_queries = {
                "configscan": ["customers", "tenants", "scans", "discoveries"],
                "compliance": ["customers", "tenants", "rules", "results"],
                "inventory": ["customers", "tenants", "assets", "relationships"],
                "threat": ["customers", "tenants", "threats", "incidents"],
                "shared": ["customers", "tenants", "audit_logs"]
            }
            
            tables_to_check = table_check_queries.get(engine_name, ["customers", "tenants"])
            table_status = {}
            
            for table in tables_to_check:
                try:
                    await connection.execute(f"SELECT 1 FROM {table} LIMIT 1")
                    table_status[table] = True
                except Exception:
                    table_status[table] = False
            
            await connection.disconnect()
            
            return {
                "engine": engine_name,
                "connected": True,
                "tables": table_status,
                "initialized": all(table_status.values())
            }
            
        except Exception as e:
            return {
                "engine": engine_name,
                "connected": False,
                "error": str(e),
                "initialized": False
            }


async def run_migrations(engine_name: str = None, force: bool = False) -> None:
    """Run database migrations"""
    runner = DatabaseMigrationRunner()
    
    if engine_name:
        if engine_name not in runner.engines:
            logger.error(f"Unknown engine: {engine_name}. Available: {runner.engines}")
            return
        
        success = await runner.initialize_engine_database(engine_name, force)
        if success:
            logger.info(f"✅ Migration completed for {engine_name}")
        else:
            logger.error(f"❌ Migration failed for {engine_name}")
    else:
        results = await runner.initialize_all_databases(force)
        successful = [engine for engine, success in results.items() if success]
        failed = [engine for engine, success in results.items() if not success]
        
        if successful:
            logger.info(f"✅ Successful migrations: {', '.join(successful)}")
        if failed:
            logger.error(f"❌ Failed migrations: {', '.join(failed)}")


async def get_migration_status(engine_name: str = None) -> Dict[str, Any]:
    """Get migration status"""
    runner = DatabaseMigrationRunner()
    
    if engine_name:
        return await runner.get_migration_status(engine_name)
    else:
        results = {}
        for engine in runner.engines:
            results[engine] = await runner.get_migration_status(engine)
        return results


def main():
    """Command line interface for migrations"""
    parser = argparse.ArgumentParser(description="Database Migration Runner")
    parser.add_argument("--engine", choices=["configscan", "compliance", "inventory", "threat", "shared", "all"], 
                       help="Specific engine to migrate (default: all)")
    parser.add_argument("--force", action="store_true", 
                       help="Continue migration even if some statements fail")
    parser.add_argument("--status", action="store_true", 
                       help="Show migration status")
    parser.add_argument("--check-connections", action="store_true",
                       help="Check database connections")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    async def run():
        if args.check_connections:
            runner = DatabaseMigrationRunner()
            await runner.check_database_connections()
        elif args.status:
            engine = args.engine if args.engine != "all" else None
            status = await get_migration_status(engine)
            print("Migration Status:")
            if isinstance(status, dict) and "engine" in status:
                # Single engine status
                print(f"  {status['engine']}: {'✅ Initialized' if status['initialized'] else '❌ Not initialized'}")
            else:
                # Multiple engines status
                for engine, info in status.items():
                    print(f"  {engine}: {'✅ Initialized' if info['initialized'] else '❌ Not initialized'}")
        else:
            engine = args.engine if args.engine != "all" else None
            await run_migrations(engine, args.force)
    
    asyncio.run(run())


if __name__ == "__main__":
    main()