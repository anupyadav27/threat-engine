"""
Database Connection Factory
Provides easy access to database connections for all engines
"""

from typing import Optional
import logging

from .postgres_connection import PostgreSQLConnection
from .neo4j_connection import Neo4jConnection
from .connection_pool import get_pool_manager, close_pool_manager
from ..config.database_config import get_database_config, get_neo4j_config
import asyncio

logger = logging.getLogger(__name__)


async def get_engine_connection(engine_name: str) -> PostgreSQLConnection:
    """Get database connection for specific engine"""
    try:
        pool_manager = await get_pool_manager()
        return await pool_manager.get_connection(engine_name)
    except Exception as e:
        logger.error(f"Failed to get connection for {engine_name}: {e}")
        raise


async def get_configscan_connection() -> PostgreSQLConnection:
    """Get ConfigScan database connection"""
    return await get_engine_connection("configscan")


async def get_compliance_connection() -> PostgreSQLConnection:
    """Get Compliance database connection"""
    return await get_engine_connection("compliance")


async def get_inventory_connection() -> PostgreSQLConnection:
    """Get Inventory database connection"""
    return await get_engine_connection("inventory")


async def get_threat_connection() -> PostgreSQLConnection:
    """Get Threat database connection"""
    return await get_engine_connection("threat")


async def get_shared_connection() -> PostgreSQLConnection:
    """Get Shared database connection"""
    return await get_engine_connection("shared")


async def close_all_connections():
    """Close all database connections"""
    await close_pool_manager()


# Convenience function for creating new single connections (not pooled)
async def create_single_connection(engine_name: str) -> PostgreSQLConnection:
    """Create a new single database connection (not from pool)"""
    config = get_database_config(engine_name)
    connection = PostgreSQLConnection(config)
    await connection.connect()
    return connection


# Health check functions
async def check_engine_health(engine_name: str) -> bool:
    """Check health of specific engine database"""
    try:
        connection = await get_engine_connection(engine_name)
        return await connection.health_check()
    except Exception as e:
        logger.error(f"Health check failed for {engine_name}: {e}")
        return False


async def check_all_engines_health() -> dict:
    """Check health of all engine databases"""
    engines = ["configscan", "compliance", "inventory", "threat", "shared"]
    results = {}
    
    for engine in engines:
        results[engine] = await check_engine_health(engine)
    
    return results


# Database initialization functions
async def initialize_engine_database(engine_name: str, schema_file: Optional[str] = None):
    """Initialize database for specific engine"""
    try:
        connection = await create_single_connection(engine_name)
        
        if schema_file:
            # Read and execute schema file
            with open(schema_file, 'r') as f:
                schema_sql = f.read()
            
            # Split and execute statements
            statements = [stmt.strip() for stmt in schema_sql.split(';') if stmt.strip()]
            
            for statement in statements:
                if statement:
                    await connection.execute(statement)
            
            logger.info(f"Database initialized for {engine_name} using {schema_file}")
        else:
            logger.warning(f"No schema file provided for {engine_name}")
        
        await connection.disconnect()
        
    except Exception as e:
        logger.error(f"Failed to initialize database for {engine_name}: {e}")
        raise


async def initialize_configscan_database():
    """Initialize ConfigScan database with proven schema"""
    import os
    schema_path = os.path.join(
        os.path.dirname(__file__), 
        "..", "..", "schemas", "configscan_schema.sql"
    )
    await initialize_engine_database("configscan", schema_path)


# Neo4j connection functions
async def get_neo4j_connection() -> Neo4jConnection:
    """Get Neo4j graph database connection"""
    try:
        config = get_neo4j_config()
        connection = Neo4jConnection(config)
        await connection.connect()
        return connection
    except Exception as e:
        logger.error(f"Failed to get Neo4j connection: {e}")
        raise


async def check_neo4j_health() -> bool:
    """Check health of Neo4j connection"""
    try:
        connection = await get_neo4j_connection()
        health = await connection.health_check()
        await connection.disconnect()
        return health
    except Exception as e:
        logger.error(f"Neo4j health check failed: {e}")
        return False