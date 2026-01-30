"""
Database Configuration Management
Handles database connections and credentials for engine_inventory
Uses environment variables directly (no pydantic_settings dependency)
"""
import os
from typing import Dict, Optional, Any


class DatabaseConnectionConfig:
    """Database connection configuration"""
    def __init__(self, host: str, port: int, database: str, username: str, password: str,
                 ssl_mode: str = "prefer", pool_size: int = 10, max_overflow: int = 20,
                 pool_timeout: int = 30, pool_recycle: int = 3600):
        self.host = host
        self.port = port
        self.database = database
        self.username = username
        self.password = password
        self.ssl_mode = ssl_mode
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
    
    @property
    def connection_string(self) -> str:
        """Get PostgreSQL connection string"""
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


class Neo4jConnectionConfig:
    """Neo4j connection configuration"""
    def __init__(self, uri: str, username: str, password: str, database: str = "neo4j",
                 max_connection_lifetime: int = 3600, max_connection_pool_size: int = 50):
        self.uri = uri
        self.username = username
        self.password = password
        self.database = database
        self.max_connection_lifetime = max_connection_lifetime
        self.max_connection_pool_size = max_connection_pool_size
    
    @property
    def connection_string(self) -> str:
        """Get Neo4j connection URI"""
        return self.uri


def get_database_config(engine_name: str = "inventory") -> DatabaseConnectionConfig:
    """Get database configuration for inventory engine from environment variables"""
    if engine_name != "inventory":
        raise ValueError(f"Inventory engine only supports 'inventory' database, got: {engine_name}")
    
    return DatabaseConnectionConfig(
        host=os.getenv("INVENTORY_DB_HOST", "localhost"),
        port=int(os.getenv("INVENTORY_DB_PORT", "5432")),
        database=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        username=os.getenv("INVENTORY_DB_USER", "inventory_user"),
        password=os.getenv("INVENTORY_DB_PASSWORD", "inventory_password"),
        ssl_mode=os.getenv("DB_SSL_MODE", "prefer"),
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "3600")),
    )


def get_inventory_config() -> DatabaseConnectionConfig:
    """Get inventory database configuration"""
    return get_database_config("inventory")


def get_neo4j_config() -> Neo4jConnectionConfig:
    """Get Neo4j database configuration"""
    return Neo4jConnectionConfig(
        uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
        username=os.getenv("NEO4J_USERNAME", "neo4j"),
        password=os.getenv("NEO4J_PASSWORD", "neo4j"),
        database=os.getenv("NEO4J_DATABASE", "neo4j"),
        max_connection_lifetime=int(os.getenv("NEO4J_MAX_CONNECTION_LIFETIME", "3600")),
        max_connection_pool_size=int(os.getenv("NEO4J_MAX_CONNECTION_POOL_SIZE", "50")),
    )
