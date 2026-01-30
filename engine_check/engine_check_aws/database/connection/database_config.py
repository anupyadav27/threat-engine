"""
Database Configuration Management for Check Engine
Uses environment variables directly (no pydantic dependency)
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
    
    @property
    def async_connection_string(self) -> str:
        """Get async PostgreSQL connection string"""
        return f"postgresql+asyncpg://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


def get_database_config(engine_name: str = "check") -> DatabaseConnectionConfig:
    """Get database configuration for check engine from environment variables"""
    if engine_name != "check":
        raise ValueError(f"Check engine only supports 'check' database, got: {engine_name}")
    
    return DatabaseConnectionConfig(
        host=os.getenv("CHECK_DB_HOST", "localhost"),
        port=int(os.getenv("CHECK_DB_PORT", "5432")),
        database=os.getenv("CHECK_DB_NAME", "threat_engine_check"),
        username=os.getenv("CHECK_DB_USER", "check_user"),
        password=os.getenv("CHECK_DB_PASSWORD", "check_password"),
        ssl_mode=os.getenv("DB_SSL_MODE", "prefer"),
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "3600")),
    )


def get_connection_string(engine_name: str = "check") -> str:
    """Get connection string for check engine"""
    return get_database_config(engine_name).connection_string


def get_async_connection_string(engine_name: str = "check") -> str:
    """Get async connection string for check engine"""
    return get_database_config(engine_name).async_connection_string


def get_connection_string(engine_name: str = "check") -> str:
    """Get connection string for check engine"""
    return get_database_config(engine_name).connection_string


def get_async_connection_string(engine_name: str = "check") -> str:
    """Get async connection string for check engine"""
    return get_database_config(engine_name).async_connection_string
