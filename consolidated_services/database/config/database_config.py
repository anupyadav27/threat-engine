"""
Centralized Database Configuration Management
Handles all database connections and credentials for consolidated services
"""

import os
from typing import Dict, Optional, Any
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class DatabaseConnectionConfig(BaseModel):
    """Database connection configuration"""
    host: str
    port: int = 5432
    database: str
    username: str
    password: str
    ssl_mode: str = "prefer"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    
    @property
    def connection_string(self) -> str:
        """Get PostgreSQL connection string"""
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
    
    @property
    def async_connection_string(self) -> str:
        """Get async PostgreSQL connection string"""
        return f"postgresql+asyncpg://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


class Neo4jConnectionConfig(BaseModel):
    """Neo4j connection configuration"""
    uri: str
    username: str
    password: str
    database: str = "neo4j"  # Neo4j database name (default is "neo4j")
    max_connection_lifetime: int = 3600  # seconds
    max_connection_pool_size: int = 50
    
    @property
    def connection_string(self) -> str:
        """Get Neo4j connection URI"""
        return self.uri


class ConsolidatedDatabaseSettings(BaseSettings):
    """Centralized database settings for all engines"""
    
    # ConfigScan Database
    configscan_host: str = Field(default="localhost", env="CONFIGSCAN_DB_HOST")
    configscan_port: int = Field(default=5432, env="CONFIGSCAN_DB_PORT")
    configscan_database: str = Field(default="threat_engine_configscan", env="CONFIGSCAN_DB_NAME")
    configscan_username: str = Field(default="configscan_user", env="CONFIGSCAN_DB_USER")
    configscan_password: str = Field(default="configscan_password", env="CONFIGSCAN_DB_PASSWORD")
    
    # Compliance Database
    compliance_host: str = Field(default="localhost", env="COMPLIANCE_DB_HOST")
    compliance_port: int = Field(default=5432, env="COMPLIANCE_DB_PORT")
    compliance_database: str = Field(default="threat_engine_compliance", env="COMPLIANCE_DB_NAME")
    compliance_username: str = Field(default="compliance_user", env="COMPLIANCE_DB_USER")
    compliance_password: str = Field(default="compliance_password", env="COMPLIANCE_DB_PASSWORD")
    
    # Inventory Database
    inventory_host: str = Field(default="localhost", env="INVENTORY_DB_HOST")
    inventory_port: int = Field(default=5432, env="INVENTORY_DB_PORT")
    inventory_database: str = Field(default="threat_engine_inventory", env="INVENTORY_DB_NAME")
    inventory_username: str = Field(default="inventory_user", env="INVENTORY_DB_USER")
    inventory_password: str = Field(default="inventory_password", env="INVENTORY_DB_PASSWORD")
    
    # Threat Database
    threat_host: str = Field(default="localhost", env="THREAT_DB_HOST")
    threat_port: int = Field(default=5432, env="THREAT_DB_PORT")
    threat_database: str = Field(default="threat_engine_threat", env="THREAT_DB_NAME")
    threat_username: str = Field(default="threat_user", env="THREAT_DB_USER")
    threat_password: str = Field(default="threat_password", env="THREAT_DB_PASSWORD")
    
    # Shared Database (for cross-engine data)
    shared_host: str = Field(default="localhost", env="SHARED_DB_HOST")
    shared_port: int = Field(default=5432, env="SHARED_DB_PORT")
    shared_database: str = Field(default="threat_engine_shared", env="SHARED_DB_NAME")
    shared_username: str = Field(default="shared_user", env="SHARED_DB_USER")
    shared_password: str = Field(default="shared_password", env="SHARED_DB_PASSWORD")
    
    # Neo4j Graph Database
    neo4j_uri: str = Field(default="bolt://localhost:7687", env="NEO4J_URI")
    neo4j_username: str = Field(default="neo4j", env="NEO4J_USERNAME")
    neo4j_password: str = Field(default="neo4j", env="NEO4J_PASSWORD")
    neo4j_database: str = Field(default="neo4j", env="NEO4J_DATABASE")
    neo4j_max_connection_lifetime: int = Field(default=3600, env="NEO4J_MAX_CONNECTION_LIFETIME")
    neo4j_max_connection_pool_size: int = Field(default=50, env="NEO4J_MAX_CONNECTION_POOL_SIZE")
    
    # Connection Pool Settings
    pool_size: int = Field(default=10, env="DB_POOL_SIZE")
    max_overflow: int = Field(default=20, env="DB_MAX_OVERFLOW")
    pool_timeout: int = Field(default=30, env="DB_POOL_TIMEOUT")
    pool_recycle: int = Field(default=3600, env="DB_POOL_RECYCLE")
    
    # General Settings
    ssl_mode: str = Field(default="prefer", env="DB_SSL_MODE")
    connection_timeout: int = Field(default=30, env="DB_CONNECTION_TIMEOUT")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
    
    def get_engine_config(self, engine_name: str) -> DatabaseConnectionConfig:
        """Get database configuration for specific engine"""
        engine_configs = {
            "configscan": DatabaseConnectionConfig(
                host=self.configscan_host,
                port=self.configscan_port,
                database=self.configscan_database,
                username=self.configscan_username,
                password=self.configscan_password,
                ssl_mode=self.ssl_mode,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
            ),
            "compliance": DatabaseConnectionConfig(
                host=self.compliance_host,
                port=self.compliance_port,
                database=self.compliance_database,
                username=self.compliance_username,
                password=self.compliance_password,
                ssl_mode=self.ssl_mode,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
            ),
            "inventory": DatabaseConnectionConfig(
                host=self.inventory_host,
                port=self.inventory_port,
                database=self.inventory_database,
                username=self.inventory_username,
                password=self.inventory_password,
                ssl_mode=self.ssl_mode,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
            ),
            "threat": DatabaseConnectionConfig(
                host=self.threat_host,
                port=self.threat_port,
                database=self.threat_database,
                username=self.threat_username,
                password=self.threat_password,
                ssl_mode=self.ssl_mode,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
            ),
            "shared": DatabaseConnectionConfig(
                host=self.shared_host,
                port=self.shared_port,
                database=self.shared_database,
                username=self.shared_username,
                password=self.shared_password,
                ssl_mode=self.ssl_mode,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
            ),
        }
        
        if engine_name not in engine_configs:
            raise ValueError(f"Unknown engine: {engine_name}. Available: {list(engine_configs.keys())}")
        
        return engine_configs[engine_name]
    
    def get_neo4j_config(self) -> Neo4jConnectionConfig:
        """Get Neo4j database configuration"""
        return Neo4jConnectionConfig(
            uri=self.neo4j_uri,
            username=self.neo4j_username,
            password=self.neo4j_password,
            database=self.neo4j_database,
            max_connection_lifetime=self.neo4j_max_connection_lifetime,
            max_connection_pool_size=self.neo4j_max_connection_pool_size,
        )
    
    def get_all_engine_configs(self) -> Dict[str, DatabaseConnectionConfig]:
        """Get all engine database configurations"""
        return {
            "configscan": self.get_engine_config("configscan"),
            "compliance": self.get_engine_config("compliance"),
            "inventory": self.get_engine_config("inventory"),
            "threat": self.get_engine_config("threat"),
            "shared": self.get_engine_config("shared"),
        }


# Global settings instance
db_settings = ConsolidatedDatabaseSettings()


def get_database_config(engine_name: str) -> DatabaseConnectionConfig:
    """Get database configuration for specific engine"""
    return db_settings.get_engine_config(engine_name)


def get_connection_string(engine_name: str) -> str:
    """Get connection string for specific engine"""
    return get_database_config(engine_name).connection_string


def get_async_connection_string(engine_name: str) -> str:
    """Get async connection string for specific engine"""
    return get_database_config(engine_name).async_connection_string


# Convenience functions for each engine
def get_configscan_config() -> DatabaseConnectionConfig:
    """Get ConfigScan database configuration"""
    return db_settings.get_engine_config("configscan")


def get_compliance_config() -> DatabaseConnectionConfig:
    """Get Compliance database configuration"""
    return db_settings.get_engine_config("compliance")


def get_inventory_config() -> DatabaseConnectionConfig:
    """Get Inventory database configuration"""
    return db_settings.get_engine_config("inventory")


def get_threat_config() -> DatabaseConnectionConfig:
    """Get Threat database configuration"""
    return db_settings.get_engine_config("threat")


def get_shared_config() -> DatabaseConnectionConfig:
    """Get Shared database configuration"""
    return db_settings.get_engine_config("shared")


def get_neo4j_config() -> Neo4jConnectionConfig:
    """Get Neo4j database configuration"""
    return db_settings.get_neo4j_config()