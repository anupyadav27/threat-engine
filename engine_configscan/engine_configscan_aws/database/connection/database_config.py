"""
Database Configuration Management
Handles database connections and credentials for engine_configscan_aws
Copied from consolidated_services for self-contained deployment
"""
import os
from typing import Dict, Optional, Any
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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


class DatabaseSettings(BaseSettings):
    """Database settings for configscan engine"""

    # pydantic-settings v2 configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    # ConfigScan Database (explicit env var bindings)
    configscan_host: str = Field(default="localhost", validation_alias="CONFIGSCAN_DB_HOST")
    configscan_port: int = Field(default=5432, validation_alias="CONFIGSCAN_DB_PORT")
    configscan_database: str = Field(default="threat_engine_configscan", validation_alias="CONFIGSCAN_DB_NAME")
    configscan_username: str = Field(default="configscan_user", validation_alias="CONFIGSCAN_DB_USER")
    configscan_password: str = Field(default="configscan_password", validation_alias="CONFIGSCAN_DB_PASSWORD")

    # Connection Pool Settings
    pool_size: int = Field(default=10, validation_alias="DB_POOL_SIZE")
    max_overflow: int = Field(default=20, validation_alias="DB_MAX_OVERFLOW")
    pool_timeout: int = Field(default=30, validation_alias="DB_POOL_TIMEOUT")
    pool_recycle: int = Field(default=3600, validation_alias="DB_POOL_RECYCLE")

    # General Settings
    ssl_mode: str = Field(default="prefer", validation_alias="DB_SSL_MODE")
    connection_timeout: int = Field(default=30, validation_alias="DB_CONNECTION_TIMEOUT")
    
    def get_configscan_config(self) -> DatabaseConnectionConfig:
        """Get configscan database configuration"""
        return DatabaseConnectionConfig(
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
        )


# Global settings instance
db_settings = DatabaseSettings()


def get_database_config(engine_name: str = "configscan") -> DatabaseConnectionConfig:
    """Get database configuration for configscan engine"""
    if engine_name != "configscan":
        raise ValueError(f"ConfigScan engine only supports 'configscan' database, got: {engine_name}")
    return db_settings.get_configscan_config()


def get_connection_string(engine_name: str = "configscan") -> str:
    """Get connection string for configscan engine"""
    return get_database_config(engine_name).connection_string


def get_async_connection_string(engine_name: str = "configscan") -> str:
    """Get async connection string for configscan engine"""
    return get_database_config(engine_name).async_connection_string


def get_configscan_config() -> DatabaseConnectionConfig:
    """Get configscan database configuration"""
    return db_settings.get_configscan_config()
