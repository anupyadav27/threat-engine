"""
Database Configuration Management
Handles database connections and credentials for engine_secops
Copied from consolidated_services for self-contained deployment
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


class DatabaseSettings(BaseSettings):
    """Database settings for secops engine"""
    
    # Shared Database (secops uses shared DB)
    shared_host: str = Field(default="localhost", env="SHARED_DB_HOST")
    shared_port: int = Field(default=5432, env="SHARED_DB_PORT")
    shared_database: str = Field(default="threat_engine_shared", env="SHARED_DB_NAME")
    shared_username: str = Field(default="shared_user", env="SHARED_DB_USER")
    shared_password: str = Field(default="shared_password", env="SHARED_DB_PASSWORD")
    
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
    
    def get_shared_config(self) -> DatabaseConnectionConfig:
        """Get shared database configuration"""
        return DatabaseConnectionConfig(
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
        )


# Global settings instance
db_settings = DatabaseSettings()


def get_database_config(engine_name: str = "shared") -> DatabaseConnectionConfig:
    """Get database configuration for secops engine (uses shared DB)"""
    if engine_name != "shared":
        raise ValueError(f"SecOps engine only supports 'shared' database, got: {engine_name}")
    return db_settings.get_shared_config()


def get_shared_config() -> DatabaseConnectionConfig:
    """Get shared database configuration"""
    return db_settings.get_shared_config()
