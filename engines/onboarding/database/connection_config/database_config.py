"""
Database Configuration Management
Handles database connections and credentials for engine_onboarding
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
    
    @property
    def async_connection_string(self) -> str:
        """Get async PostgreSQL connection string"""
        return f"postgresql+asyncpg://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"


class DatabaseSettings(BaseSettings):
    """Database settings for onboarding engine"""
    
    # Shared Database (onboarding uses shared DB)
    shared_host: str = Field(default="host.docker.internal", env="SHARED_DB_HOST")
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
        env_prefix = ""  # No prefix needed
        # Ensure environment variables are read
        @classmethod
        def customise_sources(cls, init_settings, env_settings, file_secret_settings):
            # Prioritize environment variables
            return env_settings, init_settings, file_secret_settings
    
    def get_shared_config(self) -> DatabaseConnectionConfig:
        """Get database configuration. Prefers ONBOARDING_DB_* when set (onboarding DB with scan_orchestration)."""
        import os
        # Prefer onboarding DB env when present (EKS uses ONBOARDING_DB_* for threat_engine_onboarding)
        if os.getenv("ONBOARDING_DB_HOST"):
            return DatabaseConnectionConfig(
                host=os.getenv("ONBOARDING_DB_HOST"),
                port=int(os.getenv("ONBOARDING_DB_PORT", "5432")),
                database=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
                username=os.getenv("ONBOARDING_DB_USER", "postgres"),
                password=os.getenv("ONBOARDING_DB_PASSWORD", ""),
                ssl_mode=self.ssl_mode,
                pool_size=self.pool_size,
                max_overflow=self.max_overflow,
                pool_timeout=self.pool_timeout,
                pool_recycle=self.pool_recycle,
            )
        return DatabaseConnectionConfig(
            host=os.getenv('SHARED_DB_HOST', self.shared_host),
            port=int(os.getenv('SHARED_DB_PORT', str(self.shared_port))),
            database=os.getenv('SHARED_DB_NAME', self.shared_database),
            username=os.getenv('SHARED_DB_USER', self.shared_username),
            password=os.getenv('SHARED_DB_PASSWORD', self.shared_password),
            ssl_mode=self.ssl_mode,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout,
            pool_recycle=self.pool_recycle,
        )


# Global settings instance - create lazily to ensure env vars are loaded
_db_settings = None

def _get_settings() -> DatabaseSettings:
    """Lazy initialization of settings to ensure env vars are loaded"""
    global _db_settings
    if _db_settings is None:
        _db_settings = DatabaseSettings()
    return _db_settings

db_settings = property(lambda self: _get_settings())


def get_database_config(engine_name: str = "shared") -> DatabaseConnectionConfig:
    """Get database configuration for onboarding engine (uses shared DB)"""
    if engine_name != "shared":
        raise ValueError(f"Onboarding engine only supports 'shared' database, got: {engine_name}")
    return _get_settings().get_shared_config()


def get_connection_string(engine_name: str = "shared") -> str:
    """Get connection string for onboarding engine"""
    return get_database_config(engine_name).connection_string


def get_async_connection_string(engine_name: str = "shared") -> str:
    """Get async connection string for onboarding engine"""
    return get_database_config(engine_name).async_connection_string


def get_shared_config() -> DatabaseConnectionConfig:
    """Get shared database configuration"""
    return _get_settings().get_shared_config()
