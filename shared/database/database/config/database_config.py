"""
Centralized Database Configuration Management
Handles all database connections and credentials for consolidated services
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

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, populate_by_name=True)

    # Check Engine Database (check_results, rule_metadata)
    check_host: str = Field(default="localhost", validation_alias="CHECK_DB_HOST")
    check_port: int = Field(default=5432, validation_alias="CHECK_DB_PORT")
    check_database: str = Field(default="threat_engine_check", validation_alias="CHECK_DB_NAME")
    check_username: str = Field(default="check_user", validation_alias="CHECK_DB_USER")
    check_password: str = Field(default="check_password", validation_alias="CHECK_DB_PASSWORD")

    # Discovery Engine Database (discovery_report, discovery_findings, discovery_history)
    discoveries_host: str = Field(default="localhost", validation_alias="DISCOVERY_DB_HOST")
    discoveries_port: int = Field(default=5432, validation_alias="DISCOVERY_DB_PORT")
    discoveries_database: str = Field(default="threat_engine_discoveries", validation_alias="DISCOVERY_DB_NAME")
    discoveries_username: str = Field(default="discoveries_user", validation_alias="DISCOVERY_DB_USER")
    discoveries_password: str = Field(default="discoveries_password", validation_alias="DISCOVERY_DB_PASSWORD")

    # Compliance Database
    compliance_host: str = Field(default="localhost", validation_alias="COMPLIANCE_DB_HOST")
    compliance_port: int = Field(default=5432, validation_alias="COMPLIANCE_DB_PORT")
    compliance_database: str = Field(default="threat_engine_compliance", validation_alias="COMPLIANCE_DB_NAME")
    compliance_username: str = Field(default="compliance_user", validation_alias="COMPLIANCE_DB_USER")
    compliance_password: str = Field(default="compliance_password", validation_alias="COMPLIANCE_DB_PASSWORD")

    # Inventory Database
    inventory_host: str = Field(default="localhost", validation_alias="INVENTORY_DB_HOST")
    inventory_port: int = Field(default=5432, validation_alias="INVENTORY_DB_PORT")
    inventory_database: str = Field(default="threat_engine_inventory", validation_alias="INVENTORY_DB_NAME")
    inventory_username: str = Field(default="inventory_user", validation_alias="INVENTORY_DB_USER")
    inventory_password: str = Field(default="inventory_password", validation_alias="INVENTORY_DB_PASSWORD")

    # Threat Database
    threat_host: str = Field(default="localhost", validation_alias="THREAT_DB_HOST")
    threat_port: int = Field(default=5432, validation_alias="THREAT_DB_PORT")
    threat_database: str = Field(default="threat_engine_threat", validation_alias="THREAT_DB_NAME")
    threat_username: str = Field(default="threat_user", validation_alias="THREAT_DB_USER")
    threat_password: str = Field(default="threat_password", validation_alias="THREAT_DB_PASSWORD")

    # Onboarding Database (includes scan_orchestration table)
    onboarding_host: str = Field(default="localhost", validation_alias="ONBOARDING_DB_HOST")
    onboarding_port: int = Field(default=5432, validation_alias="ONBOARDING_DB_PORT")
    onboarding_database: str = Field(default="threat_engine_onboarding", validation_alias="ONBOARDING_DB_NAME")
    onboarding_username: str = Field(default="onboarding_user", validation_alias="ONBOARDING_DB_USER")
    onboarding_password: str = Field(default="onboarding_password", validation_alias="ONBOARDING_DB_PASSWORD")

    # Shared Database (for cross-engine data) - DEPRECATED: scan_orchestration moved to onboarding
    shared_host: str = Field(default="localhost", validation_alias="SHARED_DB_HOST")
    shared_port: int = Field(default=5432, validation_alias="SHARED_DB_PORT")
    shared_database: str = Field(default="threat_engine_shared", validation_alias="SHARED_DB_NAME")
    shared_username: str = Field(default="shared_user", validation_alias="SHARED_DB_USER")
    shared_password: str = Field(default="shared_password", validation_alias="SHARED_DB_PASSWORD")

    # IAM Database
    iam_host: str = Field(default="localhost", validation_alias="IAM_DB_HOST")
    iam_port: int = Field(default=5432, validation_alias="IAM_DB_PORT")
    iam_database: str = Field(default="threat_engine_iam", validation_alias="IAM_DB_NAME")
    iam_username: str = Field(default="iam_user", validation_alias="IAM_DB_USER")
    iam_password: str = Field(default="iam_password", validation_alias="IAM_DB_PASSWORD")

    # DataSec Database
    datasec_host: str = Field(default="localhost", validation_alias="DATASEC_DB_HOST")
    datasec_port: int = Field(default=5432, validation_alias="DATASEC_DB_PORT")
    datasec_database: str = Field(default="threat_engine_datasec", validation_alias="DATASEC_DB_NAME")
    datasec_username: str = Field(default="datasec_user", validation_alias="DATASEC_DB_USER")
    datasec_password: str = Field(default="datasec_password", validation_alias="DATASEC_DB_PASSWORD")

    # SecOps Database
    secops_host: str = Field(default="localhost", validation_alias="SECOPS_DB_HOST")
    secops_port: int = Field(default=5432, validation_alias="SECOPS_DB_PORT")
    secops_database: str = Field(default="threat_engine_secops", validation_alias="SECOPS_DB_NAME")
    secops_username: str = Field(default="secops_user", validation_alias="SECOPS_DB_USER")
    secops_password: str = Field(default="secops_password", validation_alias="SECOPS_DB_PASSWORD")

    # Neo4j Graph Database
    neo4j_uri: str = Field(default="bolt://localhost:7687", validation_alias="NEO4J_URI")
    neo4j_username: str = Field(default="neo4j", validation_alias="NEO4J_USERNAME")
    neo4j_password: str = Field(default="neo4j", validation_alias="NEO4J_PASSWORD")
    neo4j_database: str = Field(default="neo4j", validation_alias="NEO4J_DATABASE")
    neo4j_max_connection_lifetime: int = Field(default=3600, validation_alias="NEO4J_MAX_CONNECTION_LIFETIME")
    neo4j_max_connection_pool_size: int = Field(default=50, validation_alias="NEO4J_MAX_CONNECTION_POOL_SIZE")

    # Connection Pool Settings
    pool_size: int = Field(default=10, validation_alias="DB_POOL_SIZE")
    max_overflow: int = Field(default=20, validation_alias="DB_MAX_OVERFLOW")
    pool_timeout: int = Field(default=30, validation_alias="DB_POOL_TIMEOUT")
    pool_recycle: int = Field(default=3600, validation_alias="DB_POOL_RECYCLE")

    # General Settings
    ssl_mode: str = Field(default="prefer", validation_alias="DB_SSL_MODE")
    connection_timeout: int = Field(default=30, validation_alias="DB_CONNECTION_TIMEOUT")

    def get_engine_config(self, engine_name: str, use_secrets_manager: bool = None) -> DatabaseConnectionConfig:
        """
        Get database configuration for specific engine.

        Args:
            engine_name: Engine name (discoveries, check, inventory, threat, etc.)
            use_secrets_manager: Override to force secrets manager usage (default: auto-detect from env)

        Returns:
            DatabaseConnectionConfig with credentials from Secrets Manager or env vars
        """
        # Support aliases: "discoveries" → "discovery"
        aliases = {"discoveries": "discovery", "configscan": "check"}
        normalized_name = aliases.get(engine_name, engine_name)

        if normalized_name not in ["check", "discovery", "compliance", "inventory", "threat", "shared", "onboarding", "iam", "datasec", "secops"]:
            raise ValueError(f"Unknown engine: {engine_name}. Available: check, discovery, compliance, inventory, threat, shared, onboarding, iam, datasec, secops")

        # Get credentials from environment variables
        engine_map = {
            "check": {"host": self.check_host, "port": self.check_port, "database": self.check_database, "username": self.check_username, "password": self.check_password},
            "discovery": {"host": self.discoveries_host, "port": self.discoveries_port, "database": self.discoveries_database, "username": self.discoveries_username, "password": self.discoveries_password},
            "compliance": {"host": self.compliance_host, "port": self.compliance_port, "database": self.compliance_database, "username": self.compliance_username, "password": self.compliance_password},
            "inventory": {"host": self.inventory_host, "port": self.inventory_port, "database": self.inventory_database, "username": self.inventory_username, "password": self.inventory_password},
            "threat": {"host": self.threat_host, "port": self.threat_port, "database": self.threat_database, "username": self.threat_username, "password": self.threat_password},
            "onboarding": {"host": self.onboarding_host, "port": self.onboarding_port, "database": self.onboarding_database, "username": self.onboarding_username, "password": self.onboarding_password},
            "shared": {"host": self.shared_host, "port": self.shared_port, "database": self.shared_database, "username": self.shared_username, "password": self.shared_password},
            "iam": {"host": self.iam_host, "port": self.iam_port, "database": self.iam_database, "username": self.iam_username, "password": self.iam_password},
            "datasec": {"host": self.datasec_host, "port": self.datasec_port, "database": self.datasec_database, "username": self.datasec_username, "password": self.datasec_password},
            "secops": {"host": self.secops_host, "port": self.secops_port, "database": self.secops_database, "username": self.secops_username, "password": self.secops_password},
        }

        creds = engine_map[normalized_name]

        pool_defaults = dict(
            ssl_mode=self.ssl_mode,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout,
            pool_recycle=self.pool_recycle,
        )

        return DatabaseConnectionConfig(
            host=creds["host"],
            port=creds["port"],
            database=creds["database"],
            username=creds["username"],
            password=creds["password"],
            **pool_defaults,
        )

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
            "check": self.get_engine_config("check"),
            "discovery": self.get_engine_config("discovery"),
            "compliance": self.get_engine_config("compliance"),
            "inventory": self.get_engine_config("inventory"),
            "threat": self.get_engine_config("threat"),
            "onboarding": self.get_engine_config("onboarding"),
            "shared": self.get_engine_config("shared"),  # DEPRECATED
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
def get_check_config() -> DatabaseConnectionConfig:
    """Get Check Engine database configuration"""
    return db_settings.get_engine_config("check")


def get_configscan_config() -> DatabaseConnectionConfig:
    """
    Get ConfigScan database configuration.

    Note: ConfigScan is an alias for the Check engine database.
    This function is provided for backward compatibility and
    API consistency with the connection layer.

    Returns:
        DatabaseConnectionConfig: Check engine database configuration

    Example:
        >>> config = get_configscan_config()
        >>> print(config.database)  # 'threat_engine_check'
    """
    return db_settings.get_engine_config("configscan")


def get_discovery_config() -> DatabaseConnectionConfig:
    """Get Discovery Engine database configuration"""
    return db_settings.get_engine_config("discovery")


def get_compliance_config() -> DatabaseConnectionConfig:
    """Get Compliance database configuration"""
    return db_settings.get_engine_config("compliance")


def get_inventory_config() -> DatabaseConnectionConfig:
    """Get Inventory database configuration"""
    return db_settings.get_engine_config("inventory")


def get_threat_config() -> DatabaseConnectionConfig:
    """Get Threat database configuration"""
    return db_settings.get_engine_config("threat")


def get_onboarding_config() -> DatabaseConnectionConfig:
    """Get Onboarding database configuration (includes scan_orchestration)"""
    return db_settings.get_engine_config("onboarding")


def get_shared_config() -> DatabaseConnectionConfig:
    """Get Shared database configuration - DEPRECATED: scan_orchestration moved to onboarding"""
    return db_settings.get_engine_config("shared")


def get_neo4j_config() -> Neo4jConnectionConfig:
    """Get Neo4j database configuration"""
    return db_settings.get_neo4j_config()
