"""
Simple Database Configuration for Engine Integration
Provides easy database connection strings without complex dependencies
"""

import os
from typing import Dict


class SimpleDatabaseConfig:
    """Simple database configuration for engine integration"""
    
    # Centralized database connection strings
    DATABASES = {
        "configscan": {
            "host": os.getenv("CONFIGSCAN_DB_HOST", "localhost"),
            "port": int(os.getenv("CONFIGSCAN_DB_PORT", "5432")),
            "database": os.getenv("CONFIGSCAN_DB_NAME", "threat_engine_configscan"),
            "user": os.getenv("CONFIGSCAN_DB_USER", "configscan_user"),
            "password": os.getenv("CONFIGSCAN_DB_PASSWORD", "configscan_password"),
        },
        "compliance": {
            "host": os.getenv("COMPLIANCE_DB_HOST", "localhost"),
            "port": int(os.getenv("COMPLIANCE_DB_PORT", "5432")),
            "database": os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
            "user": os.getenv("COMPLIANCE_DB_USER", "compliance_user"), 
            "password": os.getenv("COMPLIANCE_DB_PASSWORD", "compliance_password"),
        },
        "inventory": {
            "host": os.getenv("INVENTORY_DB_HOST", "localhost"),
            "port": int(os.getenv("INVENTORY_DB_PORT", "5432")),
            "database": os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
            "user": os.getenv("INVENTORY_DB_USER", "inventory_user"),
            "password": os.getenv("INVENTORY_DB_PASSWORD", "inventory_password"),
        },
        "threat": {
            "host": os.getenv("THREAT_DB_HOST", "localhost"),
            "port": int(os.getenv("THREAT_DB_PORT", "5432")),
            "database": os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
            "user": os.getenv("THREAT_DB_USER", "threat_user"),
            "password": os.getenv("THREAT_DB_PASSWORD", "threat_password"),
        },
        "onboarding": {
            "host": os.getenv("ONBOARDING_DB_HOST", "localhost"),
            "port": int(os.getenv("ONBOARDING_DB_PORT", "5432")),
            "database": os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
            "user": os.getenv("ONBOARDING_DB_USER", "onboarding_user"),
            "password": os.getenv("ONBOARDING_DB_PASSWORD", "onboarding_password"),
        }
    }
    
    @classmethod
    def get_connection_config(cls, engine_name: str) -> Dict[str, any]:
        """Get database connection configuration for engine"""
        if engine_name not in cls.DATABASES:
            raise ValueError(f"Unknown engine: {engine_name}. Available: {list(cls.DATABASES.keys())}")
        
        return cls.DATABASES[engine_name].copy()
    
    @classmethod  
    def get_connection_string(cls, engine_name: str) -> str:
        """Get PostgreSQL connection string for engine"""
        config = cls.get_connection_config(engine_name)
        return f"postgresql://{config['user']}:{config['password']}@{config['host']}:{config['port']}/{config['database']}"
    
    @classmethod
    def get_database_url(cls, engine_name: str) -> str:
        """Get DATABASE_URL format for engine"""
        return cls.get_connection_string(engine_name)


def get_configscan_database_url() -> str:
    """Get ConfigScan database connection URL"""
    return SimpleDatabaseConfig.get_database_url("configscan")


def get_centralized_db_config(engine_name: str) -> Dict[str, any]:
    """Get centralized database configuration for any engine"""
    return SimpleDatabaseConfig.get_connection_config(engine_name)


# Environment variable for enabling centralized database
def use_centralized_database() -> bool:
    """Check if centralized database should be used"""
    return os.getenv("USE_CENTRALIZED_DB", "true").lower() == "true"


def is_centralized_db_configured(engine_name: str) -> bool:
    """Check if centralized database is properly configured for engine"""
    try:
        config = SimpleDatabaseConfig.get_connection_config(engine_name)
        return all(config.get(key) for key in ["host", "database", "user"])
    except (ValueError, KeyError):
        return False