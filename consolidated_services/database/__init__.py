"""
Consolidated Database Management

This package provides centralized database management for all engines in the threat-engine platform.

Quick Start:
-----------
from consolidated_services.database import get_configscan_connection

async def example():
    async with get_configscan_connection() as db:
        result = await db.fetch_all("SELECT * FROM scans LIMIT 10")
        return result

Available Engines:
-----------------
- configscan: Configuration scanning data
- compliance: Compliance checking and results
- inventory: Asset inventory and discovery
- threat: Threat detection and analysis
- shared: Cross-engine shared data
"""

from .connections import (
    get_configscan_connection,
    get_compliance_connection,
    get_inventory_connection, 
    get_threat_connection,
    get_shared_connection,
    get_engine_connection,
    close_all_connections,
    PostgreSQLConnection,
    ConnectionPoolManager
)

from .config import (
    get_database_config,
    get_connection_string,
    get_async_connection_string,
    get_configscan_config,
    get_compliance_config,
    get_inventory_config,
    get_threat_config,
    get_shared_config
)

__version__ = "1.0.0"

__all__ = [
    # Connection functions
    'get_configscan_connection',
    'get_compliance_connection',
    'get_inventory_connection',
    'get_threat_connection', 
    'get_shared_connection',
    'get_engine_connection',
    'close_all_connections',
    
    # Connection classes
    'PostgreSQLConnection',
    'ConnectionPoolManager',
    
    # Configuration functions
    'get_database_config',
    'get_connection_string',
    'get_async_connection_string',
    'get_configscan_config',
    'get_compliance_config',
    'get_inventory_config',
    'get_threat_config',
    'get_shared_config',
]