"""
Centralized Database Connection Management
"""

from .connection_factory import (
    get_configscan_connection,
    get_compliance_connection,
    get_inventory_connection,
    get_threat_connection,
    get_shared_connection,
    get_engine_connection,
    close_all_connections
)

from .postgres_connection import PostgreSQLConnection
from .neo4j_connection import Neo4jConnection
from .neo4j_graph_loader import Neo4jGraphLoader
from .connection_pool import ConnectionPoolManager

__all__ = [
    # Connection factory functions
    'get_configscan_connection',
    'get_compliance_connection', 
    'get_inventory_connection',
    'get_threat_connection',
    'get_shared_connection',
    'get_engine_connection',
    'get_neo4j_connection',
    'close_all_connections',
    
    # Connection classes
    'PostgreSQLConnection',
    'Neo4jConnection',
    'Neo4jGraphLoader',
    'ConnectionPoolManager',
]