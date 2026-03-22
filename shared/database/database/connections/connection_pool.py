"""
Connection Pool Management for Consolidated Services
"""

import asyncio
from typing import Dict, Optional
import logging

from .postgres_connection import PostgreSQLConnection
from ..config.database_config import get_database_config

logger = logging.getLogger(__name__)


class ConnectionPoolManager:
    """Manages connection pools for all engines"""
    
    def __init__(self):
        self._pools: Dict[str, PostgreSQLConnection] = {}
        self._engines = ["configscan", "compliance", "inventory", "threat", "shared"]
    
    async def initialize_pools(self):
        """Initialize connection pools for all engines"""
        logger.info("Initializing database connection pools")
        
        for engine in self._engines:
            try:
                config = get_database_config(engine)
                connection = PostgreSQLConnection(config)
                await connection.create_pool()
                self._pools[engine] = connection
                logger.info(f"Connection pool initialized for {engine} engine")
            except Exception as e:
                logger.error(f"Failed to initialize connection pool for {engine}: {e}")
                # Continue with other engines even if one fails
    
    async def get_connection(self, engine_name: str) -> PostgreSQLConnection:
        """Get connection for specific engine"""
        if engine_name not in self._pools:
            # Lazy initialization if pool doesn't exist
            try:
                config = get_database_config(engine_name)
                connection = PostgreSQLConnection(config)
                await connection.create_pool()
                self._pools[engine_name] = connection
                logger.info(f"Lazy-initialized connection pool for {engine_name}")
            except Exception as e:
                logger.error(f"Failed to create connection pool for {engine_name}: {e}")
                raise
        
        return self._pools[engine_name]
    
    async def close_all_pools(self):
        """Close all connection pools"""
        logger.info("Closing all database connection pools")
        
        for engine, connection in self._pools.items():
            try:
                await connection.disconnect()
                logger.info(f"Closed connection pool for {engine}")
            except Exception as e:
                logger.error(f"Error closing connection pool for {engine}: {e}")
        
        self._pools.clear()
    
    async def health_check_all(self) -> Dict[str, bool]:
        """Perform health check on all connection pools"""
        results = {}
        
        for engine, connection in self._pools.items():
            try:
                results[engine] = await connection.health_check()
            except Exception as e:
                logger.error(f"Health check failed for {engine}: {e}")
                results[engine] = False
        
        return results
    
    def get_pool_status(self) -> Dict[str, Dict[str, any]]:
        """Get status of all connection pools"""
        status = {}
        
        for engine, connection in self._pools.items():
            status[engine] = {
                "connected": connection.is_connected,
                "database": connection.config.database,
                "host": connection.config.host,
                "port": connection.config.port,
                "pool_size": connection.config.pool_size
            }
        
        return status


# Global connection pool manager
_pool_manager: Optional[ConnectionPoolManager] = None


async def get_pool_manager() -> ConnectionPoolManager:
    """Get or create global connection pool manager"""
    global _pool_manager
    
    if _pool_manager is None:
        _pool_manager = ConnectionPoolManager()
        await _pool_manager.initialize_pools()
    
    return _pool_manager


async def close_pool_manager():
    """Close global connection pool manager"""
    global _pool_manager
    
    if _pool_manager:
        await _pool_manager.close_all_pools()
        _pool_manager = None