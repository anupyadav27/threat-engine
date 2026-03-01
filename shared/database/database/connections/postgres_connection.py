"""
PostgreSQL Database Connection Implementation
"""

import asyncio
import asyncpg
from typing import Any, Dict, List, Optional
from contextlib import asynccontextmanager
import logging

from .base_connection import BaseDatabaseConnection
from ..config.database_config import DatabaseConnectionConfig

logger = logging.getLogger(__name__)


class PostgreSQLConnection(BaseDatabaseConnection):
    """PostgreSQL database connection implementation"""
    
    def __init__(self, config: DatabaseConnectionConfig):
        super().__init__(config)
        self._connection: Optional[asyncpg.Connection] = None
        self._pool: Optional[asyncpg.Pool] = None
        self._transaction = None
    
    async def connect(self) -> None:
        """Establish PostgreSQL connection"""
        try:
            self.logger.info(f"Connecting to PostgreSQL database: {self.config.database}")
            self._connection = await asyncpg.connect(
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.username,
                password=self.config.password,
                timeout=30
            )
            self.logger.info("PostgreSQL connection established successfully")
        except Exception as e:
            self.logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise
    
    async def create_pool(self) -> None:
        """Create connection pool"""
        try:
            self.logger.info(f"Creating PostgreSQL connection pool for: {self.config.database}")
            self._pool = await asyncpg.create_pool(
                host=self.config.host,
                port=self.config.port,
                database=self.config.database,
                user=self.config.username,
                password=self.config.password,
                min_size=1,
                max_size=self.config.pool_size,
                max_queries=50000,
                max_inactive_connection_lifetime=300,
                timeout=self.config.pool_timeout,
                command_timeout=60
            )
            self.logger.info("PostgreSQL connection pool created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create PostgreSQL connection pool: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close PostgreSQL connection"""
        try:
            if self._transaction:
                await self._transaction.rollback()
                self._transaction = None
            
            if self._connection:
                await self._connection.close()
                self._connection = None
                self.logger.info("PostgreSQL connection closed")
            
            if self._pool:
                await self._pool.close()
                self._pool = None
                self.logger.info("PostgreSQL connection pool closed")
        except Exception as e:
            self.logger.error(f"Error closing PostgreSQL connection: {e}")
    
    async def execute(self, query: str, *args) -> Any:
        """Execute a query"""
        try:
            if self._pool:
                async with self._pool.acquire() as conn:
                    return await conn.execute(query, *args)
            elif self._connection:
                return await self._connection.execute(query, *args)
            else:
                raise RuntimeError("No database connection available")
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            raise
    
    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Fetch single row"""
        try:
            if self._pool:
                async with self._pool.acquire() as conn:
                    row = await conn.fetchrow(query, *args)
                    return dict(row) if row else None
            elif self._connection:
                row = await self._connection.fetchrow(query, *args)
                return dict(row) if row else None
            else:
                raise RuntimeError("No database connection available")
        except Exception as e:
            self.logger.error(f"Fetch one failed: {e}")
            raise
    
    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        """Fetch all rows"""
        try:
            if self._pool:
                async with self._pool.acquire() as conn:
                    rows = await conn.fetch(query, *args)
                    return [dict(row) for row in rows]
            elif self._connection:
                rows = await self._connection.fetch(query, *args)
                return [dict(row) for row in rows]
            else:
                raise RuntimeError("No database connection available")
        except Exception as e:
            self.logger.error(f"Fetch all failed: {e}")
            raise
    
    async def fetch_val(self, query: str, *args) -> Any:
        """Fetch single value"""
        try:
            if self._pool:
                async with self._pool.acquire() as conn:
                    return await conn.fetchval(query, *args)
            elif self._connection:
                return await self._connection.fetchval(query, *args)
            else:
                raise RuntimeError("No database connection available")
        except Exception as e:
            self.logger.error(f"Fetch val failed: {e}")
            raise
    
    async def begin_transaction(self):
        """Begin database transaction"""
        try:
            if self._pool:
                # For pool, we need to acquire a connection and start transaction
                conn = await self._pool.acquire()
                self._transaction = conn.transaction()
                await self._transaction.start()
                return conn
            elif self._connection:
                self._transaction = self._connection.transaction()
                await self._transaction.start()
                return self._connection
            else:
                raise RuntimeError("No database connection available")
        except Exception as e:
            self.logger.error(f"Begin transaction failed: {e}")
            raise
    
    async def commit_transaction(self):
        """Commit database transaction"""
        try:
            if self._transaction:
                await self._transaction.commit()
                self._transaction = None
        except Exception as e:
            self.logger.error(f"Commit transaction failed: {e}")
            raise
    
    async def rollback_transaction(self):
        """Rollback database transaction"""
        try:
            if self._transaction:
                await self._transaction.rollback()
                self._transaction = None
        except Exception as e:
            self.logger.error(f"Rollback transaction failed: {e}")
            raise
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is active"""
        if self._pool:
            return not self._pool._closed
        elif self._connection:
            return not self._connection.is_closed()
        return False
    
    async def health_check(self) -> bool:
        """Perform health check on connection"""
        try:
            result = await self.fetch_val("SELECT 1")
            return result == 1
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
    
    @asynccontextmanager
    async def transaction(self):
        """Async context manager for transactions"""
        conn = await self.begin_transaction()
        try:
            yield conn
            await self.commit_transaction()
        except Exception:
            await self.rollback_transaction()
            raise
        finally:
            if self._pool and isinstance(conn, asyncpg.Connection):
                await self._pool.release(conn)