"""
Neo4j Graph Database Connection Implementation
"""

from typing import Any, Dict, List, Optional
import logging

from .base_connection import BaseDatabaseConnection
from ..config.database_config import Neo4jConnectionConfig

logger = logging.getLogger(__name__)


class Neo4jConnection(BaseDatabaseConnection):
    """Neo4j graph database connection implementation"""
    
    def __init__(self, config: Neo4jConnectionConfig):
        super().__init__(config)
        self._driver = None
        self._session = None
    
    async def connect(self) -> None:
        """Establish Neo4j connection (async wrapper for sync driver)"""
        try:
            import asyncio
            # Run sync driver creation in executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._connect_sync)
        except Exception as e:
            self.logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def _connect_sync(self) -> None:
        """Synchronous Neo4j connection (called from async connect)"""
        try:
            from neo4j import GraphDatabase
            self.logger.info(f"Connecting to Neo4j: {self.config.uri}")
            self._driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.username, self.config.password),
                max_connection_lifetime=self.config.max_connection_lifetime,
                max_connection_pool_size=self.config.max_connection_pool_size
            )
            # Verify connection
            self._driver.verify_connectivity()
            self.logger.info("Neo4j connection established successfully")
        except ImportError:
            raise ImportError("neo4j package not installed. Install with: pip install neo4j")
    
    async def disconnect(self) -> None:
        """Close Neo4j connection (async wrapper for sync driver)"""
        try:
            import asyncio
            if self._driver:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, self._disconnect_sync)
        except Exception as e:
            self.logger.error(f"Error closing Neo4j connection: {e}")
    
    def _disconnect_sync(self) -> None:
        """Synchronous Neo4j disconnection"""
        if self._session:
            self._session.close()
            self._session = None
        
        if self._driver:
            self._driver.close()
            self._driver = None
            self.logger.info("Neo4j connection closed")
    
    def get_driver(self):
        """Get Neo4j driver instance (synchronous)"""
        if self._driver is None:
            raise RuntimeError("Neo4j driver not initialized. Call connect() first.")
        return self._driver
    
    def get_session(self, database: Optional[str] = None):
        """Get Neo4j session (synchronous)"""
        if self._driver is None:
            raise RuntimeError("Neo4j driver not initialized. Call connect() first.")
        db = database or self.config.database
        return self._driver.session(database=db)
    
    async def execute(self, query: str, *args) -> Any:
        """Execute a Cypher query (async wrapper)"""
        try:
            import asyncio
            if self._driver is None:
                await self.connect()
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._execute_sync, query, *args)
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            raise
    
    def _execute_sync(self, query: str, *args) -> Any:
        """Synchronous Cypher query execution"""
        db = self.config.database
        with self._driver.session(database=db) as session:
            if args:
                result = session.run(query, *args)
            else:
                result = session.run(query)
            return result.consume()
    
    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Fetch single record (async wrapper)"""
        try:
            import asyncio
            if self._driver is None:
                await self.connect()
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._fetch_one_sync, query, *args)
        except Exception as e:
            self.logger.error(f"Fetch one failed: {e}")
            raise
    
    def _fetch_one_sync(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Synchronous fetch one"""
        db = self.config.database
        with self._driver.session(database=db) as session:
            if args:
                result = session.run(query, *args)
            else:
                result = session.run(query)
            record = result.single()
            return dict(record) if record else None
    
    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        """Fetch all records (async wrapper)"""
        try:
            import asyncio
            if self._driver is None:
                await self.connect()
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._fetch_all_sync, query, *args)
        except Exception as e:
            self.logger.error(f"Fetch all failed: {e}")
            raise
    
    def _fetch_all_sync(self, query: str, *args) -> List[Dict[str, Any]]:
        """Synchronous fetch all"""
        db = self.config.database
        with self._driver.session(database=db) as session:
            if args:
                result = session.run(query, *args)
            else:
                result = session.run(query)
            return [dict(record) for record in result]
    
    async def fetch_val(self, query: str, *args) -> Any:
        """Fetch single value"""
        try:
            record = await self.fetch_one(query, *args)
            if record:
                return list(record.values())[0] if record.values() else None
            return None
        except Exception as e:
            self.logger.error(f"Fetch value failed: {e}")
            raise
    
    async def begin_transaction(self):
        """Begin Neo4j transaction"""
        if self._driver is None:
            await self.connect()
        db = self.config.database
        self._session = self._driver.session(database=db)
        return self._session.begin_transaction()
    
    async def commit_transaction(self):
        """Commit Neo4j transaction"""
        if self._session:
            self._session.commit()
            await self._session.close()
            self._session = None
    
    async def rollback_transaction(self):
        """Rollback Neo4j transaction"""
        if self._session:
            self._session.rollback()
            await self._session.close()
            self._session = None
    
    @property
    def is_connected(self) -> bool:
        """Check if connection is active"""
        if self._driver is None:
            return False
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False
    
    async def health_check(self) -> bool:
        """Perform health check on Neo4j connection"""
        try:
            import asyncio
            if self._driver is None:
                await self.connect()
            
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._driver.verify_connectivity)
        except Exception as e:
            self.logger.error(f"Neo4j health check failed: {e}")
            return False
