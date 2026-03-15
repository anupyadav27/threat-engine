"""
Base Database Connection Interface
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, AsyncContextManager
import logging

logger = logging.getLogger(__name__)


class BaseDatabaseConnection(ABC):
    """Abstract base class for database connections"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logger
        self._connection = None
        self._pool = None
    
    @abstractmethod
    async def connect(self) -> None:
        """Establish database connection"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Close database connection"""
        pass
    
    @abstractmethod
    async def execute(self, query: str, *args) -> Any:
        """Execute a query"""
        pass
    
    @abstractmethod
    async def fetch_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Fetch single row"""
        pass
    
    @abstractmethod
    async def fetch_all(self, query: str, *args) -> List[Dict[str, Any]]:
        """Fetch all rows"""
        pass
    
    @abstractmethod
    async def fetch_val(self, query: str, *args) -> Any:
        """Fetch single value"""
        pass
    
    @abstractmethod
    async def begin_transaction(self):
        """Begin database transaction"""
        pass
    
    @abstractmethod
    async def commit_transaction(self):
        """Commit database transaction"""
        pass
    
    @abstractmethod
    async def rollback_transaction(self):
        """Rollback database transaction"""
        pass
    
    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connection is active"""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Perform health check on connection"""
        pass
    
    async def __aenter__(self):
        """Async context manager entry"""
        if not self.is_connected:
            await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        # Don't close connection in context manager for pooled connections
        pass