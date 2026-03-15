"""
Database connection module for Threat Engine
"""
from .database_config import get_database_config, get_connection_string

__all__ = ["get_database_config", "get_connection_string"]
