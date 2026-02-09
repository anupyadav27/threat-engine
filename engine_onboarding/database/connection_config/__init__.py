"""
Database connection configuration for onboarding engine
"""
# Import database config
from .database_config import (
    DatabaseConnectionConfig,
    DatabaseSettings,
    db_settings,
    get_database_config,
    get_connection_string,
    get_async_connection_string,
    get_shared_config
)

# Re-export connection.py items (connection.py is at parent level)
# Use importlib to import the parent connection.py file explicitly
import importlib.util
import os

_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_connection_file = os.path.join(_parent_dir, "connection.py")

if os.path.exists(_connection_file):
    spec = importlib.util.spec_from_file_location("connection_module", _connection_file)
    _connection_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_connection_module)
    
    # Re-export connection.py items
    SessionLocal = _connection_module.SessionLocal
    get_db = _connection_module.get_db
    get_db_session = _connection_module.get_db_session
    check_connection = _connection_module.check_connection
    check_connection_async = _connection_module.check_connection_async
    engine = _connection_module.engine
    init_db = _connection_module.init_db
else:
    # Fallback - these will be None if connection.py doesn't exist
    SessionLocal = None
    get_db = None
    get_db_session = None
    check_connection = None
    check_connection_async = None
    engine = None
    init_db = None

__all__ = [
    # Database config
    'DatabaseConnectionConfig',
    'DatabaseSettings',
    'db_settings',
    'get_database_config',
    'get_connection_string',
    'get_async_connection_string',
    'get_shared_config',
    # Connection module items (re-exported)
    'SessionLocal',
    'get_db',
    'get_db_session',
    'check_connection',
    'check_connection_async',
    'engine',
    'init_db'
]
