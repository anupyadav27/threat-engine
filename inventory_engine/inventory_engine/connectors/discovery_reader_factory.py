"""
Discovery Reader Factory

Factory to return appropriate discovery reader based on environment.
"""

import os
from typing import Union, Optional
from .discovery_reader import DiscoveryReader
from .discovery_db_reader import DiscoveryDBReader


def get_discovery_reader(tenant_id: Optional[str] = None) -> Union[DiscoveryReader, DiscoveryDBReader]:
    """
    Factory to return appropriate discovery reader based on environment.
    
    Args:
        tenant_id: Tenant identifier (required for database mode)
    
    Returns:
        DiscoveryReader (file-based) for local development
        DiscoveryDBReader (database-based) for production
    
    Environment Variables:
        USE_DATABASE: Set to "true" for database mode (default: "false")
        DATABASE_URL: PostgreSQL connection URL (required if USE_DATABASE=true)
    """
    use_db = os.getenv("USE_DATABASE", "false").lower() == "true"
    
    if use_db:
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise ValueError("DATABASE_URL environment variable required when USE_DATABASE=true")
        if not tenant_id:
            raise ValueError("tenant_id required when USE_DATABASE=true")
        return DiscoveryDBReader(db_url, tenant_id)
    else:
        # Local development mode - use NDJSON files
        discovery_base_path = os.getenv("DISCOVERY_BASE_PATH")
        return DiscoveryReader(discovery_base_path)
