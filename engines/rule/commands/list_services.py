"""
List available services command
"""

from pathlib import Path
from typing import List
try:
    from ..config import Config
except ImportError:
    from config import Config

def list_services(config: Config, provider: str = "aws") -> List[str]:
    """
    List all available services for a specific provider
    
    Args:
        config: Config instance
        provider: Provider name (e.g., 'aws', 'azure') - defaults to 'aws' for backward compat
    """
    if not provider:
        raise ValueError("provider parameter is required")
    
    # Get provider-specific database path
    database_path = config.get_database_path(provider)
    
    if not database_path.exists():
        return []
    
    services = []
    for service_dir in database_path.iterdir():
        if service_dir.is_dir() and config.validate_service(service_dir.name, provider):
            services.append(service_dir.name)
    return sorted(services)

