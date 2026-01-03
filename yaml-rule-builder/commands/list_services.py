"""
List available services command
"""

from pathlib import Path
from typing import List
try:
    from ..config import Config
except ImportError:
    from config import Config

def list_services(config: Config) -> List[str]:
    """List all available AWS services"""
    services = []
    for service_dir in config.pythonsdk_base.iterdir():
        if service_dir.is_dir() and config.validate_service(service_dir.name):
            services.append(service_dir.name)
    return sorted(services)

