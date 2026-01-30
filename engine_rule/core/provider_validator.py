"""
Provider capability validation and readiness checks
"""

from pathlib import Path
from typing import Dict, List, Optional
try:
    from ..config import Config
except ImportError:
    from config import Config


class ProviderValidator:
    """Validates provider capabilities and service readiness"""
    
    def __init__(self, config: Config):
        self.config = config
    
    def get_provider_status(self, provider: str) -> Dict[str, any]:
        """
        Get comprehensive status for a provider
        
        Returns:
            {
                "provider": str,
                "is_registered": bool,
                "database_exists": bool,
                "total_services": int,
                "ready_services": int,
                "partial_services": int,
                "missing_services": int,
                "readiness_percentage": float
            }
        """
        status = {
            "provider": provider,
            "is_registered": False,
            "database_exists": False,
            "total_services": 0,
            "ready_services": 0,
            "partial_services": 0,
            "missing_services": 0,
            "readiness_percentage": 0.0
        }
        
        # Check if provider is registered
        try:
            adapter = self.config.get_provider_adapter(provider)
            status["is_registered"] = True
        except ValueError:
            return status
        
        # Check database path
        database_path = adapter.get_database_path(self.config.pythonsdk_base)
        if not database_path.exists():
            return status
        
        status["database_exists"] = True
        
        # Count services
        service_dirs = [d for d in database_path.iterdir() if d.is_dir() and not d.name.startswith('.')]
        status["total_services"] = len(service_dirs)
        
        if status["total_services"] == 0:
            return status
        
        # Check each service
        from .data_loader import DataLoader
        loader = DataLoader(self.config)
        
        for service_dir in service_dirs:
            service_name = service_dir.name
            capabilities = loader.check_provider_capability(provider, service_name)
            
            if capabilities["is_ready"]:
                status["ready_services"] += 1
            elif capabilities["has_dependencies"]:
                status["partial_services"] += 1
            else:
                status["missing_services"] += 1
        
        # Calculate readiness percentage
        if status["total_services"] > 0:
            ready_count = status["ready_services"]
            status["readiness_percentage"] = (ready_count / status["total_services"]) * 100
        
        return status
    
    def get_all_providers_status(self) -> Dict[str, Dict]:
        """Get status for all registered providers"""
        providers_status = {}
        
        for provider_name in self.config._provider_registry.keys():
            providers_status[provider_name] = self.get_provider_status(provider_name)
        
        return providers_status
    
    def list_ready_services(self, provider: str) -> List[str]:
        """List services that are ready (have all required files)"""
        try:
            adapter = self.config.get_provider_adapter(provider)
        except ValueError:
            return []
        
        database_path = adapter.get_database_path(self.config.pythonsdk_base)
        if not database_path.exists():
            return []
        
        ready_services = []
        from .data_loader import DataLoader
        loader = DataLoader(self.config)
        
        for service_dir in database_path.iterdir():
            if not service_dir.is_dir() or service_dir.name.startswith('.'):
                continue
            
            service_name = service_dir.name
            capabilities = loader.check_provider_capability(provider, service_name)
            
            if capabilities["is_ready"]:
                ready_services.append(service_name)
        
        return sorted(ready_services)
    
    def list_partial_services(self, provider: str) -> List[str]:
        """List services that have dependencies but missing other files"""
        try:
            adapter = self.config.get_provider_adapter(provider)
        except ValueError:
            return []
        
        database_path = adapter.get_database_path(self.config.pythonsdk_base)
        if not database_path.exists():
            return []
        
        partial_services = []
        from .data_loader import DataLoader
        loader = DataLoader(self.config)
        
        for service_dir in database_path.iterdir():
            if not service_dir.is_dir() or service_dir.name.startswith('.'):
                continue
            
            service_name = service_dir.name
            capabilities = loader.check_provider_capability(provider, service_name)
            
            if capabilities["has_dependencies"] and not capabilities["is_ready"]:
                partial_services.append(service_name)
        
        return sorted(partial_services)

