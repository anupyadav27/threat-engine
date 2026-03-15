"""
Service Feature Manager - Manage service feature enablement and filtering
"""
import json
from pathlib import Path
from typing import List, Dict, Set, Optional
import logging

logger = logging.getLogger(__name__)

class ServiceFeatureManager:
    """Manage service feature enablement"""
    
    def __init__(self, config_path: str = "config/service_list.json"):
        """
        Initialize service feature manager
        
        Args:
            config_path: Path to service_list.json
        """
        self.config_path = Path(config_path)
        self.services = self._load_services()
    
    def _load_services(self) -> Dict:
        """Load service configuration"""
        try:
            with open(self.config_path) as f:
                data = json.load(f)
            return {s['name']: s for s in data.get('services', [])}
        except Exception as e:
            logger.error(f"Error loading service config from {self.config_path}: {e}")
            return {}
    
    def get_enabled_services(self, feature: Optional[str] = None) -> List[str]:
        """
        Get enabled services, optionally filtered by feature
        
        Args:
            feature: 'discovery', 'checks', 'deviation', 'drift', or None for all enabled services
        
        Returns:
            List of enabled service names
        """
        enabled = []
        for name, config in self.services.items():
            if not config.get('enabled', False):
                continue
            
            if feature:
                if not self.is_feature_enabled(name, feature):
                    continue
            
            enabled.append(name)
        
        return enabled
    
    def is_feature_enabled(self, service: str, feature: str) -> bool:
        """
        Check if feature is enabled for service
        
        Args:
            service: Service name
            feature: 'discovery', 'checks', 'deviation', 'drift'
        
        Returns:
            True if feature is enabled, False otherwise
        """
        if service not in self.services:
            return False
        
        config = self.services[service]
        
        # Master switch must be enabled
        if not config.get('enabled', False):
            return False
        
        # Check feature-specific enablement
        features = config.get('features', {})
        
        # If features section doesn't exist, default to enabled for discovery/checks
        if not features:
            if feature in ['discovery', 'checks']:
                return True  # Default enabled for core features
            return False  # Default disabled for future features
        
        feature_config = features.get(feature, {})
        
        # If feature config doesn't exist, use defaults
        if not feature_config:
            if feature in ['discovery', 'checks']:
                return True  # Default enabled
            return False  # Default disabled
        
        return feature_config.get('enabled', True)  # Default to enabled if not specified
    
    def get_service_priority(self, service: str, feature: str) -> int:
        """
        Get priority for service feature (1=high, 2=medium, 3=low)
        
        Args:
            service: Service name
            feature: Feature name
        
        Returns:
            Priority level (1, 2, or 3)
        """
        config = self.services.get(service, {})
        features = config.get('features', {})
        feature_config = features.get(feature, {})
        return feature_config.get('priority', 2)  # Default medium priority
    
    def get_service_scope(self, service: str) -> str:
        """
        Get service scope (global, regional, etc.)
        
        Args:
            service: Service name
        
        Returns:
            Scope string
        """
        config = self.services.get(service, {})
        return config.get('scope', 'regional')
    
    def filter_services_by_features(self, services: List[str], 
                                   features: List[str]) -> List[str]:
        """
        Filter services by multiple features (all must be enabled)
        
        Args:
            services: List of service names
            features: List of features to check
        
        Returns:
            Filtered list of services
        """
        filtered = []
        for service in services:
            if all(self.is_feature_enabled(service, feature) for feature in features):
                filtered.append(service)
        return filtered
    
    def get_service_config(self, service: str) -> Optional[Dict]:
        """
        Get full service configuration
        
        Args:
            service: Service name
        
        Returns:
            Service configuration dict or None
        """
        return self.services.get(service)
    
    def reload_config(self):
        """Reload service configuration from file"""
        self.services = self._load_services()
        logger.info(f"Reloaded service configuration: {len(self.services)} services")

