"""
Engine API clients for connecting to all CSPM engines.
"""
import requests
import logging
from typing import Dict, List, Optional, Any
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class BaseEngineClient:
    """Base client for engine API communication."""
    
    def __init__(self, engine_name: str, base_url: str, timeout: int = 10):
        self.engine_name = engine_name
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Make HTTP request to engine."""
        url = f"{self.base_url}{endpoint}"
        try:
            response = requests.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs
            )
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.Timeout:
            logger.error(f"{self.engine_name} timeout: {url}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"{self.engine_name} error: {url} - {str(e)}")
            return None
    
    def health_check(self) -> Dict[str, Any]:
        """Check engine health."""
        cache_key = f"engine_health_{self.engine_name}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        result = self._make_request('GET', '/api/v1/health') or {}
        health_status = {
            'engine': self.engine_name,
            'status': 'healthy' if result else 'unhealthy',
            'response': result,
            'url': self.base_url,
        }
        cache.set(cache_key, health_status, 60)  # Cache for 60 seconds
        return health_status


class ConfigScanClient(BaseEngineClient):
    """Client for configScan engines."""
    
    def __init__(self, provider: str, base_url: str):
        super().__init__(f"configscan_{provider}", base_url)
        self.provider = provider
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan status."""
        return self._make_request('GET', f'/api/v1/scan/{scan_id}/status')
    
    def get_scan_results(self, scan_id: str, page: int = 1, page_size: int = 100) -> Optional[Dict[str, Any]]:
        """Get scan results."""
        return self._make_request(
            'GET',
            f'/api/v1/scan/{scan_id}/results',
            params={'page': page, 'page_size': page_size}
        )


class ComplianceClient(BaseEngineClient):
    """Client for compliance engine."""
    
    def __init__(self, base_url: str):
        super().__init__('compliance', base_url)
    
    def get_compliance_summary(self, tenant_id: str, scan_run_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get compliance summary for tenant."""
        params = {'tenant_id': tenant_id}
        if scan_run_id:
            params['scan_run_id'] = scan_run_id
        return self._make_request('GET', '/api/v1/compliance/summary', params=params)
    
    def get_framework_scores(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get compliance scores by framework."""
        return self._make_request('GET', f'/api/v1/compliance/frameworks/{tenant_id}')


class ThreatClient(BaseEngineClient):
    """Client for threat engine."""
    
    def __init__(self, base_url: str):
        super().__init__('threat', base_url)
    
    def get_dashboard_stats(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get threat dashboard stats."""
        return self._make_request('GET', '/api/v1/checks/dashboard', params={'tenant_id': tenant_id})
    
    def get_threat_summary(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get threat summary for tenant."""
        return self._make_request('GET', '/api/v1/threats/summary', params={'tenant_id': tenant_id})


class InventoryClient(BaseEngineClient):
    """Client for inventory engine."""
    
    def __init__(self, base_url: str):
        super().__init__('inventory', base_url)
    
    def get_inventory_summary(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get inventory summary for tenant."""
        return self._make_request('GET', '/api/v1/inventory/summary', params={'tenant_id': tenant_id})


class DataSecClient(BaseEngineClient):
    """Client for datasec engine."""
    
    def __init__(self, base_url: str):
        super().__init__('datasec', base_url)
    
    def get_datasec_summary(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get data security summary for tenant."""
        return self._make_request('GET', '/api/v1/datasec/summary', params={'tenant_id': tenant_id})


class OnboardingClient(BaseEngineClient):
    """Client for onboarding engine."""
    
    def __init__(self, base_url: str):
        super().__init__('onboarding', base_url)
    
    def get_tenant_accounts(self, tenant_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get all accounts for a tenant."""
        result = self._make_request('GET', '/api/v1/onboarding/accounts', params={'tenant_id': tenant_id})
        return result.get('accounts', []) if result else []
    
    def get_tenant_schedules(self, tenant_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get all schedules for a tenant."""
        result = self._make_request('GET', '/api/v1/onboarding/schedules', params={'tenant_id': tenant_id})
        return result.get('schedules', []) if result else []
    
    def get_execution_history(self, tenant_id: str, limit: int = 10) -> Optional[List[Dict[str, Any]]]:
        """Get recent execution history for tenant."""
        result = self._make_request(
            'GET',
            '/api/v1/onboarding/executions',
            params={'tenant_id': tenant_id, 'limit': limit}
        )
        return result.get('executions', []) if result else []


class EngineClientManager:
    """Manager for all engine clients."""
    
    def __init__(self):
        self.clients = {}
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize all engine clients from settings."""
        endpoints = getattr(settings, 'ENGINE_ENDPOINTS', {})
        
        # ConfigScan clients
        for provider in ['aws', 'azure', 'gcp', 'alicloud', 'oci', 'ibm']:
            key = f'configscan_{provider}'
            if key in endpoints:
                self.clients[key] = ConfigScanClient(provider, endpoints[key])
        
        # Other engines
        if 'compliance' in endpoints:
            self.clients['compliance'] = ComplianceClient(endpoints['compliance'])
        if 'threat' in endpoints:
            self.clients['threat'] = ThreatClient(endpoints['threat'])
        if 'inventory' in endpoints:
            self.clients['inventory'] = InventoryClient(endpoints['inventory'])
        if 'datasec' in endpoints:
            self.clients['datasec'] = DataSecClient(endpoints['datasec'])
        if 'onboarding' in endpoints:
            self.clients['onboarding'] = OnboardingClient(endpoints['onboarding'])
    
    def get_client(self, engine_name: str) -> Optional[BaseEngineClient]:
        """Get engine client by name."""
        return self.clients.get(engine_name)
    
    def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Check health of all engines."""
        results = {}
        for name, client in self.clients.items():
            results[name] = client.health_check()
        return results


# Global instance
engine_manager = EngineClientManager()
