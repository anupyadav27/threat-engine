"""
Consolidated Engine API Clients
HTTP clients for calling consolidated engine APIs through API Gateway
"""
import os
import requests
from typing import Dict, List, Any, Optional
from django.core.cache import cache
from django.conf import settings
import logging
import uuid

logger = logging.getLogger(__name__)


class EngineClientBase:
    """Enhanced base class for consolidated engine API clients"""
    
    def __init__(self, service_name: str, base_url: str = None, cache_ttl: int = 300):
        """
        Initialize engine client with API Gateway support.
        
        Args:
            service_name: Name of the service (for routing through gateway)
            base_url: Base URL (defaults to API Gateway routing)
            cache_ttl: Cache TTL in seconds (default: 5 minutes)
        """
        self.service_name = service_name
        self.use_gateway = getattr(settings, 'USE_API_GATEWAY', True)
        self.migration_mode = getattr(settings, 'MIGRATION_MODE', 'gateway')
        
        # Determine base URL based on configuration
        if base_url:
            self.base_url = base_url.rstrip('/')
        elif self.use_gateway and hasattr(settings, 'API_GATEWAY_URL'):
            self.base_url = settings.API_GATEWAY_URL.rstrip('/')
        else:
            # Fallback to legacy URLs
            self.base_url = self._get_legacy_url()
        
        self.cache_ttl = cache_ttl
        self.session = requests.Session()
        
        # Enhanced headers for consolidated architecture
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'User-Agent': f'ThreatEngine-Django-Client/{service_name}',
            'X-Client-Version': '2.0-consolidated'
        })
    
    def _get_legacy_url(self) -> str:
        """Get legacy URL mapping for backward compatibility"""
        legacy_mapping = {
            'threat': getattr(settings, 'THREAT_ENGINE_URL', 'http://engine-threat:8020'),
            'compliance': getattr(settings, 'COMPLIANCE_ENGINE_URL', 'http://engine-compliance:8010'),
            'inventory': getattr(settings, 'INVENTORY_ENGINE_URL', 'http://engine-inventory:8022'),
            'onboarding': getattr(settings, 'ONBOARDING_ENGINE_URL', 'http://engine-onboarding:8008'),
            'datasec': getattr(settings, 'DATASEC_ENGINE_URL', 'http://engine-datasec:8004'),
            'secops': getattr(settings, 'SECOPS_ENGINE_URL', 'http://engine-secops:8000'),
            'check': getattr(settings, 'CHECK_ENGINE_URL', 'http://engine-check:8002'),
            'discoveries': getattr(settings, 'DISCOVERIES_ENGINE_URL', 'http://engine-discoveries:8001'),
            'iam': getattr(settings, 'IAM_ENGINE_URL', 'http://engine-iam:8003'),
            'rule': getattr(settings, 'RULE_ENGINE_URL', 'http://engine-rule:8000'),
        }
        return legacy_mapping.get(self.service_name, f'http://engine-{self.service_name}:8000')
    
    def _add_tenant_headers(self, headers: Dict[str, str], tenant_id: str = None, user_id: str = None) -> Dict[str, str]:
        """Add tenant and user context headers for the consolidated architecture"""
        enhanced_headers = headers.copy()
        
        if tenant_id:
            enhanced_headers['X-Tenant-ID'] = tenant_id
        if user_id:
            enhanced_headers['X-User-ID'] = str(user_id)
            
        # Add correlation ID for distributed tracing
        enhanced_headers['X-Correlation-ID'] = str(uuid.uuid4())
        
        return enhanced_headers
    
    def _get(self, endpoint: str, params: Optional[Dict] = None, use_cache: bool = True, tenant_id: str = None, user_id: str = None) -> Dict[str, Any]:
        """Enhanced GET request with tenant context and caching"""
        # Build URL based on routing mode
        if self.use_gateway and not endpoint.startswith('/api/v1/'):
            # Route through API Gateway
            url = f"{self.base_url}/api/v1/{self.service_name}{endpoint}"
        else:
            url = f"{self.base_url}{endpoint}"
        
        cache_key = f"{self.service_name}:{url}:{params}:{tenant_id}" if params or tenant_id else f"{self.service_name}:{url}"
        
        if use_cache:
            cached = cache.get(cache_key)
            if cached:
                logger.debug(f"Cache hit for {url}")
                return cached
        
        try:
            # Enhanced headers with tenant context
            headers = self._add_tenant_headers({}, tenant_id, user_id)
            response = self.session.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            if use_cache:
                cache.set(cache_key, data, self.cache_ttl)
            
            logger.debug(f"Successful GET request to {url}")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {url} - {e}")
            raise
    
    def _post(self, endpoint: str, data: Optional[Dict] = None, use_cache: bool = False, tenant_id: str = None, user_id: str = None) -> Dict[str, Any]:
        """Enhanced POST request with tenant context"""
        # Build URL based on routing mode
        if self.use_gateway and not endpoint.startswith('/api/v1/'):
            url = f"{self.base_url}/api/v1/{self.service_name}{endpoint}"
        else:
            url = f"{self.base_url}{endpoint}"
        
        try:
            headers = self._add_tenant_headers({}, tenant_id, user_id)
            response = self.session.post(url, json=data, headers=headers, timeout=60)
            response.raise_for_status()
            result = response.json()
            
            logger.debug(f"Successful POST request to {url}")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {url} - {e}")
            raise
    
    def _patch(self, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None, tenant_id: str = None, user_id: str = None) -> Dict[str, Any]:
        """Enhanced PATCH request with tenant context"""
        # Build URL based on routing mode
        if self.use_gateway and not endpoint.startswith('/api/v1/'):
            url = f"{self.base_url}/api/v1/{self.service_name}{endpoint}"
        else:
            url = f"{self.base_url}{endpoint}"
        
        try:
            headers = self._add_tenant_headers({}, tenant_id, user_id)
            response = self.session.patch(url, json=data, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            
            logger.debug(f"Successful PATCH request to {url}")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {url} - {e}")
            raise


class InventoryEngineClient(EngineClientBase):
    """Client for Inventory Engine API (routed through Platform Service)"""
    
    def __init__(self):
        # Use consolidated platform service for inventory operations
        super().__init__(service_name='platform', cache_ttl=300)  # 5 minutes
    
    def get_assets(
        self,
        tenant_id: str,
        scan_run_id: Optional[str] = None,
        provider: Optional[str] = None,
        region: Optional[str] = None,
        resource_type: Optional[str] = None,
        account_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get assets list with enhanced tenant context"""
        params = {
            "tenant_id": tenant_id,
            "limit": limit,
            "offset": offset
        }
        if scan_run_id:
            params["scan_run_id"] = scan_run_id
        if provider:
            params["provider"] = provider
        if region:
            params["region"] = region
        if resource_type:
            params["resource_type"] = resource_type
        if account_id:
            params["account_id"] = account_id
        
        response = self._get("/inventory/assets", params=params, tenant_id=tenant_id, user_id=user_id)
        return response.get("assets", [])
    
    def get_asset(self, resource_uid: str, tenant_id: str, scan_run_id: Optional[str] = None) -> Dict[str, Any]:
        """Get single asset"""
        params = {"tenant_id": tenant_id}
        if scan_run_id:
            params["scan_run_id"] = scan_run_id
        
        return self._get(f"/api/v1/inventory/assets/{resource_uid}", params=params)
    
    def get_relationships(
        self,
        resource_uid: str,
        tenant_id: str,
        scan_run_id: Optional[str] = None,
        depth: int = 1,
        relation_type: Optional[str] = None,
        direction: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get asset relationships"""
        params = {
            "tenant_id": tenant_id,
            "depth": depth
        }
        if scan_run_id:
            params["scan_run_id"] = scan_run_id
        if relation_type:
            params["relation_type"] = relation_type
        if direction:
            params["direction"] = direction
        
        response = self._get(
            f"/api/v1/inventory/assets/{resource_uid}/relationships",
            params=params
        )
        return response.get("relationships", [])
    
    def get_scan_summary(self, tenant_id: str, scan_run_id: Optional[str] = None) -> Dict[str, Any]:
        """Get scan summary"""
        if scan_run_id:
            endpoint = f"/api/v1/inventory/runs/{scan_run_id}/summary"
        else:
            endpoint = "/api/v1/inventory/runs/latest/summary"
        
        params = {"tenant_id": tenant_id}
        return self._get(endpoint, params=params)
    
    def get_drift(
        self,
        tenant_id: str,
        baseline_scan: Optional[str] = None,
        compare_scan: Optional[str] = None,
        change_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get drift records"""
        params = {"tenant_id": tenant_id}
        if baseline_scan:
            params["baseline_scan"] = baseline_scan
        if compare_scan:
            params["compare_scan"] = compare_scan
        if change_type:
            params["change_type"] = change_type
        
        return self._get("/api/v1/inventory/drift", params=params)


class ThreatEngineClient(EngineClientBase):
    """Client for Threat Engine API (routed through Core Engine Service)"""
    
    def __init__(self):
        # Use consolidated core engine service for threat operations
        super().__init__(service_name='threat', cache_ttl=180)  # 3 minutes (threats change more frequently)
    
    def get_threats(
        self,
        tenant_id: str,
        scan_run_id: str = "latest",
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get threats list with enhanced tenant context"""
        params = {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
            "page": page,
            "page_size": page_size
        }
        if severity:
            params["severity"] = severity
        if threat_type:
            params["threat_type"] = threat_type
        if status:
            params["status"] = status
        
        return self._get("/list", params=params, tenant_id=tenant_id, user_id=user_id)
    
    def get_threat(self, threat_id: str, tenant_id: str) -> Dict[str, Any]:
        """Get single threat"""
        params = {"tenant_id": tenant_id}
        return self._get(f"/api/v1/threat/{threat_id}", params=params)
    
    def update_threat(
        self,
        threat_id: str,
        tenant_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update threat status"""
        params = {"tenant_id": tenant_id}
        return self._patch(f"/api/v1/threat/{threat_id}", data=updates, params=params)
    
    def get_threat_summary(self, tenant_id: str, scan_run_id: str = "latest") -> Dict[str, Any]:
        """Get threat summary"""
        params = {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id
        }
        return self._get("/api/v1/threat/summary", params=params)
    
    def get_threat_trend(
        self,
        tenant_id: str,
        days: int = 30,
        scan_run_id: Optional[str] = None,
        severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get threat trends"""
        params = {
            "tenant_id": tenant_id,
            "days": days
        }
        if scan_run_id:
            params["scan_run_id"] = scan_run_id
        if severity:
            params["severity"] = severity
        
        return self._get("/api/v1/threat/analytics/trend", params=params)
    
    def get_threat_patterns(
        self,
        scan_run_id: str,
        tenant_id: str,
        limit: int = 10
    ) -> Dict[str, Any]:
        """Get threat patterns"""
        params = {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "limit": limit
        }
        return self._get("/api/v1/threat/analytics/patterns", params=params)
    
    def get_remediation_queue(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get remediation queue"""
        params = {
            "tenant_id": tenant_id,
            "limit": limit
        }
        if status:
            params["status"] = status
        
        return self._get("/api/v1/threat/remediation/queue", params=params)
    
    # Check Results APIs
    def get_check_dashboard(self, tenant_id: str) -> Dict[str, Any]:
        """Get check results dashboard"""
        params = {"tenant_id": tenant_id}
        return self._get("/api/v1/checks/dashboard", params=params)
    
    def get_check_scan(self, scan_id: str, tenant_id: str) -> Dict[str, Any]:
        """Get check scan details"""
        params = {"tenant_id": tenant_id}
        return self._get(f"/api/v1/checks/scans/{scan_id}", params=params)
    
    def get_check_findings(
        self,
        scan_id: str,
        tenant_id: str,
        query: Optional[str] = None,
        severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get check findings"""
        params = {"tenant_id": tenant_id}
        if query:
            params["query"] = query
        if severity:
            params["severity"] = severity
        
        return self._get(f"/api/v1/checks/scans/{scan_id}/findings", params=params)
    
    # Discovery Results APIs
    def get_discovery_dashboard(self, tenant_id: str) -> Dict[str, Any]:
        """Get discovery dashboard"""
        params = {"tenant_id": tenant_id}
        return self._get("/api/v1/discoveries/dashboard", params=params)
    
    def get_discovery_scan(self, scan_id: str, tenant_id: str) -> Dict[str, Any]:
        """Get discovery scan details"""
        params = {"tenant_id": tenant_id}
        return self._get(f"/api/v1/discoveries/scans/{scan_id}", params=params)
    
    def get_discoveries(
        self,
        scan_id: str,
        tenant_id: str,
        query: Optional[str] = None,
        service: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get discoveries"""
        params = {"tenant_id": tenant_id}
        if query:
            params["query"] = query
        if service:
            params["service"] = service
        
        return self._get(f"/api/v1/discoveries/scans/{scan_id}/discoveries", params=params)


class ComplianceEngineClient(EngineClientBase):
    """Client for Compliance Engine API (routed through Core Engine Service)"""
    
    def __init__(self):
        # Use consolidated core engine service for compliance operations
        super().__init__(service_name='compliance', cache_ttl=600)  # 10 minutes (compliance changes less frequently)
    
    def generate_report(
        self,
        scan_id: str,
        csp: str,
        frameworks: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Generate compliance report"""
        data = {
            "scan_id": scan_id,
            "csp": csp,
            "frameworks": frameworks
        }
        return self._post("/api/v1/compliance/generate", data=data, use_cache=False)
    
    def get_framework_status(
        self,
        framework: str,
        scan_id: str,
        csp: str
    ) -> Dict[str, Any]:
        """Get framework compliance status"""
        params = {
            "scan_id": scan_id,
            "csp": csp
        }
        framework_encoded = framework.replace(" ", "%20").replace("/", "%2F")
        return self._get(f"/api/v1/compliance/framework/{framework_encoded}/status", params=params)
    
    def get_control_detail(
        self,
        framework: str,
        control_id: str,
        scan_id: str,
        csp: str
    ) -> Dict[str, Any]:
        """Get control detail"""
        params = {
            "scan_id": scan_id,
            "csp": csp
        }
        framework_encoded = framework.replace(" ", "%20").replace("/", "%2F")
        return self._get(f"/api/v1/compliance/framework/{framework_encoded}/control/{control_id}", params=params)
    
    def get_trends(
        self,
        csp: str,
        account_id: Optional[str] = None,
        days: int = 30,
        framework: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get compliance trends"""
        params = {
            "csp": csp,
            "days": days
        }
        if account_id:
            params["account_id"] = account_id
        if framework:
            params["framework"] = framework
        
        return self._get("/api/v1/compliance/trends", params=params)
    
    def get_account_compliance(
        self,
        account_id: str,
        scan_id: str,
        csp: str
    ) -> Dict[str, Any]:
        """Get account compliance"""
        params = {
            "scan_id": scan_id,
            "csp": csp
        }
        return self._get(f"/api/v1/compliance/accounts/{account_id}", params=params)


class DataSecEngineClient(EngineClientBase):
    """Client for DataSec Engine API"""
    
    def __init__(self):
        base_url = getattr(settings, 'DATASEC_ENGINE_URL', 'http://datasec-engine:8000')
        super().__init__(base_url=base_url, cache_ttl=300)  # 5 minutes
    
    def generate_scan(
        self,
        scan_id: str,
        csp: str
    ) -> Dict[str, Any]:
        """Generate data security scan"""
        data = {
            "scan_id": scan_id,
            "csp": csp
        }
        return self._post("/api/v1/data-security/scan", data=data, use_cache=False)
    
    def get_catalog(
        self,
        csp: str,
        scan_id: str = "latest",
        account_id: Optional[str] = None,
        service: Optional[str] = None,
        region: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get data catalog"""
        params = {
            "csp": csp,
            "scan_id": scan_id
        }
        if account_id:
            params["account_id"] = account_id
        if service:
            params["service"] = service
        if region:
            params["region"] = region
        
        return self._get("/api/v1/data-security/catalog", params=params)
    
    def get_findings(
        self,
        csp: str,
        scan_id: str = "latest"
    ) -> Dict[str, Any]:
        """Get data security findings"""
        params = {
            "csp": csp,
            "scan_id": scan_id
        }
        return self._get("/api/v1/data-security/findings", params=params)
    
    def get_classification(self, resource_arn: str) -> Dict[str, Any]:
        """Get data classification"""
        params = {"resource_arn": resource_arn}
        return self._get("/api/v1/data-security/classification", params=params)
    
    def get_residency(self, resource_arn: str) -> Dict[str, Any]:
        """Get data residency"""
        params = {"resource_arn": resource_arn}
        return self._get("/api/v1/data-security/residency", params=params)


class SecOpsEngineClient(EngineClientBase):
    """Client for SecOps Engine API (routed through Data SecOps Service)"""

    def __init__(self):
        # Use consolidated data secops service for security operations
        super().__init__(service_name='secops', cache_ttl=180)

    def list_scans(
        self,
        tenant_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List SecOps scans."""
        params = {"limit": limit}
        if tenant_id:
            params["tenant_id"] = tenant_id
        if customer_id:
            params["customer_id"] = customer_id
        if scan_id:
            params["scan_id"] = scan_id
        return self._get("/api/v1/secops/scans", params=params)

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get single SecOps scan."""
        try:
            return self._get(f"/api/v1/secops/scans/{scan_id}")
        except Exception:
            return None

    def get_findings(self, scan_id: str, limit: int = 500) -> Dict[str, Any]:
        """Get findings for a SecOps scan."""
        return self._get(
            f"/api/v1/secops/scans/{scan_id}/findings",
            params={"limit": limit},
        )


class OnboardingEngineClient(EngineClientBase):
    """Client for Onboarding Engine API (routed through Platform Service)"""
    
    def __init__(self):
        # Use consolidated platform service for onboarding operations
        super().__init__(service_name='onboarding', cache_ttl=300)  # 5 minutes
    
    def get_tenants(self) -> List[Dict[str, Any]]:
        """Get tenants list"""
        response = self._get("/api/v1/onboarding/tenants")
        return response.get("tenants", [])
    
    def get_accounts(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get accounts list"""
        params = {}
        if tenant_id:
            params["tenant_id"] = tenant_id
        
        response = self._get("/api/v1/onboarding/accounts", params=params)
        return response.get("accounts", [])
    
    def get_account(self, account_id: str) -> Dict[str, Any]:
        """Get single account"""
        return self._get(f"/api/v1/onboarding/accounts/{account_id}")
    
    def get_account_health(self, account_id: str) -> Dict[str, Any]:
        """Get account health"""
        return self._get(f"/api/v1/accounts/{account_id}/health")
    
    def get_account_statistics(self, account_id: str) -> Dict[str, Any]:
        """Get account statistics"""
        return self._get(f"/api/v1/accounts/{account_id}/statistics")
    
    def get_schedules(
        self,
        tenant_id: Optional[str] = None,
        account_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get schedules list"""
        params = {}
        if tenant_id:
            params["tenant_id"] = tenant_id
        if account_id:
            params["account_id"] = account_id
        
        response = self._get("/api/v1/schedules", params=params)
        return response.get("schedules", [])
    
    def get_schedule(self, schedule_id: str) -> Dict[str, Any]:
        """Get single schedule"""
        return self._get(f"/api/v1/schedules/{schedule_id}")
    
    def get_executions(
        self,
        schedule_id: str,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Get schedule executions"""
        params = {
            "limit": limit,
            "offset": offset
        }
        return self._get(f"/api/v1/schedules/{schedule_id}/executions", params=params)
    
    def get_execution_status(self, schedule_id: str, execution_id: str) -> Dict[str, Any]:
        """Get execution status"""
        return self._get(f"/api/v1/schedules/{schedule_id}/executions/{execution_id}/status")
    
    def get_schedule_statistics(self, schedule_id: str) -> Dict[str, Any]:
        """Get schedule statistics"""
        return self._get(f"/api/v1/schedules/{schedule_id}/statistics")


# ============================================================================
# Consolidated Service Clients (Future Architecture)
# ============================================================================

class CoreEngineClient(EngineClientBase):
    """Unified client for Core Engine Service (Threat + Compliance + Rule)"""
    
    def __init__(self):
        super().__init__(service_name='core', cache_ttl=300)
    
    # Threat Engine Methods
    def get_threats(self, tenant_id: str, scan_run_id: str = "latest", **kwargs) -> Dict[str, Any]:
        """Get threats from core engine"""
        params = {"tenant_id": tenant_id, "scan_run_id": scan_run_id, **kwargs}
        return self._get("/threat/list", params=params, tenant_id=tenant_id)
    
    def generate_threat_report(self, tenant_id: str, scan_run_id: str, **kwargs) -> Dict[str, Any]:
        """Generate threat report"""
        data = {"tenant_id": tenant_id, "scan_run_id": scan_run_id, **kwargs}
        return self._post("/threat/generate", data=data, tenant_id=tenant_id)
    
    # Compliance Engine Methods 
    def generate_compliance_report(self, tenant_id: str, scan_id: str, csp: str, **kwargs) -> Dict[str, Any]:
        """Generate compliance report"""
        data = {"tenant_id": tenant_id, "scan_id": scan_id, "csp": csp, **kwargs}
        return self._post("/compliance/generate", data=data, tenant_id=tenant_id)
    
    def get_compliance_status(self, tenant_id: str, framework: str, scan_id: str, **kwargs) -> Dict[str, Any]:
        """Get compliance framework status"""
        params = {"tenant_id": tenant_id, "scan_id": scan_id, **kwargs}
        return self._get(f"/compliance/framework/{framework}/status", params=params, tenant_id=tenant_id)


class ConfigScanServiceClient(EngineClientBase):
    """Unified client for ConfigScan Service (All CSP scanners)"""
    
    def __init__(self):
        super().__init__(service_name='configscan', cache_ttl=180)
    
    def start_scan(self, tenant_id: str, csp: str, **kwargs) -> Dict[str, Any]:
        """Start configuration scan for any CSP"""
        data = {"tenant_id": tenant_id, "csp": csp, **kwargs}
        return self._post("/scan", data=data, tenant_id=tenant_id)
    
    def start_csp_scan(self, tenant_id: str, csp: str, **kwargs) -> Dict[str, Any]:
        """Start CSP-specific scan (backward compatibility)"""
        data = {"tenant_id": tenant_id, **kwargs}
        return self._post(f"/{csp}/scan", data=data, tenant_id=tenant_id)
    
    def get_scan_status(self, tenant_id: str, scan_id: str) -> Dict[str, Any]:
        """Get scan status"""
        params = {"tenant_id": tenant_id}
        return self._get(f"/scan/{scan_id}", params=params, tenant_id=tenant_id)
    
    def list_scans(self, tenant_id: str, csp: str = None, **kwargs) -> Dict[str, Any]:
        """List scans for tenant"""
        params = {"tenant_id": tenant_id, **kwargs}
        if csp:
            params["csp"] = csp
        return self._get("/scans", params=params, tenant_id=tenant_id)


class PlatformServiceClient(EngineClientBase):
    """Unified client for Platform Service (Inventory + Onboarding + Admin)"""
    
    def __init__(self):
        super().__init__(service_name='platform', cache_ttl=300)
    
    # Inventory Methods
    def get_assets(self, tenant_id: str, **kwargs) -> List[Dict[str, Any]]:
        """Get asset inventory"""
        params = {"tenant_id": tenant_id, **kwargs}
        response = self._get("/inventory/assets", params=params, tenant_id=tenant_id)
        return response.get("assets", [])
    
    def get_asset_relationships(self, tenant_id: str, resource_uid: str, **kwargs) -> List[Dict[str, Any]]:
        """Get asset relationships"""
        params = {"tenant_id": tenant_id, **kwargs}
        response = self._get(f"/inventory/assets/{resource_uid}/relationships", params=params, tenant_id=tenant_id)
        return response.get("relationships", [])
    
    # Onboarding Methods
    def get_tenants(self) -> List[Dict[str, Any]]:
        """Get tenants list"""
        response = self._get("/onboarding/tenants")
        return response.get("tenants", [])
    
    def get_accounts(self, tenant_id: str = None) -> List[Dict[str, Any]]:
        """Get accounts list"""
        params = {}
        if tenant_id:
            params["tenant_id"] = tenant_id
        response = self._get("/onboarding/accounts", params=params, tenant_id=tenant_id)
        return response.get("accounts", [])


class DataSecOpsServiceClient(EngineClientBase):
    """Unified client for Data SecOps Service (DataSec + SecOps + UserPortal)"""
    
    def __init__(self):
        super().__init__(service_name='data-secops', cache_ttl=300)
    
    # DataSec Methods
    def get_data_catalog(self, tenant_id: str, csp: str, **kwargs) -> Dict[str, Any]:
        """Get data security catalog"""
        params = {"tenant_id": tenant_id, "csp": csp, **kwargs}
        return self._get("/datasec/catalog", params=params, tenant_id=tenant_id)
    
    def get_data_findings(self, tenant_id: str, csp: str, **kwargs) -> Dict[str, Any]:
        """Get data security findings"""
        params = {"tenant_id": tenant_id, "csp": csp, **kwargs}
        return self._get("/datasec/findings", params=params, tenant_id=tenant_id)
    
    # SecOps Methods
    def list_secops_scans(self, tenant_id: str, **kwargs) -> Dict[str, Any]:
        """List SecOps scans"""
        params = {"tenant_id": tenant_id, **kwargs}
        return self._get("/secops/scans", params=params, tenant_id=tenant_id)
    
    def get_secops_findings(self, tenant_id: str, scan_id: str, **kwargs) -> Dict[str, Any]:
        """Get SecOps findings"""
        params = {"tenant_id": tenant_id, **kwargs}
        return self._get(f"/secops/scans/{scan_id}/findings", params=params, tenant_id=tenant_id)
