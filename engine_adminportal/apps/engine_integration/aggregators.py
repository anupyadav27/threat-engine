"""
Cross-engine data aggregation for admin portal.
"""
import logging
from typing import Dict, List, Any, Optional
from django.core.cache import cache
from .clients import engine_manager

logger = logging.getLogger(__name__)


class TenantMetricsAggregator:
    """Aggregate metrics from all engines for a tenant."""
    
    def aggregate_tenant_metrics(self, tenant_id: str) -> Dict[str, Any]:
        """Aggregate all metrics for a tenant."""
        cache_key = f"tenant_metrics_{tenant_id}"
        cached = cache.get(cache_key)
        if cached:
            return cached
        
        metrics = {
            'tenant_id': tenant_id,
            'active_scans': 0,
            'compliance_score': 0.0,
            'findings_critical': 0,
            'findings_high': 0,
            'findings_medium': 0,
            'findings_low': 0,
            'resources_count': 0,
            'scan_success_rate': 0.0,
            'last_scan_timestamp': None,
            'providers': [],
        }
        
        # Get compliance data
        compliance_client = engine_manager.get_client('compliance')
        if compliance_client:
            compliance_data = compliance_client.get_compliance_summary(tenant_id)
            if compliance_data:
                metrics['compliance_score'] = compliance_data.get('overall_score', 0.0)
        
        # Get threat data
        threat_client = engine_manager.get_client('threat')
        if threat_client:
            threat_data = threat_client.get_dashboard_stats(tenant_id)
            if threat_data:
                metrics['findings_critical'] = threat_data.get('failed', 0)
                # Could parse severity from threat data
        
        # Get inventory data
        inventory_client = engine_manager.get_client('inventory')
        if inventory_client:
            inventory_data = inventory_client.get_inventory_summary(tenant_id)
            if inventory_data:
                metrics['resources_count'] = inventory_data.get('total_resources', 0)
        
        # Get onboarding data
        onboarding_client = engine_manager.get_client('onboarding')
        if onboarding_client:
            accounts = onboarding_client.get_tenant_accounts(tenant_id)
            if accounts:
                metrics['providers'] = list(set(acc.get('provider_type') for acc in accounts if acc.get('provider_type')))
                executions = onboarding_client.get_execution_history(tenant_id, limit=1)
                if executions and len(executions) > 0:
                    last_exec = executions[0]
                    metrics['last_scan_timestamp'] = last_exec.get('started_at')
                    if last_exec.get('status') == 'running':
                        metrics['active_scans'] = 1
        
        # Cache for 30 seconds
        cache.set(cache_key, metrics, 30)
        return metrics
    
    def aggregate_all_tenants(self) -> List[Dict[str, Any]]:
        """Aggregate metrics for all tenants."""
        # This would query the database for all tenants
        # For now, return empty list - will be implemented with database queries
        return []


# Global instance
metrics_aggregator = TenantMetricsAggregator()
