"""
Health checker for all engines with circuit breaker pattern.
"""
import logging
from typing import Dict, Any
from django.core.cache import cache
from .clients import engine_manager
from apps.admin_audit.models import AdminAlert

logger = logging.getLogger(__name__)


class EngineHealthChecker:
    """Health checker with circuit breaker pattern."""
    
    def __init__(self):
        self.failure_threshold = 3
        self.timeout_seconds = 300  # 5 minutes
    
    def check_engine_health(self, engine_name: str) -> Dict[str, Any]:
        """Check health of a single engine."""
        client = engine_manager.get_client(engine_name)
        if not client:
            return {
                'engine': engine_name,
                'status': 'unknown',
                'error': 'Client not configured'
            }
        
        # Check circuit breaker
        circuit_key = f"circuit_breaker_{engine_name}"
        circuit_state = cache.get(circuit_key, 'closed')
        
        if circuit_state == 'open':
            # Check if timeout has passed
            import time
            last_failure = cache.get(f"{circuit_key}_last_failure", 0)
            if time.time() - last_failure > self.timeout_seconds:
                # Try to close circuit
                cache.delete(circuit_key)
                circuit_state = 'closed'
            else:
                return {
                    'engine': engine_name,
                    'status': 'unhealthy',
                    'circuit_breaker': 'open',
                    'error': 'Circuit breaker is open'
                }
        
        # Perform health check
        health_result = client.health_check()
        
        if health_result.get('status') == 'healthy':
            # Reset failure count
            cache.delete(f"{circuit_key}_failures")
            cache.delete(f"{circuit_key}_last_failure")
            cache.set(circuit_key, 'closed', 3600)
            return health_result
        else:
            # Increment failure count
            failure_count = cache.get(f"{circuit_key}_failures", 0) + 1
            cache.set(f"{circuit_key}_failures", failure_count, 3600)
            cache.set(f"{circuit_key}_last_failure", time.time(), 3600)
            
            # Open circuit if threshold reached
            if failure_count >= self.failure_threshold:
                cache.set(circuit_key, 'open', 3600)
                self._create_alert(engine_name, 'Engine health check failed multiple times')
            
            return health_result
    
    def check_all_engines(self) -> Dict[str, Dict[str, Any]]:
        """Check health of all engines."""
        results = {}
        for engine_name in engine_manager.clients.keys():
            results[engine_name] = self.check_engine_health(engine_name)
        return results
    
    def _create_alert(self, engine_name: str, message: str):
        """Create alert for engine failure."""
        # Check if alert already exists
        existing = AdminAlert.objects.filter(
            alert_type='engine_down',
            tenant_id__isnull=True,
            status='open',
            message__icontains=engine_name
        ).first()
        
        if not existing:
            AdminAlert.objects.create(
                alert_type='engine_down',
                severity='high',
                message=f"{engine_name}: {message}",
                status='open'
            )


# Global instance
health_checker = EngineHealthChecker()
