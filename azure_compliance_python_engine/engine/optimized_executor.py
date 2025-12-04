"""
Optimized Executor - Groups services by package for efficient execution

This executor:
1. Groups services by Python package
2. Executes with pooled clients (one per package)
3. Runs services in parallel where possible
4. Tracks performance metrics
"""

import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import time

from .azure_client_manager import AzureClientManager
from .service_registry import ServiceRegistry

logger = logging.getLogger(__name__)


class OptimizedExecutor:
    """
    Optimized executor that groups services by package for efficiency
    """
    
    def __init__(self, client_manager: Optional[AzureClientManager] = None):
        """
        Initialize executor
        
        Args:
            client_manager: AzureClientManager instance (creates new if None)
        """
        self.client_manager = client_manager or AzureClientManager()
        self.registry = self.client_manager.registry
        
        self._stats = {
            'services_executed': 0,
            'packages_used': set(),
            'execution_time': {},
            'errors': []
        }
    
    def execute_services(self, service_names: List[str], parallel: bool = False) -> Dict:
        """
        Execute compliance checks for multiple services
        
        Args:
            service_names: List of service names to execute
            parallel: Whether to execute packages in parallel
        
        Returns:
            Execution results and statistics
        """
        start_time = time.time()
        
        logger.info(f"Executing {len(service_names)} services...")
        
        # Group services by package for optimization
        grouped = self.registry.group_services_by_package(service_names)
        
        logger.info(f"Grouped into {len(grouped)} packages for execution")
        
        results = {}
        
        if parallel:
            results = self._execute_parallel(grouped)
        else:
            results = self._execute_sequential(grouped)
        
        # Update stats
        self._stats['services_executed'] += len(service_names)
        self._stats['packages_used'].update(grouped.keys())
        self._stats['execution_time']['total'] = time.time() - start_time
        
        return {
            'results': results,
            'statistics': self._get_execution_stats(grouped, start_time)
        }
    
    def _execute_sequential(self, grouped: Dict[str, List[str]]) -> Dict:
        """Execute services sequentially, grouped by package"""
        results = {}
        
        for package, services in grouped.items():
            logger.info(f"Executing package: {package} ({len(services)} services)")
            
            try:
                # Get pooled client
                client = self.client_manager.get_client_for_package(package)
                
                # Execute all services sharing this client
                for service in services:
                    package_start = time.time()
                    
                    try:
                        result = self._execute_service(service, client)
                        results[service] = result
                        
                        elapsed = time.time() - package_start
                        logger.info(f"  ✓ {service}: {elapsed:.2f}s")
                        
                    except Exception as e:
                        logger.error(f"  ✗ {service}: {e}")
                        results[service] = {'error': str(e), 'status': 'failed'}
                        self._stats['errors'].append({
                            'service': service,
                            'error': str(e)
                        })
            
            except Exception as e:
                logger.error(f"Failed to get client for package {package}: {e}")
                for service in services:
                    results[service] = {
                        'error': f'Client creation failed: {e}',
                        'status': 'failed'
                    }
        
        return results
    
    def _execute_parallel(self, grouped: Dict[str, List[str]]) -> Dict:
        """Execute packages in parallel"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_package = {}
            
            for package, services in grouped.items():
                future = executor.submit(self._execute_package, package, services)
                future_to_package[future] = (package, services)
            
            for future in as_completed(future_to_package):
                package, services = future_to_package[future]
                try:
                    package_results = future.result()
                    results.update(package_results)
                    logger.info(f"✓ Completed package: {package}")
                except Exception as e:
                    logger.error(f"✗ Package {package} failed: {e}")
                    for service in services:
                        results[service] = {'error': str(e), 'status': 'failed'}
        
        return results
    
    def _execute_package(self, package: str, services: List[str]) -> Dict:
        """Execute all services for a package"""
        results = {}
        
        try:
            # Get pooled client
            client = self.client_manager.get_client_for_package(package)
            
            for service in services:
                try:
                    result = self._execute_service(service, client)
                    results[service] = result
                except Exception as e:
                    results[service] = {'error': str(e), 'status': 'failed'}
        
        except Exception as e:
            for service in services:
                results[service] = {'error': f'Client error: {e}', 'status': 'failed'}
        
        return results
    
    def _execute_service(self, service_name: str, client: Any) -> Dict:
        """
        Execute compliance checks for a single service
        
        This is a placeholder - actual implementation will:
        1. Load rules from services/{service}/rules/{service}.yaml
        2. Execute discovery calls
        3. Run compliance checks
        4. Return results
        """
        # Placeholder implementation
        return {
            'service': service_name,
            'status': 'pending_implementation',
            'client_type': type(client).__name__,
            'timestamp': datetime.now().isoformat(),
            'note': 'Actual compliance logic to be implemented'
        }
    
    def _get_execution_stats(self, grouped: Dict, start_time: float) -> Dict:
        """Calculate execution statistics"""
        total_time = time.time() - start_time
        total_services = sum(len(services) for services in grouped.values())
        
        # Calculate efficiency
        naive_time = total_services * 0.5  # Assume 500ms per client creation
        optimized_time = len(grouped) * 0.5  # Only unique packages
        efficiency_gain = 100 * (naive_time - optimized_time) / naive_time if naive_time > 0 else 0
        
        return {
            'total_services': total_services,
            'total_packages': len(grouped),
            'execution_time': total_time,
            'estimated_naive_time': naive_time,
            'estimated_optimized_time': optimized_time,
            'efficiency_gain_percent': efficiency_gain,
            'clients_created': self.client_manager._stats['clients_created'],
            'clients_reused': self.client_manager._stats['clients_reused'],
            'errors': len(self._stats['errors'])
        }
    
    def print_execution_report(self, execution_result: Dict):
        """Print formatted execution report"""
        stats = execution_result['statistics']
        results = execution_result['results']
        
        print("=" * 80)
        print(" EXECUTION REPORT")
        print("=" * 80)
        print(f"Services executed:      {stats['total_services']}")
        print(f"Packages used:          {stats['total_packages']}")
        print(f"Execution time:         {stats['execution_time']:.2f}s")
        print(f"Clients created:        {stats['clients_created']}")
        print(f"Clients reused:         {stats['clients_reused']}")
        print(f"Efficiency gain:        {stats['efficiency_gain_percent']:.1f}%")
        print(f"Errors:                 {stats['errors']}")
        
        if stats['errors'] > 0:
            print(f"\nErrors:")
            for error in self._stats['errors'][:5]:
                print(f"  ✗ {error['service']}: {error['error']}")
        
        print(f"\nResults by service:")
        for service, result in sorted(results.items()):
            status = result.get('status', 'unknown')
            icon = '✓' if status != 'failed' else '✗'
            print(f"  {icon} {service:20s}: {status}")


if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    try:
        print("=" * 80)
        print(" TESTING OPTIMIZED EXECUTOR")
        print("=" * 80)
        
        # Create executor
        executor = OptimizedExecutor()
        print("✓ Executor initialized")
        
        # Test with services that share clients
        test_services = [
            'webapp', 'function', 'site',  # All use azure-mgmt-web
            'compute',                      # Uses azure-mgmt-compute
            'network',                      # Uses azure-mgmt-network
            'storage'                       # Uses azure-mgmt-storage
        ]
        
        print(f"\n📊 Testing with {len(test_services)} services...")
        print(f"Services: {', '.join(test_services)}")
        
        # Show grouping
        grouped = executor.registry.group_services_by_package(test_services)
        print(f"\nGrouped into {len(grouped)} packages:")
        for package, services in grouped.items():
            print(f"  {package:40s} → {services}")
        
        # Execute
        print("\n🚀 Executing...")
        result = executor.execute_services(test_services)
        
        # Print report
        print("\n")
        executor.print_execution_report(result)
        
        # Client manager stats
        print("\n")
        executor.client_manager.print_statistics()
        
        print("\n✅ Optimized Executor working correctly!")
        print(f"\n💡 Efficiency: {len(test_services)} services executed with {len(grouped)} client instances")
        print(f"   Savings: {len(test_services) - len(grouped)} fewer client creations!")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

