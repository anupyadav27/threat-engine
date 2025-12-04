"""
Azure Client Manager - Enhanced client factory with pooling and lifecycle management

This manager:
1. Pools clients by Python package (not by service)
2. Reuses client instances across services sharing the same package
3. Manages client lifecycle and cleanup
4. Provides statistics and monitoring
"""

import logging
from typing import Dict, Any, Optional, List
from collections import defaultdict
from azure.identity import DefaultAzureCredential, ClientSecretCredential
import os

try:
    from .service_registry import ServiceRegistry
except ImportError:
    from service_registry import ServiceRegistry

logger = logging.getLogger(__name__)


class AzureClientManager:
    """
    Enhanced Azure client manager with pooling
    
    Unlike basic client factory that creates one client per service,
    this manager pools clients by package for efficiency.
    """
    
    def __init__(self, subscription_id: Optional[str] = None, credential: Optional[Any] = None):
        """
        Initialize client manager
        
        Args:
            subscription_id: Azure subscription ID
            credential: Azure credential object
        """
        self.subscription_id = subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        if not self.subscription_id:
            raise ValueError("AZURE_SUBSCRIPTION_ID must be set")
        
        # Initialize credential
        if credential:
            self.credential = credential
        else:
            client_id = os.getenv('AZURE_CLIENT_ID')
            client_secret = os.getenv('AZURE_CLIENT_SECRET')
            tenant_id = os.getenv('AZURE_TENANT_ID')
            
            if client_id and client_secret and tenant_id:
                self.credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                logger.info("Using ClientSecretCredential")
            else:
                self.credential = DefaultAzureCredential()
                logger.info("Using DefaultAzureCredential")
        
        # Client pool: package → client instance
        self._client_pool: Dict[str, Any] = {}
        
        # Service registry
        self.registry = ServiceRegistry()
        
        # Statistics
        self._stats = {
            'clients_created': 0,
            'clients_reused': 0,
            'services_accessed': defaultdict(int)
        }
    
    def get_client(self, service_name: str) -> Any:
        """
        Get client for a service (pooled by package)
        
        Args:
            service_name: Service name (e.g., 'compute', 'storage')
        
        Returns:
            Azure SDK client instance (pooled)
        """
        service_name = service_name.lower()
        
        # Get service info from registry
        try:
            service_info = self.registry.get_service_info(service_name)
        except ValueError as e:
            raise ValueError(
                f"Service '{service_name}' not found. "
                f"Available: {', '.join(self.registry.list_all_services()[:10])}..."
            )
        
        package = service_info['package']
        client_class_name = service_info['client']
        
        # Check if client already exists in pool
        if package in self._client_pool:
            logger.debug(f"Reusing client for '{service_name}' (package: {package})")
            self._stats['clients_reused'] += 1
            self._stats['services_accessed'][service_name] += 1
            return self._client_pool[package]
        
        # Create new client
        try:
            logger.info(f"Creating new client for '{service_name}' (package: {package})")
            
            # Convert package name: azure-mgmt-compute → azure.mgmt.compute
            import_path = package.replace('-', '.')
            
            # Import the module dynamically
            module = __import__(import_path, fromlist=[client_class_name])
            client_class = getattr(module, client_class_name)
            
            # Create client based on type
            if service_info.get('graph_based'):
                # Microsoft Graph SDK
                client = client_class(credentials=self.credential)
                logger.info(f"Created MS Graph client for {service_name}")
            
            elif service_info.get('data_plane'):
                # Data plane - return class (needs resource URL at runtime)
                logger.warning(
                    f"Data plane client '{service_name}' requires resource URL. "
                    f"Returning class, not instance."
                )
                return client_class
            
            else:
                # Standard management plane client
                client = client_class(
                    credential=self.credential,
                    subscription_id=self.subscription_id
                )
                logger.info(f"Created management plane client for {service_name}")
            
            # Add to pool
            self._client_pool[package] = client
            self._stats['clients_created'] += 1
            self._stats['services_accessed'][service_name] += 1
            
            return client
            
        except ImportError as e:
            raise ImportError(
                f"Failed to import {package}.{client_class_name}\n"
                f"Install: pip install {package.replace('.', '-')}\n"
                f"Error: {e}"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to create client for '{service_name}': {e}")
    
    def get_services_sharing_client(self, service_name: str) -> List[str]:
        """
        Get all services that share the same client as this service
        
        Useful for optimization - these services can be scanned together
        """
        service_info = self.registry.get_service_info(service_name)
        package = service_info['package']
        return self.registry.get_services_by_package(package)
    
    def get_client_for_package(self, package: str) -> Any:
        """
        Get client directly by package name
        
        Useful when you know you need a specific package
        """
        if package in self._client_pool:
            return self._client_pool[package]
        
        # Find a service using this package
        services = self.registry.get_services_by_package(package)
        if not services:
            raise ValueError(f"No services found for package '{package}'")
        
        # Get client through first service
        return self.get_client(services[0])
    
    def warm_up(self, service_names: Optional[List[str]] = None):
        """
        Pre-create clients for services
        
        Args:
            service_names: Services to warm up (all if None)
        """
        if service_names is None:
            service_names = self.registry.list_all_services()
        
        logger.info(f"Warming up clients for {len(service_names)} services...")
        
        # Group by package to minimize client creation
        grouped = self.registry.group_services_by_package(service_names)
        
        for package, services in grouped.items():
            try:
                # Create client (will be pooled)
                self.get_client(services[0])
                logger.info(f"Warmed up {package} for {len(services)} services")
            except Exception as e:
                logger.warning(f"Failed to warm up {package}: {e}")
    
    def clear_pool(self):
        """Clear all cached clients"""
        self._client_pool.clear()
        logger.info("Client pool cleared")
    
    def get_statistics(self) -> Dict:
        """Get usage statistics"""
        return {
            'clients_created': self._stats['clients_created'],
            'clients_reused': self._stats['clients_reused'],
            'efficiency': (
                100 * self._stats['clients_reused'] / 
                (self._stats['clients_created'] + self._stats['clients_reused'])
                if (self._stats['clients_created'] + self._stats['clients_reused']) > 0
                else 0
            ),
            'pool_size': len(self._client_pool),
            'services_accessed': dict(self._stats['services_accessed'])
        }
    
    def print_statistics(self):
        """Print usage statistics"""
        stats = self.get_statistics()
        
        print("=" * 80)
        print(" CLIENT MANAGER STATISTICS")
        print("=" * 80)
        print(f"Clients created:  {stats['clients_created']}")
        print(f"Clients reused:   {stats['clients_reused']}")
        print(f"Efficiency:       {stats['efficiency']:.1f}% (reuse rate)")
        print(f"Pool size:        {stats['pool_size']} clients cached")
        
        if stats['services_accessed']:
            print(f"\nServices accessed:")
            for service, count in sorted(stats['services_accessed'].items(), 
                                        key=lambda x: x[1], reverse=True)[:10]:
                print(f"  {service:20s}: {count:3d} times")


if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    try:
        print("=" * 80)
        print(" TESTING AZURE CLIENT MANAGER")
        print("=" * 80)
        
        manager = AzureClientManager()
        print(f"✓ Manager initialized for subscription: {manager.subscription_id[:8]}...")
        
        # Test client pooling
        print("\n1. Testing client pooling...")
        
        print("   Creating client for 'webapp'...")
        client1 = manager.get_client('webapp')
        print(f"   ✓ Created: {type(client1).__name__}")
        
        print("   Creating client for 'function' (same package)...")
        client2 = manager.get_client('function')
        print(f"   ✓ Got: {type(client2).__name__}")
        
        print("   Creating client for 'site' (same package)...")
        client3 = manager.get_client('site')
        print(f"   ✓ Got: {type(client3).__name__}")
        
        if client1 is client2 is client3:
            print("   ✅ All three services share the SAME client instance!")
        
        # Test different package
        print("\n2. Testing different package...")
        print("   Creating client for 'compute'...")
        client4 = manager.get_client('compute')
        print(f"   ✓ Created: {type(client4).__name__}")
        
        if client1 is not client4:
            print("   ✅ Different package = different client instance")
        
        # Show statistics
        print("\n3. Statistics:")
        manager.print_statistics()
        
        # Test service grouping
        print("\n4. Testing service grouping...")
        services = ['webapp', 'function', 'site', 'compute', 'network', 'storage']
        grouped = manager.registry.group_services_by_package(services)
        
        print(f"   Grouping {len(services)} services:")
        for package, svc_list in grouped.items():
            print(f"   {package:40s} → {svc_list}")
        
        print(f"\n   Result: {len(services)} services → {len(grouped)} client instances")
        print(f"   Efficiency: {100*(len(services)-len(grouped))/len(services):.1f}% fewer clients")
        
        print("\n✅ Client Manager working correctly!")
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

