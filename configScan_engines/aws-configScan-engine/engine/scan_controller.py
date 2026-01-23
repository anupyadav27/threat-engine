"""
Scan Controller - Orchestrate different scan modes
"""
import os
import sys
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.discovery_engine import DiscoveryEngine
from engine.check_engine import CheckEngine
from engine.database_manager import DatabaseManager
from utils.service_feature_manager import ServiceFeatureManager

logger = logging.getLogger(__name__)

class ScanController:
    """Control scan execution based on mode and features"""
    
    def __init__(self, db_manager: Optional[DatabaseManager] = None, use_ndjson: Optional[bool] = None):
        """
        Initialize scan controller
        
        Args:
            db_manager: DatabaseManager instance (optional if using NDJSON)
            use_ndjson: If True, use NDJSON files; If False, use database; 
                       If None, auto-detect from environment
        """
        self.db = db_manager
        self.use_ndjson = use_ndjson
        # Discovery engine requires database (for now), so only initialize if db_manager provided
        if db_manager:
            self.discovery_engine = DiscoveryEngine(db_manager)
        else:
            self.discovery_engine = None
            logger.warning("DiscoveryEngine not initialized (requires database). Use NDJSON mode for checks only.")
        self.check_engine = CheckEngine(db_manager, use_ndjson=use_ndjson)
        self.feature_manager = ServiceFeatureManager()
        self.scan_config = self._load_scan_config()
    
    def _load_scan_config(self) -> Dict:
        """Load scan configuration"""
        config_path = Path("config/scan_config.json")
        try:
            with open(config_path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load scan config: {e}, using defaults")
            return {
                "scan_modes": {
                    "discovery_only": {"enabled": True},
                    "check_only": {"enabled": True},
                    "full_scan": {"enabled": True}
                },
                "default_scan_mode": "full_scan"
            }
    
    def run_scan(self, 
                 customer_id: str,
                 tenant_id: str,
                 provider: str = 'aws',
                 hierarchy_id: str = None,
                 hierarchy_type: str = 'account',
                 scan_mode: str = None,
                 services: Optional[List[str]] = None,
                 regions: Optional[List[str]] = None,
                 discovery_scan_id: Optional[str] = None,
                 use_ndjson: Optional[bool] = None,
                 **kwargs) -> Dict[str, Any]:
        """
        Run scan based on mode
        
        Args:
            customer_id: Customer ID
            tenant_id: Tenant ID
            provider: CSP provider
            hierarchy_id: Hierarchy ID
            hierarchy_type: Hierarchy type
            scan_mode: 'discovery_only', 'check_only', 'full_scan', 'deviation_scan', 'drift_scan'
            services: List of services (None = all enabled)
            regions: List of regions (None = all or global)
            discovery_scan_id: Required for 'check_only' mode
            **kwargs: Additional arguments
        
        Returns:
            Dict with scan results
        """
        # Determine scan mode
        if scan_mode is None:
            scan_mode = self.scan_config.get('default_scan_mode', 'full_scan')
        
        # Validate scan mode
        scan_modes = self.scan_config.get('scan_modes', {})
        if scan_mode not in scan_modes:
            raise ValueError(f"Unknown scan mode: {scan_mode}")
        
        if not scan_modes[scan_mode].get('enabled', False):
            raise ValueError(f"Scan mode '{scan_mode}' is not enabled")
        
        logger.info(f"Running scan in mode: {scan_mode}")
        
        # Execute based on mode
        if scan_mode == 'discovery_only':
            return self._run_discovery_only(
                customer_id, tenant_id, provider, hierarchy_id, 
                hierarchy_type, services, regions, **kwargs
            )
        elif scan_mode == 'check_only':
            if not discovery_scan_id:
                raise ValueError("discovery_scan_id required for check_only mode")
            return self._run_check_only(
                discovery_scan_id, customer_id, tenant_id, provider,
                hierarchy_id, hierarchy_type, services, use_ndjson=use_ndjson, **kwargs
            )
        elif scan_mode == 'full_scan':
            return self._run_full_scan(
                customer_id, tenant_id, provider, hierarchy_id,
                hierarchy_type, services, regions, **kwargs
            )
        elif scan_mode == 'deviation_scan':
            raise NotImplementedError("Deviation scan not yet implemented")
        elif scan_mode == 'drift_scan':
            raise NotImplementedError("Drift scan not yet implemented")
        else:
            raise ValueError(f"Unsupported scan mode: {scan_mode}")
    
    def _run_discovery_only(self, customer_id: str, tenant_id: str,
                           provider: str, hierarchy_id: str,
                           hierarchy_type: str, services: Optional[List[str]],
                           regions: Optional[List[str]], **kwargs) -> Dict[str, Any]:
        """Run discovery phase only"""
        if not self.discovery_engine:
            return {
                'scan_mode': 'discovery_only',
                'status': 'skipped',
                'reason': 'DiscoveryEngine not initialized (requires database)'
            }
        
        # Filter services by discovery feature enablement
        if services:
            services = self.feature_manager.filter_services_by_features(services, ['discovery'])
        else:
            services = self.feature_manager.get_enabled_services('discovery')
        
        if not services:
            return {
                'scan_mode': 'discovery_only',
                'status': 'skipped',
                'reason': 'No services with discovery enabled'
            }
        
        logger.info(f"Running discovery for {len(services)} services")
        
        discovery_scan_id = self.discovery_engine.run_discovery_scan(
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            services=services,
            regions=regions
        )
        
        return {
            'scan_mode': 'discovery_only',
            'status': 'completed',
            'discovery_scan_id': discovery_scan_id,
            'services': services
        }
    
    def _run_check_only(self, discovery_scan_id: str, customer_id: str,
                       tenant_id: str, provider: str, hierarchy_id: str,
                       hierarchy_type: str, services: Optional[List[str]],
                       use_ndjson: Optional[bool] = None,
                       **kwargs) -> Dict[str, Any]:
        """Run check phase only (hybrid mode)"""
        # Filter services by check feature enablement
        if services:
            services = self.feature_manager.filter_services_by_features(services, ['checks'])
        else:
            services = self.feature_manager.get_enabled_services('checks')
        
        if not services:
            return {
                'scan_mode': 'check_only',
                'status': 'skipped',
                'reason': 'No services with checks enabled'
            }
        
        logger.info(f"Running checks for {len(services)} services")
        
        # Use instance default if not specified
        check_mode = use_ndjson if use_ndjson is not None else self.use_ndjson
        
        check_results = self.check_engine.run_check_scan(
            scan_id=discovery_scan_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            services=services,
            check_source='default',
            use_ndjson=check_mode
        )
        
        return {
            'scan_mode': 'check_only',
            'status': 'completed',
            'discovery_scan_id': discovery_scan_id,
            'check_scan_id': check_results.get('check_scan_id'),
            'check_results': check_results,
            'services': services
        }
    
    def _run_full_scan(self, customer_id: str, tenant_id: str,
                      provider: str, hierarchy_id: str,
                      hierarchy_type: str, services: Optional[List[str]],
                      regions: Optional[List[str]], **kwargs) -> Dict[str, Any]:
        """Run discovery + checks"""
        # Discovery phase
        discovery_result = self._run_discovery_only(
            customer_id, tenant_id, provider, hierarchy_id,
            hierarchy_type, services, regions, **kwargs
        )
        
        if discovery_result['status'] != 'completed':
            return discovery_result
        
        discovery_scan_id = discovery_result['discovery_scan_id']
        
        # Check phase
        check_result = self._run_check_only(
            discovery_scan_id, customer_id, tenant_id, provider,
            hierarchy_id, hierarchy_type, services, 
            use_ndjson=kwargs.get('use_ndjson'), **kwargs
        )
        
        return {
            'scan_mode': 'full_scan',
            'status': 'completed',
            'discovery_scan_id': discovery_scan_id,
            'check_result': check_result
        }

