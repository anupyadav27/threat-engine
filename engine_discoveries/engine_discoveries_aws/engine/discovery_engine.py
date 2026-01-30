"""
Discovery Engine - Phase 1: Run discoveries only, store in database
"""
import os
import sys
import yaml
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _project_root() -> Path:
    """Repo root (relative to this file)."""
    return Path(__file__).resolve().parent.parent.parent.parent


from engine.service_scanner import run_regional_service, run_global_service, load_service_rules
from engine.database_manager import DatabaseManager
from utils.phase_logger import PhaseLogger
from utils.progressive_output import ProgressiveOutputWriter
from utils.service_feature_manager import ServiceFeatureManager

logger = logging.getLogger(__name__)

class DiscoveryEngine:
    """Engine for running discoveries and storing in database"""
    
    def __init__(self, db_manager: DatabaseManager = None, use_database: Optional[bool] = None):
        """
        Initialize discovery engine
        
        Args:
            db_manager: DatabaseManager instance (optional if using file-only mode)
            use_database: If True, store discoveries in database; If False, files only;
                         If None, auto-detect from environment
        """
        self.db = db_manager
        self.use_database = self._determine_mode(use_database)
        # Use path relative to container
        config_path = Path(__file__).parent.parent / "config" / "service_list.json"
        if not config_path.exists():
            # Fallback for different directory structures
            config_path = Path("/app/config/service_list.json")
        self.feature_manager = ServiceFeatureManager(str(config_path))
        self.phase_logger = None
        self.output_writer = None
        
        if self.use_database and not self.db:
            raise ValueError("DatabaseManager required when using database mode")
    
    def _determine_mode(self, use_database: Optional[bool]) -> bool:
        """Determine whether to use database or file-only mode"""
        if use_database is not None:
            return use_database
        
        # Auto-detect from environment
        env_mode = os.getenv('DISCOVERY_MODE', '').lower()
        if env_mode in ('database', 'db', 'production'):
            return True
        elif env_mode in ('file', 'local', 'ndjson'):
            return False
        
        # Default: Use database if connection available, else files only
        if self.db:
            try:
                # Test database connection
                conn = self.db._get_connection()
                self.db._return_connection(conn)
                return True  # Database available, use it
            except Exception:
                logger.warning("Database connection failed, using file-only mode")
                return False
        
        return False  # Default to file-only for local development
    
    def run_discovery_scan(self, customer_id: str, tenant_id: str,
                          provider: str, hierarchy_id: str,
                          hierarchy_type: str, services: List[str],
                          regions: List[str] = None) -> str:
        """
        Run discovery scan for all services and store in database
        
        Args:
            customer_id: Customer ID
            tenant_id: Tenant ID (per CSP)
            provider: CSP provider ('aws', 'azure', 'gcp', etc.)
            hierarchy_id: CSP hierarchy ID (account_id, project_id, etc.)
            hierarchy_type: Hierarchy type ('account', 'project', 'subscription', etc.)
            services: List of service names to scan
            regions: List of regions to scan (None for global services)
        
        Returns:
            scan_id: Unique scan identifier
        """
        scan_id = f"discovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Setup phase logger and progressive output
        # Use OUTPUT_DIR env var if set (for Kubernetes), otherwise use project root
        output_base = os.getenv("OUTPUT_DIR")
        if output_base:
            base_output_dir = Path(output_base)
        else:
            base_output_dir = _project_root() / "engine_output" / "engine_configscan_aws" / "output"
        output_dir = base_output_dir / "discoveries" / scan_id
        self.phase_logger = PhaseLogger(scan_id, 'discovery', output_dir)
        self.output_writer = ProgressiveOutputWriter(scan_id, output_dir, 'discovery')
        
        self.phase_logger.info(f"Starting discovery scan: {scan_id}")
        self.phase_logger.info(f"  Customer: {customer_id}, Tenant: {tenant_id}")
        self.phase_logger.info(f"  Hierarchy: {hierarchy_id} ({hierarchy_type})")
        self.phase_logger.info(f"  Services: {len(services)}, Regions: {len(regions) if regions else 'global'}")
        
        # Filter services by discovery feature enablement
        services = self.feature_manager.filter_services_by_features(services, ['discovery'])
        if not services:
            self.phase_logger.warning("No services with discovery enabled")
            return scan_id
        
        self.phase_logger.info(f"  Filtered to {len(services)} services with discovery enabled")
        
        # Create scan record in database if available
        if self.db:
            self.db.create_scan(
                scan_id=scan_id,
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                hierarchy_id=hierarchy_id,
                hierarchy_type=hierarchy_type,
                scan_type='discovery',
                metadata={
                    'services': services,
                    'regions': regions or ['global'],
                    'total_services': len(services)
                }
            )
        
        total_discoveries = 0
        total_items = 0
        total_errors = 0
        
        # Get max workers for parallel service processing
        max_service_workers = int(os.getenv('MAX_SERVICE_WORKERS', '10'))
        max_region_workers = int(os.getenv('MAX_REGION_WORKERS', '5'))
        
        self.phase_logger.info(f"Using parallel processing: {max_service_workers} service workers, {max_region_workers} region workers")
        
        # Process services in parallel
        with ThreadPoolExecutor(max_workers=max_service_workers) as executor:
            futures = {}
            for service in services:
                future = executor.submit(
                    self._process_single_service,
                    service, scan_id, customer_id, tenant_id, provider,
                    hierarchy_id, hierarchy_type, regions
                )
                futures[future] = service
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(futures):
                service = futures[future]
                completed += 1
                try:
                    result = future.result()
                    total_discoveries += result.get('discoveries', 0)
                    total_items += result.get('items', 0)
                    if result.get('error'):
                        total_errors += 1
                        self.output_writer.track_error(
                            hierarchy_id, result.get('region'), service,
                            result.get('error_type', 'unknown'),
                            str(result.get('error', 'Unknown error'))
                        )
                    self.phase_logger.info(f"[{completed}/{len(services)}] ✅ {service} completed")
                except Exception as e:
                    total_errors += 1
                    self.phase_logger.error(f"[{completed}/{len(services)}] ❌ {service} failed: {e}", exc_info=True)
                    self.output_writer.track_error(
                        hierarchy_id, None, service, 'exception', str(e)
                    )
        
        # Update scan status in database if available
        if self.db:
            self.db.update_scan_status(scan_id, 'completed')
        
        # Generate final summary
        summary = self._generate_summary(scan_id, customer_id, tenant_id, provider,
                                        hierarchy_id, services, regions, total_discoveries, total_items, total_errors)
        
        # Finalize progressive output
        self.output_writer.finalize(summary)
        
        self.phase_logger.info(f"Discovery scan completed: {scan_id}")
        self.phase_logger.info(f"  Total discoveries: {total_discoveries}")
        self.phase_logger.info(f"  Total items: {total_items}")
        self.phase_logger.info(f"  Total errors: {total_errors}")
        self.phase_logger.info(f"  Output saved to: {self.output_writer.output_dir}")
        
        return scan_id
    
    def _process_single_service(self, service: str, scan_id: str, customer_id: str,
                                tenant_id: str, provider: str, hierarchy_id: str,
                                hierarchy_type: str, regions: List[str] = None) -> Dict[str, Any]:
        """
        Process a single service (called in parallel)
        
        Returns:
            Dict with 'discoveries', 'items', 'error', 'error_type', 'region'
        """
        result = {
            'discoveries': 0,
            'items': 0,
            'error': None,
            'error_type': None,
            'region': None
        }
        
        try:
            # Check if service has discoveries file (use absolute path)
            engine_dir = Path(__file__).parent.parent
            discoveries_file = engine_dir / "services" / service / "discoveries" / f"{service}.discoveries.yaml"
            
            if not discoveries_file.exists():
                self.phase_logger.warning(f"  ⚠️  Discoveries file not found: {discoveries_file}")
                result['error'] = f"Discoveries file not found: {discoveries_file}"
                result['error_type'] = 'missing_file'
                return result
            
            # Load discoveries config
            with open(discoveries_file) as f:
                discoveries_config = yaml.safe_load(f)
            
            discoveries_list = discoveries_config.get('discovery', [])
            self.phase_logger.info(f"  [{service}] Found {len(discoveries_list)} discoveries")
            
            # Determine if service is global or regional
            is_global = True
            for disc in discoveries_list:
                if disc.get('region') or any('region' in str(call) for call in disc.get('calls', [])):
                    is_global = False
                    break
            
            # Run discoveries (skip checks by passing skip_checks=True)
            if is_global or not regions:
                # Global service
                self.phase_logger.progress(service, None, 'started', {})
                self.phase_logger.info(f"  [{service}] Running as global service...")
                
                service_result = self._process_global_service(
                    service, scan_id, customer_id, tenant_id, provider,
                    hierarchy_id, hierarchy_type, discoveries_list
                )
                result.update(service_result)
                
            else:
                # Regional service - process regions in parallel
                max_region_workers = int(os.getenv('MAX_REGION_WORKERS', '5'))
                
                with ThreadPoolExecutor(max_workers=min(len(regions), max_region_workers)) as executor:
                    region_futures = {}
                    for region in regions:
                        future = executor.submit(
                            self._process_regional_service,
                            service, region, scan_id, customer_id, tenant_id, provider,
                            hierarchy_id, hierarchy_type, discoveries_list
                        )
                        region_futures[future] = region
                    
                    for future in as_completed(region_futures):
                        region = region_futures[future]
                        try:
                            region_result = future.result()
                            result['discoveries'] += region_result.get('discoveries', 0)
                            result['items'] += region_result.get('items', 0)
                            if region_result.get('error'):
                                result['error'] = region_result.get('error')
                                result['error_type'] = region_result.get('error_type')
                                result['region'] = region
                        except Exception as e:
                            self.phase_logger.error(f"  [{service}] Region {region} failed: {e}", exc_info=True)
                            result['error'] = str(e)
                            result['error_type'] = 'region_exception'
                            result['region'] = region
                
        except Exception as e:
            self.phase_logger.error(f"  [{service}] Error: {e}", exc_info=True)
            result['error'] = str(e)
            result['error_type'] = 'service_exception'
        
        return result
    
    def _process_global_service(self, service: str, scan_id: str, customer_id: str,
                                tenant_id: str, provider: str, hierarchy_id: str,
                                hierarchy_type: str, discoveries_list: List[Dict]) -> Dict[str, Any]:
        """Process a global service"""
        result = {
            'discoveries': 0,
            'items': 0,
            'error': None,
            'error_type': None
        }
        
        try:
            # Run discoveries only (skip checks)
            run_result = run_global_service(service, skip_checks=True)
            discovery_results = run_result.get('inventory', {})
            
            # Track all executed discoveries (not just those with items)
            all_discovery_ids = [disc.get('discovery_id') for disc in discoveries_list if disc.get('discovery_id')]
            executed_discoveries = len(discovery_results)
            total_discoveries = len(all_discovery_ids)
            
            records = []
            discovery_functions = []
            
            # Prepare records for file output (no database writes during scan)
            for discovery_id, items in discovery_results.items():
                if items:
                    items_list = items if isinstance(items, list) else [items]
                    
                    # Prepare records for output files and database
                    for item in items_list:
                        # Extract resource_uid (primary) and resource_arn (AWS-specific)
                        resource_uid = item.get('resource_uid') or item.get('resource_arn')
                        resource_arn = item.get('resource_arn')
                        
                        record = {
                            'scan_id': scan_id,
                            'customer_id': customer_id,
                            'tenant_id': tenant_id,
                            'provider': provider,
                            'account_id': hierarchy_id,
                            'region': None,
                            'service': service,
                            'hierarchy_id': hierarchy_id,
                            'hierarchy_type': hierarchy_type,
                            'discovery_id': discovery_id,
                            'resource_arn': resource_arn,
                            'resource_uid': resource_uid,
                            'resource_id': item.get('resource_id'),
                            'scan_timestamp': datetime.now().isoformat(),
                            'version': 1,
                            'emitted_fields': item,
                            'raw_response': item.get('_raw_response', {}),
                            'config_hash': None
                        }
                        records.append(record)
                    
                    result['discoveries'] += 1
                    result['items'] += len(items_list)
                    discovery_functions.append(discovery_id)
            
            # Write output to files
            if records:
                self.output_writer.append_service_output(hierarchy_id, None, service, records)
            
            # Store to database if enabled
            if self.use_database and self.db and records:
                try:
                    # Group records by discovery_id for batch storage
                    by_discovery = {}
                    for record in records:
                        discovery_id = record.get('discovery_id')
                        if not discovery_id:
                            continue
                        if discovery_id not in by_discovery:
                            by_discovery[discovery_id] = []
                        # Convert record to item format expected by database
                        item = {
                            'resource_arn': record.get('resource_arn'),
                            'resource_id': record.get('resource_id'),
                            '_raw_response': record.get('raw_response', {}),
                            **record.get('emitted_fields', {})
                        }
                        by_discovery[discovery_id].append(item)
                    
                    # Store each discovery in batch
                    for discovery_id, items in by_discovery.items():
                        try:
                            drift_results = self.db.store_discoveries_batch(
                                scan_id=scan_id,
                                customer_id=customer_id,
                                tenant_id=tenant_id,
                                provider=provider,
                                discovery_id=discovery_id,
                                items=items,
                                hierarchy_id=hierarchy_id,
                                hierarchy_type=hierarchy_type,
                                region=None,  # Global service
                                service=service
                            )
                            self.phase_logger.debug(f"  Stored {len(items)} items for {discovery_id} to database")
                        except Exception as e:
                            self.phase_logger.warning(f"  Failed to store {discovery_id} to database: {e}")
                except Exception as e:
                    self.phase_logger.warning(f"  Database storage failed for {service} (global): {e}")
            
            # Update progress with execution tracking
            self.output_writer.update_service_progress(
                hierarchy_id, None, service,
                executed_discoveries, len(records), discovery_functions,
                total_discoveries=total_discoveries
            )
            
            self.phase_logger.progress(service, None, 'completed', {
                'discoveries': executed_discoveries,
                'total_discoveries': total_discoveries,
                'items': len(records)
            })
            self.phase_logger.info(f"  ✅ {service} completed: {executed_discoveries}/{total_discoveries} discoveries, {len(records)} items")
            
        except Exception as e:
            result['error'] = str(e)
            result['error_type'] = 'global_service_exception'
            raise
        
        return result
    
    def _process_regional_service(self, service: str, region: str, scan_id: str,
                                  customer_id: str, tenant_id: str, provider: str,
                                  hierarchy_id: str, hierarchy_type: str,
                                  discoveries_list: List[Dict]) -> Dict[str, Any]:
        """Process a regional service for a specific region"""
        result = {
            'discoveries': 0,
            'items': 0,
            'error': None,
            'error_type': None
        }
        
        try:
            self.phase_logger.progress(service, region, 'started', {})
            
            # Run discoveries only (skip checks)
            run_result = run_regional_service(service, region=region, skip_checks=True)
            discovery_results = run_result.get('inventory', {})
            
            # Track all executed discoveries
            all_discovery_ids = [disc.get('discovery_id') for disc in discoveries_list if disc.get('discovery_id')]
            executed_discoveries = len(discovery_results)
            total_discoveries = len(all_discovery_ids)
            
            records = []
            discovery_functions = []
            
            # Prepare records for file output (no database writes during scan)
            for discovery_id, items in discovery_results.items():
                if items:
                    items_list = items if isinstance(items, list) else [items]
                    
                    # Prepare records for output files and database
                    for item in items_list:
                        # Extract resource_uid (primary) and resource_arn (AWS-specific)
                        resource_uid = item.get('resource_uid') or item.get('resource_arn')
                        resource_arn = item.get('resource_arn')
                        
                        record = {
                            'scan_id': scan_id,
                            'customer_id': customer_id,
                            'tenant_id': tenant_id,
                            'provider': provider,
                            'account_id': hierarchy_id,
                            'region': region,
                            'service': service,
                            'hierarchy_id': hierarchy_id,
                            'hierarchy_type': hierarchy_type,
                            'discovery_id': discovery_id,
                            'resource_arn': resource_arn,
                            'resource_uid': resource_uid,
                            'resource_id': item.get('resource_id'),
                            'scan_timestamp': datetime.now().isoformat(),
                            'version': 1,
                            'emitted_fields': item,
                            'raw_response': item.get('_raw_response', {}),
                            'config_hash': None
                        }
                        records.append(record)
                    
                    result['discoveries'] += 1
                    result['items'] += len(items_list)
                    discovery_functions.append(discovery_id)
            
            # Write output to files
            if records:
                self.output_writer.append_service_output(hierarchy_id, region, service, records)
            
            # Store to database if enabled
            if self.use_database and self.db and records:
                try:
                    # Group records by discovery_id for batch storage
                    by_discovery = {}
                    for record in records:
                        discovery_id = record.get('discovery_id')
                        if not discovery_id:
                            continue
                        if discovery_id not in by_discovery:
                            by_discovery[discovery_id] = []
                        # Convert record to item format expected by database
                        item = {
                            'resource_arn': record.get('resource_arn'),
                            'resource_id': record.get('resource_id'),
                            '_raw_response': record.get('raw_response', {}),
                            **record.get('emitted_fields', {})
                        }
                        by_discovery[discovery_id].append(item)
                    
                    # Store each discovery in batch
                    for discovery_id, items in by_discovery.items():
                        try:
                            drift_results = self.db.store_discoveries_batch(
                                scan_id=scan_id,
                                customer_id=customer_id,
                                tenant_id=tenant_id,
                                provider=provider,
                                discovery_id=discovery_id,
                                items=items,
                                hierarchy_id=hierarchy_id,
                                hierarchy_type=hierarchy_type,
                                region=region,
                                service=service
                            )
                            self.phase_logger.debug(f"  Stored {len(items)} items for {discovery_id} to database (resource_uid)")
                        except Exception as e:
                            self.phase_logger.warning(f"  Failed to store {discovery_id} to database: {e}")
                except Exception as e:
                    self.phase_logger.warning(f"  Database storage failed for {service} ({region}): {e}")
            
            # Update progress
            self.output_writer.update_service_progress(
                hierarchy_id, region, service,
                executed_discoveries, len(records), discovery_functions,
                total_discoveries=total_discoveries
            )
            
            self.phase_logger.progress(service, region, 'completed', {
                'discoveries': executed_discoveries,
                'total_discoveries': total_discoveries,
                'items': len(records)
            })
            self.phase_logger.info(f"  ✅ {service} ({region}) completed: {executed_discoveries}/{total_discoveries} discoveries, {len(records)} items")
            
        except Exception as e:
            result['error'] = str(e)
            result['error_type'] = 'regional_service_exception'
            raise
        
        return result
    
    def _generate_summary(self, scan_id: str, customer_id: str, tenant_id: str,
                         provider: str, hierarchy_id: str, services: List[str],
                         regions: List[str], total_discoveries: int, total_items: int,
                         total_errors: int = 0) -> Dict:
        """Generate final summary for discovery scan"""
        progress = self.output_writer.get_progress()
        
        # Group by service
        by_service = {}
        for key, svc_info in progress.get('services', {}).items():
            service = svc_info['service']
            if service not in by_service:
                by_service[service] = {
                    'total_records': 0,
                    'discovery_functions': [],
                    'regions': []
                }
            by_service[service]['total_records'] += svc_info['item_count']
            by_service[service]['discovery_functions'].extend(svc_info['discovery_functions'])
            if svc_info['region'] not in by_service[service]['regions']:
                by_service[service]['regions'].append(svc_info['region'])
        
        # Deduplicate discovery functions
        for service in by_service:
            by_service[service]['discovery_functions'] = list(set(by_service[service]['discovery_functions']))
        
        summary = {
            'scan_id': scan_id,
            'customer_id': customer_id,
            'tenant_id': tenant_id,
            'provider': provider,
            'account_id': hierarchy_id,
            'hierarchy_type': 'account',
            'scan_timestamp': datetime.now().isoformat(),
            'services_scanned': services,
            'regions_scanned': regions or ['global'],
            'total_records': total_items,
            'total_discoveries': total_discoveries,
            'total_services': len(by_service),
            'total_errors': total_errors,
            'by_service': by_service,
            'output_directory': str(self.output_writer.output_dir)
        }
        
        return summary
    
    def _export_discoveries_to_file(self, scan_id: str, customer_id: str,
                                    tenant_id: str, provider: str,
                                    hierarchy_id: str, services: List[str],
                                    regions: List[str] = None) -> str:
        """
        Export discoveries to local JSON/NDJSON files
        
        Returns:
            Path to output directory
        """
        # Create output directory structure
        base_output_dir = _project_root() / "engine_output" / "engine_configscan_aws" / "output"
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = base_output_dir / "discoveries" / f"{scan_id}_{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Exporting discoveries to: {output_dir}")
        
        # Query all discoveries for this scan
        all_discoveries = self.db.query_discovery(
            scan_id=scan_id,
            tenant_id=tenant_id,
            hierarchy_id=hierarchy_id
        )
        
        # Group by account_id + region + service
        by_account_region_service = {}
        by_service = {}
        by_discovery_function = {}
        
        for disc in all_discoveries:
            account_id = disc.get('hierarchy_id', hierarchy_id)
            region = disc.get('region') or 'global'
            service = disc.get('service', 'unknown')
            discovery_id = disc.get('discovery_id', 'unknown')
            
            # Group by account+region+service
            key = f"{account_id}_{region}_{service}"
            if key not in by_account_region_service:
                by_account_region_service[key] = {
                    'account_id': account_id,
                    'region': region,
                    'service': service,
                    'items': []
                }
            by_account_region_service[key]['items'].append(disc)
            
            # Group by service (for summary)
            if service not in by_service:
                by_service[service] = []
            by_service[service].append(disc)
            
            # Group by discovery function (for summary)
            if discovery_id not in by_discovery_function:
                by_discovery_function[discovery_id] = {
                    'service': service,
                    'region': region,
                    'count': 0
                }
            by_discovery_function[discovery_id]['count'] += 1
        
        # Export per account+region+service
        files_created = []
        for key, group in sorted(by_account_region_service.items()):
            account_id = group['account_id']
            region = group['region']
            service = group['service']
            items = group['items']
            
            # Create filename: {account_id}_{region}_{service}.ndjson
            if region == 'global' or region is None:
                filename = f"{account_id}_global_{service}.ndjson"
            else:
                filename = f"{account_id}_{region}_{service}.ndjson"
            
            ndjson_file = output_dir / filename
            
            with open(ndjson_file, 'w') as f:
                for disc in items:
                    # Parse JSONB fields
                    emitted_fields = disc.get('emitted_fields')
                    raw_response = disc.get('raw_response')
                    
                    if isinstance(emitted_fields, str):
                        try:
                            emitted_fields = json.loads(emitted_fields)
                        except:
                            emitted_fields = {}
                    
                    if isinstance(raw_response, str):
                        try:
                            raw_response = json.loads(raw_response)
                        except:
                            raw_response = {}
                    
                    # Create output record
                    record = {
                        'scan_id': scan_id,
                        'customer_id': disc.get('customer_id'),
                        'tenant_id': disc.get('tenant_id'),
                        'provider': disc.get('provider'),
                        'account_id': account_id,
                        'region': region,
                        'service': service,
                        'hierarchy_id': disc.get('hierarchy_id'),
                        'hierarchy_type': disc.get('hierarchy_type'),
                        'discovery_id': disc.get('discovery_id'),
                        'resource_arn': disc.get('resource_arn'),
                        'resource_id': disc.get('resource_id'),
                        'scan_timestamp': disc.get('scan_timestamp').isoformat() if disc.get('scan_timestamp') else None,
                        'version': disc.get('version'),
                        'emitted_fields': emitted_fields,
                        'raw_response': raw_response,
                        'config_hash': disc.get('config_hash')
                    }
                    
                    f.write(json.dumps(record, default=str) + "\n")
            
            files_created.append({
                'filename': filename,
                'account_id': account_id,
                'region': region,
                'service': service,
                'count': len(items)
            })
            
            logger.info(f"  ✅ {filename}: {len(items)} records")
        
        # Create enhanced summary JSON
        # Group discovery functions by service
        discovery_functions_by_service = {}
        for disc_id, info in by_discovery_function.items():
            service = info['service']
            if service not in discovery_functions_by_service:
                discovery_functions_by_service[service] = []
            discovery_functions_by_service[service].append({
                'discovery_id': disc_id,
                'count': info['count'],
                'region': info['region']
            })
        
        summary = {
            'scan_id': scan_id,
            'customer_id': customer_id,
            'tenant_id': tenant_id,
            'provider': provider,
            'account_id': hierarchy_id,
            'hierarchy_type': 'account',
            'scan_timestamp': datetime.now().isoformat(),
            'services_scanned': services,
            'regions_scanned': regions or ['global'],
            'total_records': len(all_discoveries),
            'total_services': len(by_service),
            'total_discovery_functions': len(by_discovery_function),
            'by_service': {
                service: {
                    'total_records': len(discs),
                    'discovery_functions': len([d for d_id, d in by_discovery_function.items() if d['service'] == service]),
                    'discovery_functions_list': [
                        {
                            'discovery_id': df['discovery_id'],
                            'count': df['count']
                        }
                        for df in discovery_functions_by_service.get(service, [])
                    ]
                }
                for service, discs in sorted(by_service.items())
            },
            'discovery_functions': {
                disc_id: {
                    'service': info['service'],
                    'region': info['region'],
                    'count': info['count']
                }
                for disc_id, info in sorted(by_discovery_function.items())
            },
            'files_created': files_created,
            'output_directory': str(output_dir)
        }
        
        summary_file = output_dir / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        logger.info(f"  ✅ Summary saved to {summary_file.name}")
        logger.info(f"  📊 Total: {len(all_discoveries)} records, {len(by_service)} services, {len(by_discovery_function)} discovery functions")
        
        return str(output_dir)
    
    def run_discovery_for_all_services(self, customer_id: str, tenant_id: str,
                                      provider: str, hierarchy_id: str,
                                      hierarchy_type: str,
                                      regions: List[str] = None) -> str:
        """
        Run discoveries for ALL services
        
        Args:
            regions: List of regions (None for all regions or global)
        
        Returns:
            scan_id
        """
        # Get all services
        services_dir = Path("services")
        services = [
            d.name for d in services_dir.iterdir()
            if d.is_dir() and not d.name.startswith('.')
            and (d / "discoveries").exists()
        ]
        
        logger.info(f"Found {len(services)} services with discoveries")
        
        return self.run_discovery_scan(
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            services=services,
            regions=regions
        )

