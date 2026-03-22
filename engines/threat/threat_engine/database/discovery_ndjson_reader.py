"""
NDJSON Reader for Discovery Results

Reads discovery results from NDJSON files when database is not available.
Used as fallback for local testing and development.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict, Counter

def _default_ndjson_base() -> Path:
    from engine_common.storage_paths import get_project_root
    return get_project_root() / "engine_output" / "engine_configscan_aws" / "output" / "configscan" / "discoveries"


class DiscoveryNDJSONReader:
    """Read discovery results from NDJSON files"""
    
    def __init__(self, ndjson_base: Path = None):
        """
        Initialize NDJSON reader
        
        Args:
            ndjson_base: Base directory for NDJSON files (default: engine_output/...)
        """
        self.ndjson_base = ndjson_base or _default_ndjson_base()
        self._cache = {}  # Cache loaded data
    
    def find_latest_ndjson_dir(self) -> Optional[Path]:
        """Find the most recent discovery scan directory"""
        scan_dirs = sorted(self.ndjson_base.glob("discovery_*"), reverse=True)
        for scan_dir in scan_dirs:
            discovery_dir = scan_dir / "discovery"
            if discovery_dir.exists():
                return discovery_dir
        return None
    
    def load_all_records(self, scan_id: Optional[str] = None) -> List[Dict]:
        """Load all records from NDJSON files for a scan"""
        if scan_id:
            scan_dir = self.ndjson_base / scan_id / "discovery"
        else:
            scan_dir = self.find_latest_ndjson_dir()
        
        if not scan_dir or not scan_dir.exists():
            return []
        
        # Check cache
        cache_key = str(scan_dir)
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        records = []
        # Load all NDJSON files in the discovery directory
        for ndjson_file in scan_dir.glob("*.ndjson"):
            with open(ndjson_file, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        records.append(record)
                    except json.JSONDecodeError:
                        continue
        
        # Cache results
        self._cache[cache_key] = records
        return records
    
    def get_dashboard_stats(self, tenant_id: str, customer_id: Optional[str] = None,
                           limit_recent_scans: int = 5) -> Dict[str, Any]:
        """Get dashboard statistics from NDJSON"""
        # Find all scan directories
        scan_dirs = sorted(self.ndjson_base.glob("discovery_*"), reverse=True)
        
        all_records = []
        scan_stats = {}
        
        for scan_dir in scan_dirs[:limit_recent_scans]:  # Limit to recent scans
            scan_id = scan_dir.name
            records = self.load_all_records(scan_id)
            
            # Filter by tenant/customer
            filtered = self._filter_records(records, tenant_id, customer_id)
            
            if filtered:
                all_records.extend(filtered)
                
                # Calculate scan stats
                unique_resources = len(set(r.get('resource_arn') for r in filtered if r.get('resource_arn')))
                scan_stats[scan_id] = {
                    'scan_id': scan_id,
                    'total_discoveries': len(filtered),
                    'unique_resources': unique_resources,
                    'first_seen_at': filtered[0].get('first_seen_at') if filtered else None
                }
        
        if not all_records:
            return {
                'total_discoveries': 0,
                'unique_resources': 0,
                'services_scanned': 0,
                'top_services': [],
                'recent_scans': []
            }
        
        # Service stats
        service_counts = Counter()
        service_resources = defaultdict(set)
        service_regions = defaultdict(set)
        
        for record in all_records:
            service = record.get('service', 'unknown')
            service_counts[service] += 1
            if record.get('resource_arn'):
                service_resources[service].add(record['resource_arn'])
            if record.get('region'):
                service_regions[service].add(record['region'])
        
        # Top services
        top_services = []
        for service, count in service_counts.most_common(10):
            top_services.append({
                'service': service,
                'total_discoveries': count,
                'unique_resources': len(service_resources[service]),
                'regions': list(service_regions[service]),
                'discovery_functions': []  # Can be enhanced
            })
        
        # Recent scans
        recent_scans = []
        for scan_id, stats in sorted(scan_stats.items(), key=lambda x: x[1].get('first_seen_at') or '', reverse=True):
            recent_scans.append(stats)
        
        return {
            'total_discoveries': len(all_records),
            'unique_resources': len(set(r.get('resource_arn') for r in all_records if r.get('resource_arn'))),
            'services_scanned': len(service_counts),
            'top_services': top_services,
            'recent_scans': recent_scans,
            'last_first_seen_at': recent_scans[0].get('first_seen_at') if recent_scans else None
        }
    
    def list_scans(self, tenant_id: str, customer_id: Optional[str] = None,
                   page: int = 1, page_size: int = 20) -> Tuple[List[Dict], int]:
        """List scans with pagination"""
        scan_dirs = sorted(self.ndjson_base.glob("discovery_*"), reverse=True)
        
        scans = []
        for scan_dir in scan_dirs:
            scan_id = scan_dir.name
            records = self.load_all_records(scan_id)
            filtered = self._filter_records(records, tenant_id, customer_id)
            
            if not filtered:
                continue
            
            # Calculate stats
            unique_resources = len(set(r.get('resource_arn') for r in filtered if r.get('resource_arn')))
            services = len(set(r.get('service') for r in filtered))
            regions = len(set(r.get('region') for r in filtered if r.get('region')))
            
            sample = filtered[0]
            
            scans.append({
                'scan_id': scan_id,
                'customer_id': sample.get('customer_id'),
                'tenant_id': sample.get('tenant_id'),
                'provider': sample.get('provider'),
                'account_id': sample.get('account_id'),
                'hierarchy_type': sample.get('hierarchy_type'),
                'total_discoveries': len(filtered),
                'unique_resources': unique_resources,
                'services_scanned': services,
                'regions_scanned': regions,
                'first_seen_at': sample.get('first_seen_at')
            })
        
        # Paginate
        total = len(scans)
        offset = (page - 1) * page_size
        paginated = scans[offset:offset + page_size]
        
        return paginated, total
    
    def get_scan_summary(self, scan_id: str, tenant_id: str) -> Optional[Dict]:
        """Get summary for a specific scan"""
        records = self.load_all_records(scan_id)
        filtered = [
            r for r in records
            if r.get('tenant_id') == tenant_id
        ]
        
        if not filtered:
            return None
        
        unique_resources = len(set(r.get('resource_arn') for r in filtered if r.get('resource_arn')))
        services = len(set(r.get('service') for r in filtered))
        regions = len(set(r.get('region') for r in filtered if r.get('region')))
        
        sample = filtered[0]
        
        return {
            'scan_id': scan_id,
            'customer_id': sample.get('customer_id'),
            'tenant_id': sample.get('tenant_id'),
            'provider': sample.get('provider'),
            'account_id': sample.get('account_id'),
            'hierarchy_type': sample.get('hierarchy_type'),
            'total_discoveries': len(filtered),
            'unique_resources': unique_resources,
            'services_scanned': services,
            'regions_scanned': regions,
            'first_seen_at': sample.get('first_seen_at')
        }
    
    def get_service_stats(self, scan_id: str, tenant_id: str) -> List[Dict]:
        """Get statistics for all services in a scan"""
        records = self.load_all_records(scan_id)
        filtered = [
            r for r in records
            if r.get('tenant_id') == tenant_id
        ]
        
        # Group by service
        service_stats = defaultdict(lambda: {
            'total': 0,
            'resources': set(),
            'regions': set(),
            'functions': set()
        })
        
        for record in filtered:
            service = record.get('service', 'unknown')
            service_stats[service]['total'] += 1
            if record.get('resource_arn'):
                service_stats[service]['resources'].add(record['resource_arn'])
            if record.get('region'):
                service_stats[service]['regions'].add(record['region'])
            if record.get('discovery_id'):
                service_stats[service]['functions'].add(record['discovery_id'])
        
        # Convert to list
        results = []
        for service, stats in sorted(service_stats.items()):
            results.append({
                'service': service,
                'total_discoveries': stats['total'],
                'unique_resources': len(stats['resources']),
                'regions': list(stats['regions']),
                'discovery_functions': list(stats['functions'])
            })
        
        return results
    
    def get_service_detail(self, scan_id: str, service: str, tenant_id: str) -> Optional[Dict]:
        """Get detailed statistics for a specific service in a scan"""
        records = self.load_all_records(scan_id)
        filtered = [
            r for r in records
            if r.get('tenant_id') == tenant_id
            and r.get('service', '').lower() == service.lower()
        ]
        
        if not filtered:
            return None
        
        # Overall stats
        unique_resources = len(set(r.get('resource_arn') for r in filtered if r.get('resource_arn')))
        regions = list(set(r.get('region') for r in filtered if r.get('region')))
        
        # Discovery function stats
        function_counts = defaultdict(lambda: {'total': 0, 'resources': set()})
        
        for record in filtered:
            disc_id = record.get('discovery_id', 'unknown')
            function_counts[disc_id]['total'] += 1
            if record.get('resource_arn'):
                function_counts[disc_id]['resources'].add(record['resource_arn'])
        
        # Convert functions to list
        functions = []
        for disc_id, stats in sorted(function_counts.items(), key=lambda x: x[1]['total'], reverse=True):
            functions.append({
                'discovery_id': disc_id,
                'total': stats['total'],
                'unique_resources': len(stats['resources']),
                'resource_arns': list(stats['resources'])
            })
        
        return {
            'service': service,
            'scan_id': scan_id,
            'total_discoveries': len(filtered),
            'unique_resources': unique_resources,
            'regions': regions,
            'discovery_functions': functions[:50],  # Limit to 50
            'top_resources': []  # Can be enhanced
        }
    
    def get_discoveries(self, scan_id: Optional[str] = None, tenant_id: str = None,
                       customer_id: Optional[str] = None, service: Optional[str] = None,
                       discovery_id: Optional[str] = None, resource_arn: Optional[str] = None,
                       page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """Get discoveries with filtering and pagination"""
        if scan_id:
            records = self.load_all_records(scan_id)
        else:
            # Load from latest scan
            records = self.load_all_records()
        
        # Filter
        filtered = records
        if tenant_id:
            filtered = [r for r in filtered if r.get('tenant_id') == tenant_id]
        if customer_id:
            filtered = [r for r in filtered if r.get('customer_id') == customer_id]
        if service:
            filtered = [r for r in filtered if r.get('service') == service]
        if discovery_id:
            filtered = [r for r in filtered if r.get('discovery_id') == discovery_id]
        if resource_arn:
            filtered = [r for r in filtered if r.get('resource_arn') == resource_arn]
        
        # Sort by timestamp descending
        filtered.sort(key=lambda x: x.get('first_seen_at') or '', reverse=True)
        
        # Paginate
        total = len(filtered)
        offset = (page - 1) * page_size
        paginated = filtered[offset:offset + page_size]
        
        # Format for API
        formatted = []
        for record in paginated:
            formatted.append({
                'id': None,  # No DB ID
                'scan_id': record.get('scan_id'),
                'customer_id': record.get('customer_id'),
                'tenant_id': record.get('tenant_id'),
                'provider': record.get('provider'),
                'account_id': record.get('account_id'),
                'hierarchy_type': record.get('hierarchy_type'),
                'discovery_id': record.get('discovery_id'),
                'region': record.get('region'),
                'service': record.get('service'),
                'resource_arn': record.get('resource_arn'),
                'resource_id': record.get('resource_id'),
                'raw_response': record.get('raw_response', {}),
                'emitted_fields': record.get('emitted_fields', {}),
                'config_hash': record.get('config_hash'),
                'first_seen_at': record.get('first_seen_at'),
                'version': record.get('version', 1)
            })
        
        return formatted, total
    
    def get_resource_discoveries(self, resource_arn: str, tenant_id: str,
                                customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Get all discoveries for a specific resource ARN"""
        discoveries, _ = self.get_discoveries(
            tenant_id=tenant_id,
            customer_id=customer_id,
            resource_arn=resource_arn
        )
        
        if not discoveries:
            return None
        
        # Get discovery functions
        discovery_functions = list(set(d['discovery_id'] for d in discoveries))
        
        return {
            'resource_arn': resource_arn,
            'resource_id': discoveries[0].get('resource_id') if discoveries else None,
            'resource_type': discoveries[0].get('service') if discoveries else None,
            'total_discoveries': len(discoveries),
            'discovery_functions': discovery_functions,
            'discoveries': discoveries
        }
    
    def get_discovery_function_detail(self, discovery_id: str, tenant_id: str,
                                     customer_id: Optional[str] = None,
                                     scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Get all discoveries for a specific discovery function"""
        discoveries, _ = self.get_discoveries(
            scan_id=scan_id,
            tenant_id=tenant_id,
            customer_id=customer_id,
            discovery_id=discovery_id
        )
        
        if not discoveries:
            return None
        
        # Limit to 1000
        discoveries = discoveries[:1000]
        
        # Extract service
        service = discovery_id.split('.')[1] if '.' in discovery_id else 'unknown'
        
        # Get unique resource ARNs
        resources = list(set(d['resource_arn'] for d in discoveries if d.get('resource_arn')))
        
        return {
            'discovery_id': discovery_id,
            'service': service,
            'total_discoveries': len(discoveries),
            'resources_discovered': resources,
            'discoveries': discoveries
        }
    
    def _filter_records(self, records: List[Dict], tenant_id: str,
                       customer_id: Optional[str] = None) -> List[Dict]:
        """Filter records by tenant and customer"""
        filtered = [r for r in records if r.get('tenant_id') == tenant_id]
        if customer_id:
            filtered = [r for r in filtered if r.get('customer_id') == customer_id]
        return filtered
