"""
NDJSON Reader for Check Results

Reads check results from NDJSON files when database is not available.
Used as fallback for local testing and development.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict, Counter
from datetime import datetime

# Default NDJSON location
DEFAULT_NDJSON_BASE = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/configscan/rule_check")


class NDJSONCheckReader:
    """Read check results from NDJSON files"""
    
    def __init__(self, ndjson_base: Path = None):
        """
        Initialize NDJSON reader
        
        Args:
            ndjson_base: Base directory for NDJSON files (defaults to engines-output)
        """
        self.ndjson_base = ndjson_base or DEFAULT_NDJSON_BASE
        self._cache = {}  # Cache loaded data
    
    def find_latest_ndjson(self) -> Optional[Path]:
        """Find the most recent findings.ndjson file"""
        scan_dirs = sorted(self.ndjson_base.glob("rule_check_*"), reverse=True)
        for scan_dir in scan_dirs:
            findings_file = scan_dir / "findings.ndjson"
            if findings_file.exists():
                return findings_file
        return None
    
    def load_all_records(self, ndjson_file: Path = None) -> List[Dict]:
        """Load all records from NDJSON file"""
        if ndjson_file is None:
            ndjson_file = self.find_latest_ndjson()
        
        if not ndjson_file or not ndjson_file.exists():
            return []
        
        # Check cache
        cache_key = str(ndjson_file)
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        records = []
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
        records = self.load_all_records()
        
        if not records:
            return {
                'total_checks': 0,
                'passed': 0,
                'failed': 0,
                'error': 0,
                'pass_rate': 0.0,
                'services_scanned': 0,
                'top_failing_services': [],
                'recent_scans': []
            }
        
        # Filter by tenant/customer
        filtered = self._filter_records(records, tenant_id, customer_id)
        
        # Calculate stats
        total = len(filtered)
        passed = sum(1 for r in filtered if r.get('status') == 'PASS')
        failed = sum(1 for r in filtered if r.get('status') == 'FAIL')
        error = sum(1 for r in filtered if r.get('status') == 'ERROR')
        
        # Service stats
        service_counts = Counter()
        service_status = defaultdict(lambda: {'PASS': 0, 'FAIL': 0, 'ERROR': 0})
        
        for record in filtered:
            service = record.get('resource_type', 'unknown')
            status = record.get('status', 'UNKNOWN')
            service_counts[service] += 1
            service_status[service][status] += 1
        
        # Top failing services
        top_services = []
        for service, total_svc in service_counts.most_common(10):
            stats = service_status[service]
            passed_svc = stats['PASS']
            top_services.append({
                'service': service,
                'total': total_svc,
                'passed': passed_svc,
                'failed': stats['FAIL'],
                'error': stats['ERROR'],
                'pass_rate': round((passed_svc / total_svc * 100) if total_svc > 0 else 0.0, 2)
            })
        
        # Recent scans
        scan_ids = set(r.get('scan_id') for r in filtered if r.get('scan_id'))
        recent_scans = []
        for scan_id in list(scan_ids)[:limit_recent_scans]:
            scan_records = [r for r in filtered if r.get('scan_id') == scan_id]
            scan_total = len(scan_records)
            scan_passed = sum(1 for r in scan_records if r.get('status') == 'PASS')
            scan_failed = sum(1 for r in scan_records if r.get('status') == 'FAIL')
            scan_error = sum(1 for r in scan_records if r.get('status') == 'ERROR')
            
            # Get timestamp from first record
            scan_timestamp = None
            if scan_records:
                scan_timestamp = scan_records[0].get('scan_timestamp')
            
            recent_scans.append({
                'scan_id': scan_id,
                'total_checks': scan_total,
                'passed': scan_passed,
                'failed': scan_failed,
                'error': scan_error,
                'scan_timestamp': scan_timestamp
            })
        
        # Sort by timestamp descending
        recent_scans.sort(key=lambda x: x.get('scan_timestamp') or '', reverse=True)
        
        return {
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'error': error,
            'pass_rate': round((passed / total * 100) if total > 0 else 0.0, 2),
            'services_scanned': len(service_counts),
            'accounts_scanned': 1,
            'top_failing_services': top_services,
            'recent_scans': recent_scans,
            'last_scan_timestamp': recent_scans[0].get('scan_timestamp') if recent_scans else None
        }
    
    def list_scans(self, tenant_id: str, customer_id: Optional[str] = None,
                   page: int = 1, page_size: int = 20) -> Tuple[List[Dict], int]:
        """List scans with pagination"""
        records = self.load_all_records()
        filtered = self._filter_records(records, tenant_id, customer_id)
        
        # Group by scan_id
        scans_dict = defaultdict(lambda: {
            'scan_id': None,
            'customer_id': None,
            'tenant_id': None,
            'provider': None,
            'hierarchy_id': None,
            'hierarchy_type': None,
            'records': []
        })
        
        for record in filtered:
            scan_id = record.get('scan_id')
            if not scan_id:
                continue
            
            if not scans_dict[scan_id]['scan_id']:
                scans_dict[scan_id].update({
                    'scan_id': scan_id,
                    'customer_id': record.get('customer_id'),
                    'tenant_id': record.get('tenant_id'),
                    'provider': record.get('provider'),
                    'hierarchy_id': record.get('hierarchy_id'),
                    'hierarchy_type': record.get('hierarchy_type')
                })
            
            scans_dict[scan_id]['records'].append(record)
        
        # Convert to list and calculate stats
        scans = []
        for scan_id, scan_data in scans_dict.items():
            scan_records = scan_data['records']
            total_checks = len(scan_records)
            passed = sum(1 for r in scan_records if r.get('status') == 'PASS')
            failed = sum(1 for r in scan_records if r.get('status') == 'FAIL')
            error = sum(1 for r in scan_records if r.get('status') == 'ERROR')
            services = len(set(r.get('resource_type') for r in scan_records))
            timestamp = scan_records[0].get('scan_timestamp') if scan_records else None
            
            scans.append({
                'scan_id': scan_id,
                'discovery_scan_id': scan_records[0].get('finding_data', {}).get('discovery_id') if scan_records else None,
                'customer_id': scan_data['customer_id'],
                'tenant_id': scan_data['tenant_id'],
                'provider': scan_data['provider'],
                'hierarchy_id': scan_data['hierarchy_id'],
                'hierarchy_type': scan_data['hierarchy_type'],
                'total_checks': total_checks,
                'passed': passed,
                'failed': failed,
                'error': error,
                'pass_rate': round((passed / total_checks * 100) if total_checks > 0 else 0.0, 2),
                'services_scanned': services,
                'scan_timestamp': timestamp
            })
        
        # Sort by timestamp descending
        scans.sort(key=lambda x: x.get('scan_timestamp') or '', reverse=True)
        
        # Paginate
        total = len(scans)
        offset = (page - 1) * page_size
        paginated = scans[offset:offset + page_size]
        
        return paginated, total
    
    def get_scan_summary(self, scan_id: str, tenant_id: str) -> Optional[Dict]:
        """Get summary for a specific scan"""
        records = self.load_all_records()
        filtered = [
            r for r in records
            if r.get('scan_id') == scan_id and r.get('tenant_id') == tenant_id
        ]
        
        if not filtered:
            return None
        
        total = len(filtered)
        passed = sum(1 for r in filtered if r.get('status') == 'PASS')
        failed = sum(1 for r in filtered if r.get('status') == 'FAIL')
        error = sum(1 for r in filtered if r.get('status') == 'ERROR')
        services = len(set(r.get('resource_type') for r in filtered))
        
        sample = filtered[0]
        
        return {
            'scan_id': scan_id,
            'customer_id': sample.get('customer_id'),
            'tenant_id': sample.get('tenant_id'),
            'provider': sample.get('provider'),
            'hierarchy_id': sample.get('hierarchy_id'),
            'hierarchy_type': sample.get('hierarchy_type'),
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'error': error,
            'pass_rate': round((passed / total * 100) if total > 0 else 0.0, 2),
            'services_scanned': services,
            'scan_timestamp': sample.get('scan_timestamp')
        }
    
    def get_service_stats(self, scan_id: str, tenant_id: str) -> List[Dict]:
        """Get statistics for all services in a scan"""
        records = self.load_all_records()
        filtered = [
            r for r in records
            if r.get('scan_id') == scan_id and r.get('tenant_id') == tenant_id
        ]
        
        # Group by service
        service_counts = defaultdict(lambda: {'total': 0, 'PASS': 0, 'FAIL': 0, 'ERROR': 0})
        
        for record in filtered:
            service = record.get('resource_type', 'unknown')
            status = record.get('status', 'UNKNOWN')
            service_counts[service]['total'] += 1
            service_counts[service][status] += 1
        
        # Convert to list
        results = []
        for service, stats in sorted(service_counts.items()):
            total = stats['total']
            passed = stats['PASS']
            results.append({
                'service': service,
                'total': total,
                'passed': passed,
                'failed': stats['FAIL'],
                'error': stats['ERROR'],
                'pass_rate': round((passed / total * 100) if total > 0 else 0.0, 2)
            })
        
        return results
    
    def get_service_detail(self, scan_id: str, service: str, tenant_id: str) -> Optional[Dict]:
        """Get detailed statistics for a specific service in a scan"""
        records = self.load_all_records()
        filtered = [
            r for r in records
            if r.get('scan_id') == scan_id 
            and r.get('tenant_id') == tenant_id
            and r.get('resource_type', '').lower() == service.lower()  # Case-insensitive
        ]
        
        if not filtered:
            return None
        
        # Overall stats
        total = len(filtered)
        passed = sum(1 for r in filtered if r.get('status') == 'PASS')
        failed = sum(1 for r in filtered if r.get('status') == 'FAIL')
        error = sum(1 for r in filtered if r.get('status') == 'ERROR')
        resources_affected = len(set(r.get('resource_arn') for r in filtered if r.get('resource_arn')))
        
        # Rule stats
        rule_counts = defaultdict(lambda: {'total': 0, 'PASS': 0, 'FAIL': 0, 'ERROR': 0, 'arns': set()})
        
        for record in filtered:
            rule_id = record.get('rule_id', 'unknown')
            status = record.get('status', 'UNKNOWN')
            rule_counts[rule_id]['total'] += 1
            rule_counts[rule_id][status] += 1
            if record.get('resource_arn'):
                rule_counts[rule_id]['arns'].add(record['resource_arn'])
        
        # Convert rules to list
        rules = []
        for rule_id, stats in sorted(rule_counts.items(), key=lambda x: x[1]['FAIL'], reverse=True):
            rules.append({
                'rule_id': rule_id,
                'total': stats['total'],
                'passed': stats['PASS'],
                'failed': stats['FAIL'],
                'error': stats['ERROR'],
                'resource_arns': list(stats['arns'])
            })
        
        return {
            'service': service,
            'scan_id': scan_id,
            'total_checks': total,
            'passed': passed,
            'failed': failed,
            'error': error,
            'pass_rate': round((passed / total * 100) if total > 0 else 0.0, 2),
            'resources_affected': resources_affected,
            'rules': rules[:50],  # Limit to 50 rules
            'top_failing_rules': rules[:10]  # Top 10 failing
        }
    
    def get_findings(self, scan_id: Optional[str] = None, tenant_id: str = None,
                    customer_id: Optional[str] = None, service: Optional[str] = None,
                    status: Optional[str] = None, rule_id: Optional[str] = None,
                    resource_arn: Optional[str] = None,
                    page: int = 1, page_size: int = 50) -> Tuple[List[Dict], int]:
        """Get findings with filtering and pagination"""
        records = self.load_all_records()
        
        # Filter
        filtered = records
        if tenant_id:
            filtered = [r for r in filtered if r.get('tenant_id') == tenant_id]
        if customer_id:
            filtered = [r for r in filtered if r.get('customer_id') == customer_id]
        if scan_id:
            filtered = [r for r in filtered if r.get('scan_id') == scan_id]
        if service:
            filtered = [r for r in filtered if r.get('resource_type') == service]
        if status:
            filtered = [r for r in filtered if r.get('status') == status.upper()]
        if rule_id:
            filtered = [r for r in filtered if r.get('rule_id') == rule_id]
        if resource_arn:
            filtered = [r for r in filtered if r.get('resource_arn') == resource_arn]
        
        # Sort by timestamp descending
        filtered.sort(key=lambda x: x.get('scan_timestamp') or '', reverse=True)
        
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
                'discovery_scan_id': record.get('finding_data', {}).get('discovery_id'),
                'customer_id': record.get('customer_id'),
                'tenant_id': record.get('tenant_id'),
                'provider': record.get('provider'),
                'hierarchy_id': record.get('hierarchy_id'),
                'hierarchy_type': record.get('hierarchy_type'),
                'rule_id': record.get('rule_id'),
                'resource_arn': record.get('resource_arn'),
                'resource_id': record.get('resource_id'),
                'resource_type': record.get('resource_type'),
                'status': record.get('status'),
                'checked_fields': record.get('checked_fields', []),
                'finding_data': record.get('finding_data', {}),
                'scan_timestamp': record.get('scan_timestamp')
            })
        
        return formatted, total
    
    def get_resource_findings(self, resource_arn: str, tenant_id: str,
                             customer_id: Optional[str] = None) -> Dict[str, Any]:
        """Get all findings for a specific resource ARN"""
        findings, _ = self.get_findings(
            tenant_id=tenant_id,
            customer_id=customer_id,
            resource_arn=resource_arn
        )
        
        if not findings:
            return None
        
        # Calculate stats
        total = len(findings)
        passed = sum(1 for f in findings if f['status'] == 'PASS')
        failed = sum(1 for f in findings if f['status'] == 'FAIL')
        
        return {
            'resource_arn': resource_arn,
            'resource_id': findings[0].get('resource_id') if findings else None,
            'resource_type': findings[0].get('resource_type') if findings else None,
            'total_findings': total,
            'passed': passed,
            'failed': failed,
            'findings': findings
        }
    
    def get_rule_findings(self, rule_id: str, tenant_id: str,
                         customer_id: Optional[str] = None,
                         scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Get all findings for a specific rule"""
        findings, _ = self.get_findings(
            tenant_id=tenant_id,
            customer_id=customer_id,
            scan_id=scan_id,
            rule_id=rule_id
        )
        
        if not findings:
            return None
        
        # Limit to 1000
        findings = findings[:1000]
        
        # Stats
        total = len(findings)
        passed = sum(1 for f in findings if f['status'] == 'PASS')
        failed = sum(1 for f in findings if f['status'] == 'FAIL')
        error = sum(1 for f in findings if f['status'] == 'ERROR')
        
        # Extract service
        service = rule_id.split('.')[1] if '.' in rule_id else 'unknown'
        
        # Get unique resource ARNs
        resources = list(set(f['resource_arn'] for f in findings if f.get('resource_arn')))
        
        return {
            'rule_id': rule_id,
            'service': service,
            'total_findings': total,
            'passed': passed,
            'failed': failed,
            'error': error,
            'findings': findings,
            'resources_affected': resources
        }
    
    def _filter_records(self, records: List[Dict], tenant_id: str,
                       customer_id: Optional[str] = None) -> List[Dict]:
        """Filter records by tenant and customer"""
        filtered = [r for r in records if r.get('tenant_id') == tenant_id]
        if customer_id:
            filtered = [r for r in filtered if r.get('customer_id') == customer_id]
        return filtered
