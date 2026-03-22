"""
Resource Drill-down Generator

Generates resource-level compliance reports.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from ..aggregator.result_aggregator import ResultAggregator


class ResourceDrilldown:
    """Generates resource-level compliance drill-down reports."""
    
    def __init__(self, aggregator: Optional[ResultAggregator] = None):
        """
        Initialize resource drill-down generator.
        
        Args:
            aggregator: ResultAggregator instance
        """
        self.aggregator = aggregator or ResultAggregator()
    
    def generate(
        self,
        scan_results: Dict,
        csp: str,
        resource_id: Optional[str] = None,
        service: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate resource-level compliance report.
        
        Args:
            scan_results: Scan results from CSP engine
            csp: Cloud service provider
            resource_id: Optional specific resource ID to filter
            service: Optional service name to filter
        
        Returns:
            Resource-level compliance data
        """
        results = scan_results.get('results', [])
        
        # Group by resource
        resource_data: Dict[str, List[Dict]] = defaultdict(list)
        
        for result in results:
            if service and result.get('service') != service:
                continue
            
            checks = result.get('checks', [])
            for check in checks:
                resource = check.get('resource', {})
                resource_arn = resource.get('arn') or resource.get('id') or resource.get('name', 'unknown')
                
                if resource_id and resource_arn != resource_id:
                    continue
                
                resource_data[resource_arn].append({
                    'rule_id': check.get('rule_id'),
                    'result': check.get('result'),
                    'severity': check.get('severity'),
                    'service': result.get('service'),
                    'region': result.get('region'),
                    'resource': resource,
                    'evidence': check.get('evidence', {})
                })
        
        # Calculate resource compliance scores
        resource_reports = []
        for resource_arn, checks in resource_data.items():
            passed = sum(1 for c in checks if c['result'] == 'PASS')
            failed = sum(1 for c in checks if c['result'] == 'FAIL')
            total = len(checks)
            
            score = (passed / total * 100) if total > 0 else 0.0
            
            # Get resource metadata from first check
            first_check = checks[0] if checks else {}
            resource_meta = first_check.get('resource', {})
            
            resource_reports.append({
                'resource_arn': resource_arn,
                'resource_type': resource_meta.get('type', 'unknown'),
                'service': first_check.get('service'),
                'region': first_check.get('region'),
                'compliance_score': round(score, 2),
                'checks_total': total,
                'checks_passed': passed,
                'checks_failed': failed,
                'checks': checks
            })
        
        # Sort by compliance score (lowest first - most critical)
        resource_reports.sort(key=lambda x: x['compliance_score'])
        
        return {
            'scan_id': scan_results.get('scan_id'),
            'csp': csp,
            'account_id': scan_results.get('account_id'),
            'scanned_at': scan_results.get('scanned_at'),
            'generated_at': self._get_current_timestamp(),
            'filters': {
                'resource_id': resource_id,
                'service': service
            },
            'resources': resource_reports,
            'total_resources': len(resource_reports)
        }
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat() + 'Z'

