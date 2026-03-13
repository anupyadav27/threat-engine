"""
Executive Dashboard Generator

Generates high-level executive compliance dashboard.
"""

from typing import Dict, List, Any, Optional
from ..aggregator.result_aggregator import ResultAggregator
from ..aggregator.score_calculator import ScoreCalculator


class ExecutiveDashboard:
    """Generates executive-level compliance dashboard."""
    
    def __init__(
        self,
        aggregator: Optional[ResultAggregator] = None,
        score_calculator: Optional[ScoreCalculator] = None
    ):
        """
        Initialize executive dashboard generator.
        
        Args:
            aggregator: ResultAggregator instance
            score_calculator: ScoreCalculator instance
        """
        self.aggregator = aggregator or ResultAggregator()
        self.score_calculator = score_calculator or ScoreCalculator(self.aggregator)
    
    def generate(
        self,
        scan_results: Dict,
        csp: str,
        frameworks: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Generate executive dashboard.
        
        Args:
            scan_results: Scan results from CSP engine
            csp: Cloud service provider
            frameworks: Optional list of frameworks to include
        
        Returns:
            Executive dashboard data
        """
        # Aggregate results by framework
        framework_data = self.aggregator.aggregate_by_framework(scan_results, csp, frameworks)
        
        # Calculate scores for each framework
        framework_scores = []
        for framework in framework_data.keys():
            score = self.score_calculator.calculate_framework_score(framework_data, framework)
            framework_scores.append(score)
        
        # Calculate overall score
        overall = self.score_calculator.calculate_overall_score(framework_scores)
        
        # Get top critical findings
        critical_findings = self._get_critical_findings(framework_data, limit=5)
        
        # Count findings by severity
        severity_counts = self._count_by_severity(scan_results)
        
        return {
            'scan_id': scan_results.get('scan_id'),
            'csp': csp,
            'account_id': scan_results.get('account_id'),
            'scanned_at': scan_results.get('scanned_at'),
            'generated_at': self._get_current_timestamp(),
            
            'summary': {
                'overall_compliance_score': overall['overall_compliance_score'],
                'total_frameworks': overall['total_frameworks'],
                'frameworks_passing': overall['frameworks_passing'],
                'frameworks_partial': overall['frameworks_partial'],
                'frameworks_failing': overall['frameworks_failing'],
                'frameworks_error': overall['frameworks_error'],
                **severity_counts
            },
            
            'frameworks': framework_scores,
            
            'top_critical_findings': critical_findings
        }
    
    def _get_critical_findings(
        self,
        framework_data: Dict[str, Dict[str, List[Dict]]],
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get top critical findings across all frameworks."""
        findings = []
        
        for framework, controls in framework_data.items():
            for control_id, control_checks in controls.items():
                # Only include failed checks
                failed_checks = [c for c in control_checks if c.get('check_result') == 'FAIL']
                
                for check in failed_checks:
                    severity = check.get('severity', 'medium')
                    severity_weight = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(severity, 2)
                    
                    findings.append({
                        'framework': framework,
                        'control_id': control_id,
                        'control_title': check.get('control', {}).get('control_title', ''),
                        'rule_id': check.get('rule_id'),
                        'severity': severity,
                        'severity_weight': severity_weight,
                        'service': check.get('service'),
                        'region': check.get('region'),
                        'resource': check.get('resource', {}),
                        'evidence': check.get('evidence', {})
                    })
        
        # Sort by severity (critical first) and limit
        findings.sort(key=lambda x: x['severity_weight'], reverse=True)
        return findings[:limit]
    
    def _count_by_severity(self, scan_results: Dict) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0
        }
        
        results = scan_results.get('results', [])
        for result in results:
            checks = result.get('checks', [])
            for check in checks:
                if check.get('result') == 'FAIL':
                    severity = check.get('severity', 'medium')
                    if severity == 'critical':
                        counts['critical_findings'] += 1
                    elif severity == 'high':
                        counts['high_findings'] += 1
                    elif severity == 'medium':
                        counts['medium_findings'] += 1
                    elif severity == 'low':
                        counts['low_findings'] += 1
        
        return counts
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat() + 'Z'

