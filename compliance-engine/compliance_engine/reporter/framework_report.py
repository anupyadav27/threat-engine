"""
Framework Report Generator

Generates detailed framework-specific compliance reports (audit-ready).
"""

from typing import Dict, List, Any, Optional
from ..aggregator.result_aggregator import ResultAggregator
from ..aggregator.score_calculator import ScoreCalculator


class FrameworkReport:
    """Generates framework-specific detailed compliance reports."""
    
    def __init__(
        self,
        aggregator: Optional[ResultAggregator] = None,
        score_calculator: Optional[ScoreCalculator] = None
    ):
        """
        Initialize framework report generator.
        
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
        framework: str
    ) -> Dict[str, Any]:
        """
        Generate detailed framework compliance report.
        
        Args:
            scan_results: Scan results from CSP engine
            csp: Cloud service provider
            framework: Framework name (e.g., "CIS AWS Foundations Benchmark")
        
        Returns:
            Detailed framework compliance report
        """
        # Aggregate results by framework
        framework_data = self.aggregator.aggregate_by_framework(scan_results, csp, [framework])
        
        if framework not in framework_data:
            return {
                'framework': framework,
                'status': 'NO_DATA',
                'message': f'No compliance data found for framework: {framework}'
            }
        
        # Calculate framework score
        framework_score = self.score_calculator.calculate_framework_score(framework_data, framework)
        
        # Calculate category scores
        category_scores = self.score_calculator.calculate_category_scores(framework_data, framework)
        
        # Get detailed control data
        controls = []
        for control_id, control_checks in framework_data[framework].items():
            control_data = self.aggregator.aggregate_by_control(framework_data, framework, control_id)
            controls.append(control_data)
        
        # Sort controls by control_id
        controls.sort(key=lambda x: x.get('control_id', ''))
        
        return {
            'scan_id': scan_results.get('scan_id'),
            'csp': csp,
            'account_id': scan_results.get('account_id'),
            'scanned_at': scan_results.get('scanned_at'),
            'generated_at': self._get_current_timestamp(),
            
            'framework': framework,
            'framework_version': self._get_framework_version(controls),
            
            'overall_status': framework_score['status'],
            'compliance_score': framework_score['compliance_score'],
            
            'statistics': {
                'controls_total': framework_score['controls_total'],
                'controls_applicable': framework_score['controls_applicable'],
                'controls_passed': framework_score['controls_passed'],
                'controls_failed': framework_score['controls_failed'],
                'controls_partial': framework_score['controls_partial'],
                'controls_not_applicable': framework_score['controls_not_applicable'],
                'controls_error': framework_score['controls_error']
            },
            
            'by_category': category_scores,
            
            'controls': controls
        }
    
    def _get_framework_version(self, controls: List[Dict]) -> Optional[str]:
        """Extract framework version from controls."""
        if controls:
            first_control = controls[0]
            return first_control.get('control', {}).get('framework_version')
        return None
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime
        return datetime.utcnow().isoformat() + 'Z'

