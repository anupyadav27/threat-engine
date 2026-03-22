"""
Result Aggregator

Groups scan results by compliance framework and control.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from ..mapper.rule_mapper import RuleMapper
from ..mapper.framework_loader import FrameworkControl


class ResultAggregator:
    """Aggregates scan results by compliance framework and control."""
    
    def __init__(self, rule_mapper: Optional[RuleMapper] = None):
        """
        Initialize result aggregator.
        
        Args:
            rule_mapper: RuleMapper instance (creates new if None)
        """
        from ..mapper.rule_mapper import RuleMapper
        self.rule_mapper = rule_mapper or RuleMapper()
    
    def aggregate_by_framework(
        self,
        scan_results: Dict,
        csp: str,
        frameworks: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Aggregate scan results by compliance framework.
        
        Args:
            scan_results: Scan results from CSP engine
            csp: Cloud service provider
            frameworks: Optional list of frameworks to filter (None = all)
        
        Returns:
            Dictionary organized by framework -> control -> check results
        """
        # Map rule_ids to compliance controls
        rule_to_controls = self.rule_mapper.map_scan_results(scan_results, csp)
        
        # Structure: framework -> control_id -> list of check results
        framework_data: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
        
        # Process scan results
        results = scan_results.get('results', [])
        
        for result in results:
            checks = result.get('checks', [])
            service = result.get('service', 'unknown')
            region = result.get('region', 'global')
            
            for check in checks:
                rule_id = check.get('rule_id')
                check_result = check.get('result', 'UNKNOWN')  # PASS, FAIL, ERROR
                severity = check.get('severity', 'medium')
                resource = check.get('resource', {})
                evidence = check.get('evidence', {})
                
                if not rule_id:
                    continue
                
                # Get compliance controls for this rule
                controls = rule_to_controls.get(rule_id, [])
                
                for control in controls:
                    framework = control.framework
                    control_id = control.control_id
                    
                    # Filter by requested frameworks if specified
                    if frameworks and framework not in frameworks:
                        continue
                    
                    # Create control result entry
                    control_result = {
                        'rule_id': rule_id,
                        'check_result': check_result,
                        'severity': severity,
                        'service': service,
                        'region': region,
                        'resource': resource,
                        'evidence': evidence,
                        'control': {
                            'control_id': control_id,
                            'control_title': control.control_title,
                            'control_category': control.control_category,
                            'framework_version': control.framework_version
                        }
                    }
                    
                    framework_data[framework][control_id].append(control_result)
        
        return dict(framework_data)
    
    def aggregate_by_control(
        self,
        framework_data: Dict[str, Dict[str, List[Dict]]],
        framework: str,
        control_id: str
    ) -> Dict[str, Any]:
        """
        Get aggregated data for a specific framework control.
        
        Args:
            framework_data: Output from aggregate_by_framework
            framework: Framework name
            control_id: Control ID
        
        Returns:
            Aggregated control data
        """
        if framework not in framework_data:
            return {}
        
        control_checks = framework_data[framework].get(control_id, [])
        
        if not control_checks:
            return {
                'framework': framework,
                'control_id': control_id,
                'status': 'NOT_APPLICABLE',
                'checks': []
            }
        
        # Determine control status
        # If ANY check fails, control fails
        # If ALL checks pass, control passes
        # If mix, control is PARTIAL
        
        has_fail = any(c['check_result'] == 'FAIL' for c in control_checks)
        has_pass = any(c['check_result'] == 'PASS' for c in control_checks)
        has_error = any(c['check_result'] == 'ERROR' for c in control_checks)
        
        if has_error:
            status = 'ERROR'
        elif has_fail and has_pass:
            status = 'PARTIAL'
        elif has_fail:
            status = 'FAIL'
        elif has_pass:
            status = 'PASS'
        else:
            status = 'UNKNOWN'
        
        # Get control metadata from first check
        control_meta = control_checks[0].get('control', {}) if control_checks else {}
        
        return {
            'framework': framework,
            'control_id': control_id,
            'control_title': control_meta.get('control_title', ''),
            'control_category': control_meta.get('control_category', ''),
            'framework_version': control_meta.get('framework_version'),
            'status': status,
            'checks_total': len(control_checks),
            'checks_passed': sum(1 for c in control_checks if c['check_result'] == 'PASS'),
            'checks_failed': sum(1 for c in control_checks if c['check_result'] == 'FAIL'),
            'checks_error': sum(1 for c in control_checks if c['check_result'] == 'ERROR'),
            'checks': control_checks
        }

