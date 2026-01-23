"""
Score Calculator

Calculates compliance scores (0-100%) for frameworks and controls.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict
from .result_aggregator import ResultAggregator


class ScoreCalculator:
    """Calculates compliance scores from aggregated results."""
    
    def __init__(self, aggregator: Optional[ResultAggregator] = None):
        """
        Initialize score calculator.
        
        Args:
            aggregator: ResultAggregator instance (creates new if None)
        """
        self.aggregator = aggregator or ResultAggregator()
    
    def calculate_framework_score(
        self,
        framework_data: Dict[str, Dict[str, List[Dict]]],
        framework: str
    ) -> Dict[str, Any]:
        """
        Calculate compliance score for a framework.
        
        Args:
            framework_data: Output from ResultAggregator.aggregate_by_framework
            framework: Framework name
        
        Returns:
            Framework compliance score and statistics
        """
        if framework not in framework_data:
            return {
                'framework': framework,
                'compliance_score': 0.0,
                'status': 'NO_DATA',
                'controls_total': 0,
                'controls_passed': 0,
                'controls_failed': 0,
                'controls_partial': 0,
                'controls_not_applicable': 0,
                'controls_error': 0
            }
        
        controls = framework_data[framework]
        
        controls_passed = 0
        controls_failed = 0
        controls_partial = 0
        controls_not_applicable = 0
        controls_error = 0
        
        # Process each control
        for control_id, control_checks in controls.items():
            if not control_checks:
                controls_not_applicable += 1
                continue
            
            # Determine control status
            has_fail = any(c['check_result'] == 'FAIL' for c in control_checks)
            has_pass = any(c['check_result'] == 'PASS' for c in control_checks)
            has_error = any(c['check_result'] == 'ERROR' for c in control_checks)
            
            if has_error:
                controls_error += 1
            elif has_fail and has_pass:
                controls_partial += 1
            elif has_fail:
                controls_failed += 1
            elif has_pass:
                controls_passed += 1
            else:
                controls_not_applicable += 1
        
        controls_total = len(controls)
        controls_applicable = controls_total - controls_not_applicable
        
        # Calculate score: (Passed + 0.5 * Partial) / Applicable * 100
        if controls_applicable > 0:
            score = ((controls_passed + (controls_partial * 0.5)) / controls_applicable) * 100
        else:
            score = 0.0
        
        # Determine overall status
        if controls_error > 0:
            status = 'ERROR'
        elif controls_failed > 0 or controls_partial > 0:
            status = 'PARTIAL_COMPLIANCE'
        elif controls_passed == controls_applicable and controls_applicable > 0:
            status = 'FULL_COMPLIANCE'
        else:
            status = 'NO_DATA'
        
        return {
            'framework': framework,
            'compliance_score': round(score, 2),
            'status': status,
            'controls_total': controls_total,
            'controls_applicable': controls_applicable,
            'controls_passed': controls_passed,
            'controls_failed': controls_failed,
            'controls_partial': controls_partial,
            'controls_not_applicable': controls_not_applicable,
            'controls_error': controls_error
        }
    
    def calculate_category_scores(
        self,
        framework_data: Dict[str, Dict[str, List[Dict]]],
        framework: str
    ) -> Dict[str, Dict[str, Any]]:
        """
        Calculate compliance scores by category within a framework.
        
        Args:
            framework_data: Output from ResultAggregator.aggregate_by_framework
            framework: Framework name
        
        Returns:
            Dictionary of category -> score data
        """
        if framework not in framework_data:
            return {}
        
        controls = framework_data[framework]
        
        # Group controls by category
        category_controls: Dict[str, List[str]] = defaultdict(list)
        
        for control_id, control_checks in controls.items():
            if control_checks:
                category = control_checks[0].get('control', {}).get('control_category', 'Uncategorized')
                category_controls[category].append(control_id)
        
        category_scores = {}
        
        for category, control_ids in category_controls.items():
            # Calculate score for this category
            passed = 0
            failed = 0
            partial = 0
            not_applicable = 0
            error = 0
            
            for control_id in control_ids:
                control_checks = controls[control_id]
                
                if not control_checks:
                    not_applicable += 1
                    continue
                
                has_fail = any(c['check_result'] == 'FAIL' for c in control_checks)
                has_pass = any(c['check_result'] == 'PASS' for c in control_checks)
                has_error = any(c['check_result'] == 'ERROR' for c in control_checks)
                
                if has_error:
                    error += 1
                elif has_fail and has_pass:
                    partial += 1
                elif has_fail:
                    failed += 1
                elif has_pass:
                    passed += 1
                else:
                    not_applicable += 1
            
            total = len(control_ids)
            applicable = total - not_applicable
            
            if applicable > 0:
                score = ((passed + (partial * 0.5)) / applicable) * 100
            else:
                score = 0.0
            
            # Determine status
            if error > 0:
                status = 'ERROR'
            elif failed > 0 or partial > 0:
                status = 'PARTIAL_COMPLIANCE'
            elif passed == applicable and applicable > 0:
                status = 'FULL_COMPLIANCE'
            else:
                status = 'NO_DATA'
            
            category_scores[category] = {
                'category': category,
                'compliance_score': round(score, 2),
                'status': status,
                'controls_total': total,
                'controls_applicable': applicable,
                'controls_passed': passed,
                'controls_failed': failed,
                'controls_partial': partial,
                'controls_not_applicable': not_applicable,
                'controls_error': error
            }
        
        return category_scores
    
    def calculate_overall_score(
        self,
        framework_scores: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate overall compliance score across all frameworks.
        
        Args:
            framework_scores: List of framework score dictionaries
        
        Returns:
            Overall compliance score and summary
        """
        if not framework_scores:
            return {
                'overall_compliance_score': 0.0,
                'total_frameworks': 0,
                'frameworks_passing': 0,
                'frameworks_partial': 0,
                'frameworks_failing': 0,
                'frameworks_error': 0
            }
        
        total_score = 0.0
        frameworks_passing = 0
        frameworks_partial = 0
        frameworks_failing = 0
        frameworks_error = 0
        
        for fw_score in framework_scores:
            score = fw_score.get('compliance_score', 0.0)
            status = fw_score.get('status', 'NO_DATA')
            
            total_score += score
            
            if status == 'FULL_COMPLIANCE':
                frameworks_passing += 1
            elif status == 'PARTIAL_COMPLIANCE':
                frameworks_partial += 1
            elif status == 'ERROR':
                frameworks_error += 1
            else:
                frameworks_failing += 1
        
        overall_score = total_score / len(framework_scores) if framework_scores else 0.0
        
        return {
            'overall_compliance_score': round(overall_score, 2),
            'total_frameworks': len(framework_scores),
            'frameworks_passing': frameworks_passing,
            'frameworks_partial': frameworks_partial,
            'frameworks_failing': frameworks_failing,
            'frameworks_error': frameworks_error
        }

