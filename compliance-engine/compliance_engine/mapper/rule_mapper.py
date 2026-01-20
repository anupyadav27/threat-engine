"""
Rule Mapper

Maps scan result rule_ids to compliance framework controls.
"""

from typing import Dict, List, Optional
from .framework_loader import FrameworkLoader, FrameworkControl


class RuleMapper:
    """Maps rule_ids from scan results to compliance framework controls."""
    
    def __init__(self, framework_loader: Optional[FrameworkLoader] = None):
        """
        Initialize rule mapper.
        
        Args:
            framework_loader: FrameworkLoader instance (creates new if None)
        """
        self.framework_loader = framework_loader or FrameworkLoader()
        self._mappings_cache: Dict[str, Dict[str, List[FrameworkControl]]] = {}
    
    def get_controls_for_rule(self, rule_id: str, csp: str) -> List[FrameworkControl]:
        """
        Get compliance framework controls for a given rule_id.
        
        Args:
            rule_id: Security check rule ID (e.g., "aws.accessanalyzer.resource.access_analyzer_enabled")
            csp: Cloud service provider (aws, azure, gcp, etc.)
        
        Returns:
            List of FrameworkControl objects that this rule maps to
        """
        # Load mappings for this CSP if not cached
        if csp not in self._mappings_cache:
            self._mappings_cache[csp] = self.framework_loader.get_rule_mappings(csp)
        
        csp_mappings = self._mappings_cache[csp]
        return csp_mappings.get(rule_id, [])
    
    def map_scan_results(self, scan_results: Dict, csp: str) -> Dict[str, List[FrameworkControl]]:
        """
        Map all rule_ids from scan results to compliance controls.
        
        Args:
            scan_results: Scan results dictionary with 'results' containing checks
            csp: Cloud service provider
        
        Returns:
            Dictionary mapping rule_id to list of FrameworkControl objects
        """
        rule_to_controls: Dict[str, List[FrameworkControl]] = {}
        
        results = scan_results.get('results', [])
        
        for result in results:
            checks = result.get('checks', [])
            
            for check in checks:
                rule_id = check.get('rule_id')
                if not rule_id:
                    continue
                
                # Get controls for this rule
                controls = self.get_controls_for_rule(rule_id, csp)
                
                if controls:
                    # Merge with existing controls (avoid duplicates)
                    if rule_id not in rule_to_controls:
                        rule_to_controls[rule_id] = []
                    
                    existing_controls = {(c.framework, c.control_id) for c in rule_to_controls[rule_id]}
                    for control in controls:
                        key = (control.framework, control.control_id)
                        if key not in existing_controls:
                            rule_to_controls[rule_id].append(control)
                            existing_controls.add(key)
        
        return rule_to_controls
    
    def get_frameworks_for_scan(self, scan_results: Dict, csp: str) -> List[str]:
        """
        Get list of unique frameworks covered by scan results.
        
        Args:
            scan_results: Scan results dictionary
            csp: Cloud service provider
        
        Returns:
            List of unique framework names
        """
        rule_to_controls = self.map_scan_results(scan_results, csp)
        
        frameworks = set()
        for controls in rule_to_controls.values():
            for control in controls:
                frameworks.add(control.framework)
        
        return sorted(list(frameworks))

