"""
Map configScan findings to data security modules using enriched metadata.

Uses the data_security section from rule_db metadata to map findings to modules.
"""

from typing import Dict, List, Optional, Set
import logging

from ..input.rule_db_reader import RuleDBReader

logger = logging.getLogger(__name__)


class RuleToModuleMapper:
    """Maps configScan findings to data security modules."""
    
    def __init__(self, rule_db_path: Optional[str] = None):
        """
        Initialize rule to module mapper.
        
        Args:
            rule_db_path: Path to rule database (optional)
        """
        self.rule_db_reader = RuleDBReader(rule_db_path)
    
    def get_modules_for_finding(self, finding: Dict) -> List[str]:
        """
        Get data security modules for a finding.
        
        Args:
            finding: ConfigScan finding (cspm_finding.v1 schema)
            
        Returns:
            List of data security module names
        """
        rule_id = finding.get("rule_id")
        service = finding.get("service", "").lower()
        
        if not rule_id or not service:
            return []
        
        # Get data_security info from rule_db
        data_security = self.rule_db_reader.get_data_security_info(service, rule_id)
        
        if data_security and data_security.get("applicable"):
            return data_security.get("modules", [])
        
        return []
    
    def map_finding_to_modules(self, finding: Dict) -> Dict:
        """
        Enrich a finding with data security module information.
        
        Args:
            finding: ConfigScan finding
            
        Returns:
            Finding with added data_security_modules field
        """
        modules = self.get_modules_for_finding(finding)
        
        enriched_finding = finding.copy()
        enriched_finding["data_security_modules"] = modules
        enriched_finding["is_data_security_relevant"] = len(modules) > 0
        
        return enriched_finding
    
    def map_findings_to_modules(self, findings: List[Dict]) -> List[Dict]:
        """
        Map multiple findings to data security modules.
        
        Args:
            findings: List of configScan findings
            
        Returns:
            List of enriched findings
        """
        return [self.map_finding_to_modules(finding) for finding in findings]
    
    def group_findings_by_module(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group findings by data security module.
        
        Args:
            findings: List of findings (with data_security_modules field)
            
        Returns:
            Dictionary mapping module name to list of findings
        """
        grouped = {}
        
        for finding in findings:
            modules = finding.get("data_security_modules", [])
            for module in modules:
                if module not in grouped:
                    grouped[module] = []
                grouped[module].append(finding)
        
        return grouped
    
    def get_module_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        """
        Get statistics on finding counts per module.
        
        Args:
            findings: List of findings (with data_security_modules field)
            
        Returns:
            Dictionary mapping module name to count
        """
        stats = {}
        
        for finding in findings:
            modules = finding.get("data_security_modules", [])
            for module in modules:
                stats[module] = stats.get(module, 0) + 1
        
        return stats
    
    def filter_by_module(self, findings: List[Dict], module: str) -> List[Dict]:
        """
        Filter findings to only those relevant to a specific module.
        
        Args:
            findings: List of findings (with data_security_modules field)
            module: Module name to filter by
            
        Returns:
            Filtered list of findings
        """
        return [f for f in findings if module in f.get("data_security_modules", [])]


# Convenience function
def map_finding(finding: Dict, rule_db_path: Optional[str] = None) -> Dict:
    """Map a single finding to data security modules."""
    mapper = RuleToModuleMapper(rule_db_path)
    return mapper.map_finding_to_modules(finding)

