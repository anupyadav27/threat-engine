"""
Enrich findings with data security context from enriched metadata.

Adds data_security specific information to configScan findings.
"""

from typing import Dict, List, Optional
import logging

from ..input.rule_db_reader import RuleDBReader
from ..mapper.rule_to_module_mapper import RuleToModuleMapper

logger = logging.getLogger(__name__)


class FindingEnricher:
    """Enriches findings with data security context."""
    
    def __init__(self, rule_db_path: Optional[str] = None):
        """
        Initialize finding enricher.
        
        Args:
            rule_db_path: Path to rule database (optional)
        """
        self.rule_db_reader = RuleDBReader(rule_db_path)
        self.module_mapper = RuleToModuleMapper(rule_db_path)
    
    def enrich_finding(self, finding: Dict) -> Dict:
        """
        Enrich a finding with data security context.
        
        Args:
            finding: ConfigScan finding
            
        Returns:
            Enriched finding with data_security_context field
        """
        rule_id = finding.get("rule_id")
        service = finding.get("service", "").lower()
        
        if not rule_id or not service:
            return finding
        
        # Get data_security metadata
        data_security = self.rule_db_reader.get_data_security_info(service, rule_id)
        
        # Map to modules
        enriched_finding = self.module_mapper.map_finding_to_modules(finding)
        
        # Add detailed data_security_context
        if data_security and data_security.get("applicable"):
            enriched_finding["data_security_context"] = {
                "modules": data_security.get("modules", []),
                "categories": data_security.get("categories", []),
                "priority": data_security.get("priority"),
                "impact": data_security.get("impact"),
                "sensitive_data_context": data_security.get("sensitive_data_context"),
            }
        else:
            enriched_finding["data_security_context"] = None
        
        return enriched_finding
    
    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Enrich multiple findings.
        
        Args:
            findings: List of configScan findings
            
        Returns:
            List of enriched findings
        """
        return [self.enrich_finding(finding) for finding in findings]
    
    def get_enrichment_summary(self, findings: List[Dict]) -> Dict:
        """
        Get summary of enrichment statistics.
        
        Args:
            findings: List of enriched findings
            
        Returns:
            Summary statistics
        """
        total = len(findings)
        relevant = sum(1 for f in findings if f.get("is_data_security_relevant"))
        
        # Module distribution
        module_counts = self.module_mapper.get_module_statistics(findings)
        
        # Priority distribution
        priority_counts = {}
        for finding in findings:
            context = finding.get("data_security_context")
            if context and context.get("priority"):
                priority = context["priority"]
                priority_counts[priority] = priority_counts.get(priority, 0) + 1
        
        return {
            "total_findings": total,
            "data_security_relevant": relevant,
            "coverage_percentage": (relevant / total * 100) if total > 0 else 0,
            "module_distribution": module_counts,
            "priority_distribution": priority_counts,
        }


# Convenience function
def enrich_finding(finding: Dict, rule_db_path: Optional[str] = None) -> Dict:
    """Enrich a single finding with data security context."""
    enricher = FindingEnricher(rule_db_path)
    return enricher.enrich_finding(finding)

