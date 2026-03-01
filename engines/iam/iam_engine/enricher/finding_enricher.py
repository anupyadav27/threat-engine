"""
Enrich findings with IAM security context using rule_id pattern matching.

No external YAML metadata files needed — IAM relevance and modules
are derived from the rule_id pattern (e.g. aws.iam.role.*, aws.iam.policy.*).
"""

from typing import Dict, List, Optional
import logging

from ..mapper.rule_to_module_mapper import RuleToModuleMapper

logger = logging.getLogger(__name__)


class FindingEnricher:
    """Enriches findings with IAM security context."""

    def __init__(self, rule_db_path: Optional[str] = None):
        self.module_mapper = RuleToModuleMapper()

    def enrich_finding(self, finding: Dict) -> Dict:
        rule_id = finding.get("rule_id")
        if not rule_id:
            return finding
        enriched = self.module_mapper.map_finding_to_modules(finding)
        # Add IAM security context based on module mapping
        if enriched.get("is_iam_relevant"):
            enriched["iam_security_context"] = {
                "modules": enriched.get("iam_security_modules", []),
                "applicable": True,
            }
        else:
            enriched["iam_security_context"] = None
        return enriched

    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        return [self.enrich_finding(f) for f in findings]

    def get_enrichment_summary(self, findings: List[Dict]) -> Dict:
        total = len(findings)
        relevant = sum(1 for f in findings if f.get("is_iam_relevant"))
        module_counts = self.module_mapper.get_module_statistics(findings)
        return {
            "total_findings": total,
            "iam_relevant": relevant,
            "coverage_percentage": (relevant / total * 100) if total > 0 else 0,
            "module_distribution": module_counts,
        }
