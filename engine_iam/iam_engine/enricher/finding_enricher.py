"""Enrich findings with IAM security context from rule metadata."""

from typing import Dict, List, Optional
import logging

from ..input.rule_db_reader import RuleDBReader
from ..mapper.rule_to_module_mapper import RuleToModuleMapper

logger = logging.getLogger(__name__)


class FindingEnricher:
    """Enriches findings with IAM security context."""

    def __init__(self, rule_db_path: Optional[str] = None):
        self.rule_db_reader = RuleDBReader(rule_db_path)
        self.module_mapper = RuleToModuleMapper(rule_db_path)

    def enrich_finding(self, finding: Dict) -> Dict:
        rule_id = finding.get("rule_id")
        service = (finding.get("service") or "").lower()
        if not rule_id or not service:
            return finding
        enriched = self.module_mapper.map_finding_to_modules(finding)
        info = self.rule_db_reader.get_iam_security_info(service, rule_id)
        if info and info.get("applicable"):
            enriched["iam_security_context"] = {
                "modules": info.get("modules", []),
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
