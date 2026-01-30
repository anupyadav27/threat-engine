"""Map configScan findings to IAM security modules using rule metadata."""

from typing import Dict, List, Optional
import logging

from ..input.rule_db_reader import RuleDBReader

logger = logging.getLogger(__name__)


class RuleToModuleMapper:
    """Maps findings to IAM security modules (least_privilege, mfa, policy_analysis, etc.)."""

    def __init__(self, rule_db_path: Optional[str] = None):
        self.rule_db_reader = RuleDBReader(rule_db_path)

    def get_modules_for_finding(self, finding: Dict) -> List[str]:
        rule_id = finding.get("rule_id")
        service = (finding.get("service") or "").lower()
        if not rule_id or not service:
            return []
        info = self.rule_db_reader.get_iam_security_info(service, rule_id)
        if info and info.get("applicable"):
            return info.get("modules", [])
        return []

    def map_finding_to_modules(self, finding: Dict) -> Dict:
        modules = self.get_modules_for_finding(finding)
        out = finding.copy()
        out["iam_security_modules"] = modules
        out["is_iam_relevant"] = len(modules) > 0
        return out

    def map_findings_to_modules(self, findings: List[Dict]) -> List[Dict]:
        return [self.map_finding_to_modules(f) for f in findings]

    def get_module_statistics(self, findings: List[Dict]) -> Dict[str, int]:
        stats = {}
        for f in findings:
            for m in f.get("iam_security_modules", []):
                stats[m] = stats.get(m, 0) + 1
        return stats
