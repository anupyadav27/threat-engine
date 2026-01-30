"""IAM Security Reporter - aggregates IAM-relevant findings and generates reports."""

from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict
import logging

from ..input.threat_db_reader import ThreatDBReader
from ..input.rule_db_reader import RuleDBReader
from ..enricher.finding_enricher import FindingEnricher

logger = logging.getLogger(__name__)


class IAMReporter:
    """Generates IAM security posture reports from Threat DB (threat_reports)."""

    def __init__(self, rule_db_path: Optional[str] = None):
        self.threat_db_reader = ThreatDBReader()
        self.rule_db_reader = RuleDBReader(rule_db_path)
        self.enricher = FindingEnricher(rule_db_path)

    def generate_report(
        self,
        csp: str,
        scan_id: str,
        tenant_id: str = "default-tenant",
        max_findings: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Generate IAM security report (findings filtered by IAM rule IDs, enriched)."""
        logger.info("Loading IAM security rule IDs from rule_db")
        iam_rule_ids = self.rule_db_reader.get_all_iam_security_rule_ids()
        logger.info(f"Loading configScan findings for scan {scan_id} (filtered by {len(iam_rule_ids)} IAM rule IDs)")
        iam_findings = self.configscan_reader.filter_iam_related_findings(
            csp, scan_id, iam_rule_ids=iam_rule_ids, max_findings=max_findings
        )
        logger.info("Enriching findings with IAM context")
        enriched = self.enricher.enrich_findings(iam_findings)
        iam_relevant = [f for f in enriched if f.get("is_iam_relevant", False)]
        if len(iam_relevant) < len(enriched):
            logger.warning(f"Filtered out {len(enriched) - len(iam_relevant)} non-IAM findings")
        enriched = iam_relevant
        summary = self._calculate_summary(enriched)
        report = {
            "schema_version": "cspm_iam_security_report.v1",
            "tenant_id": tenant_id,
            "scan_context": {
                "csp": csp,
                "threat_scan_run_id": scan_id,
                "generated_at": datetime.utcnow().isoformat() + "Z",
            },
            "summary": summary,
            "findings": enriched,
        }
        return report

    def _calculate_summary(self, findings: List[Dict]) -> Dict[str, Any]:
        by_status = defaultdict(int)
        by_module = defaultdict(int)
        for f in findings:
            by_status[f.get("status", "UNKNOWN")] += 1
            for m in f.get("iam_security_modules", []):
                by_module[m] += 1
        return {
            "total_findings": len(findings),
            "iam_relevant_findings": sum(1 for f in findings if f.get("is_iam_relevant")),
            "findings_by_status": dict(by_status),
            "findings_by_module": dict(by_module),
        }
