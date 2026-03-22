"""
IAM Security Reporter - aggregates IAM-relevant findings and generates reports.

Reads ALL threat findings from threat_findings table, then uses rule_id
pattern matching (e.g. aws.iam.*) to identify IAM-relevant ones.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from collections import defaultdict
import logging

from ..input.threat_db_reader import ThreatDBReader
from ..enricher.finding_enricher import FindingEnricher

logger = logging.getLogger(__name__)


class IAMReporter:
    """Generates IAM security posture reports from Threat DB (threat_findings table)."""

    def __init__(self, rule_db_path: Optional[str] = None):
        self.threat_db_reader = ThreatDBReader()
        self.enricher = FindingEnricher()

    def generate_report(
        self,
        csp: str,
        scan_id: str,
        tenant_id: str = "default-tenant",
        max_findings: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Generate IAM security report.

        Steps:
        1. Load ALL threat findings from threat_findings table
        2. Enrich each finding — mark is_iam_relevant using rule_id pattern matching
        3. Filter to keep only IAM-relevant findings
        4. Build summary and report
        """
        logger.info(f"Loading all threat findings for scan {scan_id}")
        # Load all findings (no pre-filter — enricher handles IAM relevance)
        all_findings = self.threat_db_reader.get_misconfig_findings(
            tenant_id=tenant_id, scan_run_id=scan_id
        )
        logger.info(f"Loaded {len(all_findings)} total findings, enriching with IAM context")

        # Enrich and filter IAM-relevant
        enriched = self.enricher.enrich_findings(all_findings)
        iam_relevant = [f for f in enriched if f.get("is_iam_relevant", False)]

        logger.info(f"Found {len(iam_relevant)} IAM-relevant findings from {len(all_findings)} total")

        if max_findings and len(iam_relevant) > max_findings:
            iam_relevant = iam_relevant[:max_findings]

        summary = self._calculate_summary(iam_relevant)
        report = {
            "schema_version": "cspm_iam_security_report.v1",
            "tenant_id": tenant_id,
            "scan_context": {
                "csp": csp,
                "threat_scan_run_id": scan_id,
                "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            },
            "summary": summary,
            "findings": iam_relevant,
        }
        return report

    def _calculate_summary(self, findings: List[Dict]) -> Dict[str, Any]:
        by_status = defaultdict(int)
        by_module = defaultdict(int)
        by_severity = defaultdict(int)
        for f in findings:
            by_status[f.get("status", "UNKNOWN")] += 1
            by_severity[f.get("severity", "unknown")] += 1
            for m in f.get("iam_security_modules", []):
                by_module[m] += 1
        return {
            "total_findings": len(findings),
            "iam_relevant_findings": len(findings),
            "findings_by_status": dict(by_status),
            "findings_by_severity": dict(by_severity),
            "findings_by_module": dict(by_module),
        }
