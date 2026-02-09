"""
Unified Data Security Reporter - Aggregates findings and generates comprehensive reports.

Combines enriched configScan findings with new analysis (classification, lineage, etc.)
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict
import logging

from ..input.threat_db_reader import ThreatDBReader
from ..enricher.finding_enricher import FindingEnricher
from ..analyzer.classification_analyzer import ClassificationAnalyzer
from ..analyzer.lineage_analyzer import LineageAnalyzer
from ..analyzer.residency_analyzer import ResidencyAnalyzer
from ..analyzer.activity_analyzer import ActivityAnalyzer

logger = logging.getLogger(__name__)


class DataSecurityReporter:
    """Generates comprehensive data security reports from Threat DB."""
    
    def __init__(self, rule_db_path: Optional[str] = None):
        """
        Initialize data security reporter.
        
        Args:
            rule_db_path: Path to rule database
        """
        self.threat_db_reader = ThreatDBReader()
        self.enricher = FindingEnricher(rule_db_path)
        self.classification_analyzer = ClassificationAnalyzer()
        self.lineage_analyzer = LineageAnalyzer()
        self.residency_analyzer = ResidencyAnalyzer()
        self.activity_analyzer = ActivityAnalyzer()
    
    def generate_report(
        self,
        csp: str,
        scan_id: str,
        tenant_id: str = "default-tenant",
        include_classification: bool = True,
        include_lineage: bool = True,
        include_residency: bool = True,
        include_activity: bool = True,
        allowed_regions: Optional[List[str]] = None,
        max_findings: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive data security report.
        
        Args:
            csp: Cloud service provider
            scan_id: ConfigScan scan ID
            tenant_id: Tenant ID
            include_classification: Include classification analysis
            include_lineage: Include lineage analysis
            include_residency: Include residency checks
            include_activity: Include activity monitoring
            
        Returns:
            Complete data security report
        """
        # Load ALL findings from threat_findings table
        logger.info(f"Loading all threat findings from DB (scan_id={scan_id})")
        all_findings = self.threat_db_reader.get_misconfig_findings(
            tenant_id=tenant_id,
            scan_run_id=scan_id
        )
        logger.info(f"Loaded {len(all_findings)} total findings")

        # Enrich findings — mark is_data_security_relevant using pattern matching
        logger.info("Enriching findings with data security context")
        enriched_findings = self.enricher.enrich_findings(all_findings)

        # Filter to ONLY data security relevant findings
        data_security_relevant_findings = [
            f for f in enriched_findings
            if f.get("is_data_security_relevant", False)
        ]

        logger.info(f"Found {len(data_security_relevant_findings)} data security relevant findings from {len(all_findings)} total")
        enriched_findings = data_security_relevant_findings

        if max_findings and len(enriched_findings) > max_findings:
            enriched_findings = enriched_findings[:max_findings]

        # Extract data stores from threat_findings table (by resource_type)
        logger.info("Extracting data stores from threat_findings")
        data_stores = self.threat_db_reader.filter_data_stores(
            tenant_id=tenant_id,
            scan_run_id=scan_id
        )
        
        # Get enrichment summary
        enrichment_summary = self.enricher.get_enrichment_summary(enriched_findings)
        
        # Run new analyses
        classification_results = []
        lineage_results = {}
        residency_results = []
        activity_results = {}
        
        if include_classification:
            logger.info("Running classification analysis")
            try:
                classification_results = self.classification_analyzer.classify_resources(data_stores)
            except Exception as e:
                logger.error(f"Error in classification analysis: {e}")
        
        if include_lineage:
            logger.info("Running lineage analysis")
            try:
                lineage_results = self.lineage_analyzer.build_lineage_graph(data_stores)
            except Exception as e:
                logger.error(f"Error in lineage analysis: {e}")
        
        if include_residency:
            logger.info("Running residency checks")
            try:
                # Create residency policy if allowed_regions provided
                if allowed_regions:
                    from ..analyzer.residency_analyzer import ResidencyPolicy
                    policy = ResidencyPolicy("tenant_policy", allowed_regions, f"Residency policy for {tenant_id}")
                    self.residency_analyzer.policies = [policy]
                    logger.info(f"Residency policy configured: allowed_regions={allowed_regions}")
                else:
                    logger.info("No residency policy configured - all resources will show 'unknown' status")
                
                residency_results = self.residency_analyzer.check_all_resources(data_stores)
            except Exception as e:
                logger.error(f"Error in residency checks: {e}")
        
        if include_activity:
            logger.info("Running activity monitoring")
            try:
                activity_results = self.activity_analyzer.monitor_data_access(data_stores)
            except Exception as e:
                logger.error(f"Error in activity monitoring: {e}")
        
        # Calculate summary statistics
        summary = self._calculate_summary(
            enriched_findings,
            classification_results,
            residency_results,
            activity_results
        )
        
        # Build report
        report = {
            "schema_version": "cspm_data_security_report.v1",
            "tenant_id": tenant_id,
            "scan_context": {
                "csp": csp,
                "threat_scan_run_id": scan_id,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_data_stores": len(data_stores),
            },
            "summary": summary,
            "findings": enriched_findings,
            "classification": [self._classification_to_dict(cr) for cr in classification_results],
            "lineage": lineage_results,
            "residency": [self._residency_to_dict(rr) for rr in residency_results],
            "activity": {
                resource_id: [self._activity_to_dict(ae) for ae in events]
                for resource_id, events in activity_results.items()
            },
        }
        
        return report
    
    def _calculate_summary(
        self,
        findings: List[Dict],
        classification: List,
        residency: List,
        activity: Dict[str, List]
    ) -> Dict[str, Any]:
        """Calculate summary statistics."""
        # Finding statistics
        total_findings = len(findings)
        data_security_relevant = sum(1 for f in findings if f.get("is_data_security_relevant"))
        
        # Module distribution
        module_counts = defaultdict(int)
        for finding in findings:
            for module in finding.get("data_security_modules", []):
                module_counts[module] += 1
        
        # Classification statistics
        classified_resources = len(classification)
        classification_types = defaultdict(int)
        for cr in classification:
            for cls in cr.classification:
                classification_types[cls.value] += 1
        
        # Residency statistics
        residency_compliant = sum(1 for r in residency if r.compliance_status.value == "compliant")
        residency_non_compliant = sum(1 for r in residency if r.compliance_status.value == "non_compliant")
        
        # Activity statistics
        total_activity_events = sum(len(events) for events in activity.values())
        high_risk_events = sum(
            sum(1 for ae in events if ae.risk_level == "high")
            for events in activity.values()
        )
        
        return {
            "total_findings": total_findings,
            "data_security_relevant_findings": data_security_relevant,
            "findings_by_module": dict(module_counts),
            "classification": {
                "classified_resources": classified_resources,
                "classification_types": dict(classification_types),
            },
            "residency": {
                "total_checked": len(residency),
                "compliant": residency_compliant,
                "non_compliant": residency_non_compliant,
            },
            "activity": {
                "total_events": total_activity_events,
                "high_risk_events": high_risk_events,
            },
        }
    
    def _classification_to_dict(self, classification_result) -> Dict[str, Any]:
        """Convert ClassificationResult to dictionary."""
        return {
            "resource_id": classification_result.resource_id,
            "resource_arn": classification_result.resource_arn,
            "resource_type": classification_result.resource_type,
            "classification": [c.value for c in classification_result.classification],
            "confidence": classification_result.confidence,
            "matched_patterns": classification_result.matched_patterns,
        }
    
    def _residency_to_dict(self, residency_check) -> Dict[str, Any]:
        """Convert ResidencyCheck to dictionary."""
        return {
            "resource_id": residency_check.resource_id,
            "resource_arn": residency_check.resource_arn,
            "primary_region": residency_check.primary_region,
            "replication_regions": residency_check.replication_regions,
            "policy_name": residency_check.policy_name,
            "compliance_status": residency_check.compliance_status.value,
            "violations": residency_check.violations,
        }
    
    def _activity_to_dict(self, activity_event) -> Dict[str, Any]:
        """Convert ActivityEvent to dictionary."""
        return {
            "event_id": activity_event.event_id,
            "timestamp": activity_event.timestamp.isoformat() if isinstance(activity_event.timestamp, datetime) else str(activity_event.timestamp),
            "resource_id": activity_event.resource_id,
            "resource_arn": activity_event.resource_arn,
            "principal": activity_event.principal,
            "action": activity_event.action,
            "ip_address": activity_event.ip_address,
            "location": activity_event.location,
            "anomaly_score": activity_event.anomaly_score,
            "risk_level": activity_event.risk_level,
            "alert_triggered": activity_event.alert_triggered,
        }
    
    def save_report(self, report: Dict[str, Any], output_path: str) -> None:
        """
        Save report to JSON file.
        
        Args:
            report: Report dictionary
            output_path: Path to save report
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)


# Convenience function
def generate_data_security_report(
    csp: str,
    scan_id: str,
    tenant_id: str = "default-tenant",
    rule_db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Generate a data security report from Threat DB."""
    reporter = DataSecurityReporter(rule_db_path)
    return reporter.generate_report(csp, scan_id, tenant_id=tenant_id)

