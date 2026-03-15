"""
Threat Reporter

Generates threat reports from normalized findings and detected threats.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from ..schemas.threat_report_schema import (
    ThreatReport,
    Threat,
    ThreatSummary,
    Tenant,
    ScanContext,
    AssetSnapshot,
    Evidence,
    ThreatType,
    ThreatStatus,
    Cloud,
    TriggerType
)
from ..schemas.misconfig_normalizer import MisconfigFinding


class ThreatReporter:
    """Generates threat reports"""
    
    def generate_report(
        self,
        tenant: Tenant,
        scan_context: ScanContext,
        threats: List[Threat],
        misconfig_findings: List[MisconfigFinding],
        evidence: Optional[List[Evidence]] = None
    ) -> ThreatReport:
        """
        Generate complete threat report.
        
        Args:
            tenant: Tenant information
            scan_context: Scan context
            threats: Detected threats
            misconfig_findings: Normalized misconfig findings
            evidence: Optional evidence references
        
        Returns:
            Complete threat report
        """
        # Generate threat summary
        threat_summary = self._generate_threat_summary(threats)
        
        # Extract asset snapshots
        asset_snapshots = self._extract_asset_snapshots(threats, misconfig_findings)
        
        # Use provided evidence or create empty list
        if evidence is None:
            evidence = []
        
        report = ThreatReport(
            tenant=tenant,
            scan_context=scan_context,
            threat_summary=threat_summary,
            threats=threats,
            misconfig_findings=misconfig_findings,
            asset_snapshots=asset_snapshots,
            evidence=evidence,
            generated_at=datetime.now(timezone.utc)
        )
        
        return report
    
    def _generate_threat_summary(self, threats: List[Threat]) -> ThreatSummary:
        """Generate threat summary statistics"""
        total_threats = len(threats)
        
        # Count by severity
        threats_by_severity = {}
        for threat in threats:
            severity_str = threat.severity.value
            threats_by_severity[severity_str] = threats_by_severity.get(severity_str, 0) + 1
        
        # Count by category (threat type)
        threats_by_category = {}
        for threat in threats:
            category_str = threat.threat_type.value
            threats_by_category[category_str] = threats_by_category.get(category_str, 0) + 1
        
        # Count by status
        threats_by_status = {}
        for threat in threats:
            status_str = threat.status.value
            threats_by_status[status_str] = threats_by_status.get(status_str, 0) + 1
        
        # Top threat categories
        top_threat_categories = []
        for category, count in sorted(threats_by_category.items(), key=lambda x: x[1], reverse=True):
            top_threat_categories.append({
                "category": category,
                "count": count,
                "percentage": round((count / total_threats * 100) if total_threats > 0 else 0, 2)
            })
        
        return ThreatSummary(
            total_threats=total_threats,
            threats_by_severity=threats_by_severity,
            threats_by_category=threats_by_category,
            threats_by_status=threats_by_status,
            top_threat_categories=top_threat_categories[:10]  # Top 10
        )
    
    def _extract_asset_snapshots(
        self,
        threats: List[Threat],
        misconfig_findings: List[MisconfigFinding]
    ) -> List[AssetSnapshot]:
        """Extract unique asset snapshots from threats and findings"""
        from ..schemas.threat_report_schema import AssetSnapshot, Cloud
        
        assets = {}
        
        # Extract from threats
        for threat in threats:
            for asset in threat.affected_assets:
                asset_uid = asset.get("resource_uid") or asset.get("resource_arn")
                if asset_uid and asset_uid not in assets:
                    # Determine cloud provider from ARN or resource type
                    cloud = Cloud.AWS  # Default, can be enhanced
                    if asset.get("resource_arn"):
                        arn = asset["resource_arn"]
                        if arn.startswith("arn:aws:"):
                            cloud = Cloud.AWS
                        elif arn.startswith("arn:azure:"):
                            cloud = Cloud.AZURE
                        elif arn.startswith("arn:gcp:"):
                            cloud = Cloud.GCP
                    
                    assets[asset_uid] = AssetSnapshot(
                        asset_id=asset_uid,
                        provider=cloud,
                        resource_type=asset.get("resource_type", "unknown"),
                        resource_id=asset.get("resource_id", ""),
                        resource_arn=asset.get("resource_arn"),
                        region=asset.get("region"),
                        account=asset.get("account"),
                        tags={}  # Can be enhanced to extract from findings
                    )
        
        # Extract from misconfig findings
        for finding in misconfig_findings:
            resource = finding.resource
            asset_uid = resource.get("resource_uid") or resource.get("resource_arn")
            if asset_uid and asset_uid not in assets:
                # Determine cloud provider
                cloud = Cloud.AWS  # Default
                if resource.get("resource_arn"):
                    arn = resource["resource_arn"]
                    if arn.startswith("arn:aws:"):
                        cloud = Cloud.AWS
                    elif arn.startswith("arn:azure:"):
                        cloud = Cloud.AZURE
                    elif arn.startswith("arn:gcp:"):
                        cloud = Cloud.GCP
                
                assets[asset_uid] = AssetSnapshot(
                    asset_id=asset_uid,
                    provider=cloud,
                    resource_type=resource.get("resource_type", "unknown"),
                    resource_id=resource.get("resource_id", ""),
                    resource_arn=resource.get("resource_arn"),
                    region=finding.region,
                    account=finding.account,
                    tags=resource.get("tags", {})
                )
        
        return list(assets.values())

