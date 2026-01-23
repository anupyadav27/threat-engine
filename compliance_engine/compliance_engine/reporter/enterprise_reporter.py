"""
Enterprise Reporter - Generates enterprise-grade compliance reports
"""

import hashlib
import uuid
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

from ..schemas.enterprise_report_schema import (
    EnterpriseComplianceReport, Finding, Control, Framework, Section, PostureSummary,
    Tenant, ScanContext, AssetSnapshot, Evidence, ComplianceMapping,
    AffectedAsset, Remediation, Integrity, TriggerType, Cloud, CollectionMode,
    ControlStatus, Severity, Confidence, FindingStatus, EvidenceType
)
from ..storage.evidence_manager import EvidenceManager
from ..mapper.rule_mapper import RuleMapper


class EnterpriseReporter:
    """Generates enterprise-grade compliance reports."""
    
    def __init__(
        self,
        tenant_id: str,
        s3_bucket: str = None,
        local_storage_path: str = None
    ):
        """
        Initialize enterprise reporter.
        
        Args:
            tenant_id: Tenant identifier
            s3_bucket: S3 bucket for evidence storage (optional)
            local_storage_path: Local path for evidence storage (for testing)
        """
        self.tenant_id = tenant_id
        self.evidence_manager = EvidenceManager(
            s3_bucket=s3_bucket,
            tenant_id=tenant_id,
            local_storage_path=local_storage_path
        )
        self.rule_mapper = RuleMapper()
    
    def generate_stable_finding_id(self, rule_id: str, resource_arn: str) -> str:
        """
        Generate deterministic UUID from rule_id + resource_arn.
        Ensures same finding gets same ID across scans.
        """
        key = f"{rule_id}#{resource_arn}"
        namespace = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
        return str(uuid.uuid5(namespace, key))
    
    def deduplicate_findings(
        self,
        scan_results: List[Dict[str, Any]],
        csp: str,
        scan_run_id: str,
        previous_findings: Optional[List[Finding]] = None
    ) -> Dict[str, Finding]:
        """
        Deduplicate findings by (rule_id + resource_arn).
        Returns dict mapping finding_id -> Finding.
        """
        findings_map = {}
        
        # Set scan_run_id in evidence manager
        self.evidence_manager.scan_run_id = scan_run_id
        
        # Load previous findings if provided (for first_seen_at tracking)
        previous_map = {}
        if previous_findings:
            for f in previous_findings:
                previous_map[f.finding_id] = f
        
        # Get rule to controls mapping for compliance mappings
        rule_to_controls = self.rule_mapper.map_scan_results({'results': scan_results}, csp)
        
        for result in scan_results:
            checks = result.get('checks', [])
            service = result.get('service', 'unknown')
            region = result.get('region', 'global')
            account = result.get('account', '')
            
            for check in checks:
                if check.get('result') != 'FAIL':
                    continue
                
                rule_id = check.get('rule_id')
                if not rule_id:
                    continue
                
                # Extract resource info
                resource = check.get('resource', {})
                resource_arn = resource.get('arn') or resource.get('resource_id', '')
                
                # Try to construct ARN if not present
                if not resource_arn and resource.get('resource_id'):
                    resource_type = resource.get('resource_type', service)
                    resource_id = resource.get('resource_id')
                    # Construct a unique identifier
                    resource_arn = f"arn:aws:{service}:{region}:{account}:{resource_type}/{resource_id}"
                
                if not resource_arn:
                    # Use rule_id + region + service as fallback
                    resource_arn = f"{rule_id}#{region}#{service}"
                
                # Generate stable finding_id
                finding_id = self.generate_stable_finding_id(rule_id, resource_arn)
                
                # Check if we've seen this finding before
                if finding_id in findings_map:
                    # Update last_seen_at and merge affected assets
                    existing_finding = findings_map[finding_id]
                    existing_finding.last_seen_at = datetime.utcnow().isoformat() + 'Z'
                    
                    # Add new affected asset if different
                    new_asset = AffectedAsset(
                        asset_id=resource_arn,
                        provider=csp,
                        resource_type=resource.get('resource_type', service),
                        resource_id=resource.get('resource_id', ''),
                        region=region,
                        arn=resource_arn,
                        tags=resource.get('tags')
                    )
                    
                    # Check if asset already exists
                    asset_exists = any(
                        a.asset_id == resource_arn for a in existing_finding.affected_assets
                    )
                    if not asset_exists:
                        existing_finding.affected_assets.append(new_asset)
                    
                    continue
                
                # Create new finding
                first_seen_at = datetime.utcnow().isoformat() + 'Z'
                if finding_id in previous_map:
                    first_seen_at = previous_map[finding_id].first_seen_at
                
                # Extract evidence and store separately
                evidence_list = []
                if check.get('evidence'):
                    evidence_obj = self.evidence_manager.store_evidence(
                        evidence_payload=check['evidence'],
                        evidence_type=EvidenceType.CONFIG,
                        collected_at=first_seen_at
                    )
                    evidence_list.append(evidence_obj)
                
                # Create AffectedAsset
                affected_asset = AffectedAsset(
                    asset_id=resource_arn,
                    provider=csp,
                    resource_type=resource.get('resource_type', service),
                    resource_id=resource.get('resource_id', ''),
                    region=region,
                    arn=resource_arn,
                    tags=resource.get('tags')
                )
                
                # Get compliance mappings
                compliance_mappings = []
                controls = rule_to_controls.get(rule_id, [])
                for control in controls:
                    compliance_mappings.append(ComplianceMapping(
                        framework_id=control.framework,
                        framework_version=control.framework_version,
                        control_id=control.control_id,
                        control_title=control.control_title
                    ))
                
                # Map severity
                severity_str = check.get('severity', 'medium').lower()
                try:
                    severity = Severity(severity_str)
                except ValueError:
                    severity = Severity.MEDIUM
                
                # Create Finding
                finding = Finding(
                    finding_id=finding_id,
                    rule_id=rule_id,
                    rule_version=check.get('rule_version'),
                    category=check.get('category'),
                    title=check.get('title', rule_id),
                    description=check.get('description'),
                    severity=severity,
                    confidence=Confidence.HIGH,  # Default to high
                    status=FindingStatus.OPEN,
                    first_seen_at=first_seen_at,
                    last_seen_at=first_seen_at,
                    compliance_mappings=compliance_mappings,
                    affected_assets=[affected_asset],
                    evidence=evidence_list,
                    remediation=Remediation(
                        description=check.get('remediation', ''),
                        steps=check.get('remediation_steps', []),
                        automated=check.get('automated', False),
                        estimated_effort=check.get('estimated_effort')
                    ) if check.get('remediation') else None
                )
                
                findings_map[finding_id] = finding
        
        return findings_map
    
    def _extract_asset_snapshots(self, scan_results: List[Dict[str, Any]], csp: str) -> List[AssetSnapshot]:
        """Extract unique assets from scan results."""
        assets_map = {}
        
        for result in scan_results:
            checks = result.get('checks', [])
            service = result.get('service', 'unknown')
            region = result.get('region', 'global')
            account = result.get('account', '')
            
            # Extract from checks
            for check in checks:
                resource = check.get('resource', {})
                asset_id = resource.get('arn') or resource.get('resource_id', '')
                
                if not asset_id:
                    continue
                
                if asset_id not in assets_map:
                    assets_map[asset_id] = AssetSnapshot(
                        asset_id=asset_id,
                        provider=csp,
                        resource_type=resource.get('resource_type', service),
                        resource_id=resource.get('resource_id', ''),
                        region=region,
                        arn=resource.get('arn'),
                        tags=resource.get('tags')
                    )
        
        return list(assets_map.values())
    
    def _generate_posture_summary(
        self,
        findings: List[Finding],
        controls: List[Control]
    ) -> PostureSummary:
        """Generate posture summary."""
        findings_by_severity = defaultdict(int)
        findings_by_status = defaultdict(int)
        
        for finding in findings:
            findings_by_severity[finding.severity.value] += 1
            findings_by_status[finding.status.value] += 1
        
        # Count controls
        controls_passed = sum(1 for c in controls if c.status == ControlStatus.PASS)
        controls_failed = sum(1 for c in controls if c.status == ControlStatus.FAIL)
        controls_not_applicable = sum(1 for c in controls if c.status == ControlStatus.NOT_APPLICABLE)
        
        return PostureSummary(
            total_controls=len(controls),
            controls_passed=controls_passed,
            controls_failed=controls_failed,
            controls_not_applicable=controls_not_applicable,
            total_findings=len(findings),
            findings_by_severity=dict(findings_by_severity),
            findings_by_status=dict(findings_by_status)
        )
    
    def _generate_frameworks(
        self,
        findings: List[Finding],
        scan_results: List[Dict[str, Any]],
        csp: str
    ) -> List[Framework]:
        """Generate frameworks with controls linked to findings."""
        # Group findings by framework/control
        framework_controls_map = defaultdict(lambda: defaultdict(list))
        
        for finding in findings:
            for mapping in finding.compliance_mappings:
                framework_id = mapping.framework_id
                control_id = mapping.control_id
                framework_controls_map[framework_id][control_id].append(finding.finding_id)
        
        # Get framework metadata from rule mapper
        rule_to_controls = self.rule_mapper.map_scan_results({'results': scan_results}, csp)
        
        # Build frameworks
        frameworks = []
        for framework_id, controls_map in framework_controls_map.items():
            controls = []
            
            for control_id, finding_refs in controls_map.items():
                # Get control metadata from first finding
                first_finding = next(
                    (f for f in findings if f.finding_id in finding_refs),
                    None
                )
                
                if not first_finding:
                    continue
                
                # Get control metadata
                control_mapping = next(
                    (m for m in first_finding.compliance_mappings 
                     if m.framework_id == framework_id and m.control_id == control_id),
                    None
                )
                
                if not control_mapping:
                    continue
                
                # Count assets
                affected_assets = set()
                for finding_id in finding_refs:
                    finding = next((f for f in findings if f.finding_id == finding_id), None)
                    if finding:
                        for asset in finding.affected_assets:
                            affected_assets.add(asset.asset_id)
                
                asset_count_failed = len(affected_assets)
                asset_count_total = asset_count_failed  # Simplified for now
                asset_count_passed = max(0, asset_count_total - asset_count_failed)
                
                # Determine control status
                if asset_count_failed > 0:
                    status = ControlStatus.FAIL
                else:
                    status = ControlStatus.PASS
                
                controls.append(Control(
                    control_id=control_id,
                    control_title=control_mapping.control_title or control_id,
                    status=status,
                    finding_refs=finding_refs,
                    asset_count_passed=asset_count_passed,
                    asset_count_failed=asset_count_failed,
                    asset_count_total=asset_count_total
                ))
            
            if controls:
                # Group controls by section (simplified - all in one section for now)
                frameworks.append(Framework(
                    framework_id=framework_id,
                    framework_version=None,  # TODO: Extract from mappings
                    framework_name=framework_id,  # TODO: Get proper name
                    sections=[Section(
                        section_id='1',
                        section_title='Controls',
                        controls=controls
                    )]
                ))
        
        return frameworks
    
    def generate_report(
        self,
        scan_results: Dict[str, Any],
        scan_context: ScanContext,
        tenant_name: Optional[str] = None
    ) -> EnterpriseComplianceReport:
        """
        Generate enterprise compliance report.
        
        Args:
            scan_results: Scan results dictionary with 'results' list
            scan_context: Scan context information
            tenant_name: Optional tenant display name
        
        Returns:
            EnterpriseComplianceReport
        """
        results_list = scan_results.get('results', [])
        csp = scan_context.cloud.value
        
        # Deduplicate findings
        findings_map = self.deduplicate_findings(
            results_list,
            csp,
            scan_context.scan_run_id
        )
        findings = list(findings_map.values())
        
        # Generate frameworks with controls
        frameworks = self._generate_frameworks(findings, results_list, csp)
        
        # Extract all controls for summary
        all_controls = []
        for framework in frameworks:
            for section in framework.sections:
                all_controls.extend(section.controls)
        
        # Generate posture summary
        posture_summary = self._generate_posture_summary(findings, all_controls)
        
        # Extract asset snapshots
        asset_snapshots = self._extract_asset_snapshots(results_list, csp)
        
        # Create report
        report = EnterpriseComplianceReport(
            tenant=Tenant(
                tenant_id=self.tenant_id,
                tenant_name=tenant_name
            ),
            scan_context=scan_context,
            posture_summary=posture_summary,
            findings=findings,
            frameworks=frameworks,
            asset_snapshots=asset_snapshots,
            integrity=Integrity(
                generated_at=datetime.utcnow().isoformat() + 'Z',
                generator_version='1.0.0'
            )
        )
        
        return report

