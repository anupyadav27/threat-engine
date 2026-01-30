"""
CSV Exporter

Exports compliance reports as CSV for spreadsheet analysis.
"""

from typing import Dict, List, Any
import csv
from io import StringIO


class CSVExporter:
    """Exports compliance reports as CSV."""
    
    @staticmethod
    def export_framework_report(report: Dict[str, Any]) -> str:
        """
        Export framework report as CSV.
        
        CSV format:
        framework,control_id,control_title,status,compliance_score,checks_total,checks_passed,checks_failed
        
        Args:
            report: Framework report dictionary
        
        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Framework',
            'Control ID',
            'Control Title',
            'Control Category',
            'Status',
            'Compliance Score',
            'Checks Total',
            'Checks Passed',
            'Checks Failed',
            'Checks Error'
        ])
        
        framework = report.get('framework', '')
        controls = report.get('controls', [])
        
        for control in controls:
            writer.writerow([
                framework,
                control.get('control_id', ''),
                control.get('control_title', ''),
                control.get('control_category', ''),
                control.get('status', ''),
                report.get('compliance_score', 0),
                control.get('checks_total', 0),
                control.get('checks_passed', 0),
                control.get('checks_failed', 0),
                control.get('checks_error', 0)
            ])
        
        return output.getvalue()
    
    @staticmethod
    def export_executive_summary(report: Dict[str, Any]) -> str:
        """
        Export executive dashboard summary as CSV.
        
        Args:
            report: Executive dashboard dictionary
        
        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Framework',
            'Compliance Score',
            'Status',
            'Controls Total',
            'Controls Passed',
            'Controls Failed',
            'Controls Partial'
        ])
        
        frameworks = report.get('frameworks', [])
        for fw in frameworks:
            writer.writerow([
                fw.get('framework', ''),
                fw.get('compliance_score', 0),
                fw.get('status', ''),
                fw.get('controls_total', 0),
                fw.get('controls_passed', 0),
                fw.get('controls_failed', 0),
                fw.get('controls_partial', 0)
            ])
        
        return output.getvalue()
    
    @staticmethod
    def save_framework_report(report: Dict[str, Any], filepath: str) -> None:
        """Save framework report to CSV file."""
        csv_content = CSVExporter.export_framework_report(report)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(csv_content)
    
    @staticmethod
    def save_executive_summary(report: Dict[str, Any], filepath: str) -> None:
        """Save executive summary to CSV file."""
        csv_content = CSVExporter.export_executive_summary(report)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(csv_content)
    
    @staticmethod
    def export_findings(findings: List[Dict[str, Any]]) -> str:
        """
        Export findings as CSV.
        
        Args:
            findings: List of finding dictionaries
        
        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Finding ID',
            'Rule ID',
            'Rule Version',
            'Category',
            'Title',
            'Description',
            'Severity',
            'Confidence',
            'Status',
            'First Seen At',
            'Last Seen At',
            'Resource Type',
            'Resource ID',
            'Resource ARN',
            'Region',
            'Framework',
            'Control ID'
        ])
        
        for finding in findings:
            # Get first affected asset
            asset = finding.get('affected_assets', [{}])[0] if finding.get('affected_assets') else {}
            
            # Get first compliance mapping
            mapping = finding.get('compliance_mappings', [{}])[0] if finding.get('compliance_mappings') else {}
            
            writer.writerow([
                finding.get('finding_id', ''),
                finding.get('rule_id', ''),
                finding.get('rule_version', ''),
                finding.get('category', ''),
                finding.get('title', ''),
                finding.get('description', ''),
                finding.get('severity', ''),
                finding.get('confidence', ''),
                finding.get('status', ''),
                finding.get('first_seen_at', ''),
                finding.get('last_seen_at', ''),
                asset.get('resource_type', ''),
                asset.get('resource_id', ''),
                asset.get('arn', ''),
                asset.get('region', ''),
                mapping.get('framework_id', ''),
                mapping.get('control_id', '')
            ])
        
        return output.getvalue()

