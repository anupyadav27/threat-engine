#!/usr/bin/env python3
"""
Test Enterprise Report Generation Locally

Loads scan results from local file and generates enterprise-grade compliance reports.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from compliance_engine.schemas.enterprise_report_schema import (
    ScanContext, TriggerType, Cloud, CollectionMode
)
from compliance_engine.reporter.enterprise_reporter import EnterpriseReporter
from compliance_engine.exporter.json_exporter import JSONExporter
from compliance_engine.exporter.csv_exporter import CSVExporter
from compliance_engine.exporter.pdf_exporter import PDFExporter


def load_scan_results_from_file(file_path: str) -> dict:
    """Load scan results from NDJSON file."""
    results = []
    account_id = None
    scanned_at = None
    
    print(f"Loading scan results from: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
                results.append(result)
                
                # Extract account_id from first result
                if account_id is None:
                    account_id = result.get('account')
                
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping malformed line {line_num}: {e}")
                continue
    
    print(f"Loaded {len(results)} scan result entries")
    
    # Generate scan_id from file name or timestamp
    scan_id = Path(file_path).stem.replace(' ', '_')
    
    return {
        'scan_id': scan_id,
        'account_id': account_id,
        'scanned_at': scanned_at or datetime.utcnow().isoformat() + 'Z',
        'results': results
    }


def main():
    """Main test function."""
    # Configuration
    scan_results_file = "/Users/apple/Downloads/results (3).ndjson"
    output_dir = project_root / "local_reports"
    evidence_dir = output_dir / "evidence"
    
    tenant_id = "test-tenant-001"
    tenant_name = "Test Tenant"
    
    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(evidence_dir, exist_ok=True)
    
    print("=" * 60)
    print("Enterprise Compliance Report Generation - Local Test")
    print("=" * 60)
    print()
    
    # Step 1: Load scan results
    print("Step 1: Loading scan results...")
    if not os.path.exists(scan_results_file):
        print(f"Error: Scan results file not found: {scan_results_file}")
        return 1
    
    scan_results = load_scan_results_from_file(scan_results_file)
    print(f"✅ Loaded {len(scan_results['results'])} results")
    print()
    
    # Step 2: Create scan context
    print("Step 2: Creating scan context...")
    scan_run_id = f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    scan_context = ScanContext(
        scan_run_id=scan_run_id,
        trigger_type=TriggerType.MANUAL,
        cloud=Cloud.AWS,
        collection_mode=CollectionMode.FULL,
        regions=None,  # Will be extracted from results
        started_at=scan_results.get('scanned_at', datetime.utcnow().isoformat() + 'Z'),
        completed_at=datetime.utcnow().isoformat() + 'Z'
    )
    print(f"✅ Scan Run ID: {scan_run_id}")
    print()
    
    # Step 3: Generate enterprise report
    print("Step 3: Generating enterprise compliance report...")
    reporter = EnterpriseReporter(
        tenant_id=tenant_id,
        local_storage_path=str(output_dir)
    )
    
    try:
        report = reporter.generate_report(
            scan_results=scan_results,
            scan_context=scan_context,
            tenant_name=tenant_name
        )
        print(f"✅ Report generated successfully!")
        print(f"   - Total Findings: {len(report.findings)}")
        print(f"   - Total Frameworks: {len(report.frameworks)}")
        print(f"   - Total Assets: {len(report.asset_snapshots)}")
        print()
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Step 4: Export to JSON
    print("Step 4: Exporting to JSON...")
    json_exporter = JSONExporter()
    json_content = json_exporter.export(report.model_dump(), pretty=True)
    json_file = output_dir / f"enterprise_report_{scan_run_id}.json"
    with open(json_file, 'w') as f:
        f.write(json_content)
    print(f"✅ JSON report saved: {json_file}")
    print()
    
    # Step 5: Export to CSV
    print("Step 5: Exporting to CSV...")
    try:
        csv_exporter = CSVExporter()
        # Export findings (convert Pydantic models to dicts)
        findings_dicts = [f.model_dump() for f in report.findings]
        findings_csv = csv_exporter.export_findings(findings_dicts)
        csv_file = output_dir / f"findings_{scan_run_id}.csv"
        with open(csv_file, 'w') as f:
            f.write(findings_csv)
        print(f"✅ Findings CSV saved: {csv_file}")
    except Exception as e:
        print(f"⚠️  CSV export failed: {e}")
        import traceback
        traceback.print_exc()
    print()
    
    # Step 6: Export to PDF
    print("Step 6: Exporting to PDF...")
    try:
        pdf_exporter = PDFExporter()
        pdf_bytes = pdf_exporter.export_executive_summary({
            'summary': report.posture_summary.model_dump(),
            'findings': [f.model_dump() for f in report.findings[:10]]  # Top 10 findings
        })
        pdf_file = output_dir / f"executive_summary_{scan_run_id}.pdf"
        with open(pdf_file, 'wb') as f:
            f.write(pdf_bytes)
        print(f"✅ PDF report saved: {pdf_file}")
    except Exception as e:
        print(f"⚠️  PDF export failed: {e}")
    print()
    
    # Step 7: Print summary
    print("=" * 60)
    print("Report Generation Complete!")
    print("=" * 60)
    print()
    print("Summary:")
    print(f"  - Scan Run ID: {scan_run_id}")
    print(f"  - Tenant: {tenant_name} ({tenant_id})")
    print(f"  - Total Findings: {report.posture_summary.total_findings}")
    print(f"  - Findings by Severity:")
    for severity, count in report.posture_summary.findings_by_severity.items():
        print(f"    - {severity}: {count}")
    print(f"  - Total Controls: {report.posture_summary.total_controls}")
    print(f"  - Controls Passed: {report.posture_summary.controls_passed}")
    print(f"  - Controls Failed: {report.posture_summary.controls_failed}")
    print()
    print("Output Files:")
    print(f"  - JSON: {json_file}")
    if 'csv_file' in locals():
        print(f"  - CSV: {csv_file}")
    if 'pdf_file' in locals():
        print(f"  - PDF: {pdf_file}")
    print(f"  - Evidence: {evidence_dir}")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

