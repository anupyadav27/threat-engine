#!/usr/bin/env python3
"""
Test Compliance Engine Locally Against AWS ConfigScan Output
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path("/Users/apple/Desktop/threat-engine/compliance-engine")
sys.path.insert(0, str(project_root))

from compliance_engine.schemas.enterprise_report_schema import (
    ScanContext, TriggerType, Cloud, CollectionMode
)
from compliance_engine.reporter.enterprise_reporter import EnterpriseReporter
from compliance_engine.exporter.json_exporter import JSONExporter
from compliance_engine.exporter.csv_exporter import CSVExporter
from compliance_engine.mapper.rule_mapper import RuleMapper
from compliance_engine.aggregator.result_aggregator import ResultAggregator


def load_scan_results_from_file(file_path: str) -> dict:
    """Load scan results from NDJSON file."""
    results = []
    account_id = None
    
    print(f"📂 Loading scan results from: {file_path}")
    
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
                print(f"⚠️  Warning: Skipping malformed line {line_num}: {e}")
                continue
    
    print(f"✅ Loaded {len(results)} scan result entries")
    
    return {
        'scan_id': 'aws-config-scan-latest',
        'account_id': account_id,
        'scanned_at': datetime.utcnow().isoformat() + 'Z',
        'results': results
    }


def main():
    """Main test function."""
    print("=" * 80)
    print("🔍 COMPLIANCE ENGINE - LOCAL TEST")
    print("=" * 80)
    print()
    
    # Configuration
    scan_results_file = "/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/latest/results.ndjson"
    output_dir = Path("/Users/apple/Desktop/threat-engine/engines-output/complaince-engine/output/latest")
    
    tenant_id = "test-tenant-lgtech"
    tenant_name = "LG Tech"
    
    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    print(f"📁 Output directory: {output_dir}")
    print()
    
    # Step 1: Load scan results
    print("=" * 80)
    print("STEP 1: Loading AWS ConfigScan Results")
    print("=" * 80)
    
    if not os.path.exists(scan_results_file):
        print(f"❌ Error: Scan results file not found: {scan_results_file}")
        return 1
    
    scan_results = load_scan_results_from_file(scan_results_file)
    print(f"   Account ID: {scan_results['account_id']}")
    print(f"   Results: {len(scan_results['results'])} entries")
    
    # Count checks
    total_checks = 0
    passed = 0
    failed = 0
    services = set()
    regions = set()
    
    for result in scan_results['results']:
        checks = result.get('checks', [])
        total_checks += len(checks)
        services.add(result.get('service', 'unknown'))
        regions.add(result.get('region', 'global'))
        
        for check in checks:
            if check.get('result') == 'PASS':
                passed += 1
            elif check.get('result') == 'FAIL':
                failed += 1
    
    print(f"   Total Checks: {total_checks}")
    print(f"   ✅ Passed: {passed}")
    print(f"   ❌ Failed: {failed}")
    print(f"   Services: {', '.join(sorted(services))}")
    print(f"   Regions: {', '.join(sorted(regions))}")
    print()
    
    # Step 2: Map rules to compliance frameworks
    print("=" * 80)
    print("STEP 2: Mapping Rules to Compliance Frameworks")
    print("=" * 80)
    
    rule_mapper = RuleMapper()
    rule_to_controls = rule_mapper.map_scan_results(scan_results, 'aws')
    
    print(f"   Rules Mapped: {len(rule_to_controls)}")
    
    # List frameworks covered
    frameworks = set()
    for controls in rule_to_controls.values():
        for control in controls:
            frameworks.add(control.framework)
    
    print(f"   Frameworks Covered: {len(frameworks)}")
    for fw in sorted(frameworks)[:10]:  # Show first 10
        print(f"      - {fw}")
    if len(frameworks) > 10:
        print(f"      ... and {len(frameworks) - 10} more")
    print()
    
    # Show sample mappings
    print("   Sample Rule Mappings:")
    for rule_id, controls in list(rule_to_controls.items())[:3]:
        print(f"      {rule_id}")
        for control in controls[:2]:
            print(f"         → {control.framework} {control.control_id}: {control.control_title[:60]}")
    print()
    
    # Step 3: Aggregate by framework
    print("=" * 80)
    print("STEP 3: Aggregating Results by Framework")
    print("=" * 80)
    
    aggregator = ResultAggregator(rule_mapper)
    framework_data = aggregator.aggregate_by_framework(scan_results, 'aws')
    
    for framework, controls in sorted(framework_data.items())[:10]:
        print(f"   📊 {framework}: {len(controls)} controls")
    if len(framework_data) > 10:
        print(f"   ... and {len(framework_data) - 10} more frameworks")
    print()
    
    # Step 4: Generate enterprise report
    print("=" * 80)
    print("STEP 4: Generating Enterprise Compliance Report")
    print("=" * 80)
    
    scan_run_id = f"scan-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    scan_context = ScanContext(
        scan_run_id=scan_run_id,
        trigger_type=TriggerType.MANUAL,
        cloud=Cloud.AWS,
        collection_mode=CollectionMode.FULL,
        regions=list(regions),
        started_at=scan_results.get('scanned_at', datetime.utcnow().isoformat() + 'Z'),
        completed_at=datetime.utcnow().isoformat() + 'Z'
    )
    
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
        print(f"   Total Findings: {len(report.findings)}")
        print(f"   Total Frameworks: {len(report.frameworks)}")
        print(f"   Total Assets: {len(report.asset_snapshots)}")
        print()
    except Exception as e:
        print(f"❌ Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Step 5: Export to JSON
    print("=" * 80)
    print("STEP 5: Exporting Reports")
    print("=" * 80)
    
    json_exporter = JSONExporter()
    json_content = json_exporter.export(report.model_dump(), pretty=True)
    json_file = output_dir / f"compliance_report_{scan_run_id}.json"
    with open(json_file, 'w') as f:
        f.write(json_content)
    print(f"✅ JSON: {json_file}")
    
    # Export to CSV
    try:
        csv_exporter = CSVExporter()
        findings_dicts = [f.model_dump() for f in report.findings]
        findings_csv = csv_exporter.export_findings(findings_dicts)
        csv_file = output_dir / f"findings_{scan_run_id}.csv"
        with open(csv_file, 'w') as f:
            f.write(findings_csv)
        print(f"✅ CSV: {csv_file}")
    except Exception as e:
        print(f"⚠️  CSV export failed: {e}")
    
    print()
    
    # Step 6: Summary
    print("=" * 80)
    print("📋 COMPLIANCE REPORT SUMMARY")
    print("=" * 80)
    print(f"   Scan Run ID: {scan_run_id}")
    print(f"   Tenant: {tenant_name} ({tenant_id})")
    print(f"   Account: {scan_results['account_id']}")
    print()
    print(f"   Total Findings: {report.posture_summary.total_findings}")
    print(f"   Findings by Severity:")
    for severity, count in sorted(report.posture_summary.findings_by_severity.items()):
        print(f"      - {severity}: {count}")
    print()
    print(f"   Findings by Status:")
    for status, count in sorted(report.posture_summary.findings_by_status.items()):
        print(f"      - {status}: {count}")
    print()
    print(f"   Total Controls: {report.posture_summary.total_controls}")
    print(f"   Controls Passed: {report.posture_summary.controls_passed}")
    print(f"   Controls Failed: {report.posture_summary.controls_failed}")
    print()
    
    # Show sample findings
    if report.findings:
        print("   Sample Findings (first 3):")
        for finding in report.findings[:3]:
            print(f"      - [{finding.severity.upper()}] {finding.rule_id}")
            print(f"        Asset: {finding.affected_assets[0].resource_type if finding.affected_assets else 'N/A'}")
            print(f"        Compliance: {len(finding.compliance_mappings)} framework(s)")
    
    print()
    print(f"✅ All outputs saved to: {output_dir}")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
















