#!/usr/bin/env python3
"""
Test Consolidated CSV Integration - Generate Report

This test:
1. Loads sample scan results
2. Uses consolidated CSV for framework mappings
3. Generates a compliance report
4. Saves results to a visible location
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add compliance-engine to path
sys.path.insert(0, str(Path(__file__).parent))

from compliance_engine.loader.consolidated_csv_loader import ConsolidatedCSVLoader
from compliance_engine.mapper.framework_loader import FrameworkLoader
from compliance_engine.mapper.rule_mapper import RuleMapper
from compliance_engine.aggregator.result_aggregator import ResultAggregator
from compliance_engine.aggregator.score_calculator import ScoreCalculator
from compliance_engine.reporter.executive_dashboard import ExecutiveDashboard
from compliance_engine.reporter.framework_report import FrameworkReport

def create_sample_scan_results():
    """Create sample scan results for testing."""
    return {
        'scan_id': f'test-scan-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
        'csp': 'aws',
        'account_id': '123456789012',
        'scanned_at': datetime.utcnow().isoformat() + 'Z',
        'results': [
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'service': 's3',
                'checks': [
                    {
                        'rule_id': 'aws.s3.bucket.block_public_access_enabled',
                        'result': 'FAIL',
                        'severity': 'high',
                        'resource': {'type': 's3_bucket', 'id': 'test-bucket-1'},
                        'evidence': {'public_access_blocked': False}
                    },
                    {
                        'rule_id': 'aws.s3.bucket.encryption_at_rest_enabled',
                        'result': 'PASS',
                        'severity': 'medium',
                        'resource': {'type': 's3_bucket', 'id': 'test-bucket-1'},
                        'evidence': {'encryption_enabled': True}
                    }
                ]
            },
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'service': 'iam',
                'checks': [
                    {
                        'rule_id': 'aws.iam.user.mfa_required',
                        'result': 'FAIL',
                        'severity': 'high',
                        'resource': {'type': 'iam_user', 'id': 'test-user'},
                        'evidence': {'mfa_enabled': False}
                    },
                    {
                        'rule_id': 'aws.iam.policy.no_administrative_privileges',
                        'result': 'PASS',
                        'severity': 'high',
                        'resource': {'type': 'iam_policy', 'id': 'test-policy'},
                        'evidence': {'has_admin_privileges': False}
                    }
                ]
            }
        ]
    }

def test_generate_report():
    """Generate a compliance report using consolidated CSV."""
    print("=" * 80)
    print("Testing Consolidated CSV Integration - Report Generation")
    print("=" * 80)
    print()
    
    # Create sample scan results
    print("[1] Creating sample scan results...")
    scan_results = create_sample_scan_results()
    print(f"    Scan ID: {scan_results['scan_id']}")
    print(f"    Total checks: {sum(len(r.get('checks', [])) for r in scan_results['results'])}")
    print()
    
    # Initialize components with consolidated CSV
    print("[2] Initializing components with consolidated CSV...")
    framework_loader = FrameworkLoader()
    rule_mapper = RuleMapper()
    rule_mapper.framework_loader = framework_loader
    
    # Verify consolidated CSV is being used
    mappings = framework_loader.get_rule_mappings("aws")
    print(f"    Total rule mappings loaded: {len(mappings)}")
    
    # Check frameworks available
    csv_loader = ConsolidatedCSVLoader()
    frameworks = csv_loader.get_frameworks_list()
    print(f"    Frameworks available: {len(frameworks)}")
    print(f"    Sample frameworks: {', '.join(frameworks[:5])}")
    print()
    
    # Aggregate results
    print("[3] Aggregating scan results by framework...")
    aggregator = ResultAggregator(rule_mapper)
    framework_data = aggregator.aggregate_by_framework(scan_results, "aws", None)
    
    print(f"    Frameworks detected: {len(framework_data)}")
    for framework in list(framework_data.keys())[:10]:
        controls = framework_data[framework]
        print(f"      - {framework}: {len(controls)} controls")
    print()
    
    # Calculate scores
    print("[4] Calculating compliance scores...")
    score_calculator = ScoreCalculator(aggregator)
    
    # Generate executive dashboard
    print("[5] Generating executive dashboard...")
    executive_dashboard = ExecutiveDashboard(aggregator, score_calculator)
    dashboard = executive_dashboard.generate(scan_results, "aws", None)
    
    print(f"    Overall compliance score: {dashboard.get('summary', {}).get('overall_compliance_score', 0):.1f}%")
    print(f"    Total frameworks: {dashboard.get('summary', {}).get('total_frameworks', 0)}")
    print(f"    Frameworks with data: {len(dashboard.get('frameworks', []))}")
    print()
    
    # Generate framework reports for top frameworks
    print("[6] Generating framework-specific reports...")
    framework_report = FrameworkReport(aggregator, score_calculator)
    framework_reports = {}
    
    # Get top 5 frameworks
    top_frameworks = [fw.get('framework') if isinstance(fw, dict) else fw 
                     for fw in dashboard.get('frameworks', [])[:5]]
    
    for framework in top_frameworks:
        if framework:
            fw_report = framework_report.generate(scan_results, "aws", framework)
            framework_reports[framework] = fw_report
            score = fw_report.get('compliance_score', 0)
            print(f"      - {framework}: {score:.1f}% compliance")
    print()
    
    # Create full report
    report = {
        'report_id': f"test-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        'scan_id': scan_results['scan_id'],
        'csp': 'aws',
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'source': 'consolidated_csv_test',
        'executive_dashboard': dashboard,
        'framework_reports': framework_reports,
        'test_info': {
            'consolidated_csv_used': True,
            'csv_path': str(csv_loader.csv_path),
            'total_frameworks_available': len(frameworks),
            'frameworks_in_report': len(framework_reports)
        }
    }
    
    # Save report to local directory
    output_dir = Path("/Users/apple/Desktop/threat-engine/compliance-engine/test_output")
    output_dir.mkdir(exist_ok=True)
    
    report_file = output_dir / f"consolidated_csv_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    print(f"[7] Saving report to: {report_file}")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"    ✅ Report saved successfully!")
    print()
    
    # Also create a summary file
    summary_file = output_dir / f"consolidated_csv_test_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(summary_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("Consolidated CSV Integration Test Summary\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"CSV Path: {csv_loader.csv_path}\n")
        f.write(f"CSV Exists: {csv_loader.csv_path.exists()}\n\n")
        f.write(f"Total Frameworks Available: {len(frameworks)}\n")
        f.write(f"Frameworks: {', '.join(frameworks)}\n\n")
        f.write(f"Total Rule Mappings: {len(mappings)}\n\n")
        f.write(f"Scan ID: {scan_results['scan_id']}\n")
        f.write(f"Total Checks: {sum(len(r.get('checks', [])) for r in scan_results['results'])}\n\n")
        f.write(f"Overall Compliance Score: {dashboard.get('summary', {}).get('overall_compliance_score', 0):.1f}%\n")
        f.write(f"Frameworks in Report: {len(framework_reports)}\n\n")
        f.write("Framework Scores:\n")
        for framework, fw_report in framework_reports.items():
            score = fw_report.get('compliance_score', 0)
            f.write(f"  - {framework}: {score:.1f}%\n")
        f.write("\n" + "=" * 80 + "\n")
        f.write(f"Full report saved to: {report_file}\n")
    
    print(f"    ✅ Summary saved to: {summary_file}")
    print()
    
    print("=" * 80)
    print("✅ Test completed successfully!")
    print("=" * 80)
    print()
    print("📁 Results saved to:")
    print(f"   - Full Report: {report_file}")
    print(f"   - Summary: {summary_file}")
    print()
    print("You can open these files to see the detailed results!")
    
    return report_file, summary_file

if __name__ == "__main__":
    try:
        report_file, summary_file = test_generate_report()
        print(f"\n✅ Test passed! Check the files above to see results.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
