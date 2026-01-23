#!/usr/bin/env python3
"""
Test Consolidated CSV Integration - Detailed Reports with Grouping

This test:
1. Loads sample scan results
2. Uses consolidated CSV for framework mappings
3. Generates detailed compliance reports with:
   - Grouping by Control ID (all resources per control)
   - Grouping by Resource (all compliance failures per resource)
4. Saves separate files for each framework
5. Saves to: /Users/apple/Desktop/threat-engine/engines-output/complaince-engine/output/{scan_id}/
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

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
        'scan_id': f'scan-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
        'csp': 'aws',
        'account_id': '123456789012',
        'scanned_at': datetime.now().isoformat() + 'Z',
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
                        'resource': {
                            'type': 's3_bucket',
                            'id': 'test-bucket-1',
                            'arn': 'arn:aws:s3:::test-bucket-1'
                        },
                        'evidence': {'public_access_blocked': False}
                    },
                    {
                        'rule_id': 'aws.s3.bucket.encryption_at_rest_enabled',
                        'result': 'PASS',
                        'severity': 'medium',
                        'resource': {
                            'type': 's3_bucket',
                            'id': 'test-bucket-1',
                            'arn': 'arn:aws:s3:::test-bucket-1'
                        },
                        'evidence': {'encryption_enabled': True}
                    },
                    {
                        'rule_id': 'aws.s3.bucket.versioning_enabled',
                        'result': 'FAIL',
                        'severity': 'medium',
                        'resource': {
                            'type': 's3_bucket',
                            'id': 'test-bucket-1',
                            'arn': 'arn:aws:s3:::test-bucket-1'
                        },
                        'evidence': {'versioning_enabled': False}
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
                        'resource': {
                            'type': 'iam_user',
                            'id': 'test-user',
                            'arn': 'arn:aws:iam::123456789012:user/test-user'
                        },
                        'evidence': {'mfa_enabled': False}
                    },
                    {
                        'rule_id': 'aws.iam.policy.no_administrative_privileges',
                        'result': 'PASS',
                        'severity': 'high',
                        'resource': {
                            'type': 'iam_policy',
                            'id': 'test-policy',
                            'arn': 'arn:aws:iam::123456789012:policy/test-policy'
                        },
                        'evidence': {'has_admin_privileges': False}
                    }
                ]
            },
            {
                'account_id': '123456789012',
                'region': 'us-east-1',
                'service': 'rds',
                'checks': [
                    {
                        'rule_id': 'aws.rds.instance.encryption_at_rest_enabled',
                        'result': 'FAIL',
                        'severity': 'high',
                        'resource': {
                            'type': 'rds_instance',
                            'id': 'test-db-instance',
                            'arn': 'arn:aws:rds:us-east-1:123456789012:db:test-db-instance'
                        },
                        'evidence': {'encryption_enabled': False}
                    }
                ]
            }
        ]
    }

def group_by_control(framework_data, framework):
    """
    Group results by Control ID.
    For each control, show all resources and their compliance status.
    """
    grouped = {}
    
    if framework not in framework_data:
        return grouped
    
    for control_id, control_checks in framework_data[framework].items():
        # Get control metadata from first check
        control_meta = {}
        if control_checks:
            first_check = control_checks[0]
            control_meta = first_check.get('control', {})
        
        # Group checks by resource
        resources_by_status = defaultdict(list)
        for check in control_checks:
            resource = check.get('resource', {})
            resource_id = resource.get('id') or resource.get('arn', 'unknown')
            resource_arn = resource.get('arn', resource_id)
            
            status = check.get('check_result', 'UNKNOWN')
            resources_by_status[status].append({
                'resource_id': resource_id,
                'resource_arn': resource_arn,
                'resource_type': resource.get('type', 'unknown'),
                'region': check.get('region', 'unknown'),
                'service': check.get('service', 'unknown'),
                'rule_id': check.get('rule_id'),
                'severity': check.get('severity', 'medium'),
                'evidence': check.get('evidence', {}),
                'check_result': status
            })
        
        # Calculate control statistics
        total_resources = len(control_checks)
        passed = len(resources_by_status.get('PASS', []))
        failed = len(resources_by_status.get('FAIL', []))
        partial = len(resources_by_status.get('PARTIAL', []))
        error = len(resources_by_status.get('ERROR', []))
        
        grouped[control_id] = {
            'control_id': control_id,
            'control_title': control_meta.get('control_title', ''),
            'control_category': control_meta.get('control_category', ''),
            'framework_version': control_meta.get('framework_version', ''),
            'statistics': {
                'total_resources': total_resources,
                'passed': passed,
                'failed': failed,
                'partial': partial,
                'error': error,
                'compliance_percentage': (passed / total_resources * 100) if total_resources > 0 else 0
            },
            'resources_passed': resources_by_status.get('PASS', []),
            'resources_failed': resources_by_status.get('FAIL', []),
            'resources_partial': resources_by_status.get('PARTIAL', []),
            'resources_error': resources_by_status.get('ERROR', []),
            'all_resources': {
                'passed': resources_by_status.get('PASS', []),
                'failed': resources_by_status.get('FAIL', []),
                'partial': resources_by_status.get('PARTIAL', []),
                'error': resources_by_status.get('ERROR', [])
            }
        }
    
    return grouped

def group_by_resource(framework_data, framework):
    """
    Group results by Resource.
    For each resource, show all compliance controls and their status.
    """
    resource_map = defaultdict(lambda: {
        'resource_info': {},
        'controls': defaultdict(list),
        'compliance_summary': {
            'total_controls': 0,
            'passed': 0,
            'failed': 0,
            'partial': 0,
            'error': 0
        }
    })
    
    if framework not in framework_data:
        return {}
    
    for control_id, control_checks in framework_data[framework].items():
        for check in control_checks:
            resource = check.get('resource', {})
            resource_id = resource.get('id') or resource.get('arn', 'unknown')
            resource_arn = resource.get('arn', resource_id)
            
            # Store resource info
            if not resource_map[resource_arn]['resource_info']:
                resource_map[resource_arn]['resource_info'] = {
                    'resource_id': resource_id,
                    'resource_arn': resource_arn,
                    'resource_type': resource.get('type', 'unknown'),
                    'region': check.get('region', 'unknown'),
                    'service': check.get('service', 'unknown'),
                    'account_id': check.get('account_id', 'unknown')
                }
            
            # Get control metadata
            control_meta = check.get('control', {})
            
            # Add control check to resource
            control_entry = {
                'control_id': control_id,
                'control_title': control_meta.get('control_title', ''),
                'control_category': control_meta.get('control_category', ''),
                'rule_id': check.get('rule_id'),
                'check_result': check.get('check_result', 'UNKNOWN'),
                'severity': check.get('severity', 'medium'),
                'evidence': check.get('evidence', {}),
                'framework_version': control_meta.get('framework_version', '')
            }
            
            resource_map[resource_arn]['controls'][control_id].append(control_entry)
            
            # Update summary
            status = check.get('check_result', 'UNKNOWN')
            resource_map[resource_arn]['compliance_summary']['total_controls'] += 1
            if status == 'PASS':
                resource_map[resource_arn]['compliance_summary']['passed'] += 1
            elif status == 'FAIL':
                resource_map[resource_arn]['compliance_summary']['failed'] += 1
            elif status == 'PARTIAL':
                resource_map[resource_arn]['compliance_summary']['partial'] += 1
            elif status == 'ERROR':
                resource_map[resource_arn]['compliance_summary']['error'] += 1
    
    # Convert to final format
    result = {}
    for resource_arn, data in resource_map.items():
        # Calculate compliance score
        summary = data['compliance_summary']
        total = summary['total_controls']
        passed = summary['passed']
        compliance_score = (passed / total * 100) if total > 0 else 0
        
        # Convert controls dict to list
        controls_list = []
        for control_id, checks in data['controls'].items():
            # Determine control status (if any check fails, control fails)
            has_fail = any(c['check_result'] == 'FAIL' for c in checks)
            has_pass = any(c['check_result'] == 'PASS' for c in checks)
            
            if has_fail and has_pass:
                control_status = 'PARTIAL'
            elif has_fail:
                control_status = 'FAIL'
            elif has_pass:
                control_status = 'PASS'
            else:
                control_status = 'UNKNOWN'
            
            controls_list.append({
                'control_id': control_id,
                'control_title': checks[0].get('control_title', ''),
                'control_category': checks[0].get('control_category', ''),
                'status': control_status,
                'checks': checks
            })
        
        result[resource_arn] = {
            'resource_info': data['resource_info'],
            'compliance_score': round(compliance_score, 2),
            'compliance_summary': summary,
            'controls': controls_list,
            'failed_controls': [c for c in controls_list if c['status'] == 'FAIL'],
            'passed_controls': [c for c in controls_list if c['status'] == 'PASS'],
            'partial_controls': [c for c in controls_list if c['status'] == 'PARTIAL']
        }
    
    return result

def enhance_framework_report(framework_report, framework_data, framework):
    """Enhance framework report with grouping by control and resource."""
    enhanced = framework_report.copy()
    
    # Add grouping by control
    enhanced['grouped_by_control'] = group_by_control(framework_data, framework)
    
    # Add grouping by resource
    enhanced['grouped_by_resource'] = group_by_resource(framework_data, framework)
    
    # Add summary statistics
    enhanced['grouping_summary'] = {
        'total_controls': len(enhanced['grouped_by_control']),
        'total_resources': len(enhanced['grouped_by_resource']),
        'controls_with_failures': sum(1 for c in enhanced['grouped_by_control'].values() 
                                      if c['statistics']['failed'] > 0),
        'resources_with_failures': sum(1 for r in enhanced['grouped_by_resource'].values() 
                                      if r['compliance_summary']['failed'] > 0)
    }
    
    return enhanced

def test_generate_detailed_reports():
    """Generate detailed compliance reports with grouping."""
    print("=" * 80)
    print("Testing Consolidated CSV Integration - Detailed Reports with Grouping")
    print("=" * 80)
    print()
    
    # Create sample scan results
    print("[1] Creating sample scan results...")
    scan_results = create_sample_scan_results()
    scan_id = scan_results['scan_id']
    print(f"    Scan ID: {scan_id}")
    print(f"    Total checks: {sum(len(r.get('checks', [])) for r in scan_results['results'])}")
    print()
    
    # Initialize components
    print("[2] Initializing components with consolidated CSV...")
    framework_loader = FrameworkLoader()
    rule_mapper = RuleMapper()
    rule_mapper.framework_loader = framework_loader
    
    aggregator = ResultAggregator(rule_mapper)
    score_calculator = ScoreCalculator(aggregator)
    framework_report = FrameworkReport(aggregator, score_calculator)
    
    # Aggregate results
    print("[3] Aggregating scan results by framework...")
    framework_data = aggregator.aggregate_by_framework(scan_results, "aws", None)
    
    frameworks_detected = list(framework_data.keys())
    print(f"    Frameworks detected: {len(frameworks_detected)}")
    for fw in frameworks_detected[:10]:
        print(f"      - {fw}: {len(framework_data[fw])} controls")
    print()
    
    # Create output directory
    output_base = Path("/Users/apple/Desktop/threat-engine/engines-output/complaince-engine/output")
    scan_output_dir = output_base / scan_id
    scan_output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[4] Saving reports to: {scan_output_dir}")
    print()
    
    # Generate and save reports for each framework
    framework_files = {}
    for framework in frameworks_detected:
        print(f"    Generating report for {framework}...")
        
        # Generate framework report
        fw_report = framework_report.generate(scan_results, "aws", framework)
        
        # Enhance with grouping
        enhanced_report = enhance_framework_report(fw_report, framework_data, framework)
        
        # Save to separate file
        # Sanitize framework name for filename
        safe_framework_name = framework.replace(" ", "_").replace("/", "_").replace("\\", "_")
        framework_file = scan_output_dir / f"{safe_framework_name}_compliance_report.json"
        
        with open(framework_file, 'w') as f:
            json.dump(enhanced_report, f, indent=2)
        
        framework_files[framework] = str(framework_file)
        
        # Print summary
        score = enhanced_report.get('compliance_score', 0)
        controls_total = enhanced_report.get('statistics', {}).get('controls_total', 0)
        resources_total = enhanced_report.get('grouping_summary', {}).get('total_resources', 0)
        print(f"      ✅ {framework}: {score:.1f}% ({controls_total} controls, {resources_total} resources)")
    
    print()
    
    # Generate executive summary
    print("[5] Generating executive summary...")
    executive_dashboard = ExecutiveDashboard(aggregator, score_calculator)
    dashboard = executive_dashboard.generate(scan_results, "aws", None)
    
    summary_file = scan_output_dir / "executive_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(dashboard, f, indent=2)
    
    print(f"    ✅ Executive summary saved")
    print()
    
    # Create index file
    print("[6] Creating index file...")
    index_data = {
        'scan_id': scan_id,
        'csp': 'aws',
        'account_id': scan_results.get('account_id'),
        'scanned_at': scan_results.get('scanned_at'),
        'generated_at': datetime.now().isoformat() + 'Z',
        'output_directory': str(scan_output_dir),
        'executive_summary': str(summary_file.name),
        'frameworks': {
            fw: {
                'file': Path(f).name,
                'compliance_score': framework_report.generate(scan_results, "aws", fw).get('compliance_score', 0)
            }
            for fw, f in framework_files.items()
        },
        'summary': dashboard.get('summary', {})
    }
    
    index_file = scan_output_dir / "index.json"
    with open(index_file, 'w') as f:
        json.dump(index_data, f, indent=2)
    
    print(f"    ✅ Index file saved")
    print()
    
    # Print example of grouping
    print("[7] Example Grouping Structure:")
    if frameworks_detected:
        example_framework = frameworks_detected[0]
        example_report = enhance_framework_report(
            framework_report.generate(scan_results, "aws", example_framework),
            framework_data,
            example_framework
        )
        
        print(f"    Framework: {example_framework}")
        print(f"    Grouped by Control: {len(example_report.get('grouped_by_control', {}))} controls")
        print(f"    Grouped by Resource: {len(example_report.get('grouped_by_resource', {}))} resources")
        
        # Show example control grouping
        if example_report.get('grouped_by_control'):
            example_control_id = list(example_report['grouped_by_control'].keys())[0]
            example_control = example_report['grouped_by_control'][example_control_id]
            print(f"    Example Control ({example_control_id}):")
            print(f"      - Title: {example_control.get('control_title', 'N/A')}")
            print(f"      - Resources: {example_control['statistics']['total_resources']} total")
            print(f"        • Passed: {example_control['statistics']['passed']}")
            print(f"        • Failed: {example_control['statistics']['failed']}")
        
        # Show example resource grouping
        if example_report.get('grouped_by_resource'):
            example_resource_arn = list(example_report['grouped_by_resource'].keys())[0]
            example_resource = example_report['grouped_by_resource'][example_resource_arn]
            print(f"    Example Resource ({example_resource_arn}):")
            print(f"      - Type: {example_resource['resource_info'].get('resource_type', 'N/A')}")
            print(f"      - Compliance Score: {example_resource['compliance_score']}%")
            print(f"      - Controls: {example_resource['compliance_summary']['total_controls']} total")
            print(f"        • Passed: {example_resource['compliance_summary']['passed']}")
            print(f"        • Failed: {example_resource['compliance_summary']['failed']}")
    
    print()
    print("=" * 80)
    print("✅ Test completed successfully!")
    print("=" * 80)
    print()
    print("📁 Results saved to:")
    print(f"   {scan_output_dir}")
    print()
    print("📄 Files generated:")
    print(f"   - index.json (overview of all reports)")
    print(f"   - executive_summary.json (overall compliance summary)")
    for fw, fpath in list(framework_files.items())[:5]:
        print(f"   - {Path(fpath).name} ({fw})")
    if len(framework_files) > 5:
        print(f"   ... and {len(framework_files) - 5} more framework reports")
    print()
    print("📊 Each framework report includes:")
    print("   - Grouped by Control ID (all resources per control)")
    print("   - Grouped by Resource (all compliance failures per resource)")
    print("   - Detailed control information")
    print("   - Resource-level compliance scores")
    
    return scan_output_dir, index_file

if __name__ == "__main__":
    try:
        scan_output_dir, index_file = test_generate_detailed_reports()
        print(f"\n✅ Test passed! Check the directory: {scan_output_dir}")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
