#!/usr/bin/env python3
"""
Test NDJSON Check Data Quality and Coverage

Analyzes check results from NDJSON files to validate:
- Data quality (ARN coverage, required fields)
- Coverage (services, rules, status distribution)
- API compatibility
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Any
from datetime import datetime

# Find latest NDJSON file
NDJSON_BASE = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output/configscan/rule_check")

def find_latest_ndjson() -> Path:
    """Find the most recent findings.ndjson file"""
    scan_dirs = sorted(NDJSON_BASE.glob("rule_check_*"), reverse=True)
    for scan_dir in scan_dirs:
        findings_file = scan_dir / "findings.ndjson"
        if findings_file.exists():
            return findings_file
    raise FileNotFoundError("No findings.ndjson files found")

def analyze_ndjson_data(ndjson_file: Path) -> Dict[str, Any]:
    """Analyze NDJSON check data for quality and coverage"""
    
    print(f"📂 Analyzing: {ndjson_file}")
    print(f"   Size: {ndjson_file.stat().st_size / 1024 / 1024:.2f} MB")
    print()
    
    # Statistics
    total_records = 0
    records_with_arn = 0
    records_with_id = 0
    records_with_both = 0
    
    # Status distribution
    status_counts = Counter()
    
    # Service distribution
    service_counts = Counter()
    service_status = defaultdict(lambda: {'PASS': 0, 'FAIL': 0, 'ERROR': 0})
    
    # Rule distribution
    rule_counts = Counter()
    rule_status = defaultdict(lambda: {'PASS': 0, 'FAIL': 0, 'ERROR': 0})
    
    # Field presence
    fields_present = defaultdict(int)
    fields_missing = defaultdict(int)
    
    # Required fields
    required_fields = [
        'scan_id', 'rule_id', 'resource_type', 'status',
        'customer_id', 'tenant_id', 'provider', 'hierarchy_id'
    ]
    
    # ARN patterns
    arn_patterns = Counter()
    
    # Sample records for validation
    sample_records = []
    errors = []
    
    print("📊 Reading and analyzing records...")
    
    with open(ndjson_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                record = json.loads(line)
                total_records += 1
                
                # Sample first 10 records
                if len(sample_records) < 10:
                    sample_records.append(record)
                
                # Check required fields
                for field in required_fields:
                    if field in record and record[field]:
                        fields_present[field] += 1
                    else:
                        fields_missing[field] += 1
                
                # ARN/ID coverage
                resource_arn = record.get('resource_arn')
                resource_id = record.get('resource_id')
                
                if resource_arn:
                    records_with_arn += 1
                    # Extract ARN pattern (service)
                    if resource_arn.startswith('arn:aws:'):
                        parts = resource_arn.split(':')
                        if len(parts) >= 3:
                            service = parts[2]
                            arn_patterns[service] += 1
                
                if resource_id:
                    records_with_id += 1
                
                if resource_arn and resource_id:
                    records_with_both += 1
                
                # Status
                status = record.get('status', 'UNKNOWN')
                status_counts[status] += 1
                
                # Service
                service = record.get('resource_type', 'unknown')
                service_counts[service] += 1
                service_status[service][status] += 1
                
                # Rule
                rule_id = record.get('rule_id', 'unknown')
                rule_counts[rule_id] += 1
                rule_status[rule_id][status] += 1
                
                # Check for checked_fields
                checked_fields = record.get('checked_fields', [])
                if checked_fields:
                    fields_present['checked_fields'] += 1
                else:
                    fields_missing['checked_fields'] += 1
                
                # Check for finding_data
                finding_data = record.get('finding_data', {})
                if finding_data:
                    fields_present['finding_data'] += 1
                else:
                    fields_missing['finding_data'] += 1
                
                if line_num % 10000 == 0:
                    print(f"   Processed {line_num:,} records...")
            
            except json.JSONDecodeError as e:
                errors.append(f"Line {line_num}: JSON decode error: {e}")
            except Exception as e:
                errors.append(f"Line {line_num}: Error: {e}")
    
    print(f"✅ Processed {total_records:,} records\n")
    
    # Calculate coverage percentages
    arn_coverage = (records_with_arn / total_records * 100) if total_records > 0 else 0
    id_coverage = (records_with_id / total_records * 100) if total_records > 0 else 0
    both_coverage = (records_with_both / total_records * 100) if total_records > 0 else 0
    
    # Calculate pass rate
    total_checks = status_counts['PASS'] + status_counts['FAIL'] + status_counts.get('ERROR', 0)
    pass_rate = (status_counts['PASS'] / total_checks * 100) if total_checks > 0 else 0
    
    # Build results
    results = {
        'file': str(ndjson_file),
        'total_records': total_records,
        'coverage': {
            'arn_coverage': round(arn_coverage, 2),
            'id_coverage': round(id_coverage, 2),
            'both_coverage': round(both_coverage, 2),
            'records_with_arn': records_with_arn,
            'records_with_id': records_with_id,
            'records_with_both': records_with_both
        },
        'status_distribution': dict(status_counts),
        'pass_rate': round(pass_rate, 2),
        'services': {
            'total': len(service_counts),
            'top_10': dict(service_counts.most_common(10)),
            'by_status': {svc: dict(stats) for svc, stats in service_status.items()}
        },
        'rules': {
            'total': len(rule_counts),
            'top_10_failing': sorted(
                [(rule, stats['FAIL']) for rule, stats in rule_status.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        },
        'field_presence': {
            'present': dict(fields_present),
            'missing': dict(fields_missing)
        },
        'arn_patterns': dict(arn_patterns.most_common(10)),
        'sample_records': sample_records[:3],
        'errors': errors[:10] if errors else []
    }
    
    return results

def print_analysis(results: Dict[str, Any]):
    """Print formatted analysis results"""
    
    print("=" * 80)
    print("📊 CHECK DATA QUALITY & COVERAGE ANALYSIS")
    print("=" * 80)
    print()
    
    # Basic stats
    print(f"📈 BASIC STATISTICS")
    print(f"   Total Records: {results['total_records']:,}")
    print(f"   Pass Rate: {results['pass_rate']}%")
    print(f"   Services Scanned: {results['services']['total']}")
    print(f"   Rules Evaluated: {results['rules']['total']}")
    print()
    
    # Coverage
    print(f"🎯 RESOURCE IDENTIFICATION COVERAGE")
    cov = results['coverage']
    print(f"   ARN Coverage: {cov['arn_coverage']}% ({cov['records_with_arn']:,} records)")
    print(f"   ID Coverage: {cov['id_coverage']}% ({cov['records_with_id']:,} records)")
    print(f"   Both ARN + ID: {cov['both_coverage']}% ({cov['records_with_both']:,} records)")
    print()
    
    # Status distribution
    print(f"📊 STATUS DISTRIBUTION")
    for status, count in results['status_distribution'].items():
        pct = (count / results['total_records'] * 100) if results['total_records'] > 0 else 0
        print(f"   {status:8s}: {count:8,} ({pct:5.2f}%)")
    print()
    
    # Top services
    print(f"🔝 TOP 10 SERVICES BY CHECK COUNT")
    for i, (service, count) in enumerate(results['services']['top_10'].items(), 1):
        pct = (count / results['total_records'] * 100) if results['total_records'] > 0 else 0
        stats = results['services']['by_status'].get(service, {})
        pass_count = stats.get('PASS', 0)
        fail_count = stats.get('FAIL', 0)
        pass_rate = (pass_count / count * 100) if count > 0 else 0
        print(f"   {i:2d}. {service:20s}: {count:8,} checks ({pct:5.2f}%) | "
              f"Pass: {pass_count:6,} ({pass_rate:5.2f}%) | Fail: {fail_count:6,}")
    print()
    
    # Top failing rules
    print(f"🔴 TOP 10 FAILING RULES")
    for i, (rule, fail_count) in enumerate(results['rules']['top_10_failing'], 1):
        rule_stats = results.get('rule_status', {}).get(rule, {})
        total = rule_stats.get('PASS', 0) + rule_stats.get('FAIL', 0) + rule_stats.get('ERROR', 0)
        if total > 0:
            fail_rate = (fail_count / total * 100)
            print(f"   {i:2d}. {rule:60s}: {fail_count:6,} failures ({fail_rate:5.2f}% of {total:,} checks)")
    print()
    
    # Field presence
    print(f"✅ FIELD PRESENCE")
    for field, count in sorted(results['field_presence']['present'].items()):
        pct = (count / results['total_records'] * 100) if results['total_records'] > 0 else 0
        missing = results['field_presence']['missing'].get(field, 0)
        print(f"   {field:20s}: Present: {count:8,} ({pct:5.2f}%) | Missing: {missing:8,}")
    print()
    
    # ARN patterns
    print(f"🏷️  TOP 10 ARN PATTERNS (Services)")
    for i, (service, count) in enumerate(results['arn_patterns'].items(), 1):
        pct = (count / results['coverage']['records_with_arn'] * 100) if results['coverage']['records_with_arn'] > 0 else 0
        print(f"   {i:2d}. {service:20s}: {count:8,} ({pct:5.2f}%)")
    print()
    
    # Sample record
    if results['sample_records']:
        print(f"📄 SAMPLE RECORD")
        sample = results['sample_records'][0]
        print(f"   Rule ID: {sample.get('rule_id')}")
        print(f"   Resource ARN: {sample.get('resource_arn', 'N/A')}")
        print(f"   Resource ID: {sample.get('resource_id', 'N/A')}")
        print(f"   Service: {sample.get('resource_type')}")
        print(f"   Status: {sample.get('status')}")
        print(f"   Checked Fields: {sample.get('checked_fields', [])}")
        print()
    
    # Errors
    if results['errors']:
        print(f"⚠️  ERRORS ENCOUNTERED: {len(results['errors'])}")
        for error in results['errors'][:5]:
            print(f"   {error}")
        print()
    
    # API Compatibility Check
    print(f"🔌 API COMPATIBILITY CHECK")
    required_for_api = ['scan_id', 'rule_id', 'resource_type', 'status', 'tenant_id']
    all_present = all(
        results['field_presence']['present'].get(field, 0) == results['total_records']
        for field in required_for_api
    )
    
    if all_present:
        print(f"   ✅ All required fields present - API compatible")
    else:
        print(f"   ⚠️  Some required fields missing:")
        for field in required_for_api:
            present = results['field_presence']['present'].get(field, 0)
            if present < results['total_records']:
                missing = results['total_records'] - present
                print(f"      - {field}: {missing:,} records missing")
    
    print()
    print("=" * 80)

def main():
    """Main test function"""
    try:
        # Find latest NDJSON
        ndjson_file = find_latest_ndjson()
        
        # Analyze
        results = analyze_ndjson_data(ndjson_file)
        
        # Print results
        print_analysis(results)
        
        # Save to JSON
        output_file = Path("/tmp/check_data_analysis.json")
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"💾 Full analysis saved to: {output_file}")
        
        return 0
    
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
