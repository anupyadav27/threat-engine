#!/usr/bin/env python3
"""
Ensure all SDK databases are complete and fully enriched like AWS.

This script:
1. Checks all providers (AWS, OCI, IBM, Azure, AliCloud, GCP)
2. Verifies all services are present in consolidated databases
3. Ensures all services have proper enrichment (item_fields, compliance_category, operators)
4. Compares against AWS as the gold standard
5. Reports missing services and incomplete enrichment
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict

# Provider configurations
PROVIDERS = {
    'aws': {
        'base_dir': 'aws',
        'consolidated_file': 'boto3_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': None,  # AWS doesn't have a service list file
        'expected_min_services': 400  # AWS has 411 services
    },
    'oci': {
        'base_dir': 'oci',
        'consolidated_file': 'oci_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': None,
        'expected_min_services': 50  # OCI should have many more services
    },
    'ibm': {
        'base_dir': 'ibm',
        'consolidated_file': 'ibm_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': None,
        'expected_min_services': 20  # IBM should have more services
    },
    'azure': {
        'base_dir': 'azure',
        'consolidated_file': 'azure_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': 'all_services.json',
        'expected_min_services': 150  # Azure has 160 services in all_services.json
    },
    'alicloud': {
        'base_dir': 'alicloud',
        'consolidated_file': 'alicloud_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': 'all_services.json',
        'expected_min_services': 20  # AliCloud should have more services
    },
    'gcp': {
        'base_dir': 'gcp',
        'consolidated_file': 'gcp_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': None,
        'expected_min_services': 30  # GCP should have many services
    }
}

SDK_DATABASE_ROOT = Path(__file__).parent.parent / "pythonsdk-database"


def load_json(file_path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON file."""
    if not file_path.exists():
        return None
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"  ❌ Error loading {file_path}: {e}")
        return None


def get_aws_structure_sample() -> Dict[str, Any]:
    """Get a sample AWS service structure as the gold standard."""
    aws_file = SDK_DATABASE_ROOT / "aws" / PROVIDERS['aws']['consolidated_file']
    data = load_json(aws_file)
    if not data:
        return {}
    
    # Get first service as sample
    sample_service = list(data.values())[0]
    return sample_service


def check_service_enrichment(service_data: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Check if a service has proper enrichment like AWS."""
    issues = {
        'missing_item_fields': [],
        'missing_compliance_category': [],
        'missing_operators': [],
        'missing_type': [],
        'missing_description': []
    }
    
    # Get operations based on provider structure
    operations = []
    
    if provider == 'aws':
        operations.extend(service_data.get('independent', []))
        operations.extend(service_data.get('dependent', []))
    elif provider in ['alicloud', 'ibm', 'oci']:
        operations = service_data.get('operations', [])
    elif provider == 'azure':
        # Azure may have different structure
        operations.extend(service_data.get('independent', []))
        operations.extend(service_data.get('dependent', []))
        # Also check operations_by_category
        ops_by_cat = service_data.get('operations_by_category', {})
        for cat_data in ops_by_cat.values():
            operations.extend(cat_data.get('independent', []))
            operations.extend(cat_data.get('dependent', []))
    elif provider == 'gcp':
        # GCP has resources structure
        resources = service_data.get('resources', {})
        for resource_data in resources.values():
            operations.extend(resource_data.get('independent', []))
            operations.extend(resource_data.get('dependent', []))
    
    # Check each operation
    for op in operations:
        op_name = op.get('operation') or op.get('python_method', 'unknown')
        
        # Check item_fields
        item_fields = op.get('item_fields', {})
        if not item_fields:
            issues['missing_item_fields'].append(op_name)
            continue
        
        # Check each field has proper enrichment
        for field_name, field_data in item_fields.items():
            if not isinstance(field_data, dict):
                issues['missing_type'].append(f"{op_name}.{field_name}")
                continue
            
            # Required fields: type, description, compliance_category
            if 'type' not in field_data:
                issues['missing_type'].append(f"{op_name}.{field_name}")
            
            if 'description' not in field_data:
                issues['missing_description'].append(f"{op_name}.{field_name}")
            
            if 'compliance_category' not in field_data:
                issues['missing_compliance_category'].append(f"{op_name}.{field_name}")
            
            # Identity/security fields should have operators
            compliance_cat = field_data.get('compliance_category', '')
            if compliance_cat in ['identity', 'security'] and 'operators' not in field_data:
                issues['missing_operators'].append(f"{op_name}.{field_name}")
    
    return issues


def analyze_provider(provider: str, provider_config: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a provider's database completeness."""
    print(f"\n{'='*80}")
    print(f"Analyzing {provider.upper()}")
    print(f"{'='*80}")
    
    provider_dir = SDK_DATABASE_ROOT / provider_config['base_dir']
    consolidated_file = provider_dir / provider_config['consolidated_file']
    
    result = {
        'provider': provider,
        'consolidated_file_exists': False,
        'services_count': 0,
        'expected_min': provider_config['expected_min_services'],
        'services': [],
        'enrichment_issues': defaultdict(list),
        'missing_services': [],
        'total_operations': 0,
        'operations_with_item_fields': 0,
        'operations_without_item_fields': 0
    }
    
    # Check if consolidated file exists
    if not consolidated_file.exists():
        print(f"  ❌ Consolidated file not found: {consolidated_file}")
        result['error'] = f"Consolidated file not found: {consolidated_file}"
        return result
    
    result['consolidated_file_exists'] = True
    print(f"  ✅ Found consolidated file: {consolidated_file.name}")
    
    # Load consolidated data
    data = load_json(consolidated_file)
    if not data:
        result['error'] = "Failed to load consolidated file"
        return result
    
    result['services_count'] = len(data)
    result['services'] = list(data.keys())
    print(f"  📊 Services in database: {result['services_count']}")
    
    # Check expected services from service list
    if provider_config['service_list_file']:
        service_list_path = provider_dir / provider_config['service_list_file']
        if service_list_path.exists():
            service_list = load_json(service_list_path)
            if service_list:
                expected_services = set()
                if 'services' in service_list:
                    expected_services.update(service_list['services'])
                if 'services_detail' in service_list:
                    expected_services.update(service_list['services_detail'].keys())
                
                missing = expected_services - set(result['services'])
                if missing:
                    result['missing_services'] = sorted(missing)
                    print(f"  ⚠️  Missing {len(missing)} services from service list")
                    print(f"     Missing: {', '.join(sorted(missing)[:10])}{'...' if len(missing) > 10 else ''}")
                else:
                    print(f"  ✅ All services from service list are present")
    
    # Check enrichment for each service
    print(f"  🔍 Checking enrichment...")
    total_ops = 0
    ops_with_fields = 0
    ops_without_fields = 0
    
    for service_name, service_data in data.items():
        issues = check_service_enrichment(service_data, provider)
        
        # Count operations
        if provider == 'aws':
            ops = service_data.get('independent', []) + service_data.get('dependent', [])
        elif provider in ['alicloud', 'ibm', 'oci']:
            ops = service_data.get('operations', [])
        elif provider == 'azure':
            ops = service_data.get('independent', []) + service_data.get('dependent', [])
            ops_by_cat = service_data.get('operations_by_category', {})
            for cat_data in ops_by_cat.values():
                ops.extend(cat_data.get('independent', []))
                ops.extend(cat_data.get('dependent', []))
        elif provider == 'gcp':
            ops = []
            resources = service_data.get('resources', {})
            for resource_data in resources.values():
                ops.extend(resource_data.get('independent', []))
                ops.extend(resource_data.get('dependent', []))
        else:
            ops = []
        
        total_ops += len(ops)
        
        for op in ops:
            if op.get('item_fields'):
                ops_with_fields += 1
            else:
                ops_without_fields += 1
        
        # Collect issues
        if issues['missing_item_fields']:
            result['enrichment_issues']['missing_item_fields'].extend([
                f"{service_name}.{op}" for op in issues['missing_item_fields']
            ])
        if issues['missing_compliance_category']:
            result['enrichment_issues']['missing_compliance_category'].extend([
                f"{service_name}.{field}" for field in issues['missing_compliance_category']
            ])
        if issues['missing_operators']:
            result['enrichment_issues']['missing_operators'].extend([
                f"{service_name}.{field}" for field in issues['missing_operators']
            ])
    
    result['total_operations'] = total_ops
    result['operations_with_item_fields'] = ops_with_fields
    result['operations_without_item_fields'] = ops_without_fields
    
    print(f"  📊 Total operations: {total_ops:,}")
    print(f"  ✅ Operations with item_fields: {ops_with_fields:,}")
    if ops_without_fields > 0:
        print(f"  ⚠️  Operations without item_fields: {ops_without_fields:,}")
    
    # Summary
    if result['services_count'] < result['expected_min']:
        print(f"  ⚠️  Service count ({result['services_count']}) is below expected minimum ({result['expected_min']})")
    else:
        print(f"  ✅ Service count meets expected minimum")
    
    enrichment_issue_count = sum(len(v) for v in result['enrichment_issues'].values())
    if enrichment_issue_count > 0:
        print(f"  ⚠️  Found {enrichment_issue_count} enrichment issues")
    else:
        print(f"  ✅ All services properly enriched")
    
    return result


def generate_report(results: List[Dict[str, Any]]) -> None:
    """Generate a summary report."""
    print(f"\n{'='*80}")
    print("SUMMARY REPORT")
    print(f"{'='*80}\n")
    
    # Compare against AWS
    aws_result = next((r for r in results if r['provider'] == 'aws'), None)
    if not aws_result:
        print("⚠️  AWS results not found for comparison")
        return
    
    print(f"AWS (Gold Standard):")
    print(f"  Services: {aws_result['services_count']}")
    print(f"  Operations: {aws_result['total_operations']:,}")
    print(f"  Operations with item_fields: {aws_result['operations_with_item_fields']:,}")
    print(f"  Enrichment issues: {sum(len(v) for v in aws_result['enrichment_issues'].values())}")
    print()
    
    for result in results:
        if result['provider'] == 'aws':
            continue
        
        print(f"{result['provider'].upper()}:")
        print(f"  Services: {result['services_count']} (expected: {result['expected_min']}+)")
        
        if result['services_count'] < result['expected_min']:
            print(f"  ⚠️  MISSING SERVICES: {result['expected_min'] - result['services_count']} services below expected")
        
        if result['missing_services']:
            print(f"  ⚠️  Missing from service list: {len(result['missing_services'])} services")
        
        print(f"  Operations: {result['total_operations']:,}")
        print(f"  Operations with item_fields: {result['operations_with_item_fields']:,}")
        
        if result['operations_without_item_fields'] > 0:
            print(f"  ⚠️  Operations without item_fields: {result['operations_without_item_fields']:,}")
        
        enrichment_issues = sum(len(v) for v in result['enrichment_issues'].values())
        if enrichment_issues > 0:
            print(f"  ⚠️  Enrichment issues: {enrichment_issues}")
            for issue_type, issues in result['enrichment_issues'].items():
                if issues:
                    print(f"     - {issue_type}: {len(issues)}")
        
        print()


def main():
    """Main execution."""
    print("="*80)
    print("SDK Database Completeness Check")
    print("="*80)
    print(f"Checking all providers against AWS gold standard...")
    print(f"Database root: {SDK_DATABASE_ROOT}")
    
    results = []
    
    for provider, config in PROVIDERS.items():
        try:
            result = analyze_provider(provider, config)
            results.append(result)
        except Exception as e:
            print(f"  ❌ Error analyzing {provider}: {e}")
            results.append({
                'provider': provider,
                'error': str(e)
            })
    
    # Generate report
    generate_report(results)
    
    # Save detailed results
    output_file = SDK_DATABASE_ROOT / "verification_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n✅ Detailed results saved to: {output_file}")


if __name__ == '__main__':
    main()

