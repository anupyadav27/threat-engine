#!/usr/bin/env python3
"""
Verify and consolidate SDK databases for all cloud providers.

This script:
1. Checks if consolidated fully enriched files exist for each provider
2. Verifies all per-service files are included
3. Merges per-service files if consolidated file is missing/incomplete
4. Validates enrichment completeness (item_fields, compliance_category, operators)
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
        'service_pattern': '*_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': 'all_services.json'
    },
    'azure': {
        'base_dir': 'azure',
        'consolidated_file': 'azure_dependencies_with_python_names_fully_enriched.json',
        'service_pattern': 'azure_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': 'all_services.json'
    },
    'gcp': {
        'base_dir': 'gcp',
        'consolidated_file': 'gcp_dependencies_with_python_names_fully_enriched.json',
        'service_pattern': 'gcp_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': None  # GCP uses different structure
    },
    'alicloud': {
        'base_dir': 'alicloud',
        'consolidated_file': 'alicloud_dependencies_with_python_names_fully_enriched.json',
        'service_pattern': 'alicloud_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': 'all_services.json'
    },
    'ibm': {
        'base_dir': 'ibm',
        'consolidated_file': 'ibm_dependencies_with_python_names_fully_enriched.json',
        'service_pattern': 'ibm_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': None
    },
    'oci': {
        'base_dir': 'oci',
        'consolidated_file': 'oci_dependencies_with_python_names_fully_enriched.json',
        'service_pattern': 'oci_dependencies_with_python_names_fully_enriched.json',
        'service_list_file': None
    }
}

SDK_DB_ROOT = Path(__file__).parent.parent / 'pythonsdk-database'


def load_json(file_path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON file, return None if not found."""
    if not file_path.exists():
        return None
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"  ⚠️  Error loading {file_path.name}: {e}")
        return None


def save_json(file_path: Path, data: Any):
    """Save JSON file."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True, ensure_ascii=False)


def find_service_files(provider_dir: Path, pattern: str) -> List[Path]:
    """Find all per-service enriched files."""
    service_files = []
    
    # Look for service subdirectories
    for service_dir in provider_dir.iterdir():
        if service_dir.is_dir() and not service_dir.name.startswith('.'):
            service_file = service_dir / pattern
            if service_file.exists():
                service_files.append(service_file)
    
    return sorted(service_files)


def extract_service_name_from_file(file_path: Path, provider: str) -> str:
    """Extract service name from file path."""
    # Service name is usually the parent directory name
    return file_path.parent.name


def extract_service_data(data: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Extract service data from per-service file."""
    # Different providers have different structures
    if provider == 'gcp':
        # GCP has service as top-level key
        if len(data) == 1:
            return data
        return data
    elif provider in ['azure', 'alicloud', 'ibm', 'oci']:
        # These providers may have service as top-level key or nested
        if len(data) == 1:
            return data
        return data
    
    return data


def get_services_from_list(provider_dir: Path, service_list_file: Optional[str]) -> Set[str]:
    """Get expected services from service list file."""
    if not service_list_file:
        return set()
    
    list_file = provider_dir / service_list_file
    if not list_file.exists():
        return set()
    
    data = load_json(list_file)
    if not data:
        return set()
    
    # Extract service names
    services = set()
    if 'services' in data:
        services.update(data['services'])
    if 'services_detail' in data:
        services.update(data['services_detail'].keys())
    
    return services


def validate_enrichment(service_data: Dict[str, Any], service_name: str, provider: str) -> Dict[str, Any]:
    """Validate enrichment completeness for a service."""
    issues = {
        'missing_item_fields': [],
        'missing_compliance_category': [],
        'missing_operators': [],
        'missing_optional_params_metadata': []
    }
    
    # Different providers have different structures
    operations = []
    
    if provider == 'gcp':
        # GCP structure: resources -> resource_name -> independent/dependent -> operations
        resources = service_data.get('resources', {})
        for resource_name, resource_data in resources.items():
            for op_type in ['independent', 'dependent']:
                ops = resource_data.get(op_type, [])
                operations.extend(ops)
    elif provider == 'azure':
        # Azure structure: operations_by_category -> category -> independent/dependent -> operations
        ops_by_cat = service_data.get('operations_by_category', {})
        for category, cat_data in ops_by_cat.items():
            for op_type in ['independent', 'dependent']:
                ops = cat_data.get(op_type, [])
                operations.extend(ops)
        # Also check top-level independent/dependent
        operations.extend(service_data.get('independent', []))
        operations.extend(service_data.get('dependent', []))
    elif provider in ['alicloud', 'ibm', 'oci']:
        # These have operations array directly
        operations = service_data.get('operations', [])
    else:  # aws
        # AWS has independent/dependent at top level
        operations.extend(service_data.get('independent', []))
        operations.extend(service_data.get('dependent', []))
    
    # Validate each operation
    for op in operations:
        op_name = op.get('operation') or op.get('python_method', 'unknown')
        
        # Check item_fields enrichment
        item_fields = op.get('item_fields', {})
        if not item_fields:
            issues['missing_item_fields'].append(op_name)
        else:
            # Check compliance_category in fields
            for field_name, field_data in item_fields.items():
                if isinstance(field_data, dict):
                    if 'compliance_category' not in field_data:
                        issues['missing_compliance_category'].append(f"{op_name}.{field_name}")
                    
                    # Identity/security fields should have operators
                    compliance_cat = field_data.get('compliance_category', '')
                    if compliance_cat in ['identity', 'security'] and 'operators' not in field_data:
                        issues['missing_operators'].append(f"{op_name}.{field_name}")
        
        # Check optional_params metadata
        optional_params = op.get('optional_params', {})
        if isinstance(optional_params, dict):
            for param_name, param_data in optional_params.items():
                if not isinstance(param_data, dict) or 'type' not in param_data:
                    issues['missing_optional_params_metadata'].append(f"{op_name}.{param_name}")
    
    return issues


def merge_service_files(provider_dir: Path, provider_config: Dict[str, str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Merge all per-service files into consolidated file."""
    provider = provider_config['base_dir']
    pattern = provider_config['service_pattern']
    
    print(f"  📦 Finding per-service files...")
    service_files = find_service_files(provider_dir, pattern)
    
    if not service_files:
        print(f"  ⚠️  No per-service files found")
        return {}, {'error': 'No service files found'}
    
    print(f"  📦 Found {len(service_files)} service files")
    
    consolidated = {}
    stats = {
        'total_services': 0,
        'total_operations': 0,
        'services_merged': [],
        'errors': []
    }
    
    for service_file in service_files:
        service_name = extract_service_name_from_file(service_file, provider)
        print(f"    Loading {service_name}...", end=' ')
        
        data = load_json(service_file)
        if not data:
            stats['errors'].append(f"{service_name}: Failed to load")
            print("❌")
            continue
        
        # Extract service data (handle different structures)
        service_data = extract_service_data(data, provider)
        
        if not service_data:
            stats['errors'].append(f"{service_name}: No service data found")
            print("❌")
            continue
        
        # Merge into consolidated
        consolidated.update(service_data)
        stats['services_merged'].append(service_name)
        stats['total_services'] += len(service_data)
        
        # Count operations
        for svc_name, svc_data in service_data.items():
            ops_count = svc_data.get('total_operations', 0)
            stats['total_operations'] += ops_count
        
        print(f"✅")
    
    return consolidated, stats


def verify_provider(provider: str, provider_config: Dict[str, str]) -> Dict[str, Any]:
    """Verify and consolidate a single provider."""
    print(f"\n{'='*80}")
    print(f"Provider: {provider.upper()}")
    print(f"{'='*80}")
    
    result = {
        'provider': provider,
        'status': 'unknown',
        'consolidated_exists': False,
        'consolidated_complete': False,
        'services_in_consolidated': 0,
        'services_in_per_service_files': 0,
        'missing_from_consolidated': [],
        'expected_services': 0,
        'missing_services': [],
        'enrichment_issues': {},
        'stats': {}
    }
    
    provider_dir = SDK_DB_ROOT / provider_config['base_dir']
    if not provider_dir.exists():
        result['status'] = 'error'
        result['error'] = f"Provider directory not found: {provider_dir}"
        print(f"  ❌ Directory not found: {provider_dir}")
        return result
    
    consolidated_file = provider_dir / provider_config['consolidated_file']
    
    # Find all per-service files first
    print(f"  🔍 Checking per-service files...")
    service_files = find_service_files(provider_dir, provider_config['service_pattern'])
    per_service_services = set()
    
    for service_file in service_files:
        service_name = extract_service_name_from_file(service_file, provider)
        per_service_services.add(service_name)
    
    result['services_in_per_service_files'] = len(per_service_services)
    print(f"  ✓ Found {len(per_service_services)} services in per-service files")
    
    # Check if consolidated file exists
    if consolidated_file.exists():
        print(f"  ✓ Consolidated file exists: {consolidated_file.name}")
        result['consolidated_exists'] = True
        
        # Load and verify
        consolidated_data = load_json(consolidated_file)
        if consolidated_data:
            result['services_in_consolidated'] = len(consolidated_data)
            consolidated_services = set(consolidated_data.keys())
            print(f"  ✓ Contains {len(consolidated_data)} services")
            
            # Check if all per-service files are in consolidated
            if per_service_services:
                missing_from_consolidated = per_service_services - consolidated_services
                result['missing_from_consolidated'] = list(missing_from_consolidated)
                
                if missing_from_consolidated:
                    print(f"  ⚠️  {len(missing_from_consolidated)} per-service files not in consolidated:")
                    for svc in sorted(missing_from_consolidated)[:10]:
                        print(f"     - {svc}")
                    if len(missing_from_consolidated) > 10:
                        print(f"     ... and {len(missing_from_consolidated) - 10} more")
                else:
                    print(f"  ✓ All per-service files are in consolidated")
            
            # Get expected services
            expected_services = get_services_from_list(
                provider_dir, 
                provider_config.get('service_list_file')
            )
            result['expected_services'] = len(expected_services)
            
            if expected_services:
                missing = expected_services - consolidated_services
                result['missing_services'] = list(missing)
                
                if missing:
                    print(f"  ⚠️  Missing {len(missing)} services from service list: {', '.join(sorted(missing))}")
                    result['consolidated_complete'] = False
                else:
                    print(f"  ✓ All expected services present")
                    result['consolidated_complete'] = True
            else:
                # No service list, check if consolidated has all per-service files
                if per_service_services:
                    result['consolidated_complete'] = len(missing_from_consolidated) == 0
                else:
                    result['consolidated_complete'] = True
            
            # Validate enrichment for sample services
            print(f"  🔍 Validating enrichment...")
            enrichment_issues_total = defaultdict(list)
            
            sample_size = min(5, len(consolidated_data))
            sample_services = list(consolidated_data.keys())[:sample_size]
            
            for service_name in sample_services:
                service_data = consolidated_data[service_name]
                issues = validate_enrichment(service_data, service_name, provider)
                
                for issue_type, issue_list in issues.items():
                    if issue_list:
                        enrichment_issues_total[issue_type].extend(
                            [f"{service_name}.{issue}" for issue in issue_list]
                        )
            
            if enrichment_issues_total:
                print(f"  ⚠️  Found enrichment issues in sample:")
                for issue_type, issues in enrichment_issues_total.items():
                    print(f"     - {issue_type}: {len(issues)} issues")
                    result['enrichment_issues'][issue_type] = len(issues)
            else:
                print(f"  ✓ Enrichment looks good (checked {sample_size} services)")
            
            # If missing services, try to merge them
            if result['missing_from_consolidated']:
                print(f"  🔄 Merging missing services into consolidated file...")
                merged_count = 0
                for service_name in result['missing_from_consolidated']:
                    service_file = provider_dir / service_name / provider_config['service_pattern']
                    if service_file.exists():
                        data = load_json(service_file)
                        if data:
                            service_data = extract_service_data(data, provider)
                            consolidated_data.update(service_data)
                            merged_count += 1
                
                if merged_count > 0:
                    save_json(consolidated_file, consolidated_data)
                    result['services_in_consolidated'] = len(consolidated_data)
                    print(f"  ✓ Merged {merged_count} missing services")
        else:
            result['consolidated_exists'] = False
    else:
        print(f"  ⚠️  Consolidated file missing: {consolidated_file.name}")
        result['consolidated_exists'] = False
        
        # Try to create from per-service files
        print(f"  🔄 Attempting to create from per-service files...")
        consolidated_data, stats = merge_service_files(provider_dir, provider_config)
        
        if consolidated_data:
            print(f"  ✓ Merged {stats['total_services']} services, {stats['total_operations']} operations")
            
            # Save consolidated file
            save_json(consolidated_file, consolidated_data)
            print(f"  ✓ Saved consolidated file")
            
            result['consolidated_exists'] = True
            result['services_in_consolidated'] = len(consolidated_data)
            result['stats'] = stats
            result['consolidated_complete'] = True
        else:
            result['status'] = 'error'
            result['error'] = 'Failed to create consolidated file'
            print(f"  ❌ Failed to create consolidated file")
            return result
    
    result['status'] = 'success'
    return result


def main():
    """Main execution."""
    print("="*80)
    print("SDK Database Verification and Consolidation")
    print("="*80)
    
    if not SDK_DB_ROOT.exists():
        print(f"❌ SDK database root not found: {SDK_DB_ROOT}")
        sys.exit(1)
    
    results = {}
    
    for provider, config in PROVIDERS.items():
        results[provider] = verify_provider(provider, config)
    
    # Print summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print(f"{'='*80}")
    
    for provider, result in results.items():
        status_icon = "✅" if result['status'] == 'success' else "❌"
        print(f"\n{status_icon} {provider.upper()}:")
        print(f"   Consolidated file: {'✓' if result['consolidated_exists'] else '✗'}")
        print(f"   Services: {result['services_in_consolidated']}")
        if result['missing_services']:
            print(f"   Missing: {len(result['missing_services'])} services")
        if result['enrichment_issues']:
            print(f"   Enrichment issues: {sum(result['enrichment_issues'].values())} total")
    
    # Save results
    results_file = SDK_DB_ROOT / 'verification_results.json'
    save_json(results_file, results)
    print(f"\n✓ Results saved to: {results_file}")
    
    print(f"\n{'='*80}")


if __name__ == '__main__':
    main()

