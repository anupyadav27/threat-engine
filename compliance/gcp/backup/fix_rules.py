#!/usr/bin/env python3
"""
GCP Enterprise Rule ID Fixer
Fixes rule IDs to follow enterprise standards from ENTERPRISE_CSPM_RULE_GENERATION_PROMPT.md
"""

import re
import yaml
from typing import List, Dict, Tuple
from datetime import datetime
from collections import defaultdict, Counter
import shutil

# Valid GCP services
VALID_GCP_SERVICES = {
    'accessapproval', 'aiplatform', 'apigateway', 'apikeys', 'apigee', 'appengine',
    'artifactregistry', 'backupdr', 'batch', 'bigquery', 'bigtable', 'billing',
    'certificatemanager', 'cloudbuild', 'cloudtasks', 'cloudtrace', 'composer',
    'compute', 'container', 'dataflow', 'datafusion', 'dataproc', 'datastore',
    'datastream', 'dlp', 'dns', 'essentialcontacts', 'filestore', 'firestore',
    'functions', 'healthcare', 'iam', 'kms', 'logging', 'memcache', 'monitoring',
    'notebooks', 'pubsub', 'redis', 'resourcemanager', 'run', 'scheduler',
    'secretmanager', 'securitycenter', 'serviceusage', 'spanner', 'sql',
    'storage', 'vmwareengine', 'vpcaccess'
}

# Comprehensive service name corrections
SERVICE_CORRECTIONS = {
    'cloud': {  # Needs context-based inference
        'kms': 'kms',
        'logging': 'logging',
        'storage': 'storage',
    },
    'access': 'accessapproval',
    'acm': 'certificatemanager',
    'api': 'apigateway',
    'apigatewayv2': 'apigateway',
    'app': 'appengine',
    'artifact': 'artifactregistry',
    'artifacts': 'artifactregistry',
    'backup': 'backupdr',
    'big': 'bigquery',
    'build': 'cloudbuild',
    'cdn': 'compute',  # GCP CDN is part of Compute
    'certificate': 'certificatemanager',
    'cloudsql': 'sql',
    'cloudscheduler': 'scheduler',
    'dlp_security': 'dlp',
    'fsx': 'filestore',  # FSx is AWS, map to Filestore
    'gke': 'container',
    'load': 'compute',  # Load balancing is part of Compute
    'org': 'resourcemanager',
    'organization': 'resourcemanager',
    'project': 'resourcemanager',
    'securitycenter': 'securitycenter',
    'vertex': 'aiplatform',
    'vpc': 'compute',  # VPC is part of Compute
}

# Resource name corrections
RESOURCE_CORRECTIONS = {
    'resource': {  # Context-based inference
        'apigateway': 'api',
        'storage': 'bucket',
        'compute': 'instance',
        'sql': 'instance',
        'container': 'cluster',
    },
    'object': {  # Context-based
        'storage': 'bucket',  # Most storage checks are bucket-level
    },
    'engine': 'application',
}

def infer_service_from_context(service: str, resource: str, assertion: str) -> str:
    """Infer correct service name from context."""
    if service == 'cloud':
        if 'kms' in resource or 'kms' in assertion or 'encryption' in assertion:
            return 'kms'
        elif 'log' in resource or 'log' in assertion:
            return 'logging'
        elif 'storage' in resource or 'bucket' in resource:
            return 'storage'
    
    if service in SERVICE_CORRECTIONS:
        if isinstance(SERVICE_CORRECTIONS[service], dict):
            return SERVICE_CORRECTIONS[service].get(resource, service)
        return SERVICE_CORRECTIONS[service]
    
    return service

def infer_resource_from_context(resource: str, service: str, assertion: str) -> str:
    """Infer correct resource name from context."""
    if resource == 'resource' and service in RESOURCE_CORRECTIONS['resource']:
        return RESOURCE_CORRECTIONS['resource'][service]
    
    if resource == 'object' and service == 'storage':
        return 'bucket'
    
    if resource == 'engine':
        return 'application'
    
    # Remove redundant service prefix
    if resource.startswith(service + '_'):
        return resource[len(service)+1:]
    
    return resource

def normalize_assertion(assertion: str, resource: str) -> str:
    """Normalize assertion to follow enterprise standards."""
    # Remove _check suffix
    if assertion.endswith('_check'):
        assertion = assertion[:-6]
        if not assertion.endswith(('_enabled', '_configured', '_required', '_enforced', '_blocked', '_restricted')):
            assertion += '_configured'
    
    # Add context to vague assertions
    if assertion in ['enabled', 'configured', 'encrypted', 'monitored']:
        assertion = f"{resource}_{assertion}"
    
    # Truncate if too long (max 60)
    if len(assertion) > 60:
        # Try to intelligently truncate
        parts = assertion.split('_')
        # Keep first part, last part, and as many middle parts as fit
        if len(parts) > 3:
            first = parts[0]
            last = parts[-1]
            middle = '_'.join(parts[1:-1])
            
            # Calculate available space
            available = 60 - len(first) - len(last) - 2  # -2 for underscores
            
            if len(middle) > available:
                # Truncate middle part
                middle = middle[:available]
            
            assertion = f"{first}_{middle}_{last}"
        
        # Final truncate if still too long
        if len(assertion) > 60:
            assertion = assertion[:60]
            # Remove trailing underscore if present
            if assertion.endswith('_'):
                assertion = assertion[:-1]
    
    return assertion

def fix_rule_id(rule_id: str) -> Tuple[str, List[str], bool]:
    """
    Fix a rule ID to follow enterprise standards.
    Returns: (fixed_rule, fixes_applied, is_valid)
    """
    fixes_applied = []
    
    # Handle malformed entries with colons
    if ':' in rule_id:
        # Split and take the most complete rule (longest one)
        parts = rule_id.split(':')
        rule_id = max(parts, key=lambda x: len(x.split('.')))
        fixes_applied.append("Removed malformed colon entry")
    
    parts = rule_id.split('.')
    
    # Must have exactly 4 parts
    if len(parts) < 4:
        fixes_applied.append(f"SKIP: Invalid format with {len(parts)} parts")
        return rule_id, fixes_applied, False
    
    if len(parts) > 4:
        # Consolidate extra parts into assertion
        parts = [parts[0], parts[1], parts[2], '_'.join(parts[3:])]
        fixes_applied.append("Consolidated extra parts into assertion")
    
    csp, service, resource, assertion = parts
    
    # Fix CSP
    if csp != 'gcp':
        csp = 'gcp'
        fixes_applied.append(f"Fixed CSP to 'gcp'")
    
    # Fix service name
    original_service = service
    service = infer_service_from_context(service, resource, assertion)
    if service != original_service:
        fixes_applied.append(f"Service: '{original_service}' → '{service}'")
    
    # Remove underscores from service
    if '_' in service:
        service = service.replace('_', '')
        fixes_applied.append("Removed underscores from service")
    
    # Fix resource name
    original_resource = resource
    resource = infer_resource_from_context(resource, service, assertion)
    if resource != original_resource:
        fixes_applied.append(f"Resource: '{original_resource}' → '{resource}'")
    
    # Fix assertion
    original_assertion = assertion
    assertion = normalize_assertion(assertion, resource)
    if assertion != original_assertion:
        fixes_applied.append(f"Assertion normalized")
    
    fixed_rule = f"{csp}.{service}.{resource}.{assertion}"
    is_valid = True
    
    return fixed_rule, fixes_applied, is_valid

def process_rules(rule_ids: List[str]) -> Tuple[List[str], Dict]:
    """Process all rules and return fixed list with statistics."""
    fixed_rules = []
    seen = set()
    stats = {
        'total': len(rule_ids),
        'unchanged': 0,
        'fixed': 0,
        'duplicates_removed': 0,
        'invalid_skipped': 0,
        'fixes_by_type': Counter()
    }
    
    for rule_id in rule_ids:
        fixed_rule, fixes, is_valid = fix_rule_id(rule_id)
        
        # Skip duplicates
        if fixed_rule in seen:
            stats['duplicates_removed'] += 1
            continue
        seen.add(fixed_rule)
        
        # Skip invalid
        if not is_valid:
            stats['invalid_skipped'] += 1
            continue
        
        fixed_rules.append(fixed_rule)
        
        if fixes:
            stats['fixed'] += 1
            for fix in fixes:
                if ':' in fix or '→' in fix:
                    fix_type = fix.split(':')[0] if ':' in fix else fix.split('→')[0]
                    stats['fixes_by_type'][fix_type.strip()] += 1
        else:
            stats['unchanged'] += 1
    
    # Sort rules for consistency
    fixed_rules.sort()
    
    return fixed_rules, stats

def main():
    """Main function."""
    print("=" * 80)
    print("GCP Enterprise Rule ID Fixer")
    print("=" * 80)
    print()
    
    # Paths
    rule_file = '/Users/apple/Desktop/threat-engine/compliance/gcp/rule_ids.yaml'
    backup_file = f'/Users/apple/Desktop/threat-engine/compliance/gcp/rule_ids_BACKUP_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml'
    
    # Backup
    print(f"Creating backup: {backup_file}")
    shutil.copy(rule_file, backup_file)
    print("✓ Backup created")
    print()
    
    # Read
    print(f"Reading rules from: {rule_file}")
    with open(rule_file, 'r') as f:
        data = yaml.safe_load(f)
    
    original_rules = data.get('rule_ids', [])
    print(f"Total rules: {len(original_rules)}")
    print()
    
    # Process
    print("Processing rules...")
    fixed_rules, stats = process_rules(original_rules)
    print("✓ Processing complete")
    print()
    
    # Update metadata
    data['rule_ids'] = fixed_rules
    data['metadata']['total_rules'] = len(fixed_rules)
    data['metadata']['formatted_date'] = datetime.now().isoformat()
    data['metadata']['format_version'] = 'enterprise_cspm_v2'
    data['metadata']['reviewed'] = True
    data['metadata']['last_fixed'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Write
    print(f"Writing fixed rules to: {rule_file}")
    with open(rule_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    print("✓ File written")
    print()
    
    # Statistics
    print("=" * 80)
    print("FIXING RESULTS")
    print("=" * 80)
    print(f"Original rules:        {stats['total']}")
    print(f"Fixed rules:           {len(fixed_rules)}")
    print(f"Unchanged:             {stats['unchanged']} ({stats['unchanged']/stats['total']*100:.1f}%)")
    print(f"Modified:              {stats['fixed']} ({stats['fixed']/stats['total']*100:.1f}%)")
    print(f"Duplicates removed:    {stats['duplicates_removed']}")
    print(f"Invalid skipped:       {stats['invalid_skipped']}")
    print()
    
    if stats['fixes_by_type']:
        print("Top fixes applied:")
        for fix_type, count in stats['fixes_by_type'].most_common(10):
            print(f"  - {fix_type}: {count}")
    
    print()
    print("=" * 80)
    print("✓ COMPLETE")
    print("=" * 80)
    print(f"Backup saved:  {backup_file}")
    print(f"Rules updated: {rule_file}")
    print()
    print("Next step: Review the changes and verify the rules are correct")
    print()

if __name__ == "__main__":
    main()

