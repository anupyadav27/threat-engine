#!/usr/bin/env python3
"""
GCP Enterprise Rule ID Validator and Fixer
Validates and fixes rule IDs to follow enterprise standards from ENTERPRISE_CSPM_RULE_GENERATION_PROMPT.md
"""

import re
import yaml
from typing import List, Dict, Tuple
from datetime import datetime
from collections import defaultdict

# Valid GCP services (from google-cloud-* Python client packages)
VALID_GCP_SERVICES = {
    'compute', 'storage', 'iam', 'sql', 'bigquery', 'pubsub', 'functions', 'run',
    'logging', 'monitoring', 'kms', 'secretmanager', 'container', 'artifactregistry',
    'dataproc', 'dataflow', 'cloudbuild', 'scheduler', 'appengine', 'firestore',
    'spanner', 'datastore', 'redis', 'memcache', 'aiplatform', 'apigateway',
    'certificatemanager', 'dns', 'cloudtasks', 'cloudtrace', 'dlp', 'healthcare',
    'notebooks', 'composer', 'datafusion', 'datastream', 'vmwareengine'
}

# Service name corrections
SERVICE_NAME_CORRECTIONS = {
    'cloud': None,  # Remove generic 'cloud' service
    'app': 'appengine',
    'artifact': 'artifactregistry',
    'backup': 'backupdr',
    'backupdr': 'backupdr',
    'access': 'accessapproval',
    'acm': 'certificatemanager',
    'api': 'apigateway',
    'apigee': 'apigee',
    'apikeys': 'apikeys',
    'apigatewayv2': 'apigateway',
    'artifacts': 'artifactregistry',
    'batch': 'batch',
    'big': 'bigquery',
    'bigtable': 'bigtable',
    'billingbudget': 'billing',
    'build': 'cloudbuild',
    'certificate': 'certificatemanager',
    'cloudscheduler': 'scheduler',
    'cloudtasks': 'cloudtasks',
    'cloudtrace': 'cloudtrace',
    'dlp_security': 'dlp',
    'dns': 'dns',
    'essentialcontacts': 'essentialcontacts',
    'filestore': 'filestore',
    'gke': 'container',
    'healthcare': 'healthcare',
    'notebooks': 'notebooks',
    'org': 'resourcemanager',
    'organization': 'resourcemanager',
    'project': 'resourcemanager',
    'resourcemanager': 'resourcemanager',
    'serviceusage': 'serviceusage',
    'vertex': 'aiplatform',
}

# Vague assertion patterns to detect
VAGUE_PATTERNS = [
    r'^encrypted$',
    r'^enabled$',
    r'^configured$',
    r'^exists$',
    r'_check$',
    r'^check$',
]

def validate_rule_id(rule_id: str) -> Tuple[bool, List[str]]:
    """Validate a single rule ID against enterprise standards."""
    errors = []
    warnings = []
    
    # Handle complex entries with colons (these are malformed)
    if ':' in rule_id:
        errors.append("Contains colon - malformed entry with multiple rules")
        return False, errors
    
    # Split into parts
    parts = rule_id.split('.')
    
    # Check format (exactly 4 parts)
    if len(parts) != 4:
        errors.append(f"Invalid format: must have 4 parts, got {len(parts)}")
        return False, errors
    
    csp, service, resource, assertion = parts
    
    # Validate CSP
    if csp != 'gcp':
        errors.append(f"Invalid CSP: '{csp}' (must be 'gcp')")
    
    # Validate service name
    if '_' in service:
        errors.append(f"Service contains underscore: '{service}'")
    
    if len(service) > 30:
        errors.append(f"Service too long: {len(service)} chars (max 30)")
    
    if service not in VALID_GCP_SERVICES and service not in SERVICE_NAME_CORRECTIONS:
        warnings.append(f"Unknown service: '{service}' (may need mapping)")
    
    # Validate resource name
    if resource in ['resource', 'item', 'object']:
        errors.append(f"Generic resource name: '{resource}'")
    
    if len(resource) > 50:
        errors.append(f"Resource too long: {len(resource)} chars (max 50)")
    
    # Validate assertion
    for pattern in VAGUE_PATTERNS:
        if re.match(pattern, assertion, re.IGNORECASE):
            errors.append(f"Vague assertion: '{assertion}'")
            break
    
    if len(assertion) > 60:
        errors.append(f"Assertion too long: {len(assertion)} chars (max 60)")
    
    return len(errors) == 0, errors + warnings

def fix_rule_id(rule_id: str) -> Tuple[str, List[str]]:
    """Fix a rule ID to follow enterprise standards."""
    fixes_applied = []
    
    # Handle complex entries with colons
    if ':' in rule_id:
        # Take the first part before colon
        rule_id = rule_id.split(':')[0]
        fixes_applied.append("Removed malformed colon entry")
    
    parts = rule_id.split('.')
    
    # If not 4 parts, try to fix
    if len(parts) < 4:
        fixes_applied.append(f"Skipped: Invalid format with {len(parts)} parts")
        return rule_id, fixes_applied
    
    if len(parts) > 4:
        # Try to consolidate extra parts into assertion
        parts = [parts[0], parts[1], parts[2], '_'.join(parts[3:])]
        fixes_applied.append("Consolidated extra parts into assertion")
    
    csp, service, resource, assertion = parts
    
    # Fix CSP if needed
    if csp != 'gcp':
        csp = 'gcp'
        fixes_applied.append(f"Fixed CSP to 'gcp'")
    
    # Fix service name
    original_service = service
    if service in SERVICE_NAME_CORRECTIONS:
        if SERVICE_NAME_CORRECTIONS[service] is None:
            # For 'cloud', try to infer from resource
            if resource == 'kms':
                service = 'kms'
            elif resource == 'logging':
                service = 'logging'
            elif resource == 'storage':
                service = 'storage'
            else:
                service = 'compute'  # Default fallback
            fixes_applied.append(f"Inferred service '{service}' from resource")
        else:
            service = SERVICE_NAME_CORRECTIONS[service]
            fixes_applied.append(f"Corrected service: '{original_service}' -> '{service}'")
    
    # Remove underscores from service if present
    if '_' in service:
        service = service.replace('_', '')
        fixes_applied.append(f"Removed underscores from service")
    
    # Fix resource name - remove redundant prefixes
    original_resource = resource
    if resource.startswith(service + '_'):
        resource = resource[len(service)+1:]
        fixes_applied.append(f"Removed redundant service prefix from resource")
    
    # Fix common resource name issues
    if resource == 'engine':
        resource = 'application'
        fixes_applied.append(f"Fixed generic resource: 'engine' -> 'application'")
    
    # Fix assertion - remove _check suffix
    original_assertion = assertion
    if assertion.endswith('_check'):
        assertion = assertion[:-6]
        if not assertion.endswith('_enabled') and not assertion.endswith('_configured'):
            assertion += '_configured'
        fixes_applied.append(f"Removed '_check' suffix and normalized")
    
    # Fix vague standalone assertions
    if assertion in ['enabled', 'configured', 'encrypted']:
        assertion = f"{resource}_{assertion}"
        fixes_applied.append(f"Added context to vague assertion")
    
    # Truncate if too long
    if len(assertion) > 60:
        assertion = assertion[:60]
        fixes_applied.append("Truncated overly long assertion")
    
    fixed_rule = f"{csp}.{service}.{resource}.{assertion}"
    return fixed_rule, fixes_applied

def analyze_rules(rule_ids: List[str]) -> Dict:
    """Analyze all rules and categorize issues."""
    results = {
        'valid': [],
        'fixable': {},
        'problematic': {},
        'duplicates': [],
        'stats': defaultdict(int)
    }
    
    seen = set()
    
    for rule_id in rule_ids:
        # Check for duplicates
        if rule_id in seen:
            results['duplicates'].append(rule_id)
            results['stats']['duplicates'] += 1
            continue
        seen.add(rule_id)
        
        # Validate
        is_valid, errors = validate_rule_id(rule_id)
        
        if is_valid:
            results['valid'].append(rule_id)
            results['stats']['valid'] += 1
        else:
            # Try to fix
            fixed_rule, fixes = fix_rule_id(rule_id)
            
            if fixes and 'Skipped' not in fixes[0]:
                results['fixable'][rule_id] = {
                    'fixed': fixed_rule,
                    'fixes': fixes,
                    'errors': errors
                }
                results['stats']['fixable'] += 1
            else:
                results['problematic'][rule_id] = errors
                results['stats']['problematic'] += 1
    
    results['stats']['total'] = len(rule_ids)
    return results

def main():
    """Main function to validate and fix GCP rule IDs."""
    print("=" * 80)
    print("GCP Enterprise Rule ID Validator and Fixer")
    print("=" * 80)
    print()
    
    # Read the rule file
    rule_file = '/Users/apple/Desktop/threat-engine/compliance/gcp/rule_ids.yaml'
    print(f"Reading rules from: {rule_file}")
    
    with open(rule_file, 'r') as f:
        data = yaml.safe_load(f)
    
    rule_ids = data.get('rule_ids', [])
    print(f"Total rules found: {len(rule_ids)}")
    print()
    
    # Analyze rules
    print("Analyzing rules...")
    results = analyze_rules(rule_ids)
    
    # Print statistics
    print()
    print("=" * 80)
    print("ANALYSIS RESULTS")
    print("=" * 80)
    print(f"Total Rules:       {results['stats']['total']}")
    print(f"Valid Rules:       {results['stats']['valid']} ({results['stats']['valid']/results['stats']['total']*100:.1f}%)")
    print(f"Fixable Rules:     {results['stats']['fixable']} ({results['stats']['fixable']/results['stats']['total']*100:.1f}%)")
    print(f"Problematic Rules: {results['stats']['problematic']} ({results['stats']['problematic']/results['stats']['total']*100:.1f}%)")
    print(f"Duplicate Rules:   {results['stats']['duplicates']}")
    print()
    
    # Show sample violations
    if results['fixable']:
        print("=" * 80)
        print("SAMPLE VIOLATIONS AND FIXES (showing first 20)")
        print("=" * 80)
        for i, (original, fix_info) in enumerate(list(results['fixable'].items())[:20]):
            print(f"\n{i+1}. Original: {original}")
            print(f"   Fixed:    {fix_info['fixed']}")
            print(f"   Issues:   {'; '.join(fix_info['errors'][:2])}")
            print(f"   Fixes:    {'; '.join(fix_info['fixes'][:2])}")
    
    # Show problematic rules
    if results['problematic']:
        print()
        print("=" * 80)
        print(f"PROBLEMATIC RULES (cannot auto-fix) - showing first 10")
        print("=" * 80)
        for i, (rule, errors) in enumerate(list(results['problematic'].items())[:10]):
            print(f"\n{i+1}. {rule}")
            for error in errors:
                print(f"   - {error}")
    
    print()
    print("=" * 80)
    print("RECOMMENDATION")
    print("=" * 80)
    print("The rule file contains many violations of enterprise standards:")
    print("1. Service names need normalization (remove underscores, use GCP standards)")
    print("2. Many assertions are vague or have '_check' suffixes")
    print("3. Some entries have malformed format (colons, wrong part count)")
    print()
    print("Next steps:")
    print("1. Review the sample fixes above")
    print("2. Confirm the fixing approach")
    print("3. Run the fixer to generate corrected rule_ids.yaml")
    print()

if __name__ == "__main__":
    main()

