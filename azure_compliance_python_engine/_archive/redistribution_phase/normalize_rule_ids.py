#!/usr/bin/env python3
"""
Normalize rule IDs to Azure standard format:
azure.service.resource.security_check

From patterns like:
- azure.azure.network_vpn_connection.* → azure.network.vpn_connection.*
- active.directory_app_registration.* → azure.aad.app_registration.*
- managed.identity.* → azure.aad.identity.*
"""

import csv
import re
from pathlib import Path
from collections import defaultdict

def normalize_service_name(service_name):
    """Normalize service name for rule_id"""
    service_map = {
        # Generic to specific
        'azure': None,  # Will be determined from resource
        'active': 'aad',  # Active Directory → AAD
        'managed': 'aad',  # Managed services → AAD (mostly)
        
        # Consolidations (from our mapping)
        'directory': 'aad',
        'ad': 'aad',
        'entra': 'aad',
        'entrad': 'aad',
        
        # Keep standard services as-is
        'network': 'network',
        'monitor': 'monitor',
        'monitoring': 'monitor',
        'keyvault': 'keyvault',
        'security': 'security',
        'compute': 'compute',
        'storage': 'storage',
        'backup': 'backup',
        'sql': 'sql',
        'function': 'function',
        'api': 'api',
        'rbac': 'rbac',
        'policy': 'policy',
    }
    
    return service_map.get(service_name, service_name)


def extract_resource_from_rule_id(rule_id):
    """Extract resource name from rule_id"""
    parts = rule_id.split('.')
    
    if len(parts) < 4:
        return None
    
    # Pattern: provider.service.resource.check
    # or: provider.service.subservice_resource.check
    
    resource = parts[2] if len(parts) >= 3 else None
    
    # Clean up resource name
    if resource:
        # Remove duplicate prefixes
        resource = resource.replace('azure_', '')
        resource = resource.replace('active_', '')
        resource = resource.replace('directory_', '')
    
    return resource


def infer_service_from_resource(resource, suggested_service):
    """Infer service from resource if not clear"""
    if not resource:
        return suggested_service
    
    resource_lower = resource.lower()
    
    # Resource patterns
    patterns = {
        'network': ['network', 'vpn', 'load_balancer', 'firewall', 'endpoint'],
        'monitor': ['monitoring', 'log', 'alert', 'trace', 'dashboard'],
        'keyvault': ['crypto', 'secret', 'certificate', 'key', 'grant'],
        'security': ['security', 'streaming', 'shield', 'waf'],
        'backup': ['dr_', 'recovery', 'backup'],
        'aad': ['directory', 'identity', 'user', 'group', 'mfa', 'saml', 'oidc'],
        'storage': ['bucket', 'blob', 'storage'],
        'compute': ['instance', 'vm', 'ebs', 'disk'],
        'sql': ['database', 'db_instance', 'rds'],
        'function': ['function', 'lambda'],
    }
    
    for service, keywords in patterns.items():
        for keyword in keywords:
            if keyword in resource_lower:
                return service
    
    return suggested_service


def normalize_resource_name(resource):
    """Clean up resource name"""
    if not resource:
        return resource
    
    # Remove redundant prefixes
    resource = re.sub(r'^(azure|active|managed)_', '', resource)
    resource = re.sub(r'^(network|monitoring|crypto|security)_', '', resource)
    
    # Simplify common patterns
    replacements = {
        'directory_app_registration': 'app_registration',
        'directory_enterprise_application': 'enterprise_application',
        'directory_group': 'group',
        'directory_user': 'user',
        'network_vpn_connection': 'vpn_connection',
        'network_load_balancer': 'load_balancer',
        'network_firewall': 'firewall',
        'network_network_acl': 'network_acl',
        'network_endpoint': 'endpoint',
        'monitoring_trace': 'trace',
        'monitoring_alert': 'alert',
        'monitoring_dashboard': 'dashboard',
        'crypto_private_ca': 'private_ca',
        'crypto_certificate': 'certificate',
        'crypto_grant': 'grant',
        'crypto_alias': 'alias',
    }
    
    for old, new in replacements.items():
        resource = resource.replace(old, new)
    
    return resource


def normalize_check_name(check_parts):
    """Normalize the security check/assertion part"""
    # Join remaining parts
    check = '_'.join(check_parts)
    
    # Remove redundant prefixes that match resource
    check = re.sub(r'^(network|monitoring|crypto|security|identity|secrets)_', '', check)
    
    # Simplify verbose names
    check = check.replace('_configured', '')
    check = check.replace('_enabled', '_enabled')  # Keep _enabled
    check = check.replace('_properly_configured', '')
    
    # Limit length (max 80 chars for check part)
    if len(check) > 80:
        # Keep first 70 chars and add hash
        import hashlib
        hash_suffix = hashlib.md5(check.encode()).hexdigest()[:8]
        check = check[:70] + '_' + hash_suffix
    
    return check


def create_normalized_rule_id(old_rule_id, suggested_service):
    """
    Create normalized rule ID in format:
    azure.service.resource.security_check
    """
    parts = old_rule_id.split('.')
    
    if len(parts) < 4:
        # Invalid format, return as-is
        return old_rule_id, "INVALID_FORMAT"
    
    # Extract components
    provider = 'azure'  # Always azure for this project
    old_service = parts[1]
    resource_part = parts[2]
    check_parts = parts[3:]
    
    # Normalize service
    service = normalize_service_name(old_service)
    
    # If service is still generic, use suggested service
    if not service or service == old_service and old_service in ['azure', 'active', 'managed']:
        service = suggested_service
    
    # Infer service from resource if needed
    if not service:
        service = infer_service_from_resource(resource_part, suggested_service)
    
    # Normalize resource
    resource = normalize_resource_name(resource_part)
    
    # Normalize check
    check = normalize_check_name(check_parts)
    
    # Construct new rule_id
    new_rule_id = f"{provider}.{service}.{resource}.{check}"
    
    transformation = f"{old_service} → {service}"
    
    return new_rule_id, transformation


def process_csv(input_file, output_file):
    """Process CSV and add normalized rule IDs"""
    
    rows = []
    stats = {
        'total': 0,
        'normalized': 0,
        'unchanged': 0,
        'by_service': defaultdict(int)
    }
    
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        
        # Add new columns
        new_fieldnames = list(fieldnames) + ['normalized_rule_id', 'transformation', 'status_update']
        
        for row in reader:
            stats['total'] += 1
            
            old_rule_id = row['rule_id']
            suggested_service = row['suggested_service']
            
            # Create normalized rule ID
            new_rule_id, transformation = create_normalized_rule_id(old_rule_id, suggested_service)
            
            row['normalized_rule_id'] = new_rule_id
            row['transformation'] = transformation
            
            # Check if changed
            if new_rule_id != old_rule_id:
                stats['normalized'] += 1
                row['status_update'] = 'NORMALIZED'
            else:
                stats['unchanged'] += 1
                row['status_update'] = 'UNCHANGED'
            
            stats['by_service'][suggested_service] += 1
            rows.append(row)
    
    # Write updated CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=new_fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    return stats, rows


def generate_transformation_report(stats, rows, output_file):
    """Generate detailed transformation report"""
    
    report = []
    report.append("=" * 80)
    report.append(" RULE ID NORMALIZATION REPORT")
    report.append("=" * 80)
    report.append("")
    
    report.append(f"Total rules processed:    {stats['total']}")
    report.append(f"Rules normalized:         {stats['normalized']} ({100*stats['normalized']/stats['total']:.1f}%)")
    report.append(f"Rules unchanged:          {stats['unchanged']} ({100*stats['unchanged']/stats['total']:.1f}%)")
    report.append("")
    
    report.append("By target service:")
    for service, count in sorted(stats['by_service'].items(), key=lambda x: x[1], reverse=True):
        report.append(f"  {service:20s}: {count:3d} rules")
    
    report.append("")
    report.append("=" * 80)
    report.append(" SAMPLE TRANSFORMATIONS")
    report.append("=" * 80)
    report.append("")
    
    # Show samples
    samples_shown = 0
    for row in rows:
        if row['status_update'] == 'NORMALIZED' and samples_shown < 20:
            report.append(f"OLD: {row['rule_id']}")
            report.append(f"NEW: {row['normalized_rule_id']}")
            report.append(f"     Service: {row['transformation']}")
            report.append("")
            samples_shown += 1
    
    if stats['normalized'] > 20:
        report.append(f"... and {stats['normalized'] - 20} more normalizations")
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    return '\n'.join(report)


def main():
    print("=" * 80)
    print(" RULE ID NORMALIZATION")
    print("=" * 80)
    
    script_dir = Path(__file__).parent
    input_file = script_dir / 'redistribution_mapping.csv'
    output_file = script_dir / 'redistribution_mapping_normalized.csv'
    report_file = script_dir / 'rule_normalization_report.txt'
    
    if not input_file.exists():
        print(f"❌ Error: {input_file} not found")
        return 1
    
    print(f"\n📄 Processing: {input_file}")
    
    # Process CSV
    stats, rows = process_csv(input_file, output_file)
    
    # Generate report
    report = generate_transformation_report(stats, rows, report_file)
    
    print(report)
    
    print(f"\n✅ Files created:")
    print(f"  • {output_file}")
    print(f"  • {report_file}")
    
    print("\n" + "=" * 80)
    print(f" NORMALIZATION COMPLETE")
    print(f" {stats['normalized']} rules normalized to Azure standard format")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

