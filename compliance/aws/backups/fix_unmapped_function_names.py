#!/usr/bin/env python3
"""
Fix improved function names for the 9 unmapped functions
Follow proper aws.service.resource.assertion format
"""

import json

def fix_improved_functions():
    """
    Corrections for the 9 unmapped functions
    Following proper aws.service.resource.assertion format
    """
    
    corrections = {
        # 1. VPC in different regions - resource should be vpc
        "aws_vpc_different_regions": {
            "improved_function": "aws.ec2.vpc.multi_region_deployment_configured",
            "parsed_components": {
                "service": "ec2",
                "resource": "vpc",
                "assertion": "multi_region_deployment_configured"
            },
            "notes": "VPC deployed across multiple regions for HA/DR"
        },
        
        # 2. Elastic IP Shodan check - resource should be eip
        "aws_ec2_elastic_ip_shodan": {
            "improved_function": "aws.ec2.eip.shodan_exposure_detected",
            "parsed_components": {
                "service": "ec2",
                "resource": "eip",
                "assertion": "shodan_exposure_detected"
            },
            "notes": "Elastic IP exposure detected via Shodan threat intelligence"
        },
        
        # 3. VPC endpoint connections trust boundaries
        "aws_vpc_endpoint_connections_trust_boundaries": {
            "improved_function": "aws.ec2.vpcendpoint.connection_trust_boundaries_validated",
            "parsed_components": {
                "service": "ec2",
                "resource": "vpcendpoint",
                "assertion": "connection_trust_boundaries_validated"
            },
            "notes": "VPC endpoint connections comply with trust boundary policies"
        },
        
        # 4. VPC endpoint services allowed principals
        "aws_vpc_endpoint_services_allowed_principals_trust_boundaries": {
            "improved_function": "aws.ec2.vpcendpointservice.allowed_principals_trust_boundaries_validated",
            "parsed_components": {
                "service": "ec2",
                "resource": "vpcendpointservice",
                "assertion": "allowed_principals_trust_boundaries_validated"
            },
            "notes": "VPC endpoint service allowed principals comply with trust boundaries"
        },
        
        # 5. Keyspaces network security - service should be keyspaces, not ec2
        "aws_vpc_keyspaces_network_security_check": {
            "improved_function": "aws.keyspaces.table.vpc_network_security_configured",
            "parsed_components": {
                "service": "keyspaces",
                "resource": "table",
                "assertion": "vpc_network_security_configured"
            },
            "notes": "AWS Keyspaces (Cassandra) table network security in VPC"
        },
        
        # 6. Invalid function - keep as general but fix naming
        "aws_No checks defined": {
            "improved_function": "aws.general.account.no_checks_defined",
            "parsed_components": {
                "service": "general",
                "resource": "account",
                "assertion": "no_checks_defined"
            },
            "notes": "INVALID FUNCTION - Data quality issue in source CSV"
        },
        
        # 7. IAM guest accounts - resource should be user or account
        "aws_iam_no_guest_accounts_with_permissions": {
            "improved_function": "aws.iam.user.guest_accounts_have_no_permissions",
            "parsed_components": {
                "service": "iam",
                "resource": "user",
                "assertion": "guest_accounts_have_no_permissions"
            },
            "notes": "IAM guest accounts should not have permissions"
        },
        
        # 8. KMS CMK not multi-region - assertion should be positive
        "aws_kms_cmk_not_multi_region": {
            "improved_function": "aws.kms.key.single_region_key_configured",
            "parsed_components": {
                "service": "kms",
                "resource": "key",
                "assertion": "single_region_key_configured"
            },
            "notes": "KMS key is single-region (not multi-region)"
        },
        
        # 9. Network Firewall in all VPCs - resource should be firewall
        "aws_networkfirewall_in_all_vpc": {
            "improved_function": "aws.network-firewall.firewall.deployed_in_all_vpcs",
            "parsed_components": {
                "service": "network-firewall",
                "resource": "firewall",
                "assertion": "deployed_in_all_vpcs"
            },
            "notes": "Network Firewall deployed in all VPCs (organizational policy)"
        },
    }
    
    return corrections

def apply_corrections():
    """Apply corrections to working file"""
    
    # Load working file
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'r') as f:
        data = json.load(f)
    
    corrections = fix_improved_functions()
    
    stats = {
        'total': 0,
        'corrected': 0,
        'changes': []
    }
    
    # Apply corrections
    for func in data['all_unmatched_functions']:
        stats['total'] += 1
        original = func['original_function']
        
        if original in corrections:
            correction = corrections[original]
            old_improved = func['improved_function']
            new_improved = correction['improved_function']
            
            # Update function
            func['improved_function'] = new_improved
            func['parsed_components'] = correction['parsed_components']
            
            # Update manual_mapping notes
            if 'manual_mapping' in func and func['manual_mapping'].get('notes'):
                func['manual_mapping']['notes'] = correction['notes']
            
            stats['corrected'] += 1
            stats['changes'].append({
                'original': original,
                'old_improved': old_improved,
                'new_improved': new_improved,
                'notes': correction['notes']
            })
    
    # Update by_service structure
    by_service = {}
    for func in data['all_unmatched_functions']:
        service = func['parsed_components']['service']
        if service not in by_service:
            by_service[service] = []
        by_service[service].append(func)
    
    data['unmatched_by_service'] = by_service
    
    # Save updated file
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'w') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    return stats

def also_update_main_mapping():
    """Also update the main mapping file"""
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'r') as f:
        main_data = json.load(f)
    
    corrections = fix_improved_functions()
    
    updated = 0
    for original, correction in corrections.items():
        if original in main_data['functions']:
            main_data['functions'][original]['improved_function'] = correction['improved_function']
            updated += 1
    
    # Save
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'w') as f:
        json.dump(main_data, f, indent=2, ensure_ascii=False)
    
    return updated

def print_summary(stats, main_updated):
    """Print summary of corrections"""
    
    print("\n" + "="*80)
    print("IMPROVED FUNCTION NAME CORRECTIONS - 9 UNMAPPED FUNCTIONS")
    print("="*80)
    
    print(f"\nTotal functions reviewed:       {stats['total']}")
    print(f"Corrections applied:            {stats['corrected']}")
    
    print(f"\n{'CORRECTIONS APPLIED':-^80}")
    
    for i, change in enumerate(stats['changes'], 1):
        print(f"\n{i}. {change['original']}")
        print(f"   OLD: {change['old_improved']}")
        print(f"   NEW: {change['new_improved']}")
        print(f"   → {change['notes']}")
    
    print(f"\n{'IMPROVEMENTS MADE':-^80}")
    print(f"\n  ✅ Fixed 'different' → proper resource name (vpc)")
    print(f"  ✅ Fixed 'elastic' → proper resource name (eip)")
    print(f"  ✅ Fixed 'no' → proper resource name (user)")
    print(f"  ✅ Fixed keyspaces service (ec2 → keyspaces)")
    print(f"  ✅ Fixed KMS resource (cmk → key)")
    print(f"  ✅ Fixed assertions to be descriptive and positive")
    print(f"  ✅ All assertions now in snake_case format")
    
    print(f"\n{'FILES UPDATED':-^80}")
    print(f"\n  ✅ unmatched_functions_working.json - {stats['corrected']} functions")
    print(f"  ✅ aws_function_to_compliance_mapping.json - {main_updated} functions")
    
    print("\n" + "="*80)
    print()

def main():
    print("Fixing improved function names...")
    print("  - Following aws.service.resource.assertion format")
    print("  - Proper AWS SDK resource names")
    print("  - Descriptive, positive assertions")
    
    stats = apply_corrections()
    print("  ✓ Working file updated")
    
    main_updated = also_update_main_mapping()
    print("  ✓ Main mapping file updated")
    
    print_summary(stats, main_updated)

if __name__ == "__main__":
    main()

