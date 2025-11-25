#!/usr/bin/env python3
"""
Fix EC2 resource naming in rule_ids.yaml and re-map unmapped functions
"""

import yaml
import json
from datetime import datetime
from difflib import SequenceMatcher

def backup_rule_ids():
    """Create backup"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"/Users/apple/Desktop/threat-engine/compliance/aws/backups/rule_ids_before_ec2_resource_fix_{timestamp}.yaml"
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'r') as f:
        content = f.read()
    
    with open(backup_path, 'w') as f:
        f.write(content)
    
    return backup_path

def get_corrections():
    """All corrections to apply"""
    
    corrections = {
        # EIP corrections
        'aws.ec2.elasticipshodan.elastic_ip_shodan_configured': 'aws.ec2.eip.shodan_exposure_detected',
        'aws.ec2.elastic_ip_unassigned.elastic_ip_unassigned_configured': 'aws.ec2.eip.not_in_use',
        
        # Instance-level corrections
        'aws.ec2.patchcompliance.patch_compliance_configured': 'aws.ec2.instance.patch_compliance_status_check',
        'aws.ec2.ssm_association_compliance.ssm_association_compliance_configured': 'aws.ec2.instance.ssm_association_compliant',
        'aws.ec2.stoppedinstance.stopped_instance_configured': 'aws.ec2.instance.stopped_instances_removed',
        
        # Transit Gateway
        'aws.ec2.transitgateway_auto_accept_vpc_attachments.transitgateway_auto_accept_vpc_attachments_configured': 'aws.ec2.transitgateway.auto_cross_account_attachment_disabled',
        
        # Network ACL corrections (fix compound resource names)
        'aws.ec2.networkacl_allow_ingress_any_port.networkacl_allow_ingress_any_port_configured': 'aws.ec2.networkacl.ingress_restrict_all_traffic',
        'aws.ec2.networkacl_allow_ingress_tcp_port_22.networkacl_allow_ingress_tcp_port_22_configured': 'aws.ec2.networkacl.ssh_port_22_restricted',
        'aws.ec2.networkacl_allow_ingress_tcp_port_3389.networkacl_allow_ingress_tcp_port_3389_configured': 'aws.ec2.networkacl.rdp_port_3389_restricted',
        'aws.ec2.networkacl_unrestricted_ingress.networkacl_unrestricted_ingress_configured': 'aws.ec2.networkacl.unrestricted_ingress_blocked',
        'aws.ec2.networkacl_unused.networkacl_unused_configured': 'aws.ec2.networkacl.unused_network_acl_configured',
    }
    
    return corrections

def apply_corrections_to_rule_ids():
    """Apply corrections to rule_ids.yaml"""
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'r') as f:
        rule_data = yaml.safe_load(f)
    
    corrections = get_corrections()
    
    # Apply corrections
    updated_rules = []
    stats = {'corrected': 0, 'unchanged': 0}
    
    for rule_id in rule_data['rule_ids']:
        if rule_id in corrections:
            updated_rules.append(corrections[rule_id])
            stats['corrected'] += 1
        else:
            updated_rules.append(rule_id)
            stats['unchanged'] += 1
    
    rule_data['rule_ids'] = updated_rules
    
    # Save
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'w') as f:
        yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    return stats

def try_match_unmapped():
    """Try to match unmapped functions with corrected rule_ids"""
    
    # Load files
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'r') as f:
        working = json.load(f)
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'r') as f:
        rule_data = yaml.safe_load(f)
        rule_ids = rule_data['rule_ids']
    
    mappings = {}
    
    # Manual expert mappings with corrected rule_ids
    expert_mappings = {
        "aws_vpc_different_regions": {
            "matched_rule_id": "aws.ec2.vpc.automated_isolation_supported_configured",
            "confidence": "medium",
            "notes": "VPC multi-region deployment maps to automated isolation (HA/DR pattern)"
        },
        "aws_ec2_elastic_ip_shodan": {
            "matched_rule_id": "aws.ec2.eip.shodan_exposure_detected",
            "confidence": "high",
            "notes": "Now matches after fixing elasticipshodan → eip"
        },
    }
    
    # Apply expert mappings
    for func in working['all_unmatched_functions']:
        original = func['original_function']
        improved = func['improved_function']
        
        if original in expert_mappings:
            mapping = expert_mappings[original]
            # Verify rule exists
            if mapping['matched_rule_id'] in rule_ids:
                mappings[original] = mapping
                func['manual_mapping'] = mapping
    
    return mappings, working

def update_main_mapping(new_mappings):
    """Update main mapping file"""
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'r') as f:
        main_data = json.load(f)
    
    updated = 0
    for original, mapping in new_mappings.items():
        if original in main_data['functions']:
            main_data['functions'][original]['matched_rule_id'] = mapping['matched_rule_id']
            main_data['functions'][original]['match_quality'] = 'manual_mapping'
            main_data['functions'][original]['confidence'] = mapping['confidence']
            main_data['functions'][original]['mapping_notes'] = mapping['notes']
            main_data['functions'][original]['expert_reviewed'] = True
            updated += 1
    
    # Update metadata
    if updated > 0:
        main_data['metadata']['matched_functions'] = main_data['metadata']['matched_functions'] + updated
        main_data['metadata']['unmatched_functions'] = main_data['metadata']['unmatched_functions'] - updated
        main_data['metadata']['match_rate'] = round(main_data['metadata']['matched_functions'] / main_data['metadata']['total_functions'] * 100, 1)
        
        # Update quality breakdown
        main_data['metadata']['match_quality_breakdown']['manual_mapping'] += updated
        main_data['metadata']['match_quality_breakdown']['unmatched'] -= updated
    
    # Save
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'w') as f:
        json.dump(main_data, f, indent=2, ensure_ascii=False)
    
    return updated

def update_working_file(working_data):
    """Update working file to remove newly mapped functions"""
    
    still_unmapped = []
    for func in working_data['all_unmatched_functions']:
        if func.get('manual_mapping', {}).get('matched_rule_id') is None:
            still_unmapped.append(func)
    
    # Reorganize by service
    by_service = {}
    for func in still_unmapped:
        service = func['parsed_components']['service']
        if service not in by_service:
            by_service[service] = []
        by_service[service].append(func)
    
    working_data['metadata']['total_functions'] = len(still_unmapped)
    working_data['unmatched_by_service'] = by_service
    working_data['all_unmatched_functions'] = still_unmapped
    
    # Save
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'w') as f:
        json.dump(working_data, f, indent=2, ensure_ascii=False)
    
    return len(still_unmapped)

def print_summary(rule_stats, mappings, main_updated, remaining):
    """Print summary"""
    
    print("\n" + "="*80)
    print("EC2 RESOURCE FIX + RE-MAPPING COMPLETE")
    print("="*80)
    
    print(f"\n{'RULE_IDS.YAML CORRECTIONS':-^80}")
    print(f"\n  Rules corrected:                {rule_stats['corrected']}")
    print(f"  Rules unchanged:                {rule_stats['unchanged']}")
    print(f"  Total rules:                    {rule_stats['corrected'] + rule_stats['unchanged']}")
    
    print(f"\n{'NEW MAPPINGS FOUND':-^80}")
    print(f"\n  Functions newly mapped:         {len(mappings)}")
    
    for original, mapping in mappings.items():
        print(f"\n  ✓ {original}")
        print(f"    → {mapping['matched_rule_id']}")
        print(f"    Confidence: {mapping['confidence']}")
        print(f"    Notes: {mapping['notes']}")
    
    print(f"\n{'FILES UPDATED':-^80}")
    print(f"\n  ✓ rule_ids.yaml - {rule_stats['corrected']} corrections")
    print(f"  ✓ aws_function_to_compliance_mapping.json - {main_updated} functions updated")
    print(f"  ✓ unmatched_functions_working.json - {remaining} still unmapped")
    
    print(f"\n{'FINAL STATUS':-^80}")
    print(f"\n  Remaining unmapped:             {remaining}")
    print(f"  Coverage improvement:           +{len(mappings)} functions")
    
    print("\n" + "="*80)
    print()

def main():
    print("Step 1: Backing up rule_ids.yaml...")
    backup_path = backup_rule_ids()
    print(f"  ✓ Backup created: {backup_path}")
    
    print("\nStep 2: Fixing EC2 resource names in rule_ids.yaml...")
    rule_stats = apply_corrections_to_rule_ids()
    print(f"  ✓ Applied {rule_stats['corrected']} corrections")
    
    print("\nStep 3: Re-mapping unmapped functions with corrected rules...")
    mappings, working_data = try_match_unmapped()
    print(f"  ✓ Found {len(mappings)} new mappings")
    
    print("\nStep 4: Updating main mapping file...")
    main_updated = update_main_mapping(mappings)
    print(f"  ✓ Updated {main_updated} functions")
    
    print("\nStep 5: Updating working file...")
    remaining = update_working_file(working_data)
    print(f"  ✓ {remaining} functions still unmapped")
    
    print_summary(rule_stats, mappings, main_updated, remaining)

if __name__ == "__main__":
    main()

