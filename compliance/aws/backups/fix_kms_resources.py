#!/usr/bin/env python3
"""
Fix KMS resource naming in rule_ids.yaml and find better mapping
"""

import yaml
import json
from datetime import datetime

def backup_rule_ids():
    """Create backup"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"/Users/apple/Desktop/threat-engine/compliance/aws/backups/rule_ids_before_kms_resource_fix_{timestamp}.yaml"
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'r') as f:
        content = f.read()
    
    with open(backup_path, 'w') as f:
        f.write(content)
    
    return backup_path

def get_kms_corrections():
    """All KMS resource corrections"""
    
    corrections = {
        # CMK-related compound names → key
        'aws.kms.cmkareused.cmk_are_used_configured': 'aws.kms.key.customer_managed_keys_in_use',
        'aws.kms.cmk_not_deleted_unintentionally.cmk_not_deleted_unintentionally_configured': 'aws.kms.key.not_pending_deletion',
        'aws.kms.cmk_not_multi_region.cmk_not_multi_region_configured': 'aws.kms.key.multi_region_disabled',
        'aws.kms.cmk_state_change_monitoring.cmk_state_change_monitoring_configured': 'aws.kms.key.state_change_monitoring_enabled',
        
        # Duplicate rotation rules - keep the better one
        'aws.kms.resource.cmk_rotation_enabled': 'aws.kms.key.rotation_enabled',
        'aws.kms.cmk.rotation_enabled': 'aws.kms.key.rotation_enabled',
    }
    
    return corrections

def apply_corrections():
    """Apply KMS corrections to rule_ids.yaml"""
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'r') as f:
        rule_data = yaml.safe_load(f)
    
    corrections = get_kms_corrections()
    
    # Apply corrections and remove duplicates
    updated_rules = []
    seen = set()
    stats = {'corrected': 0, 'duplicates_removed': 0, 'unchanged': 0}
    
    for rule_id in rule_data['rule_ids']:
        if rule_id in corrections:
            new_rule = corrections[rule_id]
            if new_rule not in seen:
                updated_rules.append(new_rule)
                seen.add(new_rule)
                stats['corrected'] += 1
            else:
                stats['duplicates_removed'] += 1
        else:
            if rule_id not in seen:
                updated_rules.append(rule_id)
                seen.add(rule_id)
                stats['unchanged'] += 1
    
    rule_data['rule_ids'] = updated_rules
    
    # Save
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'w') as f:
        yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    return stats

def update_kms_mapping():
    """Update the KMS multi-region function mapping"""
    
    # Load files
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'r') as f:
        working = json.load(f)
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'r') as f:
        main_mapping = json.load(f)
    
    # Better improved function name and mapping
    kms_mapping = {
        "original_function": "aws_kms_cmk_not_multi_region",
        "improved_function": "aws.kms.key.multi_region_disabled",
        "matched_rule_id": "aws.kms.key.multi_region_disabled",
        "confidence": "high",
        "notes": "KMS key should not be multi-region (single-region keys for compliance/data residency)"
    }
    
    # Update working file
    mapped = False
    for func in working['all_unmatched_functions']:
        if func['original_function'] == 'aws_kms_cmk_not_multi_region':
            func['improved_function'] = kms_mapping['improved_function']
            func['parsed_components'] = {
                'service': 'kms',
                'resource': 'key',
                'assertion': 'multi_region_disabled'
            }
            func['manual_mapping'] = {
                'matched_rule_id': kms_mapping['matched_rule_id'],
                'confidence': kms_mapping['confidence'],
                'notes': kms_mapping['notes']
            }
            mapped = True
            break
    
    # Update main mapping
    if 'aws_kms_cmk_not_multi_region' in main_mapping['functions']:
        main_mapping['functions']['aws_kms_cmk_not_multi_region'].update({
            'improved_function': kms_mapping['improved_function'],
            'matched_rule_id': kms_mapping['matched_rule_id'],
            'match_quality': 'manual_mapping',
            'confidence': kms_mapping['confidence'],
            'mapping_notes': kms_mapping['notes'],
            'expert_reviewed': True
        })
    
    return working, main_mapping, mapped

def update_metadata(main_mapping):
    """Update metadata"""
    main_mapping['metadata']['matched_functions'] += 1
    main_mapping['metadata']['unmatched_functions'] -= 1
    main_mapping['metadata']['match_rate'] = round(
        main_mapping['metadata']['matched_functions'] / main_mapping['metadata']['total_functions'] * 100, 1
    )
    main_mapping['metadata']['match_quality_breakdown']['manual_mapping'] += 1
    main_mapping['metadata']['match_quality_breakdown']['unmatched'] -= 1

def clean_working_file(working):
    """Remove newly mapped function"""
    still_unmapped = []
    for func in working['all_unmatched_functions']:
        if func.get('manual_mapping', {}).get('matched_rule_id') is None:
            still_unmapped.append(func)
    
    # Reorganize by service
    by_service = {}
    for func in still_unmapped:
        service = func['parsed_components']['service']
        if service not in by_service:
            by_service[service] = []
        by_service[service].append(func)
    
    working['metadata']['total_functions'] = len(still_unmapped)
    working['unmatched_by_service'] = by_service
    working['all_unmatched_functions'] = still_unmapped
    
    return len(still_unmapped)

def save_files(working, main_mapping):
    """Save files"""
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'w') as f:
        json.dump(working, f, indent=2, ensure_ascii=False)
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'w') as f:
        json.dump(main_mapping, f, indent=2, ensure_ascii=False)

def print_summary(rule_stats, mapped, remaining):
    """Print summary"""
    
    print("\n" + "="*80)
    print("KMS RESOURCE FIX + MAPPING COMPLETE")
    print("="*80)
    
    print(f"\n{'RULE_IDS.YAML - KMS CORRECTIONS':-^80}")
    print(f"\n  Rules corrected:                {rule_stats['corrected']}")
    print(f"  Duplicates removed:             {rule_stats['duplicates_removed']}")
    print(f"  Rules unchanged:                {rule_stats['unchanged']}")
    print(f"  Total rules:                    {len(rule_stats)}")
    
    print(f"\n  Corrections applied:")
    print(f"    • cmkareused → key")
    print(f"    • cmk_not_deleted_unintentionally → key")
    print(f"    • cmk_not_multi_region → key")
    print(f"    • cmk_state_change_monitoring → key")
    print(f"    • Removed duplicate rotation rules")
    
    if mapped:
        print(f"\n{'KMS MULTI-REGION MAPPING':-^80}")
        print(f"\n  ✓ aws_kms_cmk_not_multi_region")
        print(f"    OLD: aws.kms.key.single_region_configured")
        print(f"    NEW: aws.kms.key.multi_region_disabled")
        print(f"    → Mapped to: aws.kms.key.multi_region_disabled")
        print(f"    Confidence: HIGH")
    
    print(f"\n{'FINAL STATUS':-^80}")
    print(f"\n  Total functions:                669")
    print(f"  Successfully mapped:            {669 - remaining}")
    print(f"  Still unmapped:                 {remaining}")
    
    if remaining > 0:
        coverage = round((669 - remaining) / 669 * 100, 1)
        print(f"  Coverage:                       {coverage}%")
    
    print("\n" + "="*80)
    print()

def main():
    print("Step 1: Backing up rule_ids.yaml...")
    backup_path = backup_rule_ids()
    print(f"  ✓ Backup: {backup_path.split('/')[-1]}")
    
    print("\nStep 2: Fixing KMS resource names...")
    rule_stats = apply_corrections()
    print(f"  ✓ Corrected {rule_stats['corrected']} rules")
    print(f"  ✓ Removed {rule_stats['duplicates_removed']} duplicates")
    
    print("\nStep 3: Updating KMS multi-region mapping...")
    working, main_mapping, mapped = update_kms_mapping()
    if mapped:
        print("  ✓ KMS function mapped")
    
    print("\nStep 4: Updating metadata...")
    update_metadata(main_mapping)
    print("  ✓ Metadata updated")
    
    print("\nStep 5: Cleaning working file...")
    remaining = clean_working_file(working)
    print(f"  ✓ {remaining} functions still unmapped")
    
    print("\nStep 6: Saving files...")
    save_files(working, main_mapping)
    print("  ✓ Files saved")
    
    print_summary(rule_stats, mapped, remaining)

if __name__ == "__main__":
    main()

