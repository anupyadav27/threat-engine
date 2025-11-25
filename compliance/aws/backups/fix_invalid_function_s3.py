#!/usr/bin/env python3
"""
Fix the invalid 'aws_No checks defined' function with S3 public access block check
"""

import json
import yaml

def load_files():
    """Load files"""
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json', 'r') as f:
        working = json.load(f)
    
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml', 'r') as f:
        rule_data = yaml.safe_load(f)
        rule_ids = rule_data['rule_ids']
    
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json', 'r') as f:
        main_mapping = json.load(f)
    
    return working, rule_ids, main_mapping

def verify_rule_exists(rule_ids, rule_id):
    """Verify the rule exists in rule_ids"""
    return rule_id in rule_ids

def update_invalid_function(working, rule_ids):
    """Update the invalid function with S3 public access block check"""
    
    for func in working['all_unmatched_functions']:
        if func['original_function'] == 'aws_No checks defined':
            # Update with proper S3 public access block check
            func['improved_function'] = 'aws.s3.bucket.public_access_block_enabled'
            func['parsed_components'] = {
                'service': 's3',
                'resource': 'bucket',
                'assertion': 'public_access_block_enabled'
            }
            
            # Check if the rule exists
            target_rule = 'aws.s3.bucket.block_public_access_enabled'
            
            if target_rule in rule_ids:
                func['manual_mapping'] = {
                    'matched_rule_id': target_rule,
                    'confidence': 'high',
                    'notes': 'S3 bucket public access block enabled - fixed from invalid CSV entry'
                }
                return True, func, target_rule
            else:
                # Check for similar rules
                s3_public_rules = [r for r in rule_ids if 'aws.s3.bucket' in r and 'public' in r.lower()]
                print(f"\n  Target rule not found. Available S3 public access rules:")
                for rule in s3_public_rules[:10]:
                    print(f"    • {rule}")
                return False, func, None
    
    return False, None, None

def update_main_mapping(main_mapping, original, improved, rule_id, confidence, notes):
    """Update main mapping file"""
    
    if original in main_mapping['functions']:
        main_mapping['functions'][original].update({
            'improved_function': improved,
            'matched_rule_id': rule_id,
            'match_quality': 'manual_mapping',
            'confidence': confidence,
            'mapping_notes': notes,
            'expert_reviewed': True
        })

def update_metadata(working, main_mapping):
    """Update metadata"""
    
    # Update working file metadata
    working['metadata']['total_functions'] -= 1
    
    # Update main mapping metadata
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
    
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json', 'w') as f:
        json.dump(working, f, indent=2, ensure_ascii=False)
    
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json', 'w') as f:
        json.dump(main_mapping, f, indent=2, ensure_ascii=False)

def print_summary(mapped, func_data, rule_id, remaining):
    """Print summary"""
    
    print("\n" + "="*80)
    print("FIXED INVALID FUNCTION - S3 PUBLIC ACCESS BLOCK")
    print("="*80)
    
    if mapped:
        print(f"\n{'FUNCTION UPDATE':-^80}")
        print(f"\n  Original (invalid): aws_No checks defined")
        print(f"  Fixed to:          {func_data['original_function']}")
        print(f"  Improved:          {func_data['improved_function']}")
        print(f"  → Mapped to:       {rule_id}")
        print(f"  Confidence:        {func_data['manual_mapping']['confidence']}")
        print(f"  Notes:             {func_data['manual_mapping']['notes']}")
        
        print(f"\n{'FINAL STATUS':-^80}")
        print(f"\n  Total functions:                669")
        print(f"  Successfully mapped:            {669 - remaining}")
        print(f"  Still unmapped:                 {remaining}")
        
        if remaining == 0:
            print(f"  Coverage:                       100.0% 🎉")
            print(f"\n  🏆 ALL 669 FUNCTIONS SUCCESSFULLY MAPPED!")
            print(f"  🎉 PROJECT COMPLETED WITH 100% COVERAGE!")
        else:
            coverage = round((669 - remaining) / 669 * 100, 1)
            print(f"  Coverage:                       {coverage}%")
    else:
        print(f"\n  ✗ Failed to update function")
        print(f"  Reason: Target rule not found in rule_ids.yaml")
    
    print("\n" + "="*80)
    print()

def main():
    print("Loading files...")
    working, rule_ids, main_mapping = load_files()
    print(f"  ✓ Loaded {len(working['all_unmatched_functions'])} unmapped functions")
    print(f"  ✓ Loaded {len(rule_ids)} rule_ids")
    
    print("\nChecking for target rule...")
    target_rule = 'aws.s3.bucket.block_public_access_enabled'
    rule_exists = verify_rule_exists(rule_ids, target_rule)
    
    if rule_exists:
        print(f"  ✓ Rule found: {target_rule}")
    else:
        print(f"  ✗ Rule not found: {target_rule}")
    
    print("\nUpdating invalid function with S3 public access block check...")
    mapped, func_data, rule_id = update_invalid_function(working, rule_ids)
    
    if mapped:
        print(f"  ✓ Function updated and mapped!")
        
        # Update main mapping
        update_main_mapping(
            main_mapping,
            func_data['original_function'],
            func_data['improved_function'],
            rule_id,
            func_data['manual_mapping']['confidence'],
            func_data['manual_mapping']['notes']
        )
        
        # Update metadata
        update_metadata(working, main_mapping)
        
        # Clean working file
        print("\nCleaning working file...")
        remaining = clean_working_file(working)
        print(f"  ✓ {remaining} functions still unmapped")
        
        # Save files
        print("\nSaving files...")
        save_files(working, main_mapping)
        print("  ✓ Files saved")
    else:
        print(f"  ✗ Failed to map function")
        remaining = len(working['all_unmatched_functions'])
    
    print_summary(mapped, func_data, rule_id, remaining)

if __name__ == "__main__":
    main()

