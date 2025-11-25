#!/usr/bin/env python3
"""
Merge manually mapped functions back into the main mapping file
"""

import json

def load_files():
    """Load both the main mapping and working file"""
    print("Loading files...\n")
    
    # Load main mapping
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'r') as f:
        main_data = json.load(f)
    
    print(f"  ✓ Loaded main mapping")
    print(f"    - Total functions: {main_data['metadata']['total_functions']}")
    print(f"    - Previously matched: {main_data['metadata']['matched_functions']}")
    print(f"    - Previously unmatched: {main_data['metadata']['unmatched_functions']}")
    
    # Load working file with manual mappings
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'r') as f:
        working_data = json.load(f)
    
    print(f"\n  ✓ Loaded working file")
    total_unmatched = working_data['metadata'].get('total_unmatched') or working_data['metadata'].get('remaining_unmatched', 0)
    print(f"    - Total unmatched: {total_unmatched}")
    
    return main_data, working_data

def extract_manual_mappings(working_data):
    """Extract all manual mappings from working file"""
    
    manual_mappings = {}
    
    for func in working_data.get('all_unmatched_functions', []):
        original_func = func['original_function']
        manual_mapping = func.get('manual_mapping', {})
        
        matched_rule_id = manual_mapping.get('matched_rule_id')
        
        # Only process if a rule_id was manually added
        if matched_rule_id:
            manual_mappings[original_func] = {
                'matched_rule_id': matched_rule_id,
                'confidence': manual_mapping.get('confidence', 'manual'),
                'notes': manual_mapping.get('notes', ''),
                'match_quality': 'manual_mapping'
            }
    
    return manual_mappings

def merge_mappings(main_data, manual_mappings):
    """Merge manual mappings into main data"""
    
    functions = main_data.get('functions', {})
    stats = {
        'newly_mapped': 0,
        'already_mapped': 0,
        'not_found': 0
    }
    
    for original_func, mapping_info in manual_mappings.items():
        if original_func in functions:
            current_quality = functions[original_func].get('match_quality')
            
            if current_quality == 'unmatched':
                # Update with manual mapping
                functions[original_func]['matched_rule_id'] = mapping_info['matched_rule_id']
                functions[original_func]['match_quality'] = 'manual_mapping'
                functions[original_func]['confidence'] = mapping_info['confidence']
                functions[original_func]['expert_reviewed'] = True
                
                if mapping_info['notes']:
                    functions[original_func]['mapping_notes'] = mapping_info['notes']
                
                stats['newly_mapped'] += 1
            else:
                stats['already_mapped'] += 1
        else:
            stats['not_found'] += 1
    
    return functions, stats

def update_metadata(main_data, functions, stats):
    """Update metadata with new counts"""
    
    # Count match qualities
    match_quality_counts = {}
    matched_count = 0
    
    for func_data in functions.values():
        quality = func_data.get('match_quality', 'unknown')
        match_quality_counts[quality] = match_quality_counts.get(quality, 0) + 1
        
        if quality != 'unmatched':
            matched_count += 1
    
    # Update metadata
    main_data['metadata']['matched_functions'] = matched_count
    main_data['metadata']['unmatched_functions'] = len(functions) - matched_count
    main_data['metadata']['match_rate'] = round(matched_count / len(functions) * 100, 1) if functions else 0
    main_data['metadata']['match_quality_breakdown'] = match_quality_counts
    main_data['metadata']['newly_mapped_from_manual'] = stats['newly_mapped']
    
    return main_data

def save_updated_mapping(main_data):
    """Save the updated mapping"""
    
    output_file = "/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json"
    
    with open(output_file, 'w') as f:
        json.dump(main_data, f, indent=2, ensure_ascii=False)
    
    return output_file

def print_merge_summary(stats, main_data):
    """Print summary of merge operation"""
    
    metadata = main_data['metadata']
    
    print("\n" + "="*70)
    print("MERGE SUMMARY")
    print("="*70)
    print(f"\nManual mapping results:")
    print(f"  ├─ Newly mapped:              {stats['newly_mapped']}")
    print(f"  ├─ Already mapped (skipped):  {stats['already_mapped']}")
    print(f"  └─ Not found (error):         {stats['not_found']}")
    
    print(f"\nUpdated totals:")
    print(f"  ├─ Total functions:           {metadata['total_functions']}")
    print(f"  ├─ Matched:                   {metadata['matched_functions']} ({metadata['match_rate']}%)")
    print(f"  └─ Still unmatched:           {metadata['unmatched_functions']}")
    
    print(f"\nMatch quality breakdown:")
    for quality, count in sorted(metadata.get('match_quality_breakdown', {}).items()):
        print(f"  ├─ {quality:25} : {count}")

def main():
    # Load files
    main_data, working_data = load_files()
    
    # Extract manual mappings
    print("\nExtracting manual mappings...")
    manual_mappings = extract_manual_mappings(working_data)
    print(f"  ✓ Found {len(manual_mappings)} manual mappings")
    
    if len(manual_mappings) == 0:
        print("\n⚠ No manual mappings found in working file.")
        print("  Please update the 'manual_mapping' section in unmatched_functions_working.json")
        print("  before running this script.")
        return
    
    # Merge mappings
    print("\nMerging manual mappings into main file...")
    functions, stats = merge_mappings(main_data, manual_mappings)
    print(f"  ✓ Merged {stats['newly_mapped']} new mappings")
    
    # Update metadata
    main_data['functions'] = functions
    main_data = update_metadata(main_data, functions, stats)
    
    # Save updated mapping
    print("\nSaving updated mapping...")
    output_file = save_updated_mapping(main_data)
    print(f"  ✓ Saved to: {output_file}")
    
    # Print summary
    print_merge_summary(stats, main_data)
    
    print("\n" + "="*70)
    print()

if __name__ == "__main__":
    main()

