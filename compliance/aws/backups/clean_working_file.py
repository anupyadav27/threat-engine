#!/usr/bin/env python3
"""
Clean up working file to only contain truly unmapped functions
"""

import json

def load_files():
    """Load both files"""
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json", 'r') as f:
        main_mapping = json.load(f)
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'r') as f:
        working_file = json.load(f)
    
    return main_mapping, working_file

def clean_working_file(main_mapping, working_file):
    """Remove successfully mapped functions from working file"""
    
    # Extract functions from nested structure if needed
    if 'functions' in main_mapping:
        functions_dict = main_mapping['functions']
    else:
        functions_dict = main_mapping
    
    still_unmapped = []
    
    for func in working_file['all_unmatched_functions']:
        original = func['original_function']
        
        # Check if it's mapped in main file
        if original in functions_dict:
            mapped_data = functions_dict[original]
            if mapped_data.get('matched_rule_id'):
                # Successfully mapped, skip it
                continue
        
        # Still unmapped, keep it
        still_unmapped.append(func)
    
    return still_unmapped

def save_cleaned_file(still_unmapped):
    """Save cleaned working file"""
    
    # Organize by service
    by_service = {}
    for func in still_unmapped:
        service = func['parsed_components']['service']
        if service not in by_service:
            by_service[service] = []
        by_service[service].append(func)
    
    cleaned_data = {
        "metadata": {
            "total_functions": len(still_unmapped),
            "note": "These functions still need manual expert mapping",
            "next_step": "Review each function and update manual_mapping section"
        },
        "unmatched_by_service": by_service,
        "all_unmatched_functions": still_unmapped
    }
    
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/unmatched_functions_working.json", 'w') as f:
        json.dump(cleaned_data, f, indent=2, ensure_ascii=False)
    
    return cleaned_data

def print_summary(original_count, final_count):
    """Print summary"""
    print("\n" + "="*70)
    print("CLEANED WORKING FILE")
    print("="*70)
    
    print(f"\nOriginal unmatched:             {original_count}")
    print(f"Successfully mapped:            {original_count - final_count}")
    print(f"Still unmapped:                 {final_count}")
    
    if original_count > 0:
        print(f"Progress:                       {(original_count - final_count)/original_count*100:.1f}% mapped")
    
    print(f"\n✓ Updated: unmatched_functions_working.json")
    print("="*70)
    print()

def main():
    print("Loading files...")
    main_mapping, working_file = load_files()
    
    original_count = len(working_file['all_unmatched_functions'])
    
    print(f"  ✓ Main mapping: {len(main_mapping)} functions")
    print(f"  ✓ Working file: {original_count} functions")
    
    print("\nCleaning working file...")
    still_unmapped = clean_working_file(main_mapping, working_file)
    
    print(f"  ✓ Remaining unmapped: {len(still_unmapped)}")
    
    print("\nSaving cleaned file...")
    cleaned_data = save_cleaned_file(still_unmapped)
    print("  ✓ Saved")
    
    print_summary(original_count, len(still_unmapped))

if __name__ == "__main__":
    main()

