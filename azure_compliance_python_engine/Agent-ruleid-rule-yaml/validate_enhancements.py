"""
Validation Script - Shows before/after comparison
"""

import json

def show_comparison():
    print("=" * 80)
    print("Azure SDK Catalog Enhancement - Before/After Comparison")
    print("=" * 80)
    print()
    
    # Load both files
    with open('azure_sdk_dependencies_with_python_names.json') as f:
        original = json.load(f)
    
    with open('azure_sdk_dependencies_enhanced.json') as f:
        enhanced = json.load(f)
    
    # Compare storage service - blob containers list operation
    print("SERVICE: Storage - Blob Containers - List Operation")
    print("=" * 80)
    print()
    
    # Original
    orig_op = original['storage']['operations_by_category']['blobcontainers']['independent'][0]
    
    print("BEFORE - Optional Params:")
    print("-" * 40)
    print(json.dumps(orig_op['optional_params'], indent=2))
    print()
    
    print("BEFORE - Item Fields (first 3):")
    print("-" * 40)
    print(json.dumps(orig_op['item_fields'][:3], indent=2))
    print()
    
    # Enhanced
    enh_op = enhanced['storage']['operations_by_category']['blobcontainers']['independent'][0]
    
    print("\n" + "=" * 80)
    print("AFTER - Optional Params:")
    print("-" * 40)
    params_sample = {k: v for k, v in list(enh_op['optional_params'].items())[:3]}
    print(json.dumps(params_sample, indent=2))
    print()
    
    print("AFTER - Item Fields (first 3):")
    print("-" * 40)
    fields_sample = {k: v for k, v in list(enh_op['item_fields'].items())[:3]}
    print(json.dumps(fields_sample, indent=2))
    print()
    
    # Show security field example
    print("\n" + "=" * 80)
    print("SECURITY FIELD EXAMPLE - 'public_access'")
    print("=" * 80)
    print()
    
    if 'public_access' in enh_op['item_fields']:
        print(json.dumps(enh_op['item_fields']['public_access'], indent=2))
    print()
    
    # Show boolean field example
    print("=" * 80)
    print("BOOLEAN FIELD EXAMPLE - 'deleted'")
    print("=" * 80)
    print()
    
    if 'deleted' in enh_op['item_fields']:
        print(json.dumps(enh_op['item_fields']['deleted'], indent=2))
    print()
    
    # Statistics
    print("=" * 80)
    print("STATISTICS")
    print("=" * 80)
    
    total_fields_orig = 0
    total_fields_enh = 0
    security_fields = 0
    high_impact_fields = 0
    
    for service_name, service_data in enhanced.items():
        for category_name, category_data in service_data.get('operations_by_category', {}).items():
            for op in category_data.get('independent', []):
                if isinstance(op.get('item_fields'), dict):
                    total_fields_enh += len(op['item_fields'])
                    for field_name, field_meta in op['item_fields'].items():
                        if field_meta.get('compliance_category') == 'security':
                            security_fields += 1
                        if field_meta.get('security_impact') == 'high':
                            high_impact_fields += 1
            
            for op in category_data.get('dependent', []):
                if isinstance(op.get('item_fields'), dict):
                    total_fields_enh += len(op['item_fields'])
    
    for service_name, service_data in original.items():
        for category_name, category_data in service_data.get('operations_by_category', {}).items():
            for op in category_data.get('independent', []):
                if isinstance(op.get('item_fields'), list):
                    total_fields_orig += len(op['item_fields'])
            for op in category_data.get('dependent', []):
                if isinstance(op.get('item_fields'), list):
                    total_fields_orig += len(op['item_fields'])
    
    print(f"Total fields in original:        {total_fields_orig}")
    print(f"Total fields in enhanced:        {total_fields_enh}")
    print(f"Security-related fields:         {security_fields}")
    print(f"High security impact fields:     {high_impact_fields}")
    print()
    
    # Compliance categories breakdown
    category_counts = {}
    for service_name, service_data in enhanced.items():
        for category_name, category_data in service_data.get('operations_by_category', {}).items():
            for op in category_data.get('independent', []) + category_data.get('dependent', []):
                if isinstance(op.get('item_fields'), dict):
                    for field_name, field_meta in op['item_fields'].items():
                        cat = field_meta.get('compliance_category', 'unknown')
                        category_counts[cat] = category_counts.get(cat, 0) + 1
    
    print("Compliance Categories Distribution:")
    print("-" * 40)
    for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {cat:20s}: {count:5d}")
    
    print()
    print("=" * 80)
    print("✅ Enhancement validation complete!")
    print("=" * 80)


if __name__ == '__main__':
    show_comparison()

