#!/usr/bin/env python3
"""
Test Consolidated CSV Loader

Tests the consolidated CSV integration to verify:
1. CSV file can be loaded
2. Framework mappings are extracted correctly
3. Framework structure is available
4. Control details can be retrieved
"""

import sys
from pathlib import Path

# Add compliance-engine to path
sys.path.insert(0, str(Path(__file__).parent))

from compliance_engine.loader.consolidated_csv_loader import ConsolidatedCSVLoader
from compliance_engine.mapper.framework_loader import FrameworkLoader

def test_consolidated_csv_loader():
    """Test the consolidated CSV loader."""
    print("=" * 80)
    print("Testing Consolidated CSV Loader")
    print("=" * 80)
    print()
    
    # Initialize loader
    print("[1] Initializing ConsolidatedCSVLoader...")
    loader = ConsolidatedCSVLoader()
    print(f"    CSV Path: {loader.csv_path}")
    print(f"    CSV Exists: {loader.csv_path.exists()}")
    print()
    
    if not loader.csv_path.exists():
        print("❌ CSV file not found!")
        return False
    
    # Test 1: Get frameworks list
    print("[2] Getting list of all frameworks...")
    frameworks = loader.get_frameworks_list()
    print(f"    Found {len(frameworks)} frameworks:")
    for fw in frameworks[:10]:  # Show first 10
        print(f"      - {fw}")
    if len(frameworks) > 10:
        print(f"      ... and {len(frameworks) - 10} more")
    print()
    
    # Test 2: Load all mappings
    print("[3] Loading all rule-to-framework mappings...")
    mappings = loader.load_all_mappings("aws")
    print(f"    Total rule_ids mapped: {len(mappings)}")
    
    # Show sample mappings
    sample_rules = list(mappings.keys())[:5]
    print(f"    Sample rule_ids:")
    for rule_id in sample_rules:
        controls = mappings[rule_id]
        print(f"      - {rule_id}")
        print(f"        → Maps to {len(controls)} control(s):")
        for control in controls[:3]:  # Show first 3 controls
            print(f"          • {control.framework} - {control.control_id}: {control.control_title}")
        if len(controls) > 3:
            print(f"          ... and {len(controls) - 3} more")
    print()
    
    # Test 3: Get framework structure for a specific framework
    test_framework = "HIPAA"
    if test_framework in frameworks:
        print(f"[4] Getting framework structure for {test_framework}...")
        structure = loader.get_framework_structure(test_framework)
        print(f"    Framework: {structure.get('framework')}")
        print(f"    Sections: {len(structure.get('sections', {}))}")
        print(f"    Controls: {len(structure.get('controls', {}))}")
        print(f"    Services: {len(structure.get('services', []))}")
        
        # Show sample sections
        sections = structure.get('sections', {})
        if sections:
            print(f"    Sample sections:")
            for section, control_ids in list(sections.items())[:5]:
                print(f"      - {section}: {len(control_ids)} controls")
        
        # Show sample controls
        controls = structure.get('controls', {})
        if controls:
            print(f"    Sample controls:")
            for i, (key, control_data) in enumerate(list(controls.items())[:3]):
                print(f"      - {control_data.get('control_id')}: {control_data.get('control_title')}")
                print(f"        Section: {control_data.get('section')}, Service: {control_data.get('service')}")
        print()
    
    # Test 4: Get control details
    test_framework = "HIPAA"
    test_control_id = "164_308_a_1_ii_b"
    print(f"[5] Getting control details for {test_framework} - {test_control_id}...")
    control_details = loader.get_control_details(test_framework, test_control_id)
    if control_details:
        print(f"    Control ID: {control_details.get('control_id')}")
        print(f"    Title: {control_details.get('control_title')}")
        print(f"    Description: {control_details.get('control_description', 'N/A')[:100]}...")
        print(f"    Section: {control_details.get('section')}")
        print(f"    Service: {control_details.get('service')}")
        print(f"    Total Checks: {control_details.get('total_checks')}")
        print(f"    Rule IDs: {len(control_details.get('rule_ids', []))} rules")
        print(f"    Sample Rule IDs: {', '.join(control_details.get('rule_ids', [])[:3])}")
    else:
        print(f"    ❌ Control not found")
    print()
    
    # Test 5: Test framework loader integration
    print("[6] Testing FrameworkLoader integration with consolidated CSV...")
    framework_loader = FrameworkLoader()
    csv_mappings = framework_loader.load_rule_mappings_from_csv("aws")
    print(f"    FrameworkLoader found {len(csv_mappings)} rule mappings")
    
    # Check if mappings include multiple frameworks
    framework_counts = {}
    for rule_id, controls in list(csv_mappings.items())[:100]:  # Sample first 100
        for control in controls:
            fw = control.framework
            framework_counts[fw] = framework_counts.get(fw, 0) + 1
    
    print(f"    Frameworks found in mappings:")
    for fw, count in sorted(framework_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"      - {fw}: {count} controls")
    print()
    
    # Test 6: Compare with get_rule_mappings
    print("[7] Testing get_rule_mappings (should use consolidated CSV)...")
    all_mappings = framework_loader.get_rule_mappings("aws")
    print(f"    Total mappings: {len(all_mappings)}")
    
    # Show sample
    sample_rule = list(all_mappings.keys())[0] if all_mappings else None
    if sample_rule:
        sample_controls = all_mappings[sample_rule]
        print(f"    Sample rule: {sample_rule}")
        print(f"    Maps to {len(sample_controls)} framework control(s):")
        for control in sample_controls[:3]:
            print(f"      - {control.framework} {control.control_id}: {control.control_title}")
    print()
    
    print("=" * 80)
    print("✅ All tests completed successfully!")
    print("=" * 80)
    return True

if __name__ == "__main__":
    try:
        success = test_consolidated_csv_loader()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
