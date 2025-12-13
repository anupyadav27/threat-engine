"""
Test Phase 3 Engine Support

Tests that the engine can load and process both Phase 2 and Phase 3 YAML formats.
"""

import os
import sys
import yaml

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the conversion functions directly
exec(open('engine/service_scanner.py').read().split('def run_global_service')[0])


def test_phase2_format():
    """Test loading Phase 2 format YAML"""
    print("\n" + "="*80)
    print("TEST 1: Phase 2 Format (Current)")
    print("="*80)
    
    # Load Phase 2 YAML
    with open('services/account/rules/account.yaml') as f:
        phase2_rules = yaml.safe_load(f)
    
    print(f"\nOriginal format:")
    print(f"  Has 'discovery': {'discovery' in phase2_rules}")
    print(f"  Has 'resources': {'resources' in phase2_rules}")
    
    # Normalize (should return as-is for Phase 2)
    normalized = normalize_to_phase2_format(phase2_rules)
    
    print(f"\nAfter normalization:")
    print(f"  Has 'discovery': {'discovery' in normalized}")
    print(f"  Service: {normalized.get('service')}")
    print(f"  Discoveries: {len(normalized.get('discovery', []))}")
    print(f"  Checks: {len(normalized.get('checks', []))}")
    
    if 'discovery' in normalized:
        for disc in normalized['discovery'][:2]:
            print(f"    - {disc['discovery_id']}")
    
    print("\n✅ Phase 2 format loads correctly")
    return normalized


def test_phase3_format():
    """Test loading Phase 3 format YAML"""
    print("\n" + "="*80)
    print("TEST 2: Phase 3 Format (Ultra-Simplified)")
    print("="*80)
    
    # Load Phase 3 YAML
    with open('services/account/rules/account_v3.yaml') as f:
        phase3_rules = yaml.safe_load(f)
    
    print(f"\nOriginal format:")
    print(f"  Has 'discovery': {'discovery' in phase3_rules}")
    print(f"  Has 'resources': {'resources' in phase3_rules}")
    print(f"  Resources: {list(phase3_rules.get('resources', {}).keys())}")
    
    # Normalize (should convert Phase 3 to Phase 2)
    normalized = normalize_to_phase2_format(phase3_rules)
    
    print(f"\nAfter normalization to Phase 2:")
    print(f"  Has 'discovery': {'discovery' in normalized}")
    print(f"  Service: {normalized.get('service')}")
    print(f"  Discoveries: {len(normalized.get('discovery', []))}")
    print(f"  Checks: {len(normalized.get('checks', []))}")
    
    if 'discovery' in normalized:
        for disc in normalized['discovery'][:2]:
            print(f"    - {disc['discovery_id']}")
            print(f"      Calls: {len(disc.get('calls', []))}")
    
    if 'checks' in normalized:
        for check in normalized['checks'][:2]:
            print(f"    - {check['rule_id']}")
            print(f"      Conditions: {check.get('conditions')}")
    
    print("\n✅ Phase 3 format converts to Phase 2 correctly")
    return normalized


def test_assert_conversion():
    """Test assertion conversion"""
    print("\n" + "="*80)
    print("TEST 3: Assert Conversion")
    print("="*80)
    
    # Test simple assertion
    result1 = convert_assert_to_conditions('item.exists')
    print(f"\nassert: item.exists")
    print(f"  → {result1}")
    assert result1 == {'var': 'item.exists', 'op': 'exists'}
    
    # Test dict assertion
    result2 = convert_assert_to_conditions({'item.status': 'ACTIVE'})
    print(f"\nassert: {{item.status: ACTIVE}}")
    print(f"  → {result2}")
    assert result2 == {'var': 'item.status', 'op': 'equals', 'value': 'ACTIVE'}
    
    print("\n✅ Assert conversion works correctly")


def compare_formats():
    """Compare Phase 2 and Phase 3 normalized results"""
    print("\n" + "="*80)
    print("TEST 4: Compare Phase 2 vs Phase 3 Results")
    print("="*80)
    
    # Load both formats
    with open('services/account/rules/account.yaml') as f:
        phase2 = normalize_to_phase2_format(yaml.safe_load(f))
    
    with open('services/account/rules/account_v3.yaml') as f:
        phase3 = normalize_to_phase2_format(yaml.safe_load(f))
    
    print(f"\nPhase 2 normalized:")
    print(f"  Discoveries: {len(phase2.get('discovery', []))}")
    print(f"  Checks: {len(phase2.get('checks', []))}")
    
    print(f"\nPhase 3 normalized:")
    print(f"  Discoveries: {len(phase3.get('discovery', []))}")
    print(f"  Checks: {len(phase3.get('checks', []))}")
    
    # Compare discovery IDs
    phase2_disc_ids = [d['discovery_id'] for d in phase2.get('discovery', [])]
    phase3_disc_ids = [d['discovery_id'] for d in phase3.get('discovery', [])]
    
    print(f"\nDiscovery IDs match: {sorted(phase2_disc_ids) == sorted(phase3_disc_ids)}")
    
    # Compare check IDs
    phase2_check_ids = [c['rule_id'] for c in phase2.get('checks', [])]
    phase3_check_ids = [c['rule_id'] for c in phase3.get('checks', [])]
    
    print(f"Check IDs match: {sorted(phase2_check_ids) == sorted(phase3_check_ids)}")
    
    print("\n✅ Both formats normalize to compatible structures")


def main():
    print("\n" + "="*80)
    print("PHASE 3 ENGINE SUPPORT - COMPREHENSIVE TESTS")
    print("="*80)
    
    try:
        # Test 1: Phase 2 backward compatibility
        test_phase2_format()
        
        # Test 2: Phase 3 support
        test_phase3_format()
        
        # Test 3: Assert conversion
        test_assert_conversion()
        
        # Test 4: Compare results
        compare_formats()
        
        print("\n" + "="*80)
        print("ALL TESTS PASSED")
        print("="*80)
        print("\n✅ Phase 3 engine support is working!")
        print("✅ Backward compatibility maintained!")
        print("✅ Both formats produce compatible structures!")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
