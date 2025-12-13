"""
Simple Phase 3 Test - Tests conversion functions directly
"""

import yaml


def convert_assert_to_conditions(assertion):
    """Convert Phase 3 assert to Phase 2 conditions"""
    if isinstance(assertion, str):
        return {'var': assertion, 'op': 'exists'}
    elif isinstance(assertion, dict):
        for var, value in assertion.items():
            return {'var': var, 'op': 'equals', 'value': value}
    return assertion


def convert_phase3_to_phase2(rules):
    """Convert Phase 3 format to Phase 2 format"""
    service_name = rules.get('service', 'unknown')
    
    normalized = {
        'version': rules.get('version', '1.0'),
        'provider': rules.get('provider', 'aws'),
        'service': service_name
    }
    
    # Convert resources to discovery
    if 'resources' in rules:
        discoveries = []
        
        for resource_name, resource_def in rules['resources'].items():
            discovery_id = f'aws.{service_name}.{resource_name}'
            
            calls = []
            emit = None
            
            if isinstance(resource_def, dict):
                if 'emit' in resource_def:
                    emit = resource_def['emit']
                
                if 'actions' in resource_def:
                    for action_item in resource_def['actions']:
                        if isinstance(action_item, dict):
                            for action_name, params in action_item.items():
                                call = {'action': action_name}
                                if params and isinstance(params, dict):
                                    call['params'] = params
                                calls.append(call)
                        elif isinstance(action_item, str):
                            calls.append({'action': action_item})
                else:
                    for key, value in resource_def.items():
                        if key != 'emit':
                            call = {'action': key}
                            if isinstance(value, dict):
                                if 'params' in value:
                                    call['params'] = value['params']
                                elif value:
                                    call['params'] = value
                                if 'emit' in value:
                                    emit = value['emit']
                            calls.append(call)
            
            discovery = {
                'discovery_id': discovery_id,
                'calls': calls
            }
            
            if emit:
                discovery['emit'] = emit
            
            discoveries.append(discovery)
        
        normalized['discovery'] = discoveries
    elif 'discovery' in rules:
        normalized['discovery'] = rules['discovery']
    
    # Convert checks
    if 'checks' in rules:
        checks_list = []
        
        if isinstance(rules['checks'], dict):
            for check_name, check_def in rules['checks'].items():
                rule_id = f'aws.{service_name}.{check_name}'
                
                check_entry = {'rule_id': rule_id}
                
                if 'resource' in check_def:
                    resource_ref = check_def['resource']
                    check_entry['for_each'] = f'aws.{service_name}.{resource_ref}'
                
                if 'assert' in check_def:
                    check_entry['conditions'] = convert_assert_to_conditions(check_def['assert'])
                elif 'conditions' in check_def:
                    check_entry['conditions'] = check_def['conditions']
                
                for key in ['params', 'assertion_id']:
                    if key in check_def:
                        check_entry[key] = check_def[key]
                
                checks_list.append(check_entry)
        elif isinstance(rules['checks'], list):
            checks_list = rules['checks']
        
        normalized['checks'] = checks_list
    
    return normalized


def normalize_to_phase2_format(rules):
    """Detect format and normalize"""
    if not rules:
        return rules
    
    if 'resources' in rules:
        print("  Detected: Phase 3 format")
        return convert_phase3_to_phase2(rules)
    else:
        print("  Detected: Phase 2 format")
        return rules


def main():
    print("="*80)
    print("PHASE 3 ENGINE SUPPORT TESTS")
    print("="*80)
    
    # Test 1: Phase 2 format
    print("\n--- Test 1: Phase 2 Backward Compatibility ---")
    with open('services/account/rules/account.yaml') as f:
        phase2_yaml = yaml.safe_load(f)
    
    phase2_normalized = normalize_to_phase2_format(phase2_yaml)
    
    print(f"  Service: {phase2_normalized['service']}")
    print(f"  Discoveries: {len(phase2_normalized.get('discovery', []))}")
    print(f"  Checks: {len(phase2_normalized.get('checks', []))}")
    
    assert 'discovery' in phase2_normalized
    assert len(phase2_normalized['discovery']) == 2
    assert len(phase2_normalized['checks']) == 5
    print("  ✅ PASS")
    
    # Test 2: Phase 3 format
    print("\n--- Test 2: Phase 3 Format Support ---")
    with open('services/account/rules/account_v3.yaml') as f:
        phase3_yaml = yaml.safe_load(f)
    
    phase3_normalized = normalize_to_phase2_format(phase3_yaml)
    
    print(f"  Service: {phase3_normalized['service']}")
    print(f"  Discoveries: {len(phase3_normalized.get('discovery', []))}")
    print(f"  Checks: {len(phase3_normalized.get('checks', []))}")
    
    assert 'discovery' in phase3_normalized
    assert len(phase3_normalized['discovery']) == 2
    assert len(phase3_normalized['checks']) == 5
    print("  ✅ PASS")
    
    # Test 3: Assert conversion
    print("\n--- Test 3: Assert to Conditions Conversion ---")
    
    test_cases = [
        ('item.exists', {'var': 'item.exists', 'op': 'exists'}),
        ({'item.status': 'ACTIVE'}, {'var': 'item.status', 'op': 'equals', 'value': 'ACTIVE'})
    ]
    
    for assertion, expected in test_cases:
        result = convert_assert_to_conditions(assertion)
        print(f"  {assertion} → {result}")
        assert result == expected
    
    print("  ✅ PASS")
    
    # Test 4: Discovery IDs match
    print("\n--- Test 4: Discovery IDs Match ---")
    
    phase2_disc_ids = sorted([d['discovery_id'] for d in phase2_normalized['discovery']])
    phase3_disc_ids = sorted([d['discovery_id'] for d in phase3_normalized['discovery']])
    
    print(f"  Phase 2 IDs: {phase2_disc_ids}")
    print(f"  Phase 3 IDs: {phase3_disc_ids}")
    print(f"  Match: {phase2_disc_ids == phase3_disc_ids}")
    
    assert phase2_disc_ids == phase3_disc_ids
    print("  ✅ PASS")
    
    # Test 5: Check IDs match
    print("\n--- Test 5: Check IDs Match ---")
    
    phase2_check_ids = sorted([c['rule_id'] for c in phase2_normalized['checks']])
    phase3_check_ids = sorted([c['rule_id'] for c in phase3_normalized['checks']])
    
    print(f"  Phase 2 checks: {len(phase2_check_ids)}")
    print(f"  Phase 3 checks: {len(phase3_check_ids)}")
    print(f"  Match: {phase2_check_ids == phase3_check_ids}")
    
    assert phase2_check_ids == phase3_check_ids
    print("  ✅ PASS")
    
    # Summary
    print("\n" + "="*80)
    print("ALL TESTS PASSED!")
    print("="*80)
    print("\n✅ Phase 2 backward compatibility: WORKING")
    print("✅ Phase 3 format support: WORKING")
    print("✅ Assert conversion: WORKING")
    print("✅ Discovery IDs match: CONFIRMED")
    print("✅ Check IDs match: CONFIRMED")
    print("\n🎉 Phase 3 engine support fully functional!")
    
    return 0


if __name__ == '__main__':
    try:
        exit(main())
    except AssertionError as e:
        print(f"\n❌ Assertion failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
