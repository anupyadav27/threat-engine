#!/usr/bin/env python3
"""
Test Script for Unified run_service() Function
Phase 4.5: Verify database-driven service execution works correctly
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "engine_discoveries" / "engine_discoveries_aws"))
sys.path.insert(0, str(project_root / "engine_discoveries"))
sys.path.insert(0, str(project_root))

print("=" * 80)
print("Phase 4.5: Testing Unified run_service() Implementation")
print("=" * 80)
print()

# Test 1: Verify imports work
print("Test 1: Verify imports...")
try:
    from engine.service_scanner import run_service, run_global_service, run_regional_service
    print("✅ Successfully imported run_service, run_global_service, run_regional_service")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

# Test 2: Verify database utilities import
print("\nTest 2: Verify database utilities...")
try:
    from utils.config_loader import DiscoveryConfigLoader
    from utils.filter_engine import FilterEngine
    from utils.pagination_engine import PaginationEngine
    print("✅ Successfully imported database utilities (config_loader, filter_engine, pagination_engine)")
except ImportError as e:
    print(f"❌ Database utilities import failed: {e}")
    sys.exit(1)

# Test 3: Verify database connection and scope detection
print("\nTest 3: Database connection and scope detection...")
try:
    config_loader = DiscoveryConfigLoader(provider='aws')

    # Test global service (IAM)
    iam_scope = config_loader.get_scope('iam')
    iam_client = config_loader.get_boto3_client_name('iam')
    print(f"  IAM: scope='{iam_scope}', boto3_client_name='{iam_client}'")

    # Test regional service (EC2)
    ec2_scope = config_loader.get_scope('ec2')
    ec2_client = config_loader.get_boto3_client_name('ec2')
    print(f"  EC2: scope='{ec2_scope}', boto3_client_name='{ec2_client}'")

    # Verify expected values
    assert iam_scope == 'global', f"Expected IAM scope='global', got '{iam_scope}'"
    assert iam_client == 'iam', f"Expected IAM client='iam', got '{iam_client}'"
    assert ec2_scope == 'regional', f"Expected EC2 scope='regional', got '{ec2_scope}'"
    assert ec2_client == 'ec2', f"Expected EC2 client='ec2', got '{ec2_client}'"

    print("✅ Database scope detection working correctly")
except Exception as e:
    print(f"❌ Database test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Verify run_service() signature
print("\nTest 4: Verify run_service() function signature...")
try:
    import inspect
    sig = inspect.signature(run_service)
    params = list(sig.parameters.keys())

    expected_params = ['service_name', 'region', 'session_override', 'service_rules_override', 'skip_checks']

    print(f"  Parameters: {params}")

    for param in expected_params:
        assert param in params, f"Missing parameter: {param}"

    print("✅ run_service() signature correct")
except Exception as e:
    print(f"❌ Signature test failed: {e}")
    sys.exit(1)

# Test 5: Verify wrapper functions still exist (backward compatibility)
print("\nTest 5: Verify backward compatibility wrappers...")
try:
    import inspect

    # Check run_global_service
    global_sig = inspect.signature(run_global_service)
    global_params = list(global_sig.parameters.keys())
    print(f"  run_global_service parameters: {global_params}")
    assert 'service_name' in global_params, "run_global_service missing service_name"

    # Check run_regional_service
    regional_sig = inspect.signature(run_regional_service)
    regional_params = list(regional_sig.parameters.keys())
    print(f"  run_regional_service parameters: {regional_params}")
    assert 'service_name' in regional_params, "run_regional_service missing service_name"
    assert 'region' in regional_params, "run_regional_service missing region"

    print("✅ Backward compatibility wrappers exist with correct signatures")
except Exception as e:
    print(f"❌ Wrapper test failed: {e}")
    sys.exit(1)

# Test 6: Code metrics verification
print("\nTest 6: Code metrics verification...")
try:
    scanner_file = project_root / "engine_discoveries" / "engine_discoveries_aws" / "engine" / "service_scanner.py"

    with open(scanner_file, 'r') as f:
        lines = f.readlines()

    total_lines = len(lines)

    # Find function definitions
    run_service_line = None
    run_global_line = None
    run_regional_line = None

    for i, line in enumerate(lines):
        if line.startswith('def run_service('):
            run_service_line = i + 1
        elif line.startswith('def run_global_service('):
            run_global_line = i + 1
        elif line.startswith('def run_regional_service('):
            run_regional_line = i + 1

    print(f"  Total lines: {total_lines}")
    print(f"  run_service() at line {run_service_line}")
    print(f"  run_global_service() at line {run_global_line}")
    print(f"  run_regional_service() at line {run_regional_line}")

    # Verify file is smaller than original (4343 lines)
    assert total_lines < 4343, f"File should be smaller than 4343 lines (currently {total_lines})"

    # Verify expected reduction (~3284 lines)
    expected_size = 3284
    tolerance = 100  # Allow ±100 lines variation
    assert abs(total_lines - expected_size) < tolerance, \
        f"File size {total_lines} not close to expected {expected_size} (±{tolerance})"

    print(f"✅ Code metrics correct: {total_lines} lines (reduced from 4343, saved {4343 - total_lines} lines)")
except Exception as e:
    print(f"❌ Metrics test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 7: Verify discovery_engine.py uses run_service
print("\nTest 7: Verify discovery_engine.py integration...")
try:
    engine_file = project_root / "engine_discoveries" / "engine_discoveries_aws" / "engine" / "discovery_engine.py"

    with open(engine_file, 'r') as f:
        content = f.read()

    # Check import
    assert 'from engine.service_scanner import run_service' in content, \
        "discovery_engine.py should import run_service"

    # Check usage (should appear at least twice: global + regional)
    run_service_calls = content.count('run_service(')
    print(f"  Found {run_service_calls} calls to run_service()")
    assert run_service_calls >= 2, f"Expected at least 2 calls to run_service(), found {run_service_calls}"

    print("✅ discovery_engine.py correctly uses run_service()")
except Exception as e:
    print(f"❌ Integration test failed: {e}")
    sys.exit(1)

# Summary
print("\n" + "=" * 80)
print("Phase 4.5 Test Summary: ALL TESTS PASSED ✅")
print("=" * 80)
print()
print("Results:")
print("  ✅ Imports working")
print("  ✅ Database utilities working")
print("  ✅ Database scope detection correct (IAM=global, EC2=regional)")
print("  ✅ run_service() signature correct")
print("  ✅ Backward compatibility wrappers present")
print(f"  ✅ Code reduction: {4343 - total_lines} lines eliminated")
print("  ✅ discovery_engine.py integration complete")
print()
print("Ready for live discovery testing!")
print()
