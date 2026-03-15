#!/usr/bin/env python3
"""
Test Filter Engine - Database-Driven Filters

This script verifies that the FilterEngine correctly loads and applies
filters from the database.

Date: 2026-02-20
"""

import os
import sys

# Add paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'engine_discoveries'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from utils.config_loader import DiscoveryConfigLoader
from utils.filter_engine import FilterEngine


def test_api_filters():
    """Test API-level filters"""
    print("\n" + "=" * 80)
    print("Testing API-Level Filters")
    print("=" * 80)

    config_loader = DiscoveryConfigLoader(provider='aws')
    filter_engine = FilterEngine(config_loader)

    # Test 1: EC2 describe_snapshots - should add OwnerIds=['self']
    print("\n1. Testing aws.ec2.describe_snapshots")
    params = {}
    params = filter_engine.apply_api_filters('aws.ec2.describe_snapshots', params, 'ec2')
    expected = {'OwnerIds': ['self']}
    assert params == expected, f"Expected {expected}, got {params}"
    print(f"   ✅ PASS: {params}")

    # Test 2: IAM list_policies - should add Scope='Local'
    print("\n2. Testing aws.iam.list_policies")
    params = {}
    params = filter_engine.apply_api_filters('aws.iam.list_policies', params, 'iam')
    expected = {'Scope': 'Local'}
    assert params == expected, f"Expected {expected}, got {params}"
    print(f"   ✅ PASS: {params}")

    # Test 3: RDS describe_db_cluster_snapshots - should add IncludeShared/IncludePublic
    print("\n3. Testing aws.rds.describe_db_cluster_snapshots")
    params = {}
    params = filter_engine.apply_api_filters('aws.rds.describe_db_cluster_snapshots', params, 'rds')
    assert params.get('IncludeShared') == False, f"Expected IncludeShared=False, got {params}"
    assert params.get('IncludePublic') == False, f"Expected IncludePublic=False, got {params}"
    print(f"   ✅ PASS: {params}")

    # Test 4: S3 list_buckets - no filters (should return empty params)
    print("\n4. Testing aws.s3.list_buckets (no filters)")
    params = {}
    params = filter_engine.apply_api_filters('aws.s3.list_buckets', params, 's3')
    expected = {}
    assert params == expected, f"Expected {expected}, got {params}"
    print(f"   ✅ PASS: {params}")

    print("\n" + "=" * 80)
    print("API-Level Filter Tests: ✅ ALL PASSED")
    print("=" * 80)


def test_response_filters():
    """Test response-level filters"""
    print("\n" + "=" * 80)
    print("Testing Response-Level Filters")
    print("=" * 80)

    config_loader = DiscoveryConfigLoader(provider='aws')
    filter_engine = FilterEngine(config_loader)

    # Test 1: KMS list_aliases - should exclude alias/aws/*
    print("\n1. Testing aws.kms.list_aliases")
    items = [
        {'AliasName': 'alias/aws/s3'},       # Should be excluded
        {'AliasName': 'alias/aws/dynamodb'}, # Should be excluded
        {'AliasName': 'alias/my-key'},       # Should be kept
        {'AliasName': 'alias/customer-key'}  # Should be kept
    ]
    filtered = filter_engine.apply_response_filters('aws.kms.list_aliases', items, 'kms')
    assert len(filtered) == 2, f"Expected 2 items, got {len(filtered)}"
    assert all('alias/aws/' not in item['AliasName'] for item in filtered), "AWS aliases not excluded"
    print(f"   ✅ PASS: Filtered {len(items)} → {len(filtered)} items (excluded AWS aliases)")

    # Test 2: Secrets Manager - should exclude aws/* and rds!*
    print("\n2. Testing aws.secretsmanager.list_secrets")
    items = [
        {'Name': 'aws/rds/secret'},          # Should be excluded
        {'Name': 'rds!db-instance-1'},       # Should be excluded
        {'Name': 'my-secret'},               # Should be kept
        {'Name': 'customer-secret'}          # Should be kept
    ]
    filtered = filter_engine.apply_response_filters('aws.secretsmanager.list_secrets', items, 'secretsmanager')
    assert len(filtered) == 2, f"Expected 2 items, got {len(filtered)}"
    print(f"   ✅ PASS: Filtered {len(items)} → {len(filtered)} items (excluded AWS secrets)")

    # Test 3: EventBridge list_event_buses - should exclude 'default'
    print("\n3. Testing aws.events.list_event_buses")
    items = [
        {'Name': 'default'},            # Should be excluded
        {'Name': 'custom-bus'},         # Should be kept
        {'Name': 'my-event-bus'}        # Should be kept
    ]
    filtered = filter_engine.apply_response_filters('aws.events.list_event_buses', items, 'events')
    assert len(filtered) == 2, f"Expected 2 items, got {len(filtered)}"
    assert all(item['Name'] != 'default' for item in filtered), "Default bus not excluded"
    print(f"   ✅ PASS: Filtered {len(items)} → {len(filtered)} items (excluded default bus)")

    # Test 4: SSM describe_parameters - should exclude /aws/*
    print("\n4. Testing aws.ssm.describe_parameters")
    items = [
        {'Name': '/aws/service/ami-amazon-linux-latest'},  # Should be excluded
        {'Name': '/aws/parameter'},                        # Should be excluded
        {'Name': '/my-app/config'},                        # Should be kept
        {'Name': '/customer/setting'}                      # Should be kept
    ]
    filtered = filter_engine.apply_response_filters('aws.ssm.describe_parameters', items, 'ssm')
    assert len(filtered) == 2, f"Expected 2 items, got {len(filtered)}"
    assert all(not item['Name'].startswith('/aws/') for item in filtered), "AWS parameters not excluded"
    print(f"   ✅ PASS: Filtered {len(items)} → {len(filtered)} items (excluded AWS parameters)")

    # Test 5: S3 list_buckets - no filters (should return all items)
    print("\n5. Testing aws.s3.list_buckets (no filters)")
    items = [
        {'Name': 'my-bucket'},
        {'Name': 'another-bucket'}
    ]
    filtered = filter_engine.apply_response_filters('aws.s3.list_buckets', items, 's3')
    assert len(filtered) == len(items), f"Expected {len(items)} items, got {len(filtered)}"
    print(f"   ✅ PASS: No filtering applied ({len(filtered)} items kept)")

    print("\n" + "=" * 80)
    print("Response-Level Filter Tests: ✅ ALL PASSED")
    print("=" * 80)


def test_filter_metadata():
    """Test filter metadata queries"""
    print("\n" + "=" * 80)
    print("Testing Filter Metadata")
    print("=" * 80)

    config_loader = DiscoveryConfigLoader(provider='aws')
    filter_engine = FilterEngine(config_loader)

    # Test 1: Check if service has filters
    print("\n1. Testing has_filters()")
    assert filter_engine.has_filters('ec2') == True, "EC2 should have filters"
    assert filter_engine.has_filters('s3') == False, "S3 should not have filters"
    print(f"   ✅ PASS: has_filters() working correctly")

    # Test 2: Get filter counts
    print("\n2. Testing get_filter_count()")
    ec2_counts = filter_engine.get_filter_count('ec2')
    assert ec2_counts['api_filters'] == 2, f"Expected 2 API filters for EC2, got {ec2_counts['api_filters']}"
    assert ec2_counts['response_filters'] == 1, f"Expected 1 response filter for EC2, got {ec2_counts['response_filters']}"
    print(f"   ✅ PASS: EC2 has {ec2_counts['api_filters']} API filters, {ec2_counts['response_filters']} response filters")

    iam_counts = filter_engine.get_filter_count('iam')
    assert iam_counts['api_filters'] == 1, f"Expected 1 API filter for IAM, got {iam_counts['api_filters']}"
    assert iam_counts['response_filters'] == 2, f"Expected 2 response filters for IAM, got {iam_counts['response_filters']}"
    print(f"   ✅ PASS: IAM has {iam_counts['api_filters']} API filters, {iam_counts['response_filters']} response filters")

    # Test 3: Get filters for specific discovery
    print("\n3. Testing get_filters_for_discovery()")
    ec2_filters = filter_engine.get_filters_for_discovery('aws.ec2.describe_snapshots', 'ec2')
    assert len(ec2_filters['api_filters']) == 1, "Should have 1 API filter for describe_snapshots"
    print(f"   ✅ PASS: Found {len(ec2_filters['api_filters'])} API filter for describe_snapshots")

    print("\n" + "=" * 80)
    print("Filter Metadata Tests: ✅ ALL PASSED")
    print("=" * 80)


if __name__ == '__main__':
    print("=" * 80)
    print("FilterEngine Database-Driven Filter Tests")
    print("=" * 80)
    print("\nThis test validates that filters are correctly loaded from the database")
    print("and applied by the FilterEngine class.")

    try:
        test_api_filters()
        test_response_filters()
        test_filter_metadata()

        print("\n" + "=" * 80)
        print("✅ ALL TESTS PASSED")
        print("=" * 80)
        print("\nSummary:")
        print("  - API-level filters: ✅ Working (4/4 tests passed)")
        print("  - Response-level filters: ✅ Working (5/5 tests passed)")
        print("  - Filter metadata: ✅ Working (3/3 tests passed)")
        print("\nThe FilterEngine is correctly loading filters from the database")
        print("and applying them to discovery operations.")
        print("=" * 80)

    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
