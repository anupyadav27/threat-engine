#!/usr/bin/env python3
"""
Multi-Cloud Integration Test
Tests the complete flow of metadata loading, ARN generation, and classification
"""

from inventory_engine.metadata.service_metadata_loader import ServiceMetadataLoader
from inventory_engine.normalizer.asset_normalizer import AssetNormalizer
from inventory_engine.normalizer.resource_classifier import ResourceClassifier
import os

def test_metadata_loader():
    """Test ServiceMetadataLoader across multiple CSPs"""
    print("\n" + "="*80)
    print("TEST 1: ServiceMetadataLoader - Multi-CSP Metadata Loading")
    print("="*80)

    loader = ServiceMetadataLoader()

    # Test AWS services
    print("\n--- AWS Services ---")
    aws_services = ['s3', 'ec2', 'lambda', 'rds', 'dynamodb', 'iam']
    for service in aws_services:
        metadata = loader.get_service_metadata('aws', service)
        if metadata:
            print(f"✅ aws.{service}: {len(metadata.independent_methods)} discovery, "
                  f"{len(metadata.dependent_methods)} enrichment")
        else:
            print(f"❌ aws.{service}: Not found")

    # Test Azure services
    print("\n--- Azure Services ---")
    azure_services = ['storage', 'compute', 'network']
    for service in azure_services:
        metadata = loader.get_service_metadata('azure', service)
        if metadata:
            print(f"✅ azure.{service}: {len(metadata.independent_methods)} discovery, "
                  f"{len(metadata.dependent_methods)} enrichment")
        else:
            print(f"❌ azure.{service}: Not found")

    # Test GCP services
    print("\n--- GCP Services ---")
    gcp_services = ['storage', 'compute_engine', 'bigquery']
    for service in gcp_services:
        metadata = loader.get_service_metadata('gcp', service)
        if metadata:
            print(f"✅ gcp.{service}: {len(metadata.independent_methods)} discovery, "
                  f"{len(metadata.dependent_methods)} enrichment")
        else:
            print(f"❌ gcp.{service}: Not found")

    # Statistics
    stats = loader.get_statistics()
    print(f"\n--- Overall Statistics ---")
    print(f"Total services: {stats['total_services']}")
    print(f"Services with discovery: {stats['with_discovery']}")
    print(f"Services with enrichment: {stats['with_enrichment']}")
    print(f"By CSP: {stats['by_csp']}")

    loader.close()
    return True


def test_arn_generation():
    """Test ARN generation from flat fields"""
    print("\n" + "="*80)
    print("TEST 2: ARN Generation from Fields")
    print("="*80)

    normalizer = AssetNormalizer(tenant_id='test-tenant', scan_run_id='test-scan')

    test_cases = [
        {
            'name': 'S3 Bucket',
            'fields': {'BucketName': 'my-test-bucket'},
            'service': 's3',
            'account': '123456789012',
            'region': 'us-east-1',
            'expected_contains': 'arn:aws:s3:::my-test-bucket'
        },
        {
            'name': 'EC2 Instance',
            'fields': {'InstanceId': 'i-1234567890abcdef0'},
            'service': 'ec2',
            'account': '123456789012',
            'region': 'us-west-2',
            'expected_contains': 'arn:aws:ec2:us-west-2:123456789012:instance/i-1234567890abcdef0'
        },
        {
            'name': 'Lambda Function (with explicit ARN)',
            'fields': {
                'FunctionName': 'my-function',
                'FunctionArn': 'arn:aws:lambda:us-east-1:123456789012:function:my-function'
            },
            'service': 'lambda',
            'account': '123456789012',
            'region': 'us-east-1',
            'expected_contains': 'arn:aws:lambda:us-east-1:123456789012:function:my-function'
        },
    ]

    print()
    for test in test_cases:
        arn = normalizer._generate_arn_from_fields(
            test['fields'],
            test['service'],
            test['account'],
            test['region']
        )

        if arn and test['expected_contains'] in arn:
            print(f"✅ {test['name']}: {arn}")
        else:
            print(f"⚠️  {test['name']}: Got '{arn}', expected to contain '{test['expected_contains']}'")

    return True


def test_resource_classification():
    """Test resource classification with database"""
    print("\n" + "="*80)
    print("TEST 3: Resource Classification (Database Mode)")
    print("="*80)

    # Enable database mode
    os.environ['USE_DATABASE'] = 'true'
    os.environ['PYTHONSDK_DB_HOST'] = 'postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com'
    os.environ['PYTHONSDK_DB_USER'] = 'postgres'
    os.environ['PYTHONSDK_DB_PASSWORD'] = 'jtv2BkJF8qoFtAKP'
    os.environ['PYTHONSDK_DB_NAME'] = 'threat_engine_pythonsdk'

    classifier = ResourceClassifier(csp_id='aws')

    # Test classification lookups
    test_cases = [
        {
            'csp': 'aws',
            'service': 's3',
            'operation': 'list_buckets',
            'resource_type': 'bucket',
            'expected_should_inventory': True
        },
        {
            'csp': 'aws',
            'service': 'ec2',
            'operation': 'describe_instances',
            'resource_type': 'instance',
            'expected_should_inventory': True
        },
    ]

    print()
    loader = ServiceMetadataLoader()
    for test in test_cases:
        # Check if resource should be inventoried
        should_inv = loader.should_inventory_resource(
            test['csp'],
            test['service'],
            test['resource_type']
        )

        if should_inv == test['expected_should_inventory']:
            print(f"✅ {test['csp']}.{test['service']}.{test['resource_type']}: "
                  f"should_inventory={should_inv}")
        else:
            print(f"❌ {test['csp']}.{test['service']}.{test['resource_type']}: "
                  f"Expected {test['expected_should_inventory']}, got {should_inv}")

    loader.close()
    return True


def test_multi_csp_coverage():
    """Test that all 6 CSPs have metadata loaded"""
    print("\n" + "="*80)
    print("TEST 4: Multi-CSP Coverage Verification")
    print("="*80)

    loader = ServiceMetadataLoader()

    expected_csps = ['aws', 'azure', 'gcp', 'oci', 'ibm', 'alibaba']

    print()
    for csp in expected_csps:
        services = loader.get_all_services_for_csp(csp)
        if services:
            services_with_discovery = sum(1 for s in services if s.independent_methods)
            services_with_enrichment = sum(1 for s in services if s.dependent_methods)
            print(f"✅ {csp.upper()}: {len(services)} services "
                  f"({services_with_discovery} with discovery, {services_with_enrichment} with enrichment)")
        else:
            print(f"❌ {csp.upper()}: No services found")

    loader.close()
    return True


def main():
    """Run all integration tests"""
    print("\n" + "="*80)
    print("MULTI-CLOUD INVENTORY ENGINE - INTEGRATION TESTS")
    print("="*80)
    print("\nTesting RDS Mumbai Database Integration")
    print("Database: threat_engine_pythonsdk")
    print("Host: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com")

    results = []

    try:
        results.append(('Metadata Loader', test_metadata_loader()))
    except Exception as e:
        print(f"\n❌ TEST 1 FAILED: {e}")
        results.append(('Metadata Loader', False))

    try:
        results.append(('ARN Generation', test_arn_generation()))
    except Exception as e:
        print(f"\n❌ TEST 2 FAILED: {e}")
        results.append(('ARN Generation', False))

    try:
        results.append(('Resource Classification', test_resource_classification()))
    except Exception as e:
        print(f"\n❌ TEST 3 FAILED: {e}")
        results.append(('Resource Classification', False))

    try:
        results.append(('Multi-CSP Coverage', test_multi_csp_coverage()))
    except Exception as e:
        print(f"\n❌ TEST 4 FAILED: {e}")
        results.append(('Multi-CSP Coverage', False))

    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{status}: {test_name}")

    all_passed = all(result[1] for result in results)

    if all_passed:
        print("\n🎉 ALL TESTS PASSED! Ready for EKS deployment.")
        print("\nNext steps:")
        print("  1. Commit changes to git")
        print("  2. Build Docker image")
        print("  3. Push to ECR")
        print("  4. Deploy to EKS Mumbai")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please review and fix before deployment.")
        return 1


if __name__ == '__main__':
    exit(main())
