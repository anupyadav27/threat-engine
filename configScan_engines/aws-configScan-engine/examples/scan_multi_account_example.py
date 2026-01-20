#!/usr/bin/env python3
"""
Example: Flexible AWS Compliance Scanning

This example shows various scanning scenarios using the unified scanner.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.main_scanner import scan

def example_full_organization_scan():
    """Scan entire AWS Organization"""
    print("=" * 80)
    print("Example 1: Full Organization Scan")
    print("=" * 80)
    
    results = scan(
        role_name="ComplianceScannerRole",
        save_report=True
    )
    
    print(f"\nScanned {len(results)} service-region combinations")


def example_single_account_scan():
    """Scan single account across all regions"""
    print("=" * 80)
    print("Example 2: Single Account Scan")
    print("=" * 80)
    
    results = scan(
        account="123456789012",
        save_report=True
    )
    
    print(f"\nScanned {len(results)} service-region combinations")


def example_account_region_scan():
    """Scan single account in specific region"""
    print("=" * 80)
    print("Example 3: Account + Region Scan")
    print("=" * 80)
    
    results = scan(
        account="123456789012",
        region="us-east-1",
        max_workers=15,  # Higher parallelism for single region
        save_report=True
    )
    
    print(f"\nScanned {len(results)} services in us-east-1")


def example_service_specific_scan():
    """Scan specific service across accounts"""
    print("=" * 80)
    print("Example 4: S3 Service Scan")
    print("=" * 80)
    
    results = scan(
        role_name="ComplianceScannerRole",
        service="s3",  # Only S3 buckets
        save_report=True
    )
    
    print(f"\nScanned S3 buckets across all accounts")


def example_single_resource_scan():
    """Scan single resource"""
    print("=" * 80)
    print("Example 5: Single Resource Scan")
    print("=" * 80)
    
    results = scan(
        account="123456789012",
        region="us-east-1",
        service="ec2",
        resource="i-1234567890abcdef0",  # Specific instance
        save_report=True
    )
    
    print(f"\nScanned single EC2 instance")


def example_pattern_matching():
    """Scan resources matching pattern"""
    print("=" * 80)
    print("Example 6: Pattern Matching Scan")
    print("=" * 80)
    
    results = scan(
        account="123456789012",
        region="us-east-1",
        service="ec2",
        resource_pattern="i-*-prod-*",  # All production instances
        save_report=True
    )
    
    print(f"\nScanned production instances matching pattern")


if __name__ == '__main__':
    # Choose which example to run
    import argparse
    
    parser = argparse.ArgumentParser(description='Flexible Scanning Examples')
    parser.add_argument('--example', type=int, default=1, choices=[1, 2, 3, 4, 5, 6],
                       help='Example number to run (1-6)')
    args = parser.parse_args()
    
    examples = {
        1: example_full_organization_scan,
        2: example_single_account_scan,
        3: example_account_region_scan,
        4: example_service_specific_scan,
        5: example_single_resource_scan,
        6: example_pattern_matching
    }
    
    examples[args.example]()
