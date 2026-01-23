#!/usr/bin/env python3
"""Debug discovery reader"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inventory_engine.connectors.discovery_reader_factory import get_discovery_reader

print("Testing discovery reader...")
reader = get_discovery_reader(tenant_id="multi_account_tenant_001")

print(f"Reader type: {type(reader).__name__}")
print(f"Latest scan ID: {reader.get_latest_scan_id()}")

scan_id = "latest"
print(f"\nReading discovery records for scan: {scan_id}")
count = 0
sample_records = []

for record in reader.read_discovery_records(scan_id):
    count += 1
    if count <= 5:
        sample_records.append(record)
    if count >= 100:
        break

print(f"\nTotal records read: {count}")
print(f"\nSample records:")
for i, rec in enumerate(sample_records, 1):
    arn = rec.get('resource_arn') or 'N/A'
    arn_display = arn[:80] if arn != 'N/A' else 'N/A'
    print(f"\n{i}. Service: {rec.get('service')}, ARN: {arn_display}")
    print(f"   Account: {rec.get('account_id')}, Region: {rec.get('region')}")
    print(f"   Discovery ID: {rec.get('discovery_id')}")
