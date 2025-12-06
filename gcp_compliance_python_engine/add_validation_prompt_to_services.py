#!/usr/bin/env python3
"""
Add validation prompt header to all GCP service rule YAML files
"""

import os
from pathlib import Path

# Read the header prompt
header_file = Path(__file__).parent / "YAML_HEADER_PROMPT.txt"
with open(header_file, 'r') as f:
    header_content = f.read()

# Find all service rule files
services_dir = Path(__file__).parent / "services"
service_files = []

for service_dir in services_dir.iterdir():
    if service_dir.is_dir():
        rule_file = service_dir / f"{service_dir.name}_rules.yaml"
        if rule_file.exists():
            service_files.append(rule_file)

print(f"Found {len(service_files)} service rule files")

# Process each file
for rule_file in sorted(service_files):
    print(f"\nProcessing: {rule_file.name}")
    
    # Read current content
    with open(rule_file, 'r') as f:
        current_content = f.read()
    
    # Check if header already exists
    if "GCP COMPLIANCE ENGINE - SERVICE VALIDATION PROMPT" in current_content:
        print(f"  ⏭️  Header already exists, skipping")
        continue
    
    # Add header
    new_content = header_content + "\n\n" + current_content
    
    # Write back
    with open(rule_file, 'w') as f:
        f.write(new_content)
    
    print(f"  ✅ Added validation prompt header")

print(f"\n✅ Complete! Processed {len(service_files)} files")
print(f"\nNext steps:")
print(f"1. Open any service rule file (e.g., services/compute/compute_rules.yaml)")
print(f"2. Read the header prompt for instructions")
print(f"3. Follow the workflow to validate and fix the service")

