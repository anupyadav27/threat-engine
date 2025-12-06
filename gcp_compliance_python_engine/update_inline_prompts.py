#!/usr/bin/env python3
"""
Update all GCP service YAML files with enhanced inline validation prompts
Replaces existing header prompt with comprehensive inline template
"""

import os
import re
from pathlib import Path

# Read the inline prompt template
template_file = Path(__file__).parent / "GCP_YAML_INLINE_PROMPT.yaml"
with open(template_file, 'r') as f:
    template_content = f.read()

# Extract just the header comment section (before first YAML key)
# We'll insert this at the top of each file
inline_prompt = []
for line in template_content.split('\n'):
    if line.strip() and not line.startswith('#') and not line.startswith('service_name:'):
        break
    inline_prompt.append(line)

inline_prompt_text = '\n'.join(inline_prompt) + '\n\n'

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
updated_count = 0
for rule_file in sorted(service_files):
    print(f"\nProcessing: {rule_file.name}")
    
    # Read current content
    with open(rule_file, 'r') as f:
        current_content = f.read()
    
    # Remove old header if exists
    if "GCP COMPLIANCE ENGINE - SERVICE VALIDATION PROMPT" in current_content:
        # Find where the old header ends (first non-comment, non-empty line)
        lines = current_content.split('\n')
        first_yaml_line = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                first_yaml_line = i
                break
        
        # Reconstruct without old header
        current_content = '\n'.join(lines[first_yaml_line:])
        print(f"  📝 Removed old header")
    
    # Add new inline prompt
    new_content = inline_prompt_text + current_content
    
    # Write back
    with open(rule_file, 'w') as f:
        f.write(new_content)
    
    updated_count += 1
    print(f"  ✅ Updated with inline validation prompt")

print(f"\n✅ Complete! Updated {updated_count} files")
print(f"\nNext steps:")
print(f"1. Open SERVICE_TRACKER_VALIDATOR.md")
print(f"2. Start validating services one by one")
print(f"3. Update the tracker as you complete each service")

