#!/usr/bin/env python3
"""Quick script to get top validation errors"""
import sys
sys.path.append('/Users/apple/Desktop/threat-engine/scripts')

from validate_check_discovery_alignment import *

result = validate_csp('aws', verbose=False)

# Print top 20 errors
print("\n\nTop 20 Validation Errors:")
print("="*80)
for i, error in enumerate(result.errors[:20]):
    print(f"{i+1}. [{error['service']}] {error['rule_id']}")
    print(f"   {error['error']}\n")
