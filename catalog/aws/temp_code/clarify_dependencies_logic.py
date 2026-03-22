"""
Clarify dependencies logic in minimal_operations_list.json.
Dependencies are AND (all required), not OR (any one sufficient).
"""

import json
from pathlib import Path
from typing import Dict, List

def clarify_dependencies(service_name: str, service_dir: Path) -> bool:
    """Add dependency logic clarification to minimal_operations_list.json."""
    
    minimal_ops_file = service_dir / "minimal_operations_list.json"
    
    if not minimal_ops_file.exists():
        print(f"  ⚠️  minimal_operations_list.json not found")
        return False
    
    try:
        with open(minimal_ops_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ❌ Error reading file: {e}")
        return False
    
    # Update each operation to clarify dependency logic
    for op_info in data.get("minimal_operations", {}).get("selected_operations", []):
        dependencies = op_info.get("dependencies", [])
        
        if dependencies:
            # Dependencies are ALWAYS AND (all required) in AWS APIs
            op_info["dependencies_logic"] = "AND"
            op_info["dependencies_required"] = "ALL"  # All dependencies are required
            op_info["dependencies_count"] = len(dependencies)
            
            # Add clarification message
            if len(dependencies) > 1:
                op_info["dependencies_note"] = f"All {len(dependencies)} dependencies are required (AND logic)"
            else:
                op_info["dependencies_note"] = "This dependency is required"
        else:
            op_info["dependencies_logic"] = "NONE"
            op_info["dependencies_required"] = "NONE"
            op_info["dependencies_count"] = 0
            op_info["dependencies_note"] = "No dependencies - can be called independently"
    
    # Save updated file
    with open(minimal_ops_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    return True

def process_all_services(aws_dir: str, services: List[str]):
    """Process all services to clarify dependencies."""
    
    aws_path = Path(aws_dir)
    
    print("=" * 80)
    print("CLARIFYING DEPENDENCIES LOGIC")
    print("=" * 80)
    print("\nDependencies Logic: ALL dependencies are required (AND logic)")
    print("This means you need ALL listed dependencies to call the operation.")
    print("")
    
    for service_name in services:
        print(f"{'='*80}")
        print(f"Processing: {service_name.upper()}")
        print(f"{'='*80}")
        
        service_dir = aws_path / service_name
        
        if clarify_dependencies(service_name, service_dir):
            # Show example
            try:
                with open(service_dir / "minimal_operations_list.json", 'r') as f:
                    data = json.load(f)
                
                # Find an operation with multiple dependencies
                example_op = None
                for op in data.get("minimal_operations", {}).get("selected_operations", []):
                    if op.get("dependencies_count", 0) > 1:
                        example_op = op
                        break
                
                if example_op:
                    print(f"  ✅ Enhanced successfully")
                    print(f"\n  Example - {example_op['operation']}:")
                    print(f"    Dependencies: {', '.join(example_op['dependencies'])}")
                    print(f"    Logic: {example_op['dependencies_logic']} (ALL required)")
                    print(f"    Note: {example_op['dependencies_note']}")
                else:
                    print(f"  ✅ Enhanced successfully")
            except Exception as e:
                print(f"  ⚠️  Enhanced but could not show example: {e}")
        else:
            print(f"  ❌ Failed to process")
    
    print(f"\n\n{'='*80}")
    print("DEPENDENCIES CLARIFICATION COMPLETE")
    print(f"{'='*80}")

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_to_process = ["accessanalyzer", "ec2", "s3", "iam"]
    
    process_all_services(aws_dir, services_to_process)

