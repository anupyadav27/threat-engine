#!/usr/bin/env python3
"""
Compact JSON formatter - applies human-readable compact formatting to JSON files.
"""

import json
import sys
from pathlib import Path

def compact_json_dumps(obj, indent=2):
    """Custom JSON formatter for more compact, human-readable output."""
    def is_simple_value(val):
        """Check if value is simple (string, number, bool, null)."""
        return isinstance(val, (str, int, float, bool)) or val is None
    
    def format_value(val, level=0, in_array=False, force_single_line=False):
        if isinstance(val, dict):
            if not val:
                return "{}"
            items = []
            for k, v in val.items():
                # Force single line for consumes/produces arrays
                force_single = (k in ['consumes', 'produces'] and isinstance(v, list))
                formatted_val = format_value(v, level + 1, False, force_single)
                items.append(f'"{k}": {formatted_val}')
            
            # Single line for small objects (especially in arrays)
            content = ", ".join(items)
            if in_array or (len(content) < 100 and level > 0):
                return "{" + content + "}"
            else:
                # Multi-line for larger objects
                sep = f",\n{' ' * indent * (level + 1)}"
                return "{\n" + (' ' * indent * (level + 1)) + sep.join(items) + "\n" + (' ' * indent * level) + "}"
        
        elif isinstance(val, list):
            if not val:
                return "[]"
            
            # Check if all items are strings (common case for entity lists)
            all_strings = all(isinstance(item, str) for item in val)
            
            # For string arrays (like entity lists), always single line
            if all_strings:
                items_str = ", ".join(json.dumps(item) for item in val)
                return "[" + items_str + "]"
            
            # Format items - try to keep on single line for produces/consumes arrays
            formatted_items = [format_value(item, level + 1, True, force_single_line) for item in val]
            content = ", ".join(formatted_items)
            
            # For arrays of objects (like produces/consumes), prefer single line
            # This makes the JSON more compact and readable
            # Use single line if content is reasonable length or if forced
            if force_single_line or len(content) < 250:
                return "[" + content + "]"
            
            # Multi-line only for very long arrays
            sep = f",\n{' ' * indent * (level + 1)}"
            return "[\n" + (' ' * indent * (level + 1)) + sep.join(formatted_items) + "\n" + (' ' * indent * level) + "]"
        
        elif isinstance(val, str):
            return json.dumps(val)
        elif isinstance(val, bool):
            return "true" if val else "false"
        elif val is None:
            return "null"
        else:
            return str(val)
    
    return format_value(obj, 0, False)

def format_json_file(input_file, output_file=None):
    """Format a JSON file with compact formatting."""
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"Error: File not found: {input_file}")
        return False
    
    if output_file is None:
        output_file = input_file
    else:
        output_file = Path(output_file)
    
    print(f"Reading {input_path}...")
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    print(f"Formatting JSON...")
    formatted = compact_json_dumps(data, indent=2)
    
    print(f"Writing to {output_file}...")
    with open(output_file, 'w') as f:
        f.write(formatted)
    
    # Verify it's valid JSON
    try:
        with open(output_file, 'r') as f:
            json.load(f)
        print(f"✓ Successfully formatted and validated: {output_file}")
        return True
    except json.JSONDecodeError as e:
        print(f"✗ Error: Generated invalid JSON: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python format_json_compact.py <input_file> [output_file]")
        print("  If output_file is not specified, input_file will be overwritten.")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    success = format_json_file(input_file, output_file)
    sys.exit(0 if success else 1)

