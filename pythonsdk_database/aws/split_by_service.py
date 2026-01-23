#!/usr/bin/env python3
"""
Split the large boto3 dependencies JSON file into separate files organized by service.
Each service will have its own folder under aws/ with the service data.
"""

import json
import os
from pathlib import Path

def split_json_by_service(input_file, output_base_dir):
    """
    Split the large JSON file into separate files, one per service.
    
    Args:
        input_file: Path to the input JSON file
        output_base_dir: Base directory where service folders will be created
    """
    print(f"Reading {input_file}...")
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    total_services = len(data)
    print(f"Found {total_services} services to split")
    
    # Create output base directory if it doesn't exist
    output_base_dir = Path(output_base_dir)
    output_base_dir.mkdir(parents=True, exist_ok=True)
    
    # Process each service
    for service_name, service_data in data.items():
        # Create service directory
        service_dir = output_base_dir / service_name
        service_dir.mkdir(parents=True, exist_ok=True)
        
        # Create the JSON file for this service
        # The structure will be: {service_name: service_data}
        output_data = {service_name: service_data}
        output_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"Created: {output_file}")
    
    print(f"\nCompleted! Split {total_services} services into separate folders.")

if __name__ == "__main__":
    # Get the directory where this script is located
    script_dir = Path(__file__).parent
    
    input_file = script_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    output_base_dir = script_dir
    
    if not input_file.exists():
        print(f"Error: Input file not found: {input_file}")
        exit(1)
    
    split_json_by_service(input_file, output_base_dir)

