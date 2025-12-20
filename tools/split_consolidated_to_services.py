#!/usr/bin/env python3
"""
Split consolidated enriched JSON database into per-service files.

This script takes a main consolidated file (e.g., oci_dependencies_with_python_names_fully_enriched.json)
and splits it into individual service files in their respective service folders.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any
import argparse


def split_consolidated_file(root_path: Path, csp_name: str, main_file_name: str):
    """
    Split consolidated file into per-service files.
    
    Args:
        root_path: Root path for the CSP (e.g., pythonsdk-database/oci)
        csp_name: CSP name (oci, gcp, etc.)
        main_file_name: Name of the main consolidated file
    """
    main_file = root_path / main_file_name
    
    if not main_file.exists():
        print(f"❌ Main file not found: {main_file}")
        return False
    
    print(f"\n{'='*70}")
    print(f"SPLITTING {csp_name.upper()} CONSOLIDATED DATABASE")
    print(f"{'='*70}\n")
    print(f"Main file: {main_file.name}")
    
    # Load main consolidated file
    try:
        with open(main_file, 'r') as f:
            main_data = json.load(f)
    except Exception as e:
        print(f"❌ Error loading main file: {e}")
        return False
    
    # Determine file name pattern based on CSP
    if csp_name == 'oci':
        service_file_name = 'oci_dependencies_with_python_names_fully_enriched.json'
    elif csp_name == 'gcp':
        service_file_name = 'gcp_dependencies_with_python_names_fully_enriched.json'
    elif csp_name == 'azure':
        service_file_name = 'azure_dependencies_with_python_names_fully_enriched.json'
    elif csp_name == 'aws':
        service_file_name = 'boto3_dependencies_with_python_names_fully_enriched.json'
    elif csp_name == 'ibm':
        service_file_name = 'ibm_dependencies_with_python_names_fully_enriched.json'
    else:
        service_file_name = f'{csp_name}_dependencies_with_python_names_fully_enriched.json'
    
    services_processed = 0
    services_created = 0
    services_updated = 0
    services_skipped = 0
    errors = []
    
    # Process each service
    for service_name, service_data in main_data.items():
        # Skip metadata keys
        if service_name in ['total_services', 'metadata', 'version']:
            continue
        
        services_processed += 1
        service_path = root_path / service_name
        
        # Create service folder if it doesn't exist
        if not service_path.exists():
            service_path.mkdir(parents=True, exist_ok=True)
            print(f"[{services_processed}] {service_name} - Created folder")
        
        service_file = service_path / service_file_name
        
        # Create service-specific data structure
        service_json = {
            service_name: service_data
        }
        
        try:
            # Check if file exists
            file_existed = service_file.exists()
            
            # Write service file
            with open(service_file, 'w') as f:
                json.dump(service_json, f, indent=2)
            
            if file_existed:
                services_updated += 1
                print(f"[{services_processed}] {service_name} - Updated")
            else:
                services_created += 1
                print(f"[{services_processed}] {service_name} - Created")
                
        except Exception as e:
            services_skipped += 1
            error_msg = f"{service_name}: {str(e)}"
            errors.append(error_msg)
            print(f"[{services_processed}] {service_name} - ❌ Error: {str(e)}")
    
    # Print summary
    print(f"\n{'='*70}")
    print(f"SPLIT SUMMARY")
    print(f"{'='*70}")
    print(f"Services processed: {services_processed}")
    print(f"Files created: {services_created}")
    print(f"Files updated: {services_updated}")
    print(f"Files skipped: {services_skipped}")
    print(f"Errors: {len(errors)}")
    
    if errors:
        print(f"\nErrors:")
        for error in errors[:10]:
            print(f"  - {error}")
    
    return True


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Split consolidated enriched database into per-service files'
    )
    parser.add_argument(
        '--csp',
        required=True,
        choices=['oci', 'gcp', 'azure', 'aws', 'ibm'],
        help='Cloud Service Provider name'
    )
    parser.add_argument(
        '--root',
        help='Root path (default: pythonsdk-database/{csp})'
    )
    parser.add_argument(
        '--main-file',
        help='Main consolidated file name (auto-detected if not provided)'
    )
    
    args = parser.parse_args()
    
    # Determine root path
    if args.root:
        root_path = Path(args.root)
    else:
        root_path = Path(f'pythonsdk-database/{args.csp}')
    
    # Determine main file name
    if args.main_file:
        main_file_name = args.main_file
    else:
        if args.csp == 'oci':
            main_file_name = 'oci_dependencies_with_python_names_fully_enriched.json'
        elif args.csp == 'gcp':
            main_file_name = 'gcp_dependencies_with_python_names_fully_enriched.json'
        elif args.csp == 'azure':
            main_file_name = 'azure_dependencies_with_python_names_fully_enriched.json'
        elif args.csp == 'aws':
            main_file_name = 'boto3_dependencies_with_python_names_fully_enriched.json'
        elif args.csp == 'ibm':
            main_file_name = 'ibm_dependencies_with_python_names_fully_enriched.json'
        else:
            main_file_name = f'{args.csp}_dependencies_with_python_names_fully_enriched.json'
    
    if not root_path.exists():
        print(f"❌ Root path not found: {root_path}")
        sys.exit(1)
    
    success = split_consolidated_file(root_path, args.csp, main_file_name)
    
    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()

