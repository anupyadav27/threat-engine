#!/usr/bin/env python3
"""
Organize service folders:
1. Split consolidated boto3_dependencies_with_python_names_fully_enriched.json to each service
2. Keep only essential files in service folders:
   - boto3_dependencies_with_python_names_fully_enriched.json
   - direct_vars.json
   - dependency_index.json
3. Move all other files to backup/ folder in each service directory
"""

import json
import shutil
from pathlib import Path
from typing import Set, List

# Essential files to keep in service folders
ESSENTIAL_FILES: Set[str] = {
    'boto3_dependencies_with_python_names_fully_enriched.json',
    'direct_vars.json',
    'dependency_index.json'
}

def split_boto3_to_service_folders(base_dir: Path):
    """Split consolidated boto3 file into per-service files"""
    consolidated_path = base_dir / 'boto3_dependencies_with_python_names_fully_enriched.json'
    
    if not consolidated_path.exists():
        print(f"✗ Consolidated file not found: {consolidated_path}")
        return False
    
    print(f"Loading consolidated boto3 file...")
    with open(consolidated_path, 'r', encoding='utf-8') as f:
        consolidated_data = json.load(f)
    
    print(f"Found {len(consolidated_data)} services in consolidated file")
    
    services_processed = 0
    services_with_errors = []
    
    for service_name, service_data in consolidated_data.items():
        if not isinstance(service_data, dict):
            continue
        
        try:
            # Create service directory
            service_dir = base_dir / service_name
            service_dir.mkdir(parents=True, exist_ok=True)
            
            # Save per-service boto3 file
            output_path = service_dir / 'boto3_dependencies_with_python_names_fully_enriched.json'
            
            # Wrap in service name key to match structure
            output_data = {service_name: service_data}
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            services_processed += 1
            
        except Exception as e:
            services_with_errors.append((service_name, str(e)))
            print(f"  ✗ {service_name}: Error - {e}")
    
    print(f"  ✓ Processed {services_processed} services")
    if services_with_errors:
        print(f"  ✗ {len(services_with_errors)} services with errors")
    
    return True

def organize_service_folder(service_dir: Path) -> dict:
    """
    Organize a service folder:
    - Keep essential files
    - Move others to backup/
    Returns stats dict
    """
    if not service_dir.is_dir():
        return {'skipped': True}
    
    backup_dir = service_dir / 'backup'
    backup_dir.mkdir(exist_ok=True)
    
    stats = {
        'kept': [],
        'moved': [],
        'errors': []
    }
    
    # Get all files in service directory (not subdirectories)
    all_files = [f for f in service_dir.iterdir() 
                 if f.is_file() and not f.name.startswith('.')]
    
    for file_path in all_files:
        file_name = file_path.name
        
        if file_name in ESSENTIAL_FILES:
            stats['kept'].append(file_name)
        else:
            # Move to backup
            try:
                backup_path = backup_dir / file_name
                # Handle name conflicts
                if backup_path.exists():
                    # Add counter if file exists
                    counter = 1
                    while backup_path.exists():
                        name_parts = file_name.rsplit('.', 1)
                        if len(name_parts) == 2:
                            new_name = f"{name_parts[0]}_{counter}.{name_parts[1]}"
                        else:
                            new_name = f"{file_name}_{counter}"
                        backup_path = backup_dir / new_name
                        counter += 1
                
                shutil.move(str(file_path), str(backup_path))
                stats['moved'].append(file_name)
            except Exception as e:
                stats['errors'].append((file_name, str(e)))
    
    return stats

def organize_all_service_folders(base_dir: Path):
    """Organize all service folders"""
    print(f"\n{'='*80}")
    print("ORGANIZING SERVICE FOLDERS")
    print(f"{'='*80}")
    
    # Get all service directories
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.') 
                    and d.name != 'backup']
    
    print(f"Found {len(service_dirs)} service directories")
    
    total_kept = 0
    total_moved = 0
    total_errors = 0
    services_organized = 0
    
    for service_dir in sorted(service_dirs):
        service_name = service_dir.name
        stats = organize_service_folder(service_dir)
        
        if stats.get('skipped'):
            continue
        
        kept_count = len(stats['kept'])
        moved_count = len(stats['moved'])
        errors_count = len(stats['errors'])
        
        if kept_count > 0 or moved_count > 0:
            print(f"  ✓ {service_name}: kept {kept_count}, moved {moved_count} to backup/")
            if errors_count > 0:
                print(f"    ⚠ {errors_count} errors")
        
        total_kept += kept_count
        total_moved += moved_count
        total_errors += errors_count
        services_organized += 1
    
    print(f"\n{'='*80}")
    print("ORGANIZATION COMPLETE")
    print(f"{'='*80}")
    print(f"Services organized: {services_organized}")
    print(f"Files kept: {total_kept}")
    print(f"Files moved to backup/: {total_moved}")
    print(f"Errors: {total_errors}")

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/aws')
    
    print("="*80)
    print("ORGANIZING SERVICE FOLDERS")
    print("="*80)
    print("\nEssential files to keep:")
    for f in sorted(ESSENTIAL_FILES):
        print(f"  - {f}")
    print("\nAll other files will be moved to backup/ folder")
    
    # Step 1: Split boto3 file
    print(f"\n{'='*80}")
    print("STEP 1: Splitting boto3_dependencies_with_python_names_fully_enriched.json")
    print(f"{'='*80}")
    split_boto3_to_service_folders(base_dir)
    
    # Step 2: Organize service folders
    print(f"\n{'='*80}")
    print("STEP 2: Organizing service folders")
    print(f"{'='*80}")
    organize_all_service_folders(base_dir)
    
    print(f"\n{'='*80}")
    print("COMPLETE")
    print(f"{'='*80}")
    print("\nEach service folder now contains only:")
    for f in sorted(ESSENTIAL_FILES):
        print(f"  ✓ {f}")
    print("\nAll other files have been moved to backup/ subfolder")

if __name__ == '__main__':
    main()

