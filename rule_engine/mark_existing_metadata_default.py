#!/usr/bin/env python3
"""
Mark all existing metadata files with metadata_source: "default"
This script processes all metadata YAML files in aws_compliance_python_engine/services
"""

import yaml
from pathlib import Path
from typing import Dict, Any
import sys

def update_metadata_file(metadata_path: Path) -> bool:
    """Update a single metadata file to add metadata_source: default"""
    try:
        # Read existing metadata
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = yaml.safe_load(f)
        
        if not metadata:
            return False
        
        # Check if already has metadata_source
        if metadata.get('metadata_source') == 'default':
            return False  # Already marked, skip
        
        # Add or update metadata_source
        metadata['metadata_source'] = 'default'
        
        # Also update source and generated_by if they don't exist
        if 'source' not in metadata:
            metadata['source'] = 'default'
        elif metadata.get('source') not in ['default', 'user_generated']:
            metadata['source'] = 'default'
        
        if 'generated_by' not in metadata:
            metadata['generated_by'] = 'default'
        
        # Write back
        with open(metadata_path, 'w', encoding='utf-8') as f:
            yaml.dump(metadata, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        return True
        
    except Exception as e:
        print(f"  ✗ Error updating {metadata_path.name}: {e}")
        return False

def process_service_metadata(service_dir: Path) -> Dict[str, int]:
    """Process all metadata files in a service directory"""
    metadata_dir = service_dir / 'metadata'
    
    if not metadata_dir.exists():
        return {'total': 0, 'updated': 0, 'skipped': 0}
    
    metadata_files = list(metadata_dir.glob('*.yaml'))
    total = len(metadata_files)
    updated = 0
    skipped = 0
    
    for metadata_file in metadata_files:
        if update_metadata_file(metadata_file):
            updated += 1
        else:
            skipped += 1
    
    return {
        'total': total,
        'updated': updated,
        'skipped': skipped
    }

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services')
    
    if not base_dir.exists():
        print(f"Error: Base directory not found: {base_dir}")
        sys.exit(1)
    
    print("="*80)
    print("MARKING EXISTING METADATA AS 'default'")
    print("="*80)
    print(f"Processing: {base_dir}")
    print()
    
    # Get all service directories
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and (d / 'metadata').exists()]
    
    print(f"Found {len(service_dirs)} services with metadata directories")
    print()
    
    total_updated = 0
    total_skipped = 0
    total_files = 0
    services_processed = 0
    
    for service_dir in sorted(service_dirs):
        service_name = service_dir.name
        stats = process_service_metadata(service_dir)
        
        if stats['total'] > 0:
            print(f"  {service_name}: {stats['updated']} updated, {stats['skipped']} skipped (total: {stats['total']})")
            total_updated += stats['updated']
            total_skipped += stats['skipped']
            total_files += stats['total']
            services_processed += 1
    
    print()
    print("="*80)
    print("COMPLETE")
    print("="*80)
    print(f"Services processed: {services_processed}")
    print(f"Total metadata files: {total_files}")
    print(f"Files updated: {total_updated}")
    print(f"Files skipped (already marked): {total_skipped}")
    print()
    print("All existing metadata files now have: metadata_source: 'default'")

if __name__ == '__main__':
    main()

