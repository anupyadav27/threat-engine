"""
Rename and Cleanup Script

This script:
1. Renames *_simplified.yaml to *.yaml (removes "_simplified")
2. Backs up old *.yaml files to *.yaml.old
3. Moves simplified files to replace old files

Usage:
    python3 rename_and_cleanup.py
    
Options:
    --dry-run: Show what would be done without making changes
    --no-backup: Don't create .old backups (delete old files directly)
"""

import os
import shutil
import argparse
from pathlib import Path


def rename_simplified_files(services_dir, dry_run=False, no_backup=False):
    """
    Rename simplified files and handle old files
    
    Args:
        services_dir: Path to services directory
        dry_run: If True, don't make changes, just show what would be done
        no_backup: If True, delete old files instead of backing up
    """
    
    results = {
        'renamed': [],
        'backed_up': [],
        'deleted': [],
        'errors': []
    }
    
    # Find all simplified YAML files
    for service_dir in Path(services_dir).iterdir():
        if not service_dir.is_dir():
            continue
        
        rules_dir = service_dir / 'rules'
        if not rules_dir.exists():
            continue
        
        # Find simplified files
        for simplified_file in rules_dir.glob('*_simplified.yaml'):
            # Determine new name (without _simplified)
            service_name = simplified_file.stem.replace('_simplified', '')
            new_file = simplified_file.parent / f'{service_name}.yaml'
            
            print(f"\nProcessing: {simplified_file.name}")
            
            # Check if old file exists
            if new_file.exists():
                if no_backup:
                    # Delete old file
                    print(f"  Old file exists: {new_file.name}")
                    if not dry_run:
                        try:
                            new_file.unlink()
                            print(f"  ✅ Deleted: {new_file.name}")
                            results['deleted'].append(str(new_file))
                        except Exception as e:
                            print(f"  ❌ Error deleting: {e}")
                            results['errors'].append(str(new_file))
                            continue
                    else:
                        print(f"  [DRY RUN] Would delete: {new_file.name}")
                else:
                    # Backup old file
                    backup_file = new_file.parent / f'{new_file.name}.old'
                    print(f"  Old file exists: {new_file.name}")
                    print(f"  Creating backup: {backup_file.name}")
                    
                    if not dry_run:
                        try:
                            shutil.move(str(new_file), str(backup_file))
                            print(f"  ✅ Backed up: {new_file.name} → {backup_file.name}")
                            results['backed_up'].append(str(new_file))
                        except Exception as e:
                            print(f"  ❌ Error backing up: {e}")
                            results['errors'].append(str(new_file))
                            continue
                    else:
                        print(f"  [DRY RUN] Would backup: {new_file.name} → {backup_file.name}")
            
            # Rename simplified file to new name
            print(f"  Renaming: {simplified_file.name} → {new_file.name}")
            
            if not dry_run:
                try:
                    simplified_file.rename(new_file)
                    print(f"  ✅ Renamed successfully")
                    results['renamed'].append(str(new_file))
                except Exception as e:
                    print(f"  ❌ Error renaming: {e}")
                    results['errors'].append(str(simplified_file))
            else:
                print(f"  [DRY RUN] Would rename: {simplified_file.name} → {new_file.name}")
    
    return results


def cleanup_extra_files(services_dir, dry_run=False):
    """
    Clean up extra files like *_corrected.yaml, *_manual_corrected.yaml
    
    Args:
        services_dir: Path to services directory
        dry_run: If True, don't make changes
    """
    
    results = {
        'deleted': [],
        'errors': []
    }
    
    patterns = ['*_corrected.yaml', '*_manual_corrected.yaml', '*_generated.yaml']
    
    for service_dir in Path(services_dir).iterdir():
        if not service_dir.is_dir():
            continue
        
        rules_dir = service_dir / 'rules'
        if not rules_dir.exists():
            continue
        
        # Find extra files
        for pattern in patterns:
            for extra_file in rules_dir.glob(pattern):
                print(f"\nFound extra file: {extra_file}")
                
                if not dry_run:
                    try:
                        extra_file.unlink()
                        print(f"  ✅ Deleted: {extra_file.name}")
                        results['deleted'].append(str(extra_file))
                    except Exception as e:
                        print(f"  ❌ Error deleting: {e}")
                        results['errors'].append(str(extra_file))
                else:
                    print(f"  [DRY RUN] Would delete: {extra_file.name}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description='Rename simplified files and cleanup old files')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--no-backup', action='store_true',
                       help="Don't create .old backups (delete old files directly)")
    parser.add_argument('--services-dir', type=str, default='services',
                       help='Path to services directory')
    parser.add_argument('--cleanup-extras', action='store_true',
                       help='Also cleanup *_corrected.yaml and other extra files')
    
    args = parser.parse_args()
    
    services_dir = args.services_dir
    if not os.path.exists(services_dir):
        print(f"❌ Services directory not found: {services_dir}")
        return 1
    
    print("="*80)
    print("RENAME AND CLEANUP TOOL")
    print("="*80)
    
    if args.dry_run:
        print("\n⚠️  DRY RUN MODE - No changes will be made")
    
    if args.no_backup:
        print("\n⚠️  NO BACKUP MODE - Old files will be DELETED (not backed up)")
    else:
        print("\n📦 BACKUP MODE - Old files will be renamed to *.yaml.old")
    
    # Rename simplified files
    print("\n" + "="*80)
    print("STEP 1: RENAME SIMPLIFIED FILES")
    print("="*80)
    
    rename_results = rename_simplified_files(services_dir, args.dry_run, args.no_backup)
    
    # Cleanup extra files
    if args.cleanup_extras:
        print("\n" + "="*80)
        print("STEP 2: CLEANUP EXTRA FILES")
        print("="*80)
        
        cleanup_results = cleanup_extra_files(services_dir, args.dry_run)
    else:
        cleanup_results = {'deleted': [], 'errors': []}
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    print(f"\n✅ Renamed: {len(rename_results['renamed'])}")
    if rename_results['renamed']:
        for file in rename_results['renamed'][:10]:
            service = os.path.basename(os.path.dirname(os.path.dirname(file)))
            print(f"  - {service}")
        if len(rename_results['renamed']) > 10:
            print(f"  ... and {len(rename_results['renamed']) - 10} more")
    
    if not args.no_backup:
        print(f"\n📦 Backed up: {len(rename_results['backed_up'])}")
        if rename_results['backed_up']:
            for file in rename_results['backed_up'][:5]:
                print(f"  - {os.path.basename(file)} → {os.path.basename(file)}.old")
            if len(rename_results['backed_up']) > 5:
                print(f"  ... and {len(rename_results['backed_up']) - 5} more")
    else:
        print(f"\n🗑️  Deleted old files: {len(rename_results['deleted'])}")
    
    if args.cleanup_extras:
        print(f"\n🗑️  Cleaned up extra files: {len(cleanup_results['deleted'])}")
    
    total_errors = len(rename_results['errors']) + len(cleanup_results['errors'])
    if total_errors > 0:
        print(f"\n❌ Errors: {total_errors}")
        for error in rename_results['errors'] + cleanup_results['errors']:
            print(f"  - {error}")
    
    print(f"\n📊 Total operations:")
    print(f"   Renamed: {len(rename_results['renamed'])}")
    print(f"   Backed up: {len(rename_results['backed_up'])}")
    print(f"   Deleted: {len(rename_results['deleted']) + len(cleanup_results['deleted'])}")
    print(f"   Errors: {total_errors}")
    
    if not args.dry_run:
        print(f"\n✅ All operations completed!")
        print(f"\nResult:")
        print(f"  - Simplified files renamed to standard names")
        if not args.no_backup:
            print(f"  - Old files backed up as *.yaml.old")
        else:
            print(f"  - Old files deleted")
        if args.cleanup_extras:
            print(f"  - Extra files cleaned up")
    else:
        print(f"\n⚠️  This was a DRY RUN - no changes were made")
        print(f"\nTo apply changes, run without --dry-run:")
        print(f"  python3 rename_and_cleanup.py")
    
    return 0 if total_errors == 0 else 1


if __name__ == '__main__':
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
