#!/usr/bin/env python3
"""
Split all service YAML files in rule_db into separate discoveries and checks files
"""
import os
import yaml
from pathlib import Path
from typing import Dict, Any

def split_service_yaml(service_dir: Path) -> Dict[str, int]:
    """
    Split service YAML into discoveries (main file) and checks (separate file)
    
    Args:
        service_dir: Path to service directory (e.g., .../services/accessanalyzer/)
    
    Returns:
        Dict with counts of discoveries and checks
    """
    rules_dir = service_dir / "rules"
    if not rules_dir.exists():
        return {'discoveries': 0, 'checks': 0, 'error': 'rules directory not found'}
    
    # Find main YAML file (usually {service}.yaml)
    service_name = service_dir.name
    main_yaml = rules_dir / f"{service_name}.yaml"
    
    if not main_yaml.exists():
        # Try to find any .yaml file in rules directory
        yaml_files = list(rules_dir.glob("*.yaml"))
        if not yaml_files:
            return {'discoveries': 0, 'checks': 0, 'error': 'no YAML file found'}
        main_yaml = yaml_files[0]  # Use first YAML file found
    
    # Load YAML
    try:
        with open(main_yaml) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        return {'discoveries': 0, 'checks': 0, 'error': f'failed to load YAML: {e}'}
    
    # Check if checks section exists
    checks = data.get('checks', [])
    if not checks:
        # No checks to split, already separated
        return {
            'discoveries': len(data.get('discovery', [])),
            'checks': 0,
            'status': 'no_checks'
        }
    
    # Check if checks file already exists
    checks_file = rules_dir / f"{service_name}.checks.yaml"
    if checks_file.exists():
        return {
            'discoveries': len(data.get('discovery', [])),
            'checks': len(checks),
            'status': 'already_split'
        }
    
    # Extract discoveries (keep everything except checks)
    discoveries_data = {k: v for k, v in data.items() if k != 'checks'}
    
    # Extract checks
    checks_data = {
        'version': data.get('version', '1.0'),
        'provider': data.get('provider', 'aws'),
        'service': data.get('service', service_name),
        'checks': checks
    }
    
    # Backup original file
    backup_file = main_yaml.with_suffix('.yaml.backup')
    if not backup_file.exists():
        import shutil
        shutil.copy2(main_yaml, backup_file)
    
    # Write discoveries (remove checks section)
    with open(main_yaml, 'w') as f:
        yaml.dump(discoveries_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    # Write checks to separate file
    with open(checks_file, 'w') as f:
        yaml.dump(checks_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    return {
        'discoveries': len(discoveries_data.get('discovery', [])),
        'checks': len(checks),
        'status': 'split'
    }

def split_all_services():
    """Split all services in rule_db"""
    # Base directory
    base_dir = Path(__file__).parent / "default" / "services"
    
    if not base_dir.exists():
        print(f"❌ Services directory not found: {base_dir}")
        return
    
    # Get all service directories
    services = [d for d in base_dir.iterdir() if d.is_dir() and not d.name.startswith('.')]
    
    print(f"Found {len(services)} services to process\n")
    print("=" * 80)
    
    total_discoveries = 0
    total_checks = 0
    success_count = 0
    skipped_count = 0
    error_count = 0
    
    for service_dir in sorted(services):
        service_name = service_dir.name
        print(f"Processing {service_name}...")
        
        try:
            result = split_service_yaml(service_dir)
            
            if result.get('error'):
                print(f"  ❌ Error: {result['error']}")
                error_count += 1
            elif result.get('status') == 'already_split':
                print(f"  ⏭️  Already split: {result['discoveries']} discoveries, {result['checks']} checks")
                skipped_count += 1
                total_discoveries += result['discoveries']
                total_checks += result['checks']
            elif result.get('status') == 'no_checks':
                print(f"  ⚠️  No checks found: {result['discoveries']} discoveries")
                skipped_count += 1
                total_discoveries += result['discoveries']
            else:
                print(f"  ✅ Split: {result['discoveries']} discoveries, {result['checks']} checks")
                success_count += 1
                total_discoveries += result['discoveries']
                total_checks += result['checks']
        
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            error_count += 1
        
        print()
    
    print("=" * 80)
    print("SPLIT SUMMARY")
    print("=" * 80)
    print(f"Total Services: {len(services)}")
    print(f"  ✅ Successfully Split: {success_count}")
    print(f"  ⏭️  Skipped (already split/no checks): {skipped_count}")
    print(f"  ❌ Errors: {error_count}")
    print(f"\nTotal Discoveries: {total_discoveries}")
    print(f"Total Checks: {total_checks}")
    print("=" * 80)
    
    if success_count > 0:
        print(f"\n✅ {success_count} services successfully split!")
        print("   Original files backed up with .backup extension")
        print("   Checks saved to {service}.checks.yaml files")

if __name__ == '__main__':
    split_all_services()

