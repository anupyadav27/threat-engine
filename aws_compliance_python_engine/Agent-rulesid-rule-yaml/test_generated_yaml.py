#!/usr/bin/env python3
"""
Test Generated YAML Files

This script:
1. Copies generated YAML files to services folder
2. Optionally runs a test scan on specific services
"""

import os
import shutil
import sys
import subprocess
from pathlib import Path

def copy_generated_yamls():
    """Copy generated YAML files to services folder"""
    output_dir = Path(__file__).parent / 'output'
    services_dir = Path(__file__).parent.parent / 'services'
    
    print("=" * 80)
    print("COPYING GENERATED YAML FILES TO SERVICES FOLDER")
    print("=" * 80)
    print()
    
    copied = []
    skipped = []
    
    for yaml_file in output_dir.glob('*_generated.yaml'):
        service_name = yaml_file.stem.replace('_generated', '')
        target_dir = services_dir / service_name / 'rules'
        target_file = target_dir / f'{service_name}.yaml'
        
        # Create directory if it doesn't exist
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup existing file if it exists
        if target_file.exists():
            backup_file = target_file.with_suffix('.yaml.backup')
            shutil.copy2(target_file, backup_file)
            print(f"  📦 Backed up existing: {backup_file.name}")
        
        # Copy new file
        shutil.copy2(yaml_file, target_file)
        copied.append(service_name)
        print(f"  ✅ Copied: {service_name}")
    
    print()
    print(f"Copied {len(copied)} YAML files:")
    for service in copied:
        print(f"  - {service}")
    
    return copied


def test_service(service_name: str, region: str = None):
    """Test a specific service by running the main scanner"""
    engine_dir = Path(__file__).parent.parent
    os.chdir(engine_dir)
    
    # Set PYTHONPATH
    env = os.environ.copy()
    env['PYTHONPATH'] = str(engine_dir) + ':' + env.get('PYTHONPATH', '')
    
    cmd = ['python3', '-m', 'engine.main_scanner', '--service', service_name]
    if region:
        cmd.extend(['--region', region])
    
    print()
    print("=" * 80)
    print(f"TESTING SERVICE: {service_name}")
    print("=" * 80)
    print()
    print(f"Command: {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running test: {e}")
        return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Test generated YAML files')
    parser.add_argument('--copy-only', action='store_true', 
                       help='Only copy files, do not test')
    parser.add_argument('--test-service', type=str,
                       help='Test a specific service after copying')
    parser.add_argument('--region', type=str,
                       help='Region to test (default: us-east-1)')
    
    args = parser.parse_args()
    
    # Copy files
    copied_services = copy_generated_yamls()
    
    if args.copy_only:
        print()
        print("✅ Copy complete. Files ready for testing.")
        return
    
    # Test if requested
    if args.test_service:
        if args.test_service not in copied_services:
            print(f"⚠️  Warning: {args.test_service} was not in copied files")
        test_service(args.test_service, args.region or 'us-east-1')
    else:
        print()
        print("=" * 80)
        print("NEXT STEPS")
        print("=" * 80)
        print()
        print("To test the YAML files, run:")
        print()
        print("  # Test a specific service:")
        print("  cd ../..")
        print("  export PYTHONPATH=$PWD:$PYTHONPATH")
        print("  python3 -m engine.main_scanner --service cognito")
        print()
        print("  # Test multiple services:")
        print("  python3 -m engine.main_scanner --include-services cognito,vpc,parameterstore")
        print()
        print("  # Test all services:")
        print("  python3 -m engine.main_scanner")


if __name__ == '__main__':
    main()

