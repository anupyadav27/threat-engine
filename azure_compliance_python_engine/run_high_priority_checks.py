#!/usr/bin/env python3
"""
Run compliance checks for high-priority services only
Filters checks by severity (critical/high)
"""

import sys
import os
import yaml
import json
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def get_all_services():
    """Get all services with their check counts"""
    services_dir = Path(__file__).parent / "services"
    service_info = {}
    
    for rule_file in services_dir.glob("*/rules/*.yaml"):
        try:
            with open(rule_file) as f:
                rules = yaml.safe_load(f)
            
            service = rules.get('service', 'unknown')
            checks = rules.get('checks', [])
            
            if len(checks) > 0:
                service_info[service] = {
                    'total_checks': len(checks),
                    'has_discovery': len(rules.get('discovery', [])) > 0
                }
        except Exception as e:
            continue
    
    return service_info

# Important services (security-critical)
IMPORTANT_SERVICES = [
    'keyvault',      # Secrets management
    'storage',       # Data security
    'sql',           # Database security
    'network',       # Network security
    'compute',       # VM security
    'authorization', # RBAC/IAM
    'monitor',       # Monitoring/auditing
    'web',           # Web app security
    'api',           # API security
    'cosmosdb',      # NoSQL security
    'containerservice', # Container security
    'storageaccount', # Storage account security
]

def filter_checks_by_severity(service_name, min_severity='high'):
    """Filter checks for a service by minimum severity"""
    services_dir = Path(__file__).parent / "services"
    rule_file = services_dir / service_name / "rules" / f"{service_name}.yaml"
    
    if not rule_file.exists():
        return []
    
    try:
        with open(rule_file) as f:
            rules = yaml.safe_load(f)
        
        checks = rules.get('checks', [])
        
        # Severity levels: critical > high > medium > low
        severity_levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        min_level = severity_levels.get(min_severity.lower(), 2)
        
        filtered = []
        for check in checks:
            check_severity = check.get('severity', 'medium').lower()
            check_level = severity_levels.get(check_severity, 2)
            
            if check_level >= min_level:
                filtered.append(check)
        
        return filtered
    except Exception as e:
        print(f"Error reading {rule_file}: {e}", file=sys.stderr)
        return []

def main():
    parser = argparse.ArgumentParser(
        description='Run high-priority compliance checks',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List high-priority services
  python3 run_high_priority_checks.py --list

  # Run checks for all high-priority services
  python3 run_high_priority_checks.py --run-all

  # Run checks for specific service
  python3 run_high_priority_checks.py --service keyvault

  # Run only critical checks
  python3 run_high_priority_checks.py --run-all --min-severity critical
        """
    )
    
    parser.add_argument('--list', action='store_true',
                       help='List services with high-priority checks')
    parser.add_argument('--run-all', action='store_true',
                       help='Run checks for all high-priority services')
    parser.add_argument('--service', type=str,
                       help='Run checks for specific service')
    parser.add_argument('--min-severity', choices=['critical', 'high', 'medium', 'low'],
                       default='high', help='Minimum severity level (default: high)')
    parser.add_argument('--subscription', type=str,
                       help='Azure subscription ID')
    parser.add_argument('--location', type=str, default='eastus',
                       help='Azure location (default: eastus)')
    parser.add_argument('--min-high-priority', type=int, default=1,
                       help='Minimum high-priority checks to include service (default: 1)')
    
    args = parser.parse_args()
    
    # Get all services
    all_services = get_all_services()
    
    if args.list:
        print("=" * 80)
        print("AVAILABLE SERVICES")
        print("=" * 80)
        print()
        
        # Show important services first
        important = [(s, all_services.get(s, {})) for s in IMPORTANT_SERVICES if s in all_services]
        other = [(s, info) for s, info in all_services.items() if s not in IMPORTANT_SERVICES]
        
        print("🔒 IMPORTANT SERVICES (Security-Critical):")
        print()
        for service, info in sorted(important, key=lambda x: x[1].get('total_checks', 0), reverse=True):
            checks = info.get('total_checks', 0)
            discovery = "✅" if info.get('has_discovery') else "❌"
            print(f"  {discovery} {service:25} {checks:4} checks")
        
        print()
        print("📋 OTHER SERVICES:")
        print()
        for service, info in sorted(other, key=lambda x: x[1].get('total_checks', 0), reverse=True):
            checks = info.get('total_checks', 0)
            discovery = "✅" if info.get('has_discovery') else "❌"
            print(f"  {discovery} {service:25} {checks:4} checks")
        
        print()
        print(f"Total services: {len(all_services)}")
        print(f"Important services: {len(important)}")
        return
    
    if args.run_all:
        # Use important services if no filter specified
        services = [s for s in IMPORTANT_SERVICES if s in all_services]
        print(f"Running checks for {len(services)} important services...")
        print(f"Services: {', '.join(services)}")
        print()
        
        # Build command
        cmd_parts = [
            'python3', '-m', 'azure_compliance_python_engine.engine.main_scanner'
        ]
        
        if args.subscription:
            cmd_parts.extend(['--subscription', args.subscription])
        
        cmd_parts.extend(['--location', args.location])
        
        # Add service filters
        for service in services:
            cmd_parts.extend(['--service', service])
        
        print("Command:")
        print(' '.join(cmd_parts))
        print()
        
        # Execute
        os.execvp('python3', cmd_parts)
    
    elif args.service:
        if args.service not in all_services:
            print(f"❌ Error: Service '{args.service}' not found")
            print(f"   Available services: {', '.join(sorted(all_services.keys()))}")
            return 1
        
        service_info = all_services[args.service]
        print(f"Service: {args.service}")
        print(f"Total checks: {service_info.get('total_checks', 0)}")
        print()
        
        # Build command
        cmd_parts = [
            'python3', '-m', 'azure_compliance_python_engine.engine.main_scanner'
        ]
        
        if args.subscription:
            cmd_parts.extend(['--subscription', args.subscription])
        
        cmd_parts.extend(['--location', args.location])
        cmd_parts.extend(['--service', args.service])
        
        print("Command:")
        print(' '.join(cmd_parts))
        print()
        
        # Execute
        os.execvp('python3', cmd_parts)
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
