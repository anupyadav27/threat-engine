#!/usr/bin/env python3
"""
Generate comprehensive list of all K8s services and checks,
along with cluster inventory for tracking
"""
import os
import yaml
from pathlib import Path
from collections import defaultdict
import json

# Try to get cluster inventory
def get_cluster_inventory():
    try:
        from utils.cluster_namespace_discovery import discover_kubernetes_inventory
        inventory = discover_kubernetes_inventory()
        return inventory
    except Exception as e:
        return {"error": str(e)}

def analyze_service_file(filepath):
    """Extract service info from YAML file"""
    try:
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
        
        service_name = Path(filepath).parent.name
        checks = []
        
        if 'checks' in data:
            for check in data['checks']:
                check_info = {
                    'check_id': check.get('check_id', 'N/A'),
                    'name': check.get('name', 'N/A'),
                    'severity': check.get('severity', 'N/A'),
                    'discovery': check.get('for_each', 'N/A')
                }
                checks.append(check_info)
        
        discovery_info = []
        if 'discovery' in data:
            for disc in data['discovery']:
                disc_info = {
                    'discovery_id': disc.get('discovery_id', 'N/A'),
                    'actions': [call.get('action', 'N/A') for call in disc.get('calls', [])]
                }
                discovery_info.append(disc_info)
        
        return {
            'service': service_name,
            'component': data.get('component', 'N/A'),
            'component_type': data.get('component_type', 'N/A'),
            'check_count': len(checks),
            'checks': checks,
            'discovery': discovery_info
        }
    except Exception as e:
        return {'service': Path(filepath).parent.name, 'error': str(e)}

def main():
    services_dir = Path(__file__).parent / 'services'
    services_list = []
    
    # Find all rule files
    rule_files = list(services_dir.glob('**/*_rules.yaml'))
    
    print(f"Found {len(rule_files)} rule files\n")
    
    for rule_file in sorted(rule_files):
        service_info = analyze_service_file(rule_file)
        services_list.append(service_info)
        print(f"✓ {service_info['service']}: {service_info.get('check_count', 0)} checks")
    
    # Get cluster inventory
    print("\n🔍 Discovering cluster inventory...")
    inventory = get_cluster_inventory()
    
    # Generate summary
    total_checks = sum(s.get('check_count', 0) for s in services_list)
    
    summary = {
        'total_services': len(services_list),
        'total_checks': total_checks,
        'services': services_list,
        'cluster_inventory': inventory
    }
    
    # Write to JSON
    output_file = Path(__file__).parent / 'K8S_SERVICES_AND_CHECKS_LIST.json'
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2, default=str)
    
    print(f"\n✅ Generated: {output_file}")
    print(f"📊 Total Services: {len(services_list)}")
    print(f"📋 Total Checks: {total_checks}")
    
    # Generate markdown version
    md_file = Path(__file__).parent / 'K8S_SERVICES_AND_CHECKS_LIST.md'
    generate_markdown(services_list, inventory, md_file, total_checks)
    
    print(f"📄 Generated: {md_file}")

def generate_markdown(services_list, inventory, output_file, total_checks):
    """Generate markdown tracking document"""
    with open(output_file, 'w') as f:
        f.write("# K8s Services and Checks Tracking List\n\n")
        f.write(f"**Generated**: {Path(__file__).parent}\n\n")
        f.write(f"## Summary\n\n")
        f.write(f"- **Total Services**: {len(services_list)}\n")
        f.write(f"- **Total Checks**: {total_checks}\n\n")
        
        # Cluster Inventory
        f.write("## Cluster Inventory\n\n")
        if 'error' in inventory:
            f.write(f"⚠️ Error getting inventory: {inventory['error']}\n\n")
        else:
            cluster_info = inventory.get('cluster_info', {})
            f.write(f"**Kubernetes Version**: {cluster_info.get('git_version', 'N/A')}\n")
            f.write(f"**Platform**: {cluster_info.get('platform', 'N/A')}\n")
            f.write(f"**Provider**: {cluster_info.get('provider', 'local')}\n")
            f.write(f"**Nodes**: {len(inventory.get('nodes', []))}\n")
            f.write(f"**Namespaces**: {len(inventory.get('namespaces', []))}\n\n")
            
            # List namespaces
            if inventory.get('namespaces'):
                f.write("### Namespaces\n\n")
                for ns in inventory['namespaces']:
                    f.write(f"- `{ns.get('name')}` ({ns.get('status', 'N/A')})\n")
                f.write("\n")
        
        # Services List
        f.write("## Services and Checks\n\n")
        
        for service in services_list:
            service_name = service.get('service', 'unknown')
            check_count = service.get('check_count', 0)
            component = service.get('component', 'N/A')
            component_type = service.get('component_type', 'N/A')
            
            f.write(f"### {service_name} ({check_count} checks)\n\n")
            f.write(f"- **Component**: {component}\n")
            f.write(f"- **Type**: {component_type}\n")
            f.write(f"- **Rule File**: `services/{service_name}/{service_name}_rules.yaml`\n\n")
            
            # Discovery
            if service.get('discovery'):
                f.write("**Discovery**:\n")
                for disc in service['discovery']:
                    f.write(f"- `{disc.get('discovery_id')}` - Actions: {', '.join(disc.get('actions', []))}\n")
                f.write("\n")
            
            # Checks
            if check_count > 0:
                f.write("**Checks**:\n\n")
                for check in service['checks'][:10]:  # Show first 10
                    f.write(f"- `{check['check_id']}` - {check['name']} [{check['severity']}]\n")
                if check_count > 10:
                    f.write(f"- ... and {check_count - 10} more checks\n")
                f.write("\n")
            
            f.write("---\n\n")

if __name__ == '__main__':
    main()
