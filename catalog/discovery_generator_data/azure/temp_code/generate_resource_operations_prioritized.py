"""
Generate prioritized resource operations file for Azure services.
Adapted for Azure structure (no ARNs, different resource model).
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime

def get_root_operations(service_dir: Path) -> List[str]:
    """Get root operations from dependency_index or minimal_operations_list."""
    root_operations = []
    
    # Try minimal_operations_list first
    minimal_ops_file = service_dir / "minimal_operations_list.json"
    if minimal_ops_file.exists():
        try:
            with open(minimal_ops_file, 'r') as f:
                data = json.load(f)
            root_operations = data.get("root_operations_available", [])
        except Exception:
            pass
    
    # Fallback to dependency_index
    if not root_operations:
        dependency_index_file = service_dir / "dependency_index.json"
        if dependency_index_file.exists():
            try:
                with open(dependency_index_file, 'r') as f:
                    data = json.load(f)
                roots = data.get("roots", [])
                root_operations = [r.get("op") for r in roots if r.get("op")]
            except Exception:
                pass
    
    return root_operations

def get_yaml_discovery_operations(service_name: str, base_dir: Path) -> Set[str]:
    """Get YAML discovery operations if they exist."""
    # Azure might have discovery YAMLs in a different location
    # For now, return empty set - can be extended later
    yaml_discovery_ops = set()
    
    # Check if there's a discovery YAML file
    discovery_yaml = base_dir / service_name / f"{service_name}_discovery.yaml"
    if discovery_yaml.exists():
        try:
            import yaml
            with open(discovery_yaml, 'r') as f:
                data = yaml.safe_load(f)
            discovery = data.get("discovery", [])
            for disc in discovery:
                discovery_id = disc.get("discovery_id", "")
                if discovery_id:
                    # Extract operation name from discovery_id
                    # Format: azure.service.operation_name
                    parts = discovery_id.split('.')
                    if len(parts) >= 3:
                        op_name = parts[2]
                        # Convert snake_case to CamelCase
                        op_name = ''.join(word.capitalize() for word in op_name.split('_'))
                        yaml_discovery_ops.add(op_name)
        except Exception:
            pass
    
    return yaml_discovery_ops

def generate_resource_operations_file(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate prioritized resource operations file for a service."""
    
    try:
        # Get root operations
        root_operations = get_root_operations(service_dir)
        
        # Get YAML discovery operations
        yaml_discovery_ops = get_yaml_discovery_operations(service_name, service_dir.parent)
        
        # Build report
        report = {
            "service": service_name,
            "generated_at": datetime.now().isoformat(),
            "root_operations": sorted(root_operations),
            "yaml_discovery_operations": sorted(list(yaml_discovery_ops)),
            "primary_resources": [],
            "other_resources": [],
            "summary": {
                "total_resources": 0,
                "primary_resources_count": 0,
                "other_resources_count": 0,
                "resources_with_arn": 0,
                "resources_from_root_ops": 0
            }
        }
        
        return report
        
    except Exception as e:
        return {"error": str(e)}

def generate_all_services(base_dir: Path):
    """Generate prioritized resource operations for all services."""
    
    print("="*80)
    print("GENERATING PRIORITIZED RESOURCE OPERATIONS FOR ALL AZURE SERVICES")
    print("="*80)
    
    # Get all service directories
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.') 
                    and (d / 'dependency_index.json').exists()]
    
    print(f"Found {len(service_dirs)} service directories")
    print()
    
    services_processed = 0
    services_with_errors = []
    
    for service_dir in sorted(service_dirs):
        service_name = service_dir.name
        try:
            report = generate_resource_operations_file(service_name, service_dir)
            
            if not report:
                services_with_errors.append((service_name, "Could not generate report"))
                continue
            
            if "error" in report:
                services_with_errors.append((service_name, report["error"]))
                continue
            
            # Save JSON report
            json_file = service_dir / "resource_operations_prioritized.json"
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"✓ {service_name}: {len(report['root_operations'])} root ops, "
                  f"{len(report['yaml_discovery_operations'])} YAML discovery ops")
            
            services_processed += 1
            
            if services_processed % 20 == 0:
                print(f"  Progress: {services_processed} services processed...")
                
        except Exception as e:
            services_with_errors.append((service_name, str(e)))
            print(f"  ✗ {service_name}: Error - {e}")
    
    print(f"\n{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"Services processed: {services_processed}")
    
    if services_with_errors:
        print(f"\nServices with errors: {len(services_with_errors)}")
        for service, error in services_with_errors[:10]:
            print(f"  - {service}: {error}")

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/azure')
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        generate_all_services(base_dir)
    else:
        # Generate for single service (compute) as test
        service_name = 'compute'
        service_dir = base_dir / service_name
        
        print(f"Generating resource operations prioritized for: {service_name}")
        print("="*80)
        
        report = generate_resource_operations_file(service_name, service_dir)
        
        if report and "error" not in report:
            json_file = service_dir / "resource_operations_prioritized.json"
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\n✓ Saved to: {json_file}")
            print(f"\nSummary:")
            print(f"  Root Operations: {len(report['root_operations'])}")
            print(f"  YAML Discovery Operations: {len(report['yaml_discovery_operations'])}")
            print(f"\nFirst 5 root operations:")
            for i, op in enumerate(report['root_operations'][:5], 1):
                print(f"  {i}. {op}")
        else:
            print(f"Error: {report.get('error', 'Unknown error')}")

if __name__ == '__main__':
    main()

