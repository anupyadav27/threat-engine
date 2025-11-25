#!/usr/bin/env python3
"""
FIX DISCOVERY REFERENCES
Automatically fix discovery reference mismatches in generated checks
"""

import yaml
from pathlib import Path
from collections import defaultdict

class DiscoveryFixer:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.fixed_count = 0
        self.error_count = 0
        
    def fix_service(self, service_name):
        """Fix discovery references for a service"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return False
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            # Get existing discovery IDs
            existing_discoveries = {d['discovery_id'] for d in data.get('discovery', [])}
            
            # Track which discoveries are needed
            needed_discoveries = set()
            
            # Check what discoveries are referenced in checks
            for check in data.get('checks', []):
                discovery_ref = check.get('for_each', {}).get('discovery')
                if discovery_ref:
                    needed_discoveries.add(discovery_ref)
            
            # Find missing discoveries
            missing = needed_discoveries - existing_discoveries
            
            if not missing:
                return True  # All good
            
            # Add missing discoveries
            for missing_discovery in missing:
                # Extract resource type from discovery_id
                parts = missing_discovery.split('.')
                if len(parts) >= 3:
                    resource_type = parts[2]
                    
                    # Create a simple discovery step
                    new_discovery = {
                        "discovery_id": missing_discovery,
                        "for_each": f"aws.{service_name}.{resource_type.rstrip('s')}" if resource_type.endswith('s') else None,
                        "calls": [{
                            "client": service_name,
                            "action": f"describe_{resource_type}",
                            "save_as": resource_type,
                            "on_error": "continue"
                        }],
                        "emit": {
                            "item": {
                                "resource_id": "{{ item.id }}",
                                "compliant": "{{ true }}"
                            }
                        }
                    }
                    
                    # Remove for_each if None
                    if new_discovery['for_each'] is None:
                        del new_discovery['for_each']
                        new_discovery['calls'][0] = {
                            "client": service_name,
                            "action": f"list_{resource_type}",
                            "save_as": resource_type,
                            "on_error": "continue"
                        }
                        new_discovery['emit'] = {
                            "items_for": f"{resource_type}[]",
                            "as": resource_type.rstrip('s'),
                            "item": {
                                "id": f"{{{{ {resource_type.rstrip('s')}.Id }}}}",
                                "compliant": "{{ true }}"
                            }
                        }
                    
                    data['discovery'].append(new_discovery)
                    print(f"  ✅ Added discovery: {missing_discovery}")
            
            # Save fixed file
            with open(rules_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
            
            self.fixed_count += 1
            return True
            
        except Exception as e:
            print(f"  ❌ Error fixing {service_name}: {str(e)}")
            self.error_count += 1
            return False
    
    def fix_all_services(self):
        """Fix all services"""
        
        print(f"\n{'='*80}")
        print(f"FIXING DISCOVERY REFERENCES")
        print(f"{'='*80}\n")
        
        services = []
        for service_dir in sorted(self.services_dir.iterdir()):
            if service_dir.is_dir():
                rules_file = service_dir / "rules" / f"{service_dir.name}.yaml"
                if rules_file.exists():
                    services.append(service_dir.name)
        
        print(f"Services to fix: {len(services)}\n")
        
        for i, service_name in enumerate(services, 1):
            print(f"[{i}/{len(services)}] {service_name}")
            self.fix_service(service_name)
        
        print(f"\n{'='*80}")
        print(f"FIX COMPLETE")
        print(f"{'='*80}")
        print(f"✅ Fixed: {self.fixed_count}")
        print(f"❌ Errors: {self.error_count}")
        print(f"\nNext: Run validation again")

if __name__ == '__main__':
    fixer = DiscoveryFixer()
    fixer.fix_all_services()

