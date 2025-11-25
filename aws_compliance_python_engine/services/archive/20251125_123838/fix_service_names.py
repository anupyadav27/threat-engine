#!/usr/bin/env python3
"""
SERVICE NAME FIXER
Fix known service name mismatches that prevent proper validation
"""

import yaml
from pathlib import Path
import shutil
from datetime import datetime

class ServiceNameFixer:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        
        # Known service name mappings
        self.service_mappings = {
            # Service folder name → Correct boto3 service name
            'identitycenter': 'identitystore',
            'kinesisfirehose': 'firehose',
            'kinesisvideostreams': 'kinesisvideo',
            'timestream': 'timestream-query',  # or timestream-write
            'workflows': None,  # Not a standalone service, mark for removal
            'fargate': None,  # Part of ECS, not standalone
            'edr': None,  # Not a real service
            'no': None,  # Invalid placeholder
        }
        
        # Services that are part of another service
        self.merged_services = {
            'vpc': 'ec2',  # VPC operations are in EC2 client
            'vpcflowlogs': 'ec2',
            'ebs': 'ec2',
            'eip': 'ec2',
        }
        
        self.fixes_applied = 0
        self.services_fixed = []
        
    def fix_service_client_name(self, service_dir_name, correct_client_name):
        """Fix the client name in all discovery steps"""
        
        rules_file = self.services_dir / service_dir_name / "rules" / f"{service_dir_name}.yaml"
        
        if not rules_file.exists():
            return False
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            fixed_in_file = 0
            
            # Update service name in metadata
            if data.get('service') == service_dir_name:
                data['service'] = correct_client_name
                fixed_in_file += 1
            
            # Fix client names in discovery calls
            for disc_step in data.get('discovery', []):
                for call in disc_step.get('calls', []):
                    if call.get('client') == service_dir_name:
                        call['client'] = correct_client_name
                        fixed_in_file += 1
            
            if fixed_in_file > 0:
                # Save fixed file
                with open(rules_file, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
                
                print(f"  ✅ Fixed {fixed_in_file} references: {service_dir_name} → {correct_client_name}")
                self.fixes_applied += fixed_in_file
                self.services_fixed.append(service_dir_name)
                return True
            
            return False
            
        except Exception as e:
            print(f"  ❌ Error fixing {service_dir_name}: {str(e)}")
            return False
    
    def mark_invalid_service(self, service_dir_name):
        """Mark an invalid service (not a real AWS service)"""
        
        rules_file = self.services_dir / service_dir_name / "rules" / f"{service_dir_name}.yaml"
        
        if not rules_file.exists():
            return False
        
        # Add a comment to the file marking it as invalid
        try:
            with open(rules_file, 'r') as f:
                content = f.read()
            
            header = f"""# WARNING: '{service_dir_name}' is not a valid standalone AWS service
# This service should be removed or merged with the correct service
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Status: INVALID

"""
            with open(rules_file, 'w') as f:
                f.write(header + content)
            
            print(f"  ⚠️  Marked as invalid: {service_dir_name}")
            return True
            
        except Exception as e:
            print(f"  ❌ Error marking {service_dir_name}: {str(e)}")
            return False
    
    def fix_all_service_names(self):
        """Fix all known service name issues"""
        
        print(f"\n{'='*80}")
        print(f"SERVICE NAME FIXER")
        print(f"{'='*80}\n")
        
        # Fix service name mappings
        print("Fixing service name mappings...\n")
        for service_dir_name, correct_name in self.service_mappings.items():
            if correct_name:
                print(f"[FIX] {service_dir_name} → {correct_name}")
                self.fix_service_client_name(service_dir_name, correct_name)
            else:
                print(f"[MARK] {service_dir_name} → Invalid service")
                self.mark_invalid_service(service_dir_name)
        
        # Fix merged services
        print("\nFixing merged services (using parent client)...\n")
        for service_dir_name, parent_service in self.merged_services.items():
            print(f"[MERGE] {service_dir_name} → {parent_service} client")
            self.fix_service_client_name(service_dir_name, parent_service)
        
        print(f"\n{'='*80}")
        print(f"FIX SUMMARY")
        print(f"{'='*80}")
        print(f"Services fixed: {len(self.services_fixed)}")
        print(f"Total fixes: {self.fixes_applied}")
        print(f"\nFixed services: {', '.join(self.services_fixed)}")

if __name__ == '__main__':
    print("🔧 Starting Service Name Fixer...\n")
    
    fixer = ServiceNameFixer()
    fixer.fix_all_service_names()
    
    print(f"\n🎉 Service name fixes complete!")
    print(f"\nNext: Re-run test_driven_validator.py to verify improvements")

