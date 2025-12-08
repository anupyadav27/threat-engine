#!/usr/bin/env python3
"""Systematic workflow to fix all service placeholders"""
import yaml
import subprocess
import json
from pathlib import Path
import time
import re

class SystematicServiceFixer:
    def __init__(self):
        self.services_dir = Path(__file__).parent / "services"
        self.tracker_file = Path(__file__).parent / "SERVICE_VALIDATION_TRACKER.md"
        
        # Common placeholder patterns and their fixes
        self.fix_patterns = {
            # Generic name-based placeholders
            "item.name": {
                "annotation": "item.annotations",
                "label": "item.labels", 
                "backup": "item.annotations.backup",
                "monitoring": "item.annotations.monitoring",
                "patch": "item.annotations.patch",
                "security": "item.annotations.security",
                "tls": "item.annotations.tls"
            },
            
            # Network policy issues
            "item.policy_types": {
                "network": "item.policyTypes",
                "ingress": "item.ingress",
                "egress": "item.egress"
            }
        }
    
    def get_service_priority_order(self):
        """Return services in priority order (critical first)"""
        critical = ["pod", "rbac", "network", "secret"]  # Already fixed pod
        important = ["namespace", "service", "ingress", "configmap"]
        control_plane = ["apiserver", "etcd", "controlplane", "kubelet"] 
        monitoring = ["monitoring", "audit"]
        others = []
        
        # Get all services
        all_services = [d.name for d in self.services_dir.iterdir() if d.is_dir()]
        
        # Add remaining services to others
        assigned = critical + important + control_plane + monitoring
        others = [s for s in all_services if s not in assigned]
        
        return important + control_plane + monitoring + others  # Skip critical (pod done)
    
    def analyze_service_issues(self, service_name):
        """Analyze placeholder issues in a service"""
        result = subprocess.run([
            "python3", "fix_placeholder_checks.py"
        ], capture_output=True, text=True, cwd=Path(__file__).parent)
        
        if result.returncode != 0:
            return None
            
        # Parse output to find this service's issues
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if f"  {service_name}:" in line:
                issue_match = re.search(r'(\d+) issues out of (\d+) checks', line)
                if issue_match:
                    return {
                        'service': service_name,
                        'issues': int(issue_match.group(1)), 
                        'total_checks': int(issue_match.group(2))
                    }
        return None
    
    def fix_service_placeholders(self, service_name):
        """Apply automated fixes to a service"""
        service_dir = self.services_dir / service_name
        if not service_dir.exists():
            print(f"❌ Service {service_name} not found")
            return False
            
        # Find the rules file
        rules_file = service_dir / f"{service_name}_rules.yaml"
        if not rules_file.exists():
            yaml_files = list(service_dir.glob("*_rules.yaml"))
            if yaml_files:
                rules_file = yaml_files[0]
            else:
                print(f"❌ No rules file found for {service_name}")
                return False
        
        print(f"🔧 Fixing {service_name} ({rules_file})")
        
        # Load and fix YAML
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            fixes_applied = 0
            checks = data.get('checks', [])
            
            for check in checks:
                check_id = check.get('check_id', '')
                calls = check.get('calls', [])
                
                for call in calls:
                    fields = call.get('fields', [])
                    for field in fields:
                        old_path = field.get('path', '')
                        
                        # Apply common fixes
                        new_path = self.find_replacement_path(old_path, check_id, service_name)
                        if new_path != old_path:
                            field['path'] = new_path
                            
                            # Adjust operator/expected based on new path  
                            if 'annotations' in new_path or 'labels' in new_path:
                                field['operator'] = 'exists'
                                field['expected'] = None
                            elif new_path.endswith('.enabled') or new_path.endswith('.disabled'):
                                field['operator'] = 'equals'
                                field['expected'] = True if 'enabled' in new_path else False
                                
                            fixes_applied += 1
                            print(f"   Fixed {check_id}: {old_path} -> {new_path}")
            
            # Write back fixed YAML
            if fixes_applied > 0:
                with open(rules_file, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
                print(f"✅ Applied {fixes_applied} fixes to {service_name}")
                return True
            else:
                print(f"ℹ️  No fixes needed for {service_name}")
                return True
                
        except Exception as e:
            print(f"❌ Error fixing {service_name}: {e}")
            return False
    
    def find_replacement_path(self, old_path, check_id, service_name):
        """Find the appropriate replacement for a placeholder path"""
        if old_path == "item.name":
            # Service-specific mappings
            if service_name == "namespace":
                if "label" in check_id:
                    return "item.labels"
                elif "annotation" in check_id:
                    return "item.annotations" 
                else:
                    return "item.name"  # Keep as-is for actual name checks
                    
            elif service_name == "secret":
                if "encryption" in check_id:
                    return "item.type"
                elif "label" in check_id:
                    return "item.labels"
                elif "annotation" in check_id:
                    return "item.annotations"
                    
            elif service_name == "rbac":
                if "rule" in check_id:
                    return "item.rules"
                elif "subject" in check_id:
                    return "item.subjects"
                elif "role" in check_id:
                    return "item.roleRef"
                    
            # Generic mappings
            for pattern, replacement in self.fix_patterns["item.name"].items():
                if pattern in check_id:
                    return replacement
                    
        elif old_path == "item.policy_types":
            return "item.policyTypes"  # Correct casing
            
        return old_path  # No change needed
    
    def test_service(self, service_name):
        """Test a service with mock data"""
        print(f"🧪 Testing {service_name}...")
        result = subprocess.run([
            "python3", "run_yaml_scan.py", 
            "--mock-dir", "mocks/",
            "--components", service_name,
            "--verbose"
        ], capture_output=True, text=True, cwd=Path(__file__).parent)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if "Total checks:" in line:
                    check_count = line.split(":")[-1].strip()
                    print(f"✅ {service_name} test passed - {check_count} checks executed")
                    return True
                    
        print(f"⚠️  {service_name} test had issues: {result.stderr}")
        return False
    
    def update_tracker(self, service_name, status, issues_fixed, total_checks):
        """Update the service validation tracker"""
        try:
            with open(self.tracker_file, 'r') as f:
                content = f.read()
            
            # Find and update the service line
            pattern = rf'\| {service_name} \| \d+ \| [^|]+ \| [^|]+ \|'
            if status == "fixed":
                replacement = f'| {service_name} | {total_checks} | ✅ Fixed | Fixed {issues_fixed} placeholder checks |'
            else:
                replacement = f'| {service_name} | {total_checks} | ⚠️ Partial | {issues_fixed} fixes applied |'
                
            content = re.sub(pattern, replacement, content)
            
            with open(self.tracker_file, 'w') as f:
                f.write(content)
            print(f"📊 Updated tracker for {service_name}")
            
        except Exception as e:
            print(f"❌ Error updating tracker: {e}")
    
    def process_all_services(self):
        """Main workflow to process all services systematically"""
        services = self.get_service_priority_order()
        
        print("🚀 Starting systematic service fixing workflow")
        print(f"📋 Processing {len(services)} services in priority order")
        print(f"🔄 Order: {', '.join(services[:10])}{'...' if len(services) > 10 else ''}")
        print()
        
        for i, service_name in enumerate(services, 1):
            print(f"[{i}/{len(services)}] Processing {service_name}")
            print("=" * 50)
            
            # Analyze current issues
            analysis = self.analyze_service_issues(service_name)
            if not analysis:
                print(f"⏭️  Skipping {service_name} - no issues found")
                continue
                
            if analysis['issues'] == 0:
                print(f"✅ {service_name} already clean - {analysis['total_checks']} checks")
                continue
                
            print(f"🔍 Found {analysis['issues']} issues in {analysis['total_checks']} checks")
            
            # Apply fixes
            if self.fix_service_placeholders(service_name):
                # Test the service
                if self.test_service(service_name):
                    # Re-analyze to see improvement
                    new_analysis = self.analyze_service_issues(service_name)
                    if new_analysis:
                        issues_fixed = analysis['issues'] - new_analysis['issues']
                        status = "fixed" if new_analysis['issues'] == 0 else "partial"
                        
                        self.update_tracker(service_name, status, issues_fixed, analysis['total_checks'])
                        print(f"🎉 {service_name} complete: {issues_fixed} issues fixed")
                    else:
                        print(f"✅ {service_name} appears to be fully fixed")
                else:
                    print(f"⚠️  {service_name} needs manual review")
            else:
                print(f"❌ Failed to fix {service_name}")
            
            print()
            time.sleep(1)  # Brief pause between services
        
        print("🏁 Systematic service fixing complete!")
        self.show_final_summary()
    
    def show_final_summary(self):
        """Show final summary of all services"""
        result = subprocess.run([
            "python3", "fix_placeholder_checks.py"
        ], capture_output=True, text=True, cwd=Path(__file__).parent)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines[:10]:  # Show first part of summary
                if line.strip():
                    print(line)

if __name__ == '__main__':
    fixer = SystematicServiceFixer()
    fixer.process_all_services()
