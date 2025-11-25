#!/usr/bin/env python3
"""
RULE FIELD MAPPING ANALYZER
Analyze all rules and create mapping of:
1. What fields each check requires
2. What AWS API functions provide those fields
3. Validate discovery provides required fields
"""

import yaml
import json
from pathlib import Path
from collections import defaultdict
import re

class RuleFieldAnalyzer:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.analysis = {}
        
    def extract_fields_from_condition(self, condition, prefix=""):
        """Extract field references from condition"""
        fields = set()
        
        if isinstance(condition, dict):
            # Check for var field
            if 'var' in condition:
                var_field = condition['var']
                fields.add(var_field)
            
            # Check for nested conditions (all, any)
            if 'all' in condition:
                for sub_cond in condition['all']:
                    fields.update(self.extract_fields_from_condition(sub_cond, prefix))
            
            if 'any' in condition:
                for sub_cond in condition['any']:
                    fields.update(self.extract_fields_from_condition(sub_cond, prefix))
        
        return fields
    
    def extract_emitted_fields(self, discovery_step):
        """Extract fields that a discovery step emits"""
        emitted_fields = set()
        
        emit = discovery_step.get('emit', {})
        item = emit.get('item', {})
        
        for field_name in item.keys():
            emitted_fields.add(field_name)
        
        return emitted_fields
    
    def analyze_service(self, service_name):
        """Analyze a single service's rules"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return None
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            service_analysis = {
                'service': service_name,
                'total_checks': len(data.get('checks', [])),
                'total_discovery': len(data.get('discovery', [])),
                'discovery_map': {},  # discovery_id -> {api_call, emitted_fields}
                'checks': [],  # {rule_id, required_fields, discovery_used, field_coverage}
                'issues': []
            }
            
            # Analyze discovery steps
            for disc in data.get('discovery', []):
                disc_id = disc.get('discovery_id')
                api_calls = []
                
                for call in disc.get('calls', []):
                    api_calls.append({
                        'client': call.get('client'),
                        'action': call.get('action'),
                        'fields': call.get('fields', [])
                    })
                
                emitted_fields = self.extract_emitted_fields(disc)
                
                service_analysis['discovery_map'][disc_id] = {
                    'api_calls': api_calls,
                    'emitted_fields': list(emitted_fields),
                    'depends_on': disc.get('for_each')
                }
            
            # Analyze checks
            for check in data.get('checks', []):
                rule_id = check.get('rule_id')
                discovery_ref = check.get('for_each', {}).get('discovery')
                conditions = check.get('conditions', {})
                
                # Extract required fields
                required_fields = self.extract_fields_from_condition(conditions)
                
                # Check if discovery provides required fields
                if discovery_ref in service_analysis['discovery_map']:
                    provided_fields = set(service_analysis['discovery_map'][discovery_ref]['emitted_fields'])
                    
                    # Extract field base names (remove prefixes like "encryption.", "bucket.")
                    required_base_fields = set()
                    for field in required_fields:
                        # Extract the last part after the last dot
                        parts = field.split('.')
                        if len(parts) > 1:
                            required_base_fields.add(parts[-1])
                        else:
                            required_base_fields.add(field)
                    
                    missing_fields = required_base_fields - provided_fields
                    
                    field_coverage = {
                        'required': list(required_fields),
                        'provided': list(provided_fields),
                        'missing': list(missing_fields),
                        'coverage_pct': 100.0 if not missing_fields else (len(provided_fields) / (len(required_fields) or 1) * 100)
                    }
                    
                    if missing_fields:
                        service_analysis['issues'].append({
                            'type': 'missing_fields',
                            'rule_id': rule_id,
                            'discovery': discovery_ref,
                            'missing_fields': list(missing_fields)
                        })
                else:
                    field_coverage = {
                        'required': list(required_fields),
                        'provided': [],
                        'missing': list(required_fields),
                        'coverage_pct': 0
                    }
                    service_analysis['issues'].append({
                        'type': 'missing_discovery',
                        'rule_id': rule_id,
                        'discovery': discovery_ref
                    })
                
                service_analysis['checks'].append({
                    'rule_id': rule_id,
                    'discovery_used': discovery_ref,
                    'field_coverage': field_coverage
                })
            
            return service_analysis
            
        except Exception as e:
            return {
                'service': service_name,
                'error': str(e)
            }
    
    def analyze_all_services(self):
        """Analyze all services"""
        
        print(f"\n{'='*80}")
        print(f"RULE FIELD MAPPING ANALYSIS")
        print(f"{'='*80}\n")
        
        services = []
        for service_dir in sorted(self.services_dir.iterdir()):
            if service_dir.is_dir():
                rules_file = service_dir / "rules" / f"{service_dir.name}.yaml"
                if rules_file.exists():
                    services.append(service_dir.name)
        
        print(f"Analyzing {len(services)} services...\n")
        
        all_analysis = []
        total_issues = 0
        total_checks = 0
        
        for i, service_name in enumerate(services, 1):
            print(f"[{i}/{len(services)}] {service_name}")
            
            analysis = self.analyze_service(service_name)
            
            if analysis and 'error' not in analysis:
                all_analysis.append(analysis)
                
                issues_count = len(analysis['issues'])
                checks_count = analysis['total_checks']
                
                total_issues += issues_count
                total_checks += checks_count
                
                if issues_count > 0:
                    print(f"  ⚠️  {issues_count} issues found")
                else:
                    print(f"  ✅ {checks_count} checks validated")
            else:
                print(f"  ❌ Error: {analysis.get('error', 'Unknown')}")
        
        # Summary
        print(f"\n{'='*80}")
        print(f"ANALYSIS SUMMARY")
        print(f"{'='*80}")
        print(f"Total services: {len(all_analysis)}")
        print(f"Total checks: {total_checks}")
        print(f"Total issues: {total_issues}")
        
        # Issue breakdown
        issue_types = defaultdict(int)
        for analysis in all_analysis:
            for issue in analysis['issues']:
                issue_types[issue['type']] += 1
        
        print(f"\nIssue breakdown:")
        for issue_type, count in sorted(issue_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  • {issue_type}: {count}")
        
        # Save detailed analysis
        output_file = self.services_dir / "FIELD_MAPPING_ANALYSIS.json"
        with open(output_file, 'w') as f:
            json.dump(all_analysis, f, indent=2)
        
        print(f"\n📄 Detailed analysis: {output_file}")
        
        # Create AWS API mapping
        self.create_aws_api_mapping(all_analysis)
        
        # Create validation report
        self.create_validation_report(all_analysis)
        
        return all_analysis
    
    def create_aws_api_mapping(self, all_analysis):
        """Create mapping of AWS APIs needed"""
        
        print(f"\n{'='*80}")
        print(f"AWS API MAPPING")
        print(f"{'='*80}\n")
        
        api_mapping = {}
        
        for analysis in all_analysis:
            service = analysis['service']
            api_mapping[service] = {
                'list_apis': [],
                'get_apis': [],
                'describe_apis': [],
                'other_apis': []
            }
            
            for disc_id, disc_info in analysis['discovery_map'].items():
                for api_call in disc_info['api_calls']:
                    action = api_call.get('action')
                    
                    if not action:
                        continue
                    
                    if action.startswith('list_'):
                        api_mapping[service]['list_apis'].append(action)
                    elif action.startswith('get_'):
                        api_mapping[service]['get_apis'].append(action)
                    elif action.startswith('describe_'):
                        api_mapping[service]['describe_apis'].append(action)
                    else:
                        api_mapping[service]['other_apis'].append(action)
        
        # Save API mapping
        output_file = self.services_dir / "AWS_API_MAPPING.json"
        with open(output_file, 'w') as f:
            json.dump(api_mapping, f, indent=2)
        
        print(f"📄 API mapping: {output_file}")
        
        # Print summary
        total_apis = sum(
            len(apis['list_apis']) + len(apis['get_apis']) + 
            len(apis['describe_apis']) + len(apis['other_apis'])
            for apis in api_mapping.values()
        )
        
        print(f"\nTotal unique API calls: {total_apis}")
        
        return api_mapping
    
    def create_validation_report(self, all_analysis):
        """Create human-readable validation report"""
        
        report_file = self.services_dir / "FIELD_VALIDATION_REPORT.md"
        
        with open(report_file, 'w') as f:
            f.write("# Rule Field Validation Report\n\n")
            f.write("## Summary\n\n")
            
            total_services = len(all_analysis)
            total_checks = sum(a['total_checks'] for a in all_analysis)
            total_issues = sum(len(a['issues']) for a in all_analysis)
            clean_services = sum(1 for a in all_analysis if len(a['issues']) == 0)
            
            f.write(f"- **Total Services**: {total_services}\n")
            f.write(f"- **Total Checks**: {total_checks}\n")
            f.write(f"- **Total Issues**: {total_issues}\n")
            f.write(f"- **Clean Services**: {clean_services} ({clean_services/total_services*100:.1f}%)\n")
            f.write(f"- **Issues Rate**: {total_issues/total_checks*100:.1f}% of checks\n\n")
            
            # Services with issues
            f.write("## Services with Issues\n\n")
            
            services_with_issues = [a for a in all_analysis if len(a['issues']) > 0]
            services_with_issues.sort(key=lambda x: len(x['issues']), reverse=True)
            
            for analysis in services_with_issues[:20]:  # Top 20
                service = analysis['service']
                issues_count = len(analysis['issues'])
                checks_count = analysis['total_checks']
                
                f.write(f"### {service}\n\n")
                f.write(f"- Checks: {checks_count}\n")
                f.write(f"- Issues: {issues_count}\n")
                f.write(f"- Issue rate: {issues_count/checks_count*100:.1f}%\n\n")
                
                # Show sample issues
                for issue in analysis['issues'][:3]:
                    f.write(f"**Issue**: {issue['type']}\n")
                    f.write(f"- Rule: `{issue['rule_id']}`\n")
                    if 'missing_fields' in issue:
                        f.write(f"- Missing fields: {', '.join(issue['missing_fields'])}\n")
                    f.write("\n")
                
                if len(analysis['issues']) > 3:
                    f.write(f"... and {len(analysis['issues']) - 3} more issues\n\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            f.write("1. **Fix Missing Fields**: Update discovery steps to emit required fields\n")
            f.write("2. **Validate API Calls**: Ensure AWS Boto3 methods match actual service APIs\n")
            f.write("3. **Test with AWS**: Run checks against real AWS accounts to validate\n")
            f.write("4. **Refine Conditions**: Update check conditions to use available fields\n\n")
        
        print(f"📄 Validation report: {report_file}")

if __name__ == '__main__':
    analyzer = RuleFieldAnalyzer()
    analyzer.analyze_all_services()
    
    print(f"\n🎉 Analysis complete!")
    print(f"\nNext steps:")
    print(f"1. Review FIELD_MAPPING_ANALYSIS.json for detailed field mappings")
    print(f"2. Review AWS_API_MAPPING.json to validate AWS API calls")
    print(f"3. Review FIELD_VALIDATION_REPORT.md for human-readable summary")
    print(f"4. Fix identified issues in discovery and check definitions")

