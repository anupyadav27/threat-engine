#!/usr/bin/env python3
"""
PATTERN-BASED FIXER
Fix common API method patterns across services
"""

import yaml
from pathlib import Path
import re

class PatternFixer:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        
        # Common pattern fixes
        self.method_patterns = {
            # SQS patterns
            'sqs': {
                'describe_queues': 'list_queues',
                'get_queue': 'get_queue_url',
            },
            
            # SNS patterns
            'sns': {
                'describe_topics': 'list_topics',
                'describe_subscriptions': 'list_subscriptions',
                'describe_topics_not_publicly_accessibles': 'get_topic_attributes',
            },
            
            # API Gateway REST API
            'apigateway': {
                'describe_stages': 'get_stages',
                'describe_resources': 'get_resources',
                'describe_authorizers': 'get_authorizers',
                'describe_usageplans': 'get_usage_plans',
                'describe_certificates': 'get_client_certificates',
                'describe_restapis': 'get_rest_apis',
                'describe_throttles': 'get_stages',  # Throttle is in stage settings
                'describe_apikeys': 'get_api_keys',
                'describe_requestvalidators': 'get_request_validators',
            },
            
            # API Gateway V2 (HTTP/WebSocket)
            'apigatewayv2': {
                'describe_api_logging': 'get_apis',
                'describe_stages': 'get_stages',
            },
            
            # AppSync
            'appsync': {
                'describe_field_logging': 'get_graphql_api',
            },
            
            # Bedrock
            'bedrock': {
                'describe_model_logging': 'list_foundation_models',
            },
            
            # Route53
            'route53': {
                'describe_healthcheck_logging': 'list_health_checks',
                'describe_trafficpolicys': 'list_traffic_policies',
                'describe_hostedzones': 'list_hosted_zones',
                'describe_recordsets': 'list_resource_record_sets',
            },
            
            # WAF
            'waf': {
                'describe_webacl_logging': 'get_logging_configuration',
                'describe_rules': 'list_rules',
                'describe_ipsets': 'list_ip_sets',
                'describe_regexpatternsets': 'list_regex_pattern_sets',
                'describe_rulegroups': 'list_rule_groups',
            },
            
            # X-Ray
            'xray': {
                'describe_samplingrules': 'get_sampling_rules',
            },
            
            # SSM
            'ssm': {
                'describe_manageds': 'describe_instance_information',
                'describe_baselines': 'describe_patch_baselines',
                'describe_restapis': 'describe_automation_executions',
                'describe_automations': 'describe_automation_executions',
                'describe_patchgroups': 'describe_patch_groups',
                'describe_patchbaselines': 'describe_patch_baselines',
            },
            
            # Step Functions
            'stepfunctions': {
                'describe_statemachine_logging': 'describe_state_machine',
            },
            
            # Storage Gateway
            'storagegateway': {
                'describe_gateways': 'list_gateways',
            },
            
            # Transfer Family
            'transfer': {
                'list_transfers': 'list_servers',
            },
            
            # Workspaces
            'workspaces': {
                'list_workspacess': 'describe_workspaces',
                'describe_resources': 'describe_workspaces',
            },
        }
        
        # Service name corrections (additional)
        self.service_name_fixes = {
            'cognito': 'cognito-idp',
            'directoryservice': 'ds',
            'elastic': 'es',
        }
        
        self.fixes_applied = 0
        self.services_fixed = []
        
    def fix_service_patterns(self, service_name):
        """Fix patterns for a specific service"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return 0
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return 0
            
            fixed_count = 0
            
            # Get pattern mappings for this service
            patterns = self.method_patterns.get(service_name, {})
            
            if not patterns:
                return 0
            
            # Fix in discovery calls
            for disc_step in data.get('discovery', []):
                for call in disc_step.get('calls', []):
                    action = call.get('action')
                    if action in patterns:
                        call['action'] = patterns[action]
                        fixed_count += 1
            
            if fixed_count > 0:
                # Save fixed file
                with open(rules_file, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
                
                self.fixes_applied += fixed_count
                self.services_fixed.append(service_name)
            
            return fixed_count
            
        except Exception as e:
            print(f"  ❌ Error fixing {service_name}: {str(e)}")
            return 0
    
    def fix_additional_service_names(self, service_name):
        """Fix additional service name issues"""
        
        if service_name not in self.service_name_fixes:
            return 0
        
        correct_name = self.service_name_fixes[service_name]
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return 0
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            fixed_count = 0
            
            # Update service name
            if data.get('service') == service_name:
                data['service'] = correct_name
                fixed_count += 1
            
            # Fix client names
            for disc_step in data.get('discovery', []):
                for call in disc_step.get('calls', []):
                    if call.get('client') == service_name:
                        call['client'] = correct_name
                        fixed_count += 1
            
            if fixed_count > 0:
                with open(rules_file, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
                
                self.fixes_applied += fixed_count
            
            return fixed_count
            
        except Exception as e:
            return 0
    
    def fix_all_patterns(self):
        """Fix patterns across all services"""
        
        print(f"\n{'='*80}")
        print(f"PATTERN-BASED FIXER")
        print(f"{'='*80}\n")
        
        print("Fixing method patterns...\n")
        
        # Fix method patterns
        for service_name in self.method_patterns.keys():
            fixed = self.fix_service_patterns(service_name)
            if fixed > 0:
                print(f"  ✅ {service_name}: {fixed} method patterns fixed")
        
        print("\nFixing additional service names...\n")
        
        # Fix service names
        for service_name in self.service_name_fixes.keys():
            fixed = self.fix_additional_service_names(service_name)
            if fixed > 0:
                correct = self.service_name_fixes[service_name]
                print(f"  ✅ {service_name} → {correct}: {fixed} references fixed")
        
        print(f"\n{'='*80}")
        print(f"FIX SUMMARY")
        print(f"{'='*80}")
        print(f"Services fixed: {len(set(self.services_fixed))}")
        print(f"Total pattern fixes: {self.fixes_applied}")
        
        if self.services_fixed:
            print(f"\nFixed services: {', '.join(sorted(set(self.services_fixed)))}")

if __name__ == '__main__':
    print("🔧 Starting Pattern-Based Fixer...\n")
    
    fixer = PatternFixer()
    fixer.fix_all_patterns()
    
    print(f"\n🎉 Pattern fixes complete!")
    print(f"\nNext: Re-run test_driven_validator.py to verify improvements")

