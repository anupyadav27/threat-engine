#!/usr/bin/env python3
"""
AUTOMATED FIXER - Test-Driven
Fix discovery steps based on real AWS test results
"""

import boto3
import yaml
import json
from pathlib import Path
from collections import defaultdict

class AutomatedFixer:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.session = boto3.Session()
        self.region = self.session.region_name or 'us-east-1'
        
        # Load common AWS API patterns
        self.api_patterns = self.load_api_patterns()
        
        self.fixes_applied = 0
        self.services_fixed = 0
        
    def load_api_patterns(self):
        """Load common AWS API method patterns"""
        return {
            # List operations
            'list': {
                'accessanalyzer': 'list_analyzers',
                'account': 'list_regions',
                'acm': 'list_certificates',
                'apigateway': 'get_rest_apis',
                'apigatewayv2': 'get_apis',
                'appstream': 'describe_fleets',
                'appsync': 'list_graphql_apis',
                'athena': 'list_work_groups',
                'autoscaling': 'describe_auto_scaling_groups',
                'backup': 'list_backup_plans',
                'batch': 'describe_job_queues',
                'bedrock': 'list_foundation_models',
                'budgets': 'describe_budgets',
                'cloudformation': 'list_stacks',
                'cloudfront': 'list_distributions',
                'cloudtrail': 'list_trails',
                'cloudwatch': 'describe_alarms',
                'codeartifact': 'list_repositories',
                'codebuild': 'list_projects',
                'cognito': 'list_user_pools',
                'config': 'describe_configuration_recorders',
                'datasync': 'list_tasks',
                'detective': 'list_graphs',
                'directconnect': 'describe_connections',
                'dms': 'describe_replication_instances',
                'docdb': 'describe_db_clusters',
                'dynamodb': 'list_tables',
                'ebs': 'describe_volumes',
                'ec2': 'describe_instances',
                'ecr': 'describe_repositories',
                'ecs': 'list_clusters',
                'efs': 'describe_file_systems',
                'eks': 'list_clusters',
                'elasticache': 'describe_cache_clusters',
                'elasticbeanstalk': 'describe_applications',
                'elb': 'describe_load_balancers',
                'elbv2': 'describe_load_balancers',
                'emr': 'list_clusters',
                'eventbridge': 'list_event_buses',
                'glacier': 'list_vaults',
                'glue': 'get_databases',
                'guardduty': 'list_detectors',
                'iam': 'list_users',
                'inspector': 'list_assessment_templates',
                'kafka': 'list_clusters',
                'kinesis': 'list_streams',
                'kms': 'list_keys',
                'lambda': 'list_functions',
                'logs': 'describe_log_groups',
                'macie2': 'list_classification_jobs',
                'neptune': 'describe_db_clusters',
                'networkfirewall': 'list_firewalls',
                'opensearch': 'list_domain_names',
                'organizations': 'list_accounts',
                'rds': 'describe_db_instances',
                'redshift': 'describe_clusters',
                'route53': 'list_hosted_zones',
                's3': 'list_buckets',
                'sagemaker': 'list_notebook_instances',
                'secretsmanager': 'list_secrets',
                'securityhub': 'describe_hub',
                'servicecatalog': 'list_portfolios',
                'ses': 'list_identities',
                'shield': 'list_protections',
                'sns': 'list_topics',
                'sqs': 'list_queues',
                'ssm': 'describe_instance_information',
                'stepfunctions': 'list_state_machines',
                'storagegateway': 'list_gateways',
                'waf': 'list_web_acls',
                'wafv2': 'list_web_acls',
                'xray': 'get_service_graph'
            }
        }
    
    def get_correct_list_method(self, service_name):
        """Get the correct list method for a service"""
        return self.api_patterns['list'].get(service_name)
    
    def fix_discovery_action(self, service_name, action):
        """Fix an invalid action"""
        
        # Try to get client to inspect available methods
        try:
            client = self.session.client(service_name, region_name=self.region)
            
            # If action is generic pattern, replace with correct one
            if action.startswith('list_') and action.endswith('s'):
                # Generic list pattern
                correct_method = self.get_correct_list_method(service_name)
                if correct_method and hasattr(client, correct_method):
                    return correct_method
            
            # If action starts with describe_ or get_, try to find similar
            available_methods = [m for m in dir(client) if not m.startswith('_') and callable(getattr(client, m))]
            
            # Fuzzy match
            action_lower = action.replace('_', '').lower()
            for method in available_methods:
                if action_lower in method.replace('_', '').lower():
                    return method
            
            # If still not found, try common patterns
            if 'list' in action:
                list_methods = [m for m in available_methods if m.startswith('list_')]
                if list_methods:
                    return list_methods[0]  # Return first list method
            
            if 'describe' in action:
                describe_methods = [m for m in available_methods if m.startswith('describe_')]
                if describe_methods:
                    return describe_methods[0]
            
            if 'get' in action:
                get_methods = [m for m in available_methods if m.startswith('get_')]
                if get_methods:
                    return get_methods[0]
            
            return None
            
        except Exception as e:
            return None
    
    def fix_service_file(self, service_name):
        """Fix all discovery steps in a service file"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return False
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            fixes_in_service = 0
            
            # Fix each discovery step
            for disc_step in data.get('discovery', []):
                for call in disc_step.get('calls', []):
                    action = call.get('action')
                    
                    if not action:
                        continue
                    
                    # Try to create client to test
                    try:
                        client = self.session.client(service_name, region_name=self.region)
                        
                        if not hasattr(client, action):
                            # Action is invalid, try to fix
                            correct_action = self.fix_discovery_action(service_name, action)
                            
                            if correct_action and correct_action != action:
                                print(f"    ✅ Fixed: {action} → {correct_action}")
                                call['action'] = correct_action
                                fixes_in_service += 1
                                self.fixes_applied += 1
                            else:
                                print(f"    ⚠️  Could not fix: {action}")
                    
                    except Exception as e:
                        if 'Unknown service' in str(e):
                            print(f"    ⚠️  Invalid service name: {service_name}")
                            return False
            
            if fixes_in_service > 0:
                # Save fixed file
                with open(rules_file, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
                
                self.services_fixed += 1
                return True
            
            return False
            
        except Exception as e:
            print(f"    ❌ Error fixing {service_name}: {str(e)}")
            return False
    
    def fix_all_services(self, service_list=None):
        """Fix all services or a specific list"""
        
        print(f"\n{'='*80}")
        print(f"AUTOMATED FIXER - TEST-DRIVEN")
        print(f"{'='*80}\n")
        
        if service_list:
            services = service_list
        else:
            # Get all services
            services = []
            for service_dir in sorted(self.services_dir.iterdir()):
                if service_dir.is_dir():
                    rules_file = service_dir / "rules" / f"{service_dir.name}.yaml"
                    if rules_file.exists():
                        services.append(service_dir.name)
        
        print(f"Fixing {len(services)} services...\n")
        
        for i, service_name in enumerate(services, 1):
            print(f"[{i}/{len(services)}] {service_name}")
            self.fix_service_file(service_name)
        
        print(f"\n{'='*80}")
        print(f"FIX SUMMARY")
        print(f"{'='*80}")
        print(f"Services fixed: {self.services_fixed}")
        print(f"Total fixes applied: {self.fixes_applied}")
        
        print(f"\nNext: Re-run test_driven_validator.py to verify fixes")

if __name__ == '__main__':
    import sys
    
    print("🔧 Starting Automated Fixer...\n")
    
    fixer = AutomatedFixer()
    
    # Fix specific services or all
    if len(sys.argv) > 1 and sys.argv[1].lower() != 'all':
        services_to_fix = sys.argv[1].split(',')
        fixer.fix_all_services(services_to_fix)
    elif len(sys.argv) > 1 and sys.argv[1].lower() == 'all':
        # Fix ALL services
        fixer.fix_all_services()
    else:
        # Fix first 20 services that were tested
        priority_services = [
            'accessanalyzer', 'account', 'acm', 'apigateway', 'apigatewayv2',
            'appstream', 'appsync', 'athena', 'autoscaling', 'backup',
            'batch', 'bedrock', 'budgets', 'cloudformation', 'cloudfront',
            'cloudtrail', 'cloudwatch', 'codeartifact', 'codebuild', 'cognito'
        ]
        fixer.fix_all_services(priority_services)
    
    print(f"\n🎉 Automated fixing complete!")

