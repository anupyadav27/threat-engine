#!/usr/bin/env python3
"""
BOTO3 SCHEMA-BASED AUTO-FIXER
Automatically fixes service YAML files based on comprehensive Boto3 validation
"""

import boto3
import yaml
import json
from pathlib import Path
from datetime import datetime

class Boto3SchemaAutoFixer:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.session = boto3.Session()
        
        # Load validation report and recommendations
        with open(self.services_dir / "BOTO3_FIX_RECOMMENDATIONS.json") as f:
            self.recommendations = json.load(f)
        
        with open(self.services_dir / "COMPREHENSIVE_VALIDATION_REPORT.json") as f:
            self.validation_report = json.load(f)
        
        # Manual fix mappings for common patterns
        self.operation_fixes = {
            # Pattern: incorrect -> correct
            'describe_contacts': 'list_alternate_contacts',
            'describe_v2api_logging': 'get_apis',  # For API Gateway V2
            'list_resource_encryption': 'get_resources',  # Get resources then check encryption
            'list_stage_logging': 'get_stages',  # Get stages then check logging
            'list_restapi_logging': 'get_rest_apis',  # Get APIs then check logging
            'list_resource_logging': 'get_resources',
            'describe_workgroups': 'list_work_groups',
            'list_cognitos': 'list_user_pools',
            'list_budgets_actions': 'describe_budget_actions_for_budget',
            'list_stacks_configuration': 'describe_stacks',
            'list_distribution_logging': 'list_distributions',
            'list_trail_logging': 'describe_trails',
            'list_loggroup_encryption': 'describe_log_groups',
            'list_loggroup_logging': 'describe_log_groups',
            'list_logstream_encryption': 'describe_log_streams',
            'list_artifacts': 'list_repositories',
            'list_builds_encryption': 'batch_get_builds',
            'list_builds_configuration': 'list_builds',
            'describe_domainconfigs': 'describe_user_pool_domain',
            'list_userpool_logging': 'describe_user_pool',
            'list_rules_logging': 'describe_config_rules',
            'describe_controls': 'list_enabled_controls',
            'list_cost_metrics': 'get_cost_and_usage',
            'describe_anomalys': 'get_anomalies',
            'describe_anomaly_monitors': 'get_anomaly_monitors',
            'describe_budgets': 'describe_budgets',
            'describe_tasks': 'describe_task_execution',
            'describe_graphs': 'list_graphs',
            'list_connections_encryption': 'describe_connections',
            'describe_services': 'describe_directories',
            'list_services_encryption': 'describe_directories',
            'describe_tasks_encryption': 'describe_replication_tasks',
            'list_tasks_configuration': 'describe_replication_tasks',
            'describe_instances_encryption': 'describe_db_clusters',
            'list_instances_configuration': 'describe_db_clusters',
            'list_tables_encryption': 'describe_table',
            'describe_volumes_encryption': 'describe_volumes',
            'list_volumes_configuration': 'describe_volumes',
            'list_snapshots_encryption': 'describe_snapshots',
            'describe_instances': 'describe_instances',
            'describe_images': 'describe_images',
            'describe_volumes': 'describe_volumes',
            'describe_repositories_encryption': 'describe_repositories',
            'describe_services_configuration': 'describe_services',
            'describe_services_encryption': 'describe_services',
            'describe_filesystems': 'describe_file_systems',
            'list_filesystems_encryption': 'describe_file_systems',
            'list_ips_configuration': 'describe_addresses',
            'describe_clusters': 'describe_cluster',
            'list_cluster_logging': 'describe_cluster',
            'describe_domains_encryption': 'describe_domain',
            'list_domains_configuration': 'describe_domain',
            'describe_clusters_encryption': 'describe_cache_clusters',
            'list_clusters_configuration': 'describe_cache_clusters',
            'describe_environments': 'describe_environments',
            'list_environment_logging': 'describe_environments',
            'describe_loadbalancers': 'describe_load_balancers',
            'describe_targetgroups': 'describe_target_groups',
            'list_loadbalancer_logging': 'describe_load_balancer_attributes',
            'describe_clusters_encryption': 'describe_cluster',
            'list_clusters_logging': 'describe_cluster',
            'describe_eventbuses': 'describe_event_bus',
            'describe_archives': 'describe_archive',
            'describe_connections': 'describe_connection',
            'describe_rules': 'describe_rule',
            'list_eventbus_logging': 'describe_event_bus',
            'list_deliverystreams_encryption': 'describe_delivery_stream',
            'describe_filesystems_encryption': 'describe_file_systems',
            'describe_vaults': 'describe_vault',
            'describe_accelerators': 'describe_accelerator',
            'describe_databases': 'get_databases',
            'list_database_encryption': 'get_database',
            'describe_detectors': 'get_detector',
            'list_detector_logging': 'get_detector',
            'list_iam_users': 'list_users',
            'describe_policies': 'get_policy',
            'describe_roles': 'get_role',
            'list_functions_encryption': 'get_function',
            'list_instance_encryption': 'get_instance',
            'describe_sessions': 'list_classification_jobs',
            'describe_buckets': 'list_buckets',
            'list_account_encryption': 'list_accounts',
            'describe_vpcs': 'describe_vpcs',
            'describe_securitygroups': 'describe_security_groups',
            'describe_subnets': 'describe_subnets',
        }
        
        self.fixes_applied = 0
        self.services_fixed = []
    
    def fix_service_file(self, service_name):
        """Fix a single service YAML file"""
        
        rules_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not rules_file.exists():
            return 0
        
        try:
            with open(rules_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return 0
            
            fixed_count = 0
            
            # Fix discovery steps
            for disc_step in data.get('discovery', []):
                for call in disc_step.get('calls', []):
                    action = call.get('action')
                    
                    # Apply fixes
                    if action and action in self.operation_fixes:
                        new_action = self.operation_fixes[action]
                        call['action'] = new_action
                        fixed_count += 1
                        print(f"    ✅ {action} → {new_action}")
            
            if fixed_count > 0:
                # Save fixed file
                with open(rules_file, 'w') as f:
                    yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)
                
                self.fixes_applied += fixed_count
                self.services_fixed.append(service_name)
            
            return fixed_count
            
        except Exception as e:
            print(f"    ❌ Error: {str(e)}")
            return 0
    
    def fix_all_services(self):
        """Fix all services based on recommendations"""
        
        print(f"\n{'='*80}")
        print(f"BOTO3 SCHEMA-BASED AUTO-FIXER")
        print(f"{'='*80}\n")
        
        print(f"Applying fixes based on comprehensive validation...\n")
        
        # Get unique services from recommendations
        services_to_fix = set()
        for fix in self.recommendations['detailed_fixes']:
            services_to_fix.add(fix['service'])
        
        # Sort for consistent output
        services_to_fix = sorted(services_to_fix)
        
        print(f"Services to fix: {len(services_to_fix)}\n")
        
        for idx, service_name in enumerate(services_to_fix, 1):
            print(f"[{idx}/{len(services_to_fix)}] {service_name}")
            
            fixed = self.fix_service_file(service_name)
            
            if fixed == 0:
                print(f"    ⚠️  No automatic fixes available")
        
        print(f"\n{'='*80}")
        print(f"FIX SUMMARY")
        print(f"{'='*80}")
        print(f"Services processed: {len(services_to_fix)}")
        print(f"Services fixed: {len(self.services_fixed)}")
        print(f"Total fixes applied: {self.fixes_applied}")
        
        if self.services_fixed:
            print(f"\nFixed services: {', '.join(sorted(self.services_fixed))}")
        
        print(f"\nNext: Re-run comprehensive_boto3_validator.py to verify")

if __name__ == '__main__':
    print("🔧 Starting Boto3 Schema-Based Auto-Fixer...\n")
    
    fixer = Boto3SchemaAutoFixer()
    fixer.fix_all_services()
    
    print(f"\n✅ Auto-fixing complete!")

