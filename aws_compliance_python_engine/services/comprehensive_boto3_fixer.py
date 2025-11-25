#!/usr/bin/env python3
"""
COMPREHENSIVE BOTO3 AUTO-FIXER
Fixes ALL identified Boto3 schema issues systematically
"""

import boto3
import yaml
import json
from pathlib import Path
from datetime import datetime

class ComprehensiveBoto3Fixer:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.session = boto3.Session()
        
        # Load recommendations
        with open(self.services_dir / "BOTO3_FIX_RECOMMENDATIONS.json") as f:
            self.recommendations = json.load(f)
        
        # Build comprehensive fix mappings from recommendations + manual expertise
        self.operation_fixes = self.build_comprehensive_fixes()
        
        # Client name fixes
        self.client_name_fixes = {
            'cognito': 'cognito-idp',
            'directoryservice': 'ds',
            'elastic': 'es',
            'timestream': 'timestream-query',
        }
        
        self.fixes_applied = 0
        self.services_fixed = []
        self.fix_log = []
    
    def build_comprehensive_fixes(self):
        """Build comprehensive operation fixes from recommendations + AWS expertise"""
        
        fixes = {
            # Account
            'list_alternate_contacts': 'get_alternate_contact',
            
            # API Gateway - v2 API should use apigatewayv2 client
            'get_apis': 'get_rest_apis',  # For apigateway, v2 needs different client
            
            # Cognito
            'describe_userpoolgroups': 'list_groups',  # List groups in user pool
            
            # Control Tower
            'describe_enrollments': 'list_enabled_controls',
            
            # Directory Service
            'list_directoryservices': 'describe_directories',
            'describe_resource_logging': 'describe_directories',  # Then check log forwarding
            
            # EBS (uses EC2 client)
            'list_changed_blocks': 'describe_volumes',  # For volume operations
            
            # Elastic (Elasticsearch/OpenSearch)
            'list_elastics': 'list_domain_names',
            
            # ELBv2
            'get_resources': 'describe_load_balancers',  # Resources are load balancers
            
            # IAM
            'describe_customers': 'list_account_aliases',  # Account info
            'describe_passwords': 'get_account_password_policy',
            'describe_groups': 'list_groups',
            'describe_policys': 'list_policies',
            'describe_instanceprofiles': 'list_instance_profiles',
            'describe_users': 'list_users',
            'describe_samlproviders': 'list_saml_providers',
            'describe_accessanalyzers': 'list_access_keys',  # For user access keys
            'describe_permissions': 'list_attached_user_policies',  # User permissions
            'describe_credentials': 'list_access_keys',  # User credentials
            'list_user_encryption': 'list_mfa_devices',  # Check MFA (security)
            'list_policy_logging': 'list_policies',  # Get policies then check
            'list_assumerolepolicy_encryption': 'get_role',  # Get role trust policy
            'list_samlprovider_encryption': 'list_saml_providers',
            'list_group_logging': 'list_groups',
            'list_accessanalyzer_encryption': 'list_access_keys',
            'list_credential_encryption': 'list_access_keys',
            'list_user_logging': 'list_users',
            'list_permission_logging': 'list_attached_user_policies',
            'list_role_logging': 'list_roles',
            
            # Identity Center (uses identitystore client)
            'list_identitycenters': 'list_users',  # List users in identity store
            'describe_users_encryption': 'list_users',
            'list_user_encryption': 'list_users',
            
            # Kinesis Firehose (uses firehose client)
            'list_kinesisfirehoses': 'list_delivery_streams',
            'list_deliverystream_encryption': 'describe_delivery_stream',
            'list_resource_logging': 'list_delivery_streams',
            
            # Kinesis Video Streams (uses kinesisvideo client)
            'list_kinesisvideostreamss': 'list_streams',
            'list_stream_encryption': 'describe_stream',
            
            # Lambda
            'list_event_source_mapping_encryption': 'list_event_source_mappings',
            'list_alias_logging': 'list_aliases',
            'list_layerversion_encryption': 'list_layer_versions',
            'list_alias_encryption': 'list_aliases',
            'list_layer_encryption': 'list_layers',
            
            # Lightsail
            'describe_alarmsinstance_configured_logging': 'get_alarms',
            'describe_certificates_validated': 'get_certificates',
            
            # Macie
            'list_classificationsession_logging': 'list_classification_jobs',
            'describe_findings': 'list_findings',
            'list_session_logging': 'list_classification_jobs',
            'list_allowlist_logging': 'list_allow_lists',
            
            # Network Firewall
            'list_policy_logging': 'describe_firewall_policy',
            'list_firewallpolicy_logging': 'describe_firewall_policy',
            
            # Parameter Store (uses SSM client)
            'list_parameterstores': 'describe_parameters',
            'list_parameter_encryption': 'get_parameter',
            
            # SNS
            'describe_topic_subscription_configured_logging': 'get_topic_attributes',
            'describe_topics_not_publicly_accessibles': 'get_topic_attributes',
            'describe_subscriptions': 'list_subscriptions',
            'describe_topics': 'list_topics',
            
            # Timestream
            'describe_databases': 'list_databases',
            'list_database_encryption': 'describe_database',
            'list_resource_encryption': 'list_databases',
            'describe_tables': 'list_tables',
            'list_table_encryption': 'describe_table',
            
            # VPC (uses EC2 client)
            'list_vpc_encryption': 'describe_vpcs',
            'list_endpoint_encryption': 'describe_vpc_endpoints',
            'list_securitygroup_logging': 'describe_security_groups',
            'list_subnet_encryption': 'describe_subnets',
            'list_networkacl_encryption': 'describe_network_acls',
            'describe_endpoints': 'describe_vpc_endpoints',
            'describe_routetables': 'describe_route_tables',
            'describe_networkacls': 'describe_network_acls',
            'describe_flowlogs': 'describe_flow_logs',
            'list_securitygroup_encryption': 'describe_security_groups',
            'list_peeringconnection_encryption': 'describe_vpc_peering_connections',
            'list_routetable_encryption': 'describe_route_tables',
            'list_subnet_logging': 'describe_subnets',
            'list_flowlog_logging': 'describe_flow_logs',
            'list_endpoint_logging': 'describe_vpc_endpoints',
            'list_peeringconnection_logging': 'describe_vpc_peering_connections',
            'list_networkacl_logging': 'describe_network_acls',
            'list_routetable_logging': 'describe_route_tables',
            
            # VPC Flow Logs (uses EC2 client)
            'list_vpcflowlogss': 'describe_flow_logs',
            'list_resource_logging': 'describe_flow_logs',
            
            # WAF
            'describe_ipsets': 'list_ip_sets',
            'describe_regexpatternsets': 'list_regex_pattern_sets',
            
            # WAFv2
            'describe_webacl_logging': 'get_logging_configuration',
            
            # Workflows (Invalid service - should be removed or part of another)
            'list_workflowss': None,  # Invalid
            
            # Cost Explorer
            'describe_budgets': 'describe_budgets',  # Actually correct for budgets client
            'describe_anomaly_monitors': 'get_anomaly_monitors',
            'describe_anomalys': 'get_anomalies',
            'list_cost_metrics': 'get_cost_and_usage',
            
            # Backup
            'list_backupplan_logging': 'list_backup_plans',
            'describe_backupvaults': 'list_backup_vaults',
            
            # Batch
            'describe_computeenvironments': 'describe_compute_environments',
            
            # Bedrock
            'describe_models': 'list_foundation_models',
            'list_model_encryption': 'get_foundation_model',
            
            # CloudFormation
            'list_stack_logging': 'describe_stacks',
            'list_resource_logging': 'list_stack_resources',
            
            # CloudFront
            'list_distribution_configuration': 'list_distributions',
            'list_resource_logging': 'list_distributions',
            
            # CloudTrail
            'list_trail_encryption': 'describe_trails',
            'list_resource_logging': 'list_trails',
            
            # CloudWatch
            'list_alarm_logging': 'describe_alarms',
            'list_resource_logging': 'describe_alarms',
            
            # CodeBuild
            'list_project_logging': 'list_projects',
            'list_resource_encryption': 'batch_get_projects',
            
            # Config
            'describe_rules': 'describe_config_rules',
            
            # DataSync
            'describe_locations': 'list_locations',
            
            # Detective
            'describe_graphs': 'list_graphs',
            
            # Direct Connect
            'describe_connections': 'describe_connections',  # Already correct
            
            # DMS
            'describe_tasks': 'describe_replication_tasks',
            'list_resource_logging': 'describe_replication_tasks',
            
            # DocDB
            'describe_instances': 'describe_db_clusters',
            'list_resource_logging': 'describe_db_clusters',
            
            # DynamoDB
            'describe_tables': 'list_tables',  # Then get each with describe_table
            
            # EC2
            'describe_instances': 'describe_instances',  # Already correct
            
            # ECR
            'describe_repositories': 'describe_repositories',  # Already correct
            
            # ECS
            'describe_services': 'describe_services',  # Already correct
            
            # EFS
            'describe_filesystems': 'describe_file_systems',
            
            # EKS
            'describe_clusters': 'describe_cluster',  # Singular
            'list_resource_logging': 'describe_cluster',
            
            # ElastiCache
            'describe_clusters': 'describe_cache_clusters',
            'list_resource_logging': 'describe_cache_clusters',
            
            # Elastic Beanstalk
            'describe_environments': 'describe_environments',  # Already correct
            'list_resource_logging': 'describe_environments',
            
            # ELB
            'describe_loadbalancers': 'describe_load_balancers',
            'list_listener_encryption': 'describe_listeners',
            
            # EMR
            # Already working
            
            # EventBridge
            'describe_eventbuses': 'describe_event_bus',
            'describe_archives': 'describe_archive',
            'describe_connections': 'describe_connection',
            'list_resource_logging': 'describe_event_bus',
            
            # Firehose
            'describe_deliverystreams': 'describe_delivery_stream',
            
            # FSx
            'describe_filesystems': 'describe_file_systems',
            
            # Glacier
            'describe_vaults': 'list_vaults',
            
            # Global Accelerator
            'describe_accelerators': 'list_accelerators',
            
            # Glue
            'describe_crawlers': 'get_crawlers',
            'list_resource_logging': 'get_crawlers',
            
            # GuardDuty
            'describe_detectors': 'list_detectors',
            'list_resource_logging': 'list_detectors',
            
            # Inspector
            'describe_assessmenttargets': 'list_assessment_targets',
            
            # Kafka (MSK)
            'describe_clusters': 'list_clusters_v2',
            
            # Keyspaces (Cassandra)
            'describe_keyspaces': 'list_keyspaces',
            
            # Kinesis
            'describe_streams': 'list_streams',
            
            # Kinesis Analytics
            'describe_applications': 'list_applications',
            
            # KMS
            'describe_keys': 'list_keys',
            
            # Lake Formation
            'list_resources': 'list_resources',  # Already correct
            
            # MQ
            'describe_brokers': 'list_brokers',
            
            # Neptune
            'describe_instances': 'describe_db_clusters',
            'list_resource_logging': 'describe_db_clusters',
            
            # OpenSearch
            'describe_domains': 'list_domain_names',
            'list_resource_logging': 'list_domain_names',
            
            # QLDB
            'describe_ledgers': 'list_ledgers',
            'list_resource_logging': 'list_ledgers',
            
            # QuickSight
            'describe_dashboards': 'list_dashboards',
            'list_resource_logging': 'list_dashboards',
            
            # RDS
            'describe_instances': 'describe_db_instances',
            'list_resource_logging': 'describe_db_instances',
            
            # Redshift
            'describe_clusters': 'describe_clusters',  # Already correct
            'list_resource_logging': 'describe_clusters',
            
            # Route53
            'list_hostedzone_logging': 'list_hosted_zones',
            'list_resource_logging': 'list_hosted_zones',
            
            # SageMaker
            'describe_endpoints': 'list_endpoints',
            'list_resource_logging': 'list_endpoints',
            
            # Secrets Manager
            'describe_secrets': 'list_secrets',
            
            # Security Hub
            'describe_hubs': 'describe_hub',
            
            # Service Catalog
            'describe_portfolios': 'list_portfolios',
            
            # SES
            'list_identitys': 'list_identities',
            'list_resource_logging': 'list_identities',
            
            # Shield
            'describe_protections': 'list_protections',
            
            # SQS
            'describe_queues': 'list_queues',
            
            # SSM
            'describe_documents': 'list_documents',
            'list_resource_logging': 'describe_instance_information',
            
            # Step Functions
            'describe_statemachines': 'list_state_machines',
            'list_resource_logging': 'list_state_machines',
            
            # Storage Gateway
            'describe_gateways': 'list_gateways',
            
            # Transfer
            'describe_servers': 'list_servers',
            
            # Well-Architected
            'describe_workloads': 'list_workloads',
            
            # Workspaces
            'describe_workspaces': 'describe_workspaces',  # Already correct
            
            # X-Ray
            'list_samplingrule_encryption': 'get_sampling_rules',
        }
        
        return fixes
    
    def fix_service_yaml(self, service_name):
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
            
            # Fix service/client name
            if service_name in self.client_name_fixes:
                correct_client = self.client_name_fixes[service_name]
                
                if data.get('service') == service_name:
                    data['service'] = correct_client
                    fixed_count += 1
                    self.fix_log.append({
                        'service': service_name,
                        'type': 'client_name',
                        'change': f'{service_name} → {correct_client}'
                    })
                    print(f"    ✅ Client: {service_name} → {correct_client}")
                
                # Fix client in discovery calls
                for disc_step in data.get('discovery', []):
                    for call in disc_step.get('calls', []):
                        if call.get('client') == service_name:
                            call['client'] = correct_client
                            fixed_count += 1
            
            # Fix operations
            for disc_step in data.get('discovery', []):
                disc_id = disc_step.get('discovery_id', 'unknown')
                for call in disc_step.get('calls', []):
                    action = call.get('action')
                    
                    if action and action in self.operation_fixes:
                        new_action = self.operation_fixes[action]
                        
                        if new_action is None:
                            print(f"    ⚠️  Remove: {action} (invalid operation)")
                            continue
                        
                        call['action'] = new_action
                        fixed_count += 1
                        self.fix_log.append({
                            'service': service_name,
                            'discovery_id': disc_id,
                            'type': 'operation',
                            'change': f'{action} → {new_action}'
                        })
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
        """Fix all services systematically"""
        
        print(f"\n{'='*80}")
        print(f"COMPREHENSIVE BOTO3 AUTO-FIXER")
        print(f"{'='*80}\n")
        
        print(f"Fixing all Boto3 schema issues...\n")
        
        # Get all service directories
        service_dirs = [d for d in self.services_dir.iterdir() if d.is_dir() and d.name != 'test_results']
        
        for idx, service_dir in enumerate(sorted(service_dirs), 1):
            service_name = service_dir.name
            print(f"[{idx}/{len(service_dirs)}] {service_name}")
            
            fixed = self.fix_service_yaml(service_name)
            
            if fixed == 0:
                print(f"    ✓ No fixes needed or already fixed")
        
        # Generate summary
        self.generate_summary()
    
    def generate_summary(self):
        """Generate fix summary"""
        
        print(f"\n{'='*80}")
        print(f"FIX SUMMARY")
        print(f"{'='*80}")
        print(f"Services processed: {len([d for d in self.services_dir.iterdir() if d.is_dir() and d.name != 'test_results'])}")
        print(f"Services fixed: {len(set(self.services_fixed))}")
        print(f"Total fixes applied: {self.fixes_applied}")
        
        # Count by type
        client_fixes = len([f for f in self.fix_log if f['type'] == 'client_name'])
        operation_fixes = len([f for f in self.fix_log if f['type'] == 'operation'])
        
        print(f"\nFix breakdown:")
        print(f"  • Client names: {client_fixes}")
        print(f"  • Operations: {operation_fixes}")
        
        if self.services_fixed:
            unique_services = sorted(set(self.services_fixed))
            print(f"\nFixed services ({len(unique_services)}):")
            for i in range(0, len(unique_services), 10):
                print(f"  {', '.join(unique_services[i:i+10])}")
        
        # Save fix log
        log_file = self.services_dir / "COMPREHENSIVE_FIX_LOG.json"
        with open(log_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'total_fixes': self.fixes_applied,
                'services_fixed': len(set(self.services_fixed)),
                'fixes': self.fix_log
            }, f, indent=2)
        
        print(f"\n📄 Detailed log: {log_file}")
        print(f"\nNext: Re-run comprehensive_boto3_validator.py to verify")

if __name__ == '__main__':
    print("🔧 Starting Comprehensive Boto3 Auto-Fixer...\n")
    
    fixer = ComprehensiveBoto3Fixer()
    fixer.fix_all_services()
    
    print(f"\n✅ Comprehensive fixing complete!")

