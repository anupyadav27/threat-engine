#!/usr/bin/env python3
"""
ENHANCED PATTERN-BASED CHECK GENERATOR
Generates high-quality checks using AWS service patterns and S3 as reference
"""

import yaml
from pathlib import Path
import json

# AWS Service API patterns (common Boto3 methods)
AWS_API_PATTERNS = {
    'ec2': {
        'list_method': 'describe_instances',
        'resource_field': 'Instances',
        'id_field': 'InstanceId',
        'name_field': 'InstanceId',
        'encryption_method': 'describe_volumes',
        'logging_method': None,
        'config_method': 'describe_instance_attribute'
    },
    'iam': {
        'list_method': 'list_users',
        'resource_field': 'Users',
        'id_field': 'UserId',
        'name_field': 'UserName',
        'policy_method': 'list_user_policies'
    },
    'rds': {
        'list_method': 'describe_db_instances',
        'resource_field': 'DBInstances',
        'id_field': 'DBInstanceIdentifier',
        'name_field': 'DBInstanceIdentifier',
        'encryption_method': 'describe_db_instances',
        'logging_method': 'describe_db_log_files'
    },
    'lambda': {
        'list_method': 'list_functions',
        'resource_field': 'Functions',
        'id_field': 'FunctionArn',
        'name_field': 'FunctionName',
        'config_method': 'get_function_configuration'
    },
    'eks': {
        'list_method': 'list_clusters',
        'resource_field': 'clusters',
        'describe_method': 'describe_cluster',
        'id_field': 'name',
        'name_field': 'name'
    },
    'cloudwatch': {
        'list_method': 'describe_alarms',
        'resource_field': 'MetricAlarms',
        'id_field': 'AlarmName',
        'name_field': 'AlarmName'
    },
    'kms': {
        'list_method': 'list_keys',
        'resource_field': 'Keys',
        'describe_method': 'describe_key',
        'id_field': 'KeyId',
        'name_field': 'KeyId'
    },
    'sns': {
        'list_method': 'list_topics',
        'resource_field': 'Topics',
        'id_field': 'TopicArn',
        'name_field': 'TopicArn'
    },
    'sqs': {
        'list_method': 'list_queues',
        'resource_field': 'QueueUrls',
        'id_field': 'QueueUrl',
        'name_field': 'QueueUrl'
    }
}

class EnhancedCheckGenerator:
    def __init__(self):
        self.services_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services")
        self.implemented_services = {'s3'}
        
    def get_service_api_pattern(self, service_name):
        """Get or infer API pattern for service"""
        if service_name in AWS_API_PATTERNS:
            return AWS_API_PATTERNS[service_name]
        
        # Generic fallback
        return {
            'list_method': f"list_{service_name}s",
            'resource_field': f"{service_name.capitalize()}s",
            'id_field': 'Id',
            'name_field': 'Name'
        }
    
    def detect_check_pattern(self, rule_id, metadata):
        """Detect what type of check this is"""
        rule_lower = rule_id.lower()
        title_lower = metadata.get('title', '').lower()
        requirement = metadata.get('requirement', '').lower()
        
        patterns = {
            'encryption': ['encrypt', 'kms', 'cmk', 'cmek', 'sse'],
            'logging': ['log', 'audit', 'cloudtrail', 'cloudwatch'],
            'access': ['public', 'access', 'rbac', 'iam', 'policy', 'permission'],
            'network': ['vpc', 'security_group', 'network', 'private', 'tls', 'ssl'],
            'versioning': ['version', 'backup', 'snapshot'],
            'monitoring': ['monitor', 'alarm', 'metric', 'alert'],
            'compliance': ['compliance', 'standard', 'cis', 'pci']
        }
        
        combined_text = f"{rule_lower} {title_lower} {requirement}"
        
        for pattern_type, keywords in patterns.items():
            if any(kw in combined_text for kw in keywords):
                return pattern_type
        
        return 'generic'
    
    def generate_discovery_steps(self, service_name, metadata_list):
        """Generate intelligent discovery steps"""
        api_pattern = self.get_service_api_pattern(service_name)
        
        # Extract unique resources from metadata
        resources = set()
        for meta in metadata_list:
            parts = meta['rule_id'].split('.')
            if len(parts) >= 3:
                resources.add(parts[2])
        
        discovery_steps = []
        
        # Step 1: List main resources
        main_resource = list(resources)[0] if resources else service_name
        
        discovery_steps.append({
            "discovery_id": f"aws.{service_name}.{main_resource}s",
            "calls": [{
                "client": service_name,
                "action": api_pattern['list_method'],
                "save_as": f"{main_resource}_list",
                "on_error": "continue",
                "fields": [api_pattern['resource_field']]
            }],
            "emit": {
                "items_for": f"{main_resource}_list[]",
                "as": main_resource,
                "item": {
                    "id": f"{{{{ {main_resource}.{api_pattern['id_field']} }}}}",
                    "name": f"{{{{ {main_resource}.{api_pattern.get('name_field', 'Name')} }}}}"
                }
            }
        })
        
        # Step 2: Encryption discovery if needed
        if any('encrypt' in m['rule_id'].lower() for m in metadata_list):
            discovery_steps.append({
                "discovery_id": f"aws.{service_name}.{main_resource}_encryption",
                "for_each": f"aws.{service_name}.{main_resource}s",
                "calls": [{
                    "client": service_name,
                    "action": api_pattern.get('encryption_method', api_pattern['list_method']),
                    "params": {
                        f"{main_resource.capitalize()}Id": "{{ item.id }}"
                    },
                    "save_as": "encryption",
                    "on_error": "continue"
                }],
                "emit": {
                    "item": {
                        "resource_id": "{{ item.id }}",
                        "encryption_enabled": "{{ encryption.Encrypted if encryption.Encrypted is defined else false }}"
                    }
                }
            })
        
        # Step 3: Logging discovery if needed
        if any('log' in m['rule_id'].lower() for m in metadata_list):
            discovery_steps.append({
                "discovery_id": f"aws.{service_name}.{main_resource}_logging",
                "for_each": f"aws.{service_name}.{main_resource}s",
                "calls": [{
                    "client": service_name,
                    "action": api_pattern.get('logging_method', f"describe_{main_resource}_logging"),
                    "params": {
                        f"{main_resource.capitalize()}Id": "{{ item.id }}"
                    },
                    "save_as": "logging",
                    "on_error": "continue"
                }],
                "emit": {
                    "item": {
                        "resource_id": "{{ item.id }}",
                        "logging_enabled": "{{ logging.LoggingEnabled is defined if logging else false }}"
                    }
                }
            })
        
        return discovery_steps
    
    def generate_check(self, metadata, service_name, pattern_type):
        """Generate a check based on pattern"""
        
        rule_id = metadata['rule_id']
        title = metadata['title']
        severity = metadata['severity']
        requirement = metadata.get('requirement', '')
        description = metadata.get('description', '')
        references = metadata.get('references', [])
        
        parts = rule_id.split('.')
        resource_type = parts[2] if len(parts) > 2 else service_name
        
        # Pattern-specific check generation
        if pattern_type == 'encryption':
            discovery_id = f"aws.{service_name}.{resource_type}_encryption"
            condition = {
                "var": "encryption.encryption_enabled",
                "op": "equals",
                "value": True
            }
            remediation = f"""Enable encryption for {service_name} {resource_type}:

1. Open {service_name.upper()} console
2. Select the {resource_type}
3. Navigate to Properties/Configuration > Encryption
4. Enable encryption
5. Choose encryption key:
   - AWS managed key (default)
   - Customer managed key (KMS) for enhanced control
6. Save changes

AWS CLI:
aws {service_name} modify-{resource_type} --{resource_type}-id <id> --encrypted --kms-key-id <key-id>

Security Best Practices:
• Use customer-managed KMS keys for sensitive data
• Enable automatic key rotation
• Implement proper key access policies
• Audit key usage regularly"""

        elif pattern_type == 'logging':
            discovery_id = f"aws.{service_name}.{resource_type}_logging"
            condition = {
                "var": "logging.logging_enabled",
                "op": "equals",
                "value": True
            }
            remediation = f"""Enable logging for {service_name} {resource_type}:

1. Open {service_name.upper()} console
2. Select the {resource_type}
3. Go to Logging/Monitoring settings
4. Enable logging
5. Configure log destination:
   - CloudWatch Logs
   - S3 bucket (for long-term retention)
6. Set log level (INFO, DEBUG, ERROR)
7. Save changes

AWS CLI:
aws {service_name} update-{resource_type}-logging --{resource_type}-id <id> --logging-enabled

Best Practices:
• Enable all security-relevant log types
• Send logs to centralized logging service
• Set appropriate retention periods
• Configure log encryption
• Set up log monitoring and alerting"""

        elif pattern_type == 'access':
            discovery_id = f"aws.{service_name}.{resource_type}s"
            condition = {
                "var": f"{resource_type}.is_public",
                "op": "equals",
                "value": False
            }
            remediation = f"""Restrict public access for {service_name} {resource_type}:

1. Open {service_name.upper()} console
2. Select the {resource_type}
3. Go to Permissions/Access Control
4. Review current permissions:
   - Remove public access grants
   - Remove wildcard (*) principals
   - Implement least privilege
5. Update resource policy or IAM policies
6. Enable resource-level access control
7. Save changes

Security Recommendations:
• Use IAM roles instead of access keys
• Implement condition keys for additional security
• Enable MFA for sensitive operations
• Regularly audit access permissions
• Use AWS Organizations SCPs for guardrails"""

        elif pattern_type == 'network':
            discovery_id = f"aws.{service_name}.{resource_type}s"
            condition = {
                "var": f"{resource_type}.in_vpc",
                "op": "equals",
                "value": True
            }
            remediation = f"""Configure network security for {service_name} {resource_type}:

1. Ensure {resource_type} is deployed in VPC
2. Configure security groups:
   - Restrict inbound traffic to necessary ports
   - Limit source IP ranges
   - Use least privilege
3. Configure network ACLs for subnet-level control
4. Enable VPC Flow Logs for network monitoring
5. Use Private Link/VPC Endpoints where available
6. Enable TLS/SSL for data in transit

Network Security Best Practices:
• Deploy in private subnets when possible
• Use NAT Gateway for outbound internet access
• Implement defense in depth
• Enable encryption in transit
• Monitor network traffic"""

        elif pattern_type == 'versioning':
            discovery_id = f"aws.{service_name}.{resource_type}s"
            condition = {
                "var": f"{resource_type}.versioning_enabled",
                "op": "equals",
                "value": True
            }
            remediation = f"""Enable versioning for {service_name} {resource_type}:

1. Open {service_name.upper()} console
2. Select the {resource_type}
3. Go to Properties > Versioning
4. Enable versioning
5. Configure retention policies
6. Set up lifecycle rules (optional)
7. Save changes

Benefits:
• Protection against accidental deletion
• Ability to recover from ransomware
• Audit trail of changes
• Point-in-time recovery"""

        elif pattern_type == 'monitoring':
            discovery_id = f"aws.{service_name}.{resource_type}s"
            condition = {
                "var": f"{resource_type}.monitoring_enabled",
                "op": "equals",
                "value": True
            }
            remediation = f"""Enable monitoring for {service_name} {resource_type}:

1. Open CloudWatch console
2. Create alarm for {resource_type}
3. Configure metrics to monitor
4. Set alarm thresholds
5. Configure SNS notifications
6. Enable detailed monitoring (if available)
7. Create dashboard for visualization

Monitoring Best Practices:
• Monitor security-relevant metrics
• Set up automated alerting
• Integrate with SIEM/SOC
• Regular review of metrics
• Implement automated remediation"""

        else:  # generic
            discovery_id = f"aws.{service_name}.{resource_type}s"
            condition = {
                "var": f"{resource_type}.compliant",
                "op": "equals",
                "value": True
            }
            remediation = f"""Configure {service_name} {resource_type} for compliance:

Requirement: {requirement}

Description: {description[:300] if description else 'N/A'}

Steps:
1. Open {service_name.upper()} console
2. Select the {resource_type}
3. Review security configuration
4. Apply required settings per organizational policy
5. Verify compliance
6. Save changes

General Security Recommendations:
• Follow AWS Well-Architected Framework
• Implement defense in depth
• Enable logging and monitoring
• Use encryption where applicable
• Regular security audits"""

        # Add AWS documentation references
        if not references:
            references = [
                f"https://docs.aws.amazon.com/{service_name}/latest/userguide/security.html",
                f"https://docs.aws.amazon.com/{service_name}/latest/userguide/best-practices.html",
                f"https://docs.aws.amazon.com/securityhub/latest/userguide/{service_name}-controls.html"
            ]
        
        check = {
            "title": title,
            "severity": severity,
            "rule_id": rule_id,
            "for_each": {
                "discovery": discovery_id,
                "as": resource_type,
                "item": resource_type
            },
            "conditions": condition,
            "remediation": remediation,
            "references": references
        }
        
        return check
    
    def generate_service_file(self, service_name, metadata_list):
        """Generate complete service YAML file"""
        
        print(f"\n  📝 Generating {service_name}...")
        
        # Generate discovery
        discovery_steps = self.generate_discovery_steps(service_name, metadata_list)
        print(f"     Discovery: {len(discovery_steps)} steps")
        
        # Generate checks
        checks = []
        for meta in metadata_list:
            pattern_type = self.detect_check_pattern(meta['rule_id'], meta)
            check = self.generate_check(meta, service_name, pattern_type)
            checks.append(check)
        
        print(f"     Checks: {len(checks)}")
        
        # Create service YAML
        service_yaml = {
            "version": "1.0",
            "provider": "aws",
            "service": service_name,
            "discovery": discovery_steps,
            "checks": checks
        }
        
        # Save file
        rules_dir = self.services_dir / service_name / "rules"
        rules_dir.mkdir(exist_ok=True, parents=True)
        
        output_file = rules_dir / f"{service_name}.yaml"
        with open(output_file, 'w') as f:
            yaml.dump(service_yaml, f, default_flow_style=False, sort_keys=False, width=120, allow_unicode=True)
        
        print(f"     ✅ Saved to {output_file}")
        
        return len(checks)
    
    def generate_all(self, limit=None):
        """Generate checks for all services"""
        
        # Get services to process
        services = []
        for service_dir in sorted(self.services_dir.iterdir()):
            if not service_dir.is_dir():
                continue
            
            service_name = service_dir.name
            if service_name in self.implemented_services:
                continue
            
            metadata_dir = service_dir / "metadata"
            if metadata_dir.exists() and any(metadata_dir.glob("*.yaml")):
                metadata_files = list(metadata_dir.glob("*.yaml"))
                services.append({
                    'name': service_name,
                    'count': len(metadata_files),
                    'files': metadata_files
                })
        
        services = sorted(services, key=lambda x: x['count'], reverse=True)
        
        if limit:
            services = services[:limit]
        
        print(f"\n{'='*80}")
        print(f"ENHANCED PATTERN-BASED CHECK GENERATION")
        print(f"{'='*80}")
        print(f"Services to process: {len(services)}")
        print(f"Total checks: {sum(s['count'] for s in services)}")
        
        results = []
        total_generated = 0
        
        for i, service in enumerate(services, 1):
            service_name = service['name']
            print(f"\n[{i}/{len(services)}] {service_name} ({service['count']} rules)")
            
            try:
                # Load metadata
                metadata_list = []
                for yaml_file in service['files']:
                    with open(yaml_file, 'r') as f:
                        data = yaml.safe_load(f)
                        if data:
                            metadata_list.append(data)
                
                # Generate
                generated = self.generate_service_file(service_name, metadata_list)
                
                results.append({
                    'service': service_name,
                    'status': 'success',
                    'checks_generated': generated
                })
                total_generated += generated
                
            except Exception as e:
                print(f"     ❌ Error: {str(e)}")
                results.append({
                    'service': service_name,
                    'status': 'error',
                    'error': str(e)
                })
        
        # Summary
        print(f"\n{'='*80}")
        print(f"GENERATION COMPLETE")
        print(f"{'='*80}")
        successful = sum(1 for r in results if r['status'] == 'success')
        print(f"✅ Successful: {successful}/{len(services)}")
        print(f"📊 Total checks generated: {total_generated}")
        
        # Save summary
        summary_file = self.services_dir / "GENERATION_SUMMARY.json"
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n📄 Summary saved: {summary_file}")
        
        return results

if __name__ == '__main__':
    import sys
    
    generator = EnhancedCheckGenerator()
    
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else None
    
    if limit:
        print(f"Generating top {limit} services...")
    else:
        print("Generating ALL 101 services...")
    
    results = generator.generate_all(limit=limit)
    
    print(f"\n🎉 Generation complete!")
    print(f"\nNext steps:")
    print(f"1. Run: python3 services/analyze_coverage.py")
    print(f"2. Run: python3 services/validate_all_checks.py")
    print(f"3. Test with AWS credentials")

