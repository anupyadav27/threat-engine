"""
Compliance Mock Data Generator

Generates realistic mock scan results for testing compliance engine.
"""

import random
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path


class ComplianceMockDataGenerator:
    """Generates mock scan results for compliance testing."""
    
    def __init__(self):
        """Initialize mock data generator."""
        self.services = [
            's3', 'iam', 'ec2', 'rds', 'lambda', 'cloudtrail', 
            'cloudwatch', 'kms', 'vpc', 'elb', 'elbv2', 'sns', 
            'sqs', 'dynamodb', 'redshift', 'efs', 'eks'
        ]
        
        self.regions = [
            'us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1',
            'ap-southeast-1', 'eu-central-1'
        ]
        
        # Common rule_ids that map to multiple frameworks
        self.common_rules = [
            'aws.s3.bucket.block_public_access_enabled',
            'aws.s3.bucket.encryption_at_rest_enabled',
            'aws.s3.bucket.versioning_enabled',
            'aws.iam.user.mfa_required',
            'aws.iam.policy.no_administrative_privileges',
            'aws.iam.policy.overly_permissive_configured',
            'aws.iam.root.mfa_enabled',
            'aws.iam.no.root_access_key_configured',
            'aws.cloudtrail.trail.flow_logging_enabled',
            'aws.cloudtrail.trail.kms_encryption_enabled',
            'aws.cloudtrail.trail.log_file_validation_enabled',
            'aws.rds.instance.encryption_at_rest_enabled',
            'aws.rds.instance.backup_enabled',
            'aws.rds.instance.public_access_disabled',
            'aws.ec2.instance.no_public_ip_assigned_configured',
            'aws.ec2.volume.encryption_at_rest_enabled',
            'aws.kms.cmk.rotation_enabled',
            'aws.guardduty.detector.enabled',
            'aws.securityhub.hub.securityhub_enabled_in_all_regions'
        ]
    
    def generate_resource_id(self, service: str, index: int) -> str:
        """Generate a realistic resource ID."""
        resource_ids = {
            's3': f'test-bucket-{index}',
            'iam': f'test-user-{index}',
            'ec2': f'i-{random.randint(10000000000000000, 99999999999999999)}',
            'rds': f'test-db-instance-{index}',
            'lambda': f'test-function-{index}',
            'kms': f'{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(100000000000, 999999999999)}'
        }
        return resource_ids.get(service, f'test-{service}-{index}')
    
    def generate_resource_arn(self, service: str, resource_id: str, region: str, account_id: str) -> str:
        """Generate a realistic resource ARN."""
        arn_templates = {
            's3': f'arn:aws:s3:::{resource_id}',
            'iam': f'arn:aws:iam::{account_id}:user/{resource_id}',
            'ec2': f'arn:aws:ec2:{region}:{account_id}:instance/{resource_id}',
            'rds': f'arn:aws:rds:{region}:{account_id}:db:{resource_id}',
            'lambda': f'arn:aws:lambda:{region}:{account_id}:function:{resource_id}',
            'kms': f'arn:aws:kms:{region}:{account_id}:key/{resource_id}'
        }
        return arn_templates.get(service, f'arn:aws:{service}:{region}:{account_id}:{resource_id}')
    
    def generate_scan_results(
        self,
        account_id: str = "123456789012",
        num_resources: int = 20,
        pass_rate: float = 0.6
    ) -> Dict[str, Any]:
        """
        Generate mock scan results.
        
        Args:
            account_id: AWS account ID
            num_resources: Number of resources to generate
            pass_rate: Probability of a check passing (0.0 to 1.0)
        
        Returns:
            Mock scan results dictionary
        """
        scan_id = f"mock-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        results = []
        
        resource_index = 1
        for _ in range(num_resources):
            service = random.choice(self.services)
            region = random.choice(self.regions)
            resource_id = self.generate_resource_id(service, resource_index)
            resource_arn = self.generate_resource_arn(service, resource_id, region, account_id)
            
            # Select 2-5 rules for this resource
            num_checks = random.randint(2, 5)
            selected_rules = random.sample(self.common_rules, min(num_checks, len(self.common_rules)))
            
            checks = []
            for rule_id in selected_rules:
                # Determine result based on pass_rate
                result = 'PASS' if random.random() < pass_rate else 'FAIL'
                severity = random.choice(['high', 'medium', 'low'])
                
                # Generate evidence based on result
                evidence = self._generate_evidence(rule_id, result)
                
                checks.append({
                    'rule_id': rule_id,
                    'result': result,
                    'severity': severity,
                    'resource': {
                        'type': f'{service}_{resource_id.split("-")[0]}',
                        'id': resource_id,
                        'arn': resource_arn
                    },
                    'evidence': evidence
                })
            
            results.append({
                'account_id': account_id,
                'region': region,
                'service': service,
                'checks': checks
            })
            
            resource_index += 1
        
        return {
            'scan_id': scan_id,
            'csp': 'aws',
            'account_id': account_id,
            'scanned_at': datetime.now().isoformat() + 'Z',
            'results': results
        }
    
    def _generate_evidence(self, rule_id: str, result: str) -> Dict[str, Any]:
        """Generate realistic evidence based on rule_id and result."""
        evidence_map = {
            'aws.s3.bucket.block_public_access_enabled': {
                'PASS': {'public_access_blocked': True},
                'FAIL': {'public_access_blocked': False}
            },
            'aws.s3.bucket.encryption_at_rest_enabled': {
                'PASS': {'encryption_enabled': True, 'encryption_type': 'AES256'},
                'FAIL': {'encryption_enabled': False}
            },
            'aws.s3.bucket.versioning_enabled': {
                'PASS': {'versioning_enabled': True},
                'FAIL': {'versioning_enabled': False}
            },
            'aws.iam.user.mfa_required': {
                'PASS': {'mfa_enabled': True},
                'FAIL': {'mfa_enabled': False}
            },
            'aws.iam.policy.no_administrative_privileges': {
                'PASS': {'has_admin_privileges': False},
                'FAIL': {'has_admin_privileges': True}
            },
            'aws.rds.instance.encryption_at_rest_enabled': {
                'PASS': {'encryption_enabled': True},
                'FAIL': {'encryption_enabled': False}
            },
            'aws.cloudtrail.trail.flow_logging_enabled': {
                'PASS': {'logging_enabled': True},
                'FAIL': {'logging_enabled': False}
            }
        }
        
        if rule_id in evidence_map:
            return evidence_map[rule_id].get(result, {})
        
        # Default evidence
        return {'status': result.lower()}
