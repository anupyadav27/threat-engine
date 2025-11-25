#!/usr/bin/env python3
"""
Fix EC2 resource naming issues in rule_ids.yaml
Identify and correct improper resource names
"""

import yaml
import json

def load_files():
    """Load rule_ids and check for naming issues"""
    with open("/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml", 'r') as f:
        rule_data = yaml.safe_load(f)
    
    return rule_data

def analyze_ec2_resources(rule_data):
    """Analyze EC2 resources for naming issues"""
    
    rule_ids = rule_data['rule_ids']
    
    # Find EC2 rules with potential issues
    ec2_rules = [r for r in rule_ids if r.startswith('aws.ec2.')]
    
    # Known problematic patterns
    issues = []
    
    for rule_id in ec2_rules:
        parts = rule_id.split('.')
        if len(parts) >= 3:
            service = parts[1]
            resource = parts[2]
            
            # Check for compound/improper resource names
            if '_' in resource and resource not in ['security_group', 'launch_template', 'network_interface', 
                                                      'reserved_instance', 'spot_instance', 'transit_gateway',
                                                      'vpc_endpoint', 'vpn_connection', 'customer_gateway',
                                                      'dedicated_host', 'ebs_public_snapshot', 'ebs', 
                                                      'auto_scaling_group']:
                # Potential issue
                if 'elasticipshodan' in resource:
                    issues.append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'suggested_fix': 'eip',
                        'reason': 'elasticipshodan should be eip (Elastic IP)'
                    })
                elif 'elastic_ip_unassigned' in resource:
                    issues.append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'suggested_fix': 'eip',
                        'reason': 'elastic_ip_unassigned should be eip'
                    })
                elif 'patchcompliance' in resource:
                    issues.append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'suggested_fix': 'instance',
                        'reason': 'patchcompliance should be instance (patch compliance is instance-level)'
                    })
                elif 'networkacl' in resource:
                    issues.append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'suggested_fix': 'networkacl',
                        'reason': 'Already correct - networkacl is the AWS SDK resource'
                    })
                elif 'transitgateway' in resource and 'transit_gateway' not in resource:
                    issues.append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'suggested_fix': 'transitgateway',
                        'reason': 'transitgateway is correct (AWS SDK uses transitgateway)'
                    })
                elif 'vpnconnection' in resource:
                    issues.append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'suggested_fix': 'vpnconnection',
                        'reason': 'vpnconnection is correct (AWS SDK)'
                    })
                elif 'vpcendpoint' in resource:
                    issues.append({
                        'rule_id': rule_id,
                        'resource': resource,
                        'suggested_fix': 'vpcendpoint',
                        'reason': 'vpcendpoint is correct (AWS SDK uses describe_vpc_endpoints)'
                    })
    
    return issues

def create_corrections():
    """Create comprehensive corrections for rule_ids.yaml"""
    
    corrections = {
        # EIP corrections
        'aws.ec2.elasticipshodan.elastic_ip_shodan_configured': {
            'new': 'aws.ec2.eip.shodan_exposure_detected',
            'reason': 'Fix resource: elasticipshodan → eip'
        },
        'aws.ec2.elastic_ip_unassigned.elastic_ip_unassigned_configured': {
            'new': 'aws.ec2.eip.not_in_use',
            'reason': 'Fix resource: elastic_ip_unassigned → eip, simplify assertion'
        },
        
        # Patch compliance
        'aws.ec2.patchcompliance.patch_compliance_configured': {
            'new': 'aws.ec2.instance.patch_compliance_status_check',
            'reason': 'Fix resource: patchcompliance → instance'
        },
        
        # SSM association compliance
        'aws.ec2.ssm_association_compliance.ssm_association_compliance_configured': {
            'new': 'aws.ec2.instance.ssm_association_compliant',
            'reason': 'Fix resource: ssm_association_compliance → instance'
        },
        
        # Stopped instance
        'aws.ec2.stoppedinstance.stopped_instance_configured': {
            'new': 'aws.ec2.instance.stopped_instances_removed',
            'reason': 'Fix resource: stoppedinstance → instance'
        },
        
        # Transit gateway
        'aws.ec2.transitgateway_auto_accept_vpc_attachments.transitgateway_auto_accept_vpc_attachments_configured': {
            'new': 'aws.ec2.transitgateway.auto_cross_account_attachment_disabled',
            'reason': 'Fix resource: transitgateway_auto_accept_vpc_attachments → transitgateway'
        },
    }
    
    return corrections

def print_analysis(issues):
    """Print analysis"""
    
    print("\n" + "="*80)
    print("EC2 RESOURCE NAMING ANALYSIS")
    print("="*80)
    
    print(f"\nPotential issues found: {len(issues)}")
    
    for i, issue in enumerate(issues, 1):
        print(f"\n{i}. {issue['rule_id']}")
        print(f"   Current resource: {issue['resource']}")
        print(f"   Suggested fix: {issue['suggested_fix']}")
        print(f"   Reason: {issue['reason']}")

def main():
    print("Analyzing rule_ids.yaml for EC2 resource naming issues...")
    
    rule_data = load_files()
    issues = analyze_ec2_resources(rule_data)
    
    print_analysis(issues)
    
    print(f"\n{'RECOMMENDED CORRECTIONS':-^80}")
    corrections = create_corrections()
    print(f"\nTotal corrections to apply: {len(corrections)}")
    
    for old_rule, fix in corrections.items():
        print(f"\n  OLD: {old_rule}")
        print(f"  NEW: {fix['new']}")
        print(f"   → {fix['reason']}")
    
    print("\n" + "="*80)
    print()

if __name__ == "__main__":
    main()

