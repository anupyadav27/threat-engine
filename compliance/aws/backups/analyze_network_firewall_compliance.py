#!/usr/bin/env python3
"""
Analyze network firewall compliance IDs and create mappings
"""

import csv
import json
import yaml
from difflib import SequenceMatcher

def get_network_security_functions():
    """Get all functions from the 3 ISO network security compliance IDs"""
    
    compliance_ids = [
        'iso27001_2022_multi_cloud_A.8.20_0076',  # Network Security
        'iso27001_2022_multi_cloud_A.8.21_0077',  # Security of Network Services
        'iso27001_2022_multi_cloud_A.8.22_0078'   # Segregation of Networks
    ]
    
    functions_by_compliance = {}
    
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/aws_consolidated_rules_cleaned.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            comp_id = row['unique_compliance_id']
            if comp_id in compliance_ids:
                aws_checks = row.get('aws_checks', '')
                if aws_checks and aws_checks not in ['nan', '']:
                    # Split by semicolon
                    funcs = [f.strip() for f in aws_checks.split(';') if f.strip()]
                    functions_by_compliance[comp_id] = {
                        'compliance_id': comp_id,
                        'control': row.get('requirement_id', ''),
                        'title': row.get('requirement_name', ''),
                        'functions': funcs
                    }
    
    return functions_by_compliance

def create_improved_function_names(functions_by_compliance):
    """Create improved function names for user's suggested checks"""
    
    # User's suggested checks mapped to improved function names
    suggested_mappings = {
        # A.8.20 - Network Security
        "aws_ec2_security_group_allow_ingress_from_internet_to_tcp_port_check": "aws.ec2.securitygroup.tcp_port_ingress_from_internet_restricted",
        "aws_ec2_security_group_not_uses_restricted_ports_check": "aws.ec2.securitygroup.restricted_ports_not_used",
        "aws_ec2_security_group_allow_ingress_from_internet_to_all_ports_check": "aws.ec2.securitygroup.ingress_from_internet_to_all_ports_blocked",
        "aws_vpc_default_security_group_restricts_all_traffic_check": "aws.ec2.securitygroup.default_restricts_all_traffic",
        "aws_ec2_security_group_allow_ingress_from_internet_to_udp_port_check": "aws.ec2.securitygroup.udp_port_ingress_from_internet_restricted",
        
        # A.8.21 - Security of Network Services
        "aws_vpc_flow_logs_enabled_in_all_vpcs_check": "aws.ec2.vpc.flow_logs_enabled_in_all_vpcs",
        "aws_cloudtrail_security_trail_enabled_check": "aws.cloudtrail.trail.security_trail_enabled",
        "aws_guardduty_is_enabled_check": "aws.guardduty.detector.enabled",
        "aws_vpc_network_acl_unused_check": "aws.ec2.networkacl.unused_network_acl_removed",
        "aws_config_enabled_in_all_regions_check": "aws.config.recorder.enabled_in_all_regions",
        
        # A.8.22 - Segregation of Networks
        "aws_ec2_security_group_different_env_cross_talk_check": "aws.ec2.securitygroup.environment_segregation_enforced",
        "aws_vpc_subnet_segregation_check": "aws.ec2.subnet.network_segregation_configured",
        "aws_ec2_security_group_allow_ingress_from_other_accounts_check": "aws.ec2.securitygroup.cross_account_ingress_restricted",
        "aws_vpc_peering_connection_security_check": "aws.ec2.vpcpeeringconnection.security_configuration_validated",
        "aws_ec2_instance_multiple_network_interfaces_check": "aws.ec2.instance.multiple_network_interfaces_reviewed",
    }
    
    return suggested_mappings

def find_rule_mappings(improved_functions, rule_ids):
    """Find matching rule_ids for improved functions"""
    
    mappings = {}
    
    for original, improved in improved_functions.items():
        # Parse improved function
        parts = improved.split('.')
        if len(parts) == 4:
            service = parts[1]
            resource = parts[2]
            
            # Find best matching rule_id
            service_rules = [r for r in rule_ids if r.startswith(f'aws.{service}.{resource}.')]
            
            best_match = None
            best_score = 0
            
            for rule_id in service_rules:
                score = SequenceMatcher(None, improved.lower(), rule_id.lower()).ratio()
                if score > best_score:
                    best_score = score
                    best_match = rule_id
            
            mappings[original] = {
                'improved_function': improved,
                'matched_rule_id': best_match if best_score >= 0.60 else None,
                'similarity_score': best_score,
                'confidence': 'high' if best_score >= 0.75 else 'medium' if best_score >= 0.65 else 'low' if best_score >= 0.60 else None
            }
    
    return mappings

def print_analysis(functions_by_compliance, improved_functions, mappings):
    """Print comprehensive analysis"""
    
    print("\n" + "="*80)
    print("NETWORK FIREWALL COMPLIANCE - FUNCTION ANALYSIS & MAPPING")
    print("="*80)
    
    print(f"\n{'COMPLIANCE REQUIREMENTS':-^80}")
    
    for comp_id, data in sorted(functions_by_compliance.items()):
        print(f"\n{data['control']}: {data['title']}")
        print(f"  Compliance ID: {comp_id}")
        print(f"  Total functions: {len(data['functions'])}")
    
    print(f"\n{'USER SUGGESTED CHECKS - IMPROVED NAMES':-^80}")
    
    for original, improved in sorted(improved_functions.items()):
        print(f"\n  {original}")
        print(f"    → {improved}")
    
    print(f"\n{'RULE_ID MAPPINGS':-^80}")
    
    mapped_count = sum(1 for m in mappings.values() if m['matched_rule_id'])
    unmapped_count = len(mappings) - mapped_count
    
    print(f"\n  Total checks analyzed:          {len(mappings)}")
    print(f"  Successfully mapped:            {mapped_count}")
    print(f"  No matching rule found:         {unmapped_count}")
    
    print(f"\n{'DETAILED MAPPINGS':-^80}")
    
    for original, mapping in sorted(mappings.items()):
        print(f"\n  {original}")
        print(f"    Improved: {mapping['improved_function']}")
        if mapping['matched_rule_id']:
            print(f"    ✓ Mapped to: {mapping['matched_rule_id']}")
            print(f"    Confidence: {mapping['confidence']} (score: {mapping['similarity_score']:.3f})")
        else:
            print(f"    ✗ No matching rule found (best score: {mapping['similarity_score']:.3f})")
    
    print("\n" + "="*80)
    print()

def main():
    print("Loading data...")
    
    # Get functions from compliance IDs
    functions_by_compliance = get_network_security_functions()
    print(f"  ✓ Loaded {len(functions_by_compliance)} compliance requirements")
    
    # Get improved function names
    improved_functions = create_improved_function_names(functions_by_compliance)
    print(f"  ✓ Created {len(improved_functions)} improved function names")
    
    # Load rule_ids
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml', 'r') as f:
        rule_data = yaml.safe_load(f)
        rule_ids = rule_data['rule_ids']
    print(f"  ✓ Loaded {len(rule_ids)} rule_ids")
    
    # Find mappings
    print("\nFinding rule_id mappings...")
    mappings = find_rule_mappings(improved_functions, rule_ids)
    print(f"  ✓ Analyzed {len(mappings)} functions")
    
    # Print analysis
    print_analysis(functions_by_compliance, improved_functions, mappings)

if __name__ == "__main__":
    main()

