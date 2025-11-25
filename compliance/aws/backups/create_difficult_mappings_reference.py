#!/usr/bin/env python3
"""
Extract the last 9 difficult mappings that were updated
Create a reference file for updating other CSP data
"""

import json
import csv

def get_last_9_mappings():
    """Get the last 9 functions that were difficult to map and had their names updated"""
    
    # The 9 difficult mappings with before/after changes
    difficult_mappings = [
        {
            "sequence": 1,
            "original_function": "aws_vpc_different_regions",
            "aws_checks_earlier": "aws_vpc_different_regions",
            "improved_function_earlier": "aws.ec2.different.regions",
            "improved_function_new": "aws.ec2.vpc.multi_region_deployment_configured",
            "matched_rule_id": "aws.ec2.vpc.automated_isolation_supported_configured",
            "confidence": "medium",
            "compliance_ids": ["iso27001_2022_multi_cloud_A.8.20_0076", "iso27001_2022_multi_cloud_A.8.21_0077", "iso27001_2022_multi_cloud_A.8.22_0078"],
            "notes": "VPC multi-region deployment maps to automated isolation (HA/DR pattern)"
        },
        {
            "sequence": 2,
            "original_function": "aws_ec2_elastic_ip_shodan",
            "aws_checks_earlier": "aws_ec2_elastic_ip_shodan",
            "improved_function_earlier": "aws.ec2.elastic.ip_shodan",
            "improved_function_new": "aws.ec2.eip.shodan_exposure_detected",
            "matched_rule_id": "aws.ec2.eip.shodan_exposure_detected",
            "confidence": "high",
            "compliance_ids": ["iso27001_2022_multi_cloud_A.8.20_0076", "iso27001_2022_multi_cloud_A.8.21_0077", "iso27001_2022_multi_cloud_A.8.22_0078"],
            "notes": "Elastic IP Shodan exposure - fixed resource name from 'elastic' to 'eip'"
        },
        {
            "sequence": 3,
            "original_function": "aws_vpc_endpoint_connections_trust_boundaries",
            "aws_checks_earlier": "aws_vpc_endpoint_connections_trust_boundaries",
            "improved_function_earlier": "aws.ec2.vpcendpoint.connection_trust_boundaries_validated",
            "improved_function_new": "aws.ec2.vpcendpoint.policy_least_privilege",
            "matched_rule_id": "aws.ec2.vpcendpoint.policy_least_privilege",
            "confidence": "high",
            "compliance_ids": ["iso27001_2022_multi_cloud_A.8.20_0076", "iso27001_2022_multi_cloud_A.8.21_0077", "iso27001_2022_multi_cloud_A.8.22_0078"],
            "notes": "VPC endpoint connection trust boundaries = policy least privilege principle"
        },
        {
            "sequence": 4,
            "original_function": "aws_vpc_endpoint_services_allowed_principals_trust_boundaries",
            "aws_checks_earlier": "aws_vpc_endpoint_services_allowed_principals_trust_boundaries",
            "improved_function_earlier": "aws.ec2.vpcendpointservice.allowed_principals_trust_boundaries_validated",
            "improved_function_new": "aws.ec2.vpcendpoint.policy_least_privilege",
            "matched_rule_id": "aws.ec2.vpcendpoint.policy_least_privilege",
            "confidence": "high",
            "compliance_ids": ["iso27001_2022_multi_cloud_A.8.20_0076", "iso27001_2022_multi_cloud_A.8.21_0077", "iso27001_2022_multi_cloud_A.8.22_0078"],
            "notes": "VPC endpoint service allowed principals trust boundaries = policy least privilege"
        },
        {
            "sequence": 5,
            "original_function": "aws_vpc_keyspaces_network_security_check",
            "aws_checks_earlier": "aws_vpc_keyspaces_network_security_check",
            "improved_function_earlier": "aws.ec2.keyspaces.network_security_check",
            "improved_function_new": "aws.keyspaces.keyspace.vpc_endpoint_enabled",
            "matched_rule_id": "aws.keyspaces.resource.keyspace_security_configuration_configured",
            "confidence": "medium",
            "compliance_ids": ["iso27001_2022_multi_cloud_A.8.20_0076"],
            "notes": "Keyspaces VPC network security - fixed service from 'ec2' to 'keyspaces'"
        },
        {
            "sequence": 6,
            "original_function": "aws_iam_no_guest_accounts_with_permissions",
            "aws_checks_earlier": "aws_iam_no_guest_accounts_with_permissions",
            "improved_function_earlier": "aws.iam.user.no_permissions_for_guest_accounts",
            "improved_function_new": "aws.iam.user.guest_accounts_have_no_permissions",
            "matched_rule_id": "aws.iam.no_guest_accounts_with_permissions.no_guest_accounts_with_permissions_configured",
            "confidence": "high",
            "compliance_ids": ["rbi_bank_multi_cloud_9.3_0027"],
            "notes": "IAM guest accounts should have no permissions - exact match found in suggested rules"
        },
        {
            "sequence": 7,
            "original_function": "aws_kms_cmk_not_multi_region",
            "aws_checks_earlier": "aws_kms_cmk_not_multi_region",
            "improved_function_earlier": "aws.kms.key.single_region_configured",
            "improved_function_new": "aws.kms.key.multi_region_disabled",
            "matched_rule_id": "aws.kms.key.multi_region_disabled",
            "confidence": "high",
            "compliance_ids": ["iso27001_2022_multi_cloud_A.8.20_0076"],
            "notes": "KMS key multi-region disabled (single-region keys for compliance/data residency)"
        },
        {
            "sequence": 8,
            "original_function": "aws_networkfirewall_in_all_vpc",
            "aws_checks_earlier": "aws_networkfirewall_in_all_vpc",
            "improved_function_earlier": "aws.network-firewall.firewall.deployed_in_all_vpcs",
            "improved_function_new": "aws.network-firewall.firewall.deployed_in_all_vpcs",
            "matched_rule_id": "aws.ec2.vpc.flow_logging_enabled",
            "confidence": "high",
            "compliance_ids": ["iso27001_2022_multi_cloud_A.8.20_0076", "iso27001_2022_multi_cloud_A.8.21_0077", "iso27001_2022_multi_cloud_A.8.22_0078"],
            "notes": "Network firewall organizational policy - mapped to VPC flow logging (+ 15 related security controls)"
        },
        {
            "sequence": 9,
            "original_function": "aws_No checks defined",
            "aws_checks_earlier": "aws_No checks defined",
            "improved_function_earlier": "aws.general.account.no_checks_defined",
            "improved_function_new": "aws.s3.bucket.public_access_block_enabled",
            "matched_rule_id": "aws.s3.bucket.block_public_access_enabled",
            "confidence": "high",
            "compliance_ids": ["nist_800_171_r2_multi_cloud_3_13_4_3.13.4_Prevent_unauthorized_and_unintended_0010"],
            "notes": "Fixed invalid CSV entry to S3 bucket public access block"
        }
    ]
    
    return difficult_mappings

def load_csv_data():
    """Load original CSV data to get compliance details"""
    
    compliance_details = {}
    
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/aws_consolidated_rules_cleaned.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            comp_id = row['unique_compliance_id']
            if comp_id not in compliance_details:
                compliance_details[comp_id] = {
                    'compliance_id': comp_id,
                    'framework': row.get('compliance_framework', ''),
                    'requirement_id': row.get('requirement_id', ''),
                    'requirement_name': row.get('requirement_name', ''),
                    'technology': row.get('technology', '')
                }
    
    return compliance_details

def create_reference_file(difficult_mappings, compliance_details):
    """Create reference file for CSP updates"""
    
    reference_data = {
        "metadata": {
            "purpose": "Reference file for updating other CSP data with corrected AWS function names",
            "total_mappings": len(difficult_mappings),
            "date_created": "2025-11-23",
            "notes": "These 9 functions had difficult mappings and required improved function name updates"
        },
        "mappings": []
    }
    
    for mapping in difficult_mappings:
        # Get compliance details
        comp_details_list = []
        for comp_id in mapping['compliance_ids']:
            if comp_id in compliance_details:
                comp_details_list.append(compliance_details[comp_id])
        
        reference_entry = {
            "sequence": mapping['sequence'],
            "original_function": mapping['original_function'],
            "aws_checks_earlier": mapping['aws_checks_earlier'],
            "aws_checks_new": mapping['original_function'],  # Keep the same original function
            "improved_function_earlier": mapping['improved_function_earlier'],
            "improved_function_new": mapping['improved_function_new'],
            "matched_rule_id": mapping['matched_rule_id'],
            "confidence": mapping['confidence'],
            "compliance_details": comp_details_list,
            "notes": mapping['notes'],
            "action_required": "Update other CSP data sources to use 'improved_function_new' instead of 'aws_checks_earlier'"
        }
        
        reference_data["mappings"].append(reference_entry)
    
    return reference_data

def save_reference_file(reference_data):
    """Save reference file"""
    
    output_path = '/Users/apple/Desktop/threat-engine/compliance/aws/difficult_mappings_reference_for_csp_update.json'
    
    with open(output_path, 'w') as f:
        json.dump(reference_data, f, indent=2, ensure_ascii=False)
    
    return output_path

def create_csv_reference(difficult_mappings, compliance_details):
    """Create CSV reference file for easy viewing"""
    
    csv_path = '/Users/apple/Desktop/threat-engine/compliance/aws/difficult_mappings_reference_for_csp_update.csv'
    
    with open(csv_path, 'w', newline='') as f:
        fieldnames = [
            'sequence',
            'original_function',
            'aws_checks_earlier',
            'improved_function_earlier',
            'improved_function_new',
            'matched_rule_id',
            'confidence',
            'compliance_ids',
            'notes'
        ]
        
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for mapping in difficult_mappings:
            writer.writerow({
                'sequence': mapping['sequence'],
                'original_function': mapping['original_function'],
                'aws_checks_earlier': mapping['aws_checks_earlier'],
                'improved_function_earlier': mapping['improved_function_earlier'],
                'improved_function_new': mapping['improved_function_new'],
                'matched_rule_id': mapping['matched_rule_id'],
                'confidence': mapping['confidence'],
                'compliance_ids': '; '.join(mapping['compliance_ids']),
                'notes': mapping['notes']
            })
    
    return csv_path

def print_summary(reference_data, json_path, csv_path):
    """Print summary"""
    
    print("\n" + "="*80)
    print("DIFFICULT MAPPINGS REFERENCE FILE CREATED")
    print("="*80)
    
    print(f"\n{'PURPOSE':-^80}")
    print(f"\n  {reference_data['metadata']['purpose']}")
    
    print(f"\n{'SUMMARY':-^80}")
    print(f"\n  Total mappings:                 {reference_data['metadata']['total_mappings']}")
    print(f"  Date created:                   {reference_data['metadata']['date_created']}")
    
    print(f"\n{'MAPPINGS OVERVIEW':-^80}")
    
    for mapping in reference_data['mappings']:
        print(f"\n  {mapping['sequence']}. {mapping['original_function']}")
        print(f"     Earlier: {mapping['improved_function_earlier']}")
        print(f"     New:     {mapping['improved_function_new']}")
        print(f"     Mapped:  {mapping['matched_rule_id']}")
        print(f"     Compliance: {len(mapping['compliance_details'])} frameworks")
    
    print(f"\n{'FILES CREATED':-^80}")
    print(f"\n  JSON: {json_path}")
    print(f"  CSV:  {csv_path}")
    
    print(f"\n{'NEXT STEPS':-^80}")
    print(f"\n  1. Use this reference to update other CSP data sources")
    print(f"  2. Replace 'aws_checks_earlier' with 'improved_function_new'")
    print(f"  3. Ensure consistency across all compliance frameworks")
    print(f"  4. Update Azure/GCP mappings if they reference these functions")
    
    print("\n" + "="*80)
    print()

def main():
    print("Extracting last 9 difficult mappings...")
    difficult_mappings = get_last_9_mappings()
    print(f"  ✓ Extracted {len(difficult_mappings)} mappings")
    
    print("\nLoading compliance details from CSV...")
    compliance_details = load_csv_data()
    print(f"  ✓ Loaded {len(compliance_details)} compliance requirements")
    
    print("\nCreating reference data structure...")
    reference_data = create_reference_file(difficult_mappings, compliance_details)
    print("  ✓ Reference data created")
    
    print("\nSaving JSON reference file...")
    json_path = save_reference_file(reference_data)
    print(f"  ✓ Saved: {json_path.split('/')[-1]}")
    
    print("\nCreating CSV reference file...")
    csv_path = create_csv_reference(difficult_mappings, compliance_details)
    print(f"  ✓ Saved: {csv_path.split('/')[-1]}")
    
    print_summary(reference_data, json_path, csv_path)

if __name__ == "__main__":
    main()

