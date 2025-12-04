#!/usr/bin/env python3
"""
Azure Expert Review - Correct service mappings based on actual Azure services

Issues Found:
1. Streaming services (Kinesis Firehose, Kafka) → AWS/other CSP services, not Azure
2. MLOps Monitoring → Should be Azure Machine Learning, not Monitor
3. Registry operations → Container Registry, not KeyVault or generic Security
4. Privacy/Breach detection → Microsoft Purview or Defender, not generic Security
5. Some resource names are AWS-specific (VPC, target groups)

"""

import csv
import json
from pathlib import Path
from collections import defaultdict

# Azure Expert Corrections
AZURE_EXPERT_CORRECTIONS = {
    # Streaming Services - Azure has Event Hubs, Stream Analytics, NOT Kinesis
    'streaming_stream_consumer': {
        'correct_service': 'event',  # Azure Event Hubs
        'correct_resource': 'event_hub_consumer',
        'reason': 'Azure Event Hubs for streaming, not generic streaming'
    },
    'streaming_firehose': {
        'correct_service': 'data',  # Azure Stream Analytics or Data Factory
        'correct_resource': 'stream_analytics',
        'reason': 'Azure Stream Analytics, not AWS Kinesis Firehose'
    },
    'streaming_video_stream': {
        'correct_service': 'data',  # Azure Media Services
        'correct_resource': 'media_stream',
        'reason': 'Azure Media Services for video streaming'
    },
    'streaming_stream': {
        'correct_service': 'event',
        'correct_resource': 'event_hub',
        'reason': 'Azure Event Hubs for event streaming'
    },
    'streaming_analytics_application': {
        'correct_service': 'data',  # Azure Stream Analytics
        'correct_resource': 'stream_analytics_job',
        'reason': 'Azure Stream Analytics service'
    },
    
    # MLOps - Should be Machine Learning, not Monitor
    'mlops_monitoring': {
        'correct_service': 'machine',  # Azure Machine Learning
        'correct_resource': 'ml_workspace',
        'reason': 'Azure Machine Learning Workspace, not Monitor'
    },
    
    # Container Registry - Not KeyVault
    'registry_replication_config': {
        'correct_service': 'containerregistry',
        'correct_resource': 'replication',
        'reason': 'Azure Container Registry replication'
    },
    'registry_repo': {
        'correct_service': 'containerregistry',
        'correct_resource': 'repository',
        'reason': 'Azure Container Registry repository'
    },
    
    # Privacy & Compliance - Microsoft Purview
    'privacy_rights': {
        'correct_service': 'purview',
        'correct_resource': 'data_policy',
        'reason': 'Microsoft Purview for data governance'
    },
    'privacy_masking': {
        'correct_service': 'purview',
        'correct_resource': 'data_masking',
        'reason': 'Microsoft Purview data masking'
    },
    'privacy_audit': {
        'correct_service': 'purview',
        'correct_resource': 'audit_log',
        'reason': 'Microsoft Purview audit logs'
    },
    'privacy_breach_detection': {
        'correct_service': 'purview',  # or defender
        'correct_resource': 'breach_detection',
        'reason': 'Microsoft Purview or Defender for breach detection'
    },
    
    # Network Resources - AWS-specific names need correction
    'network_vpc': {
        'correct_service': 'network',
        'correct_resource': 'virtual_network',  # Azure calls it VNet, not VPC
        'reason': 'Azure Virtual Network (VNet), not AWS VPC'
    },
    'network_target_group': {
        'correct_service': 'network',
        'correct_resource': 'backend_pool',  # Azure Load Balancer uses Backend Pools
        'reason': 'Azure Load Balancer Backend Pool, not AWS Target Group'
    },
    
    # Platform/API Gateway - Azure API Management
    'platform_api_endpoint': {
        'correct_service': 'api',
        'correct_resource': 'api_endpoint',
        'reason': 'Azure API Management'
    },
    'platform_api_key': {
        'correct_service': 'api',
        'correct_resource': 'subscription_key',  # Azure APIM uses Subscription Keys
        'reason': 'Azure API Management Subscription Key'
    },
    'platform_stage': {
        'correct_service': 'api',
        'correct_resource': 'api_version',  # Azure APIM uses versions, not stages
        'reason': 'Azure API Management Version (not AWS API Gateway Stage)'
    },
    'platform_authorizer': {
        'correct_service': 'api',
        'correct_resource': 'authorization_policy',
        'reason': 'Azure API Management Authorization Policy'
    },
    
    # Secrets Management
    'secrets_parameter': {
        'correct_service': 'keyvault',
        'correct_resource': 'secret',  # Not parameter, just secret
        'reason': 'Azure Key Vault Secret (not AWS Systems Manager Parameter)'
    },
    
    # Serverless - Azure Functions
    'serverless_version': {
        'correct_service': 'function',
        'correct_resource': 'function_version',
        'reason': 'Azure Functions, not generic serverless'
    },
    
    # Disaster Recovery - Azure Site Recovery
    'dr_source_server': {
        'correct_service': 'backup',  # or 'siterecovery'
        'correct_resource': 'protected_item',
        'reason': 'Azure Site Recovery protected item'
    },
    'dr_job': {
        'correct_service': 'backup',
        'correct_resource': 'backup_job',
        'reason': 'Azure Backup/Recovery job'
    },
    'dr_plan': {
        'correct_service': 'backup',
        'correct_resource': 'recovery_plan',
        'reason': 'Azure Site Recovery plan'
    },
    'dr_recovery_instance': {
        'correct_service': 'backup',
        'correct_resource': 'recovery_point',
        'reason': 'Azure recovery point'
    },
}

def apply_azure_expert_corrections(input_csv, output_csv):
    """Apply Azure expert corrections to the normalized CSV"""
    
    rows = []
    corrections_made = defaultdict(int)
    
    with open(input_csv, 'r') as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames) + ['azure_expert_corrected', 'correction_reason']
        
        for row in reader:
            resource = row['resource']
            current_service = row['suggested_service']
            normalized_id = row['normalized_rule_id']
            
            # Check if this resource needs correction
            if resource in AZURE_EXPERT_CORRECTIONS:
                correction = AZURE_EXPERT_CORRECTIONS[resource]
                corrected_service = correction['correct_service']
                corrected_resource = correction['correct_resource']
                reason = correction['reason']
                
                # Update the normalized rule ID
                parts = normalized_id.split('.')
                if len(parts) >= 4:
                    # azure.service.resource.check
                    parts[1] = corrected_service
                    parts[2] = corrected_resource
                    corrected_id = '.'.join(parts)
                    
                    row['normalized_rule_id'] = corrected_id
                    row['suggested_service'] = corrected_service
                    row['azure_expert_corrected'] = 'YES'
                    row['correction_reason'] = reason
                    
                    corrections_made[f"{current_service} → {corrected_service}"] += 1
                else:
                    row['azure_expert_corrected'] = 'NO'
                    row['correction_reason'] = ''
            else:
                row['azure_expert_corrected'] = 'NO'
                row['correction_reason'] = ''
            
            rows.append(row)
    
    # Write corrected CSV
    with open(output_csv, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    
    return corrections_made, rows


def generate_corrections_report(corrections_made, total_rows, output_file):
    """Generate report of Azure expert corrections"""
    
    report = []
    report.append("=" * 80)
    report.append(" AZURE EXPERT CORRECTIONS REPORT")
    report.append("=" * 80)
    report.append("")
    
    total_corrections = sum(corrections_made.values())
    
    report.append(f"Total rules reviewed:     {len(total_rows)}")
    report.append(f"Rules corrected:          {total_corrections}")
    report.append(f"Rules unchanged:          {len(total_rows) - total_corrections}")
    report.append("")
    
    report.append("Corrections by service change:")
    for change, count in sorted(corrections_made.items(), key=lambda x: x[1], reverse=True):
        report.append(f"  {change:40s}: {count:3d} rules")
    
    report.append("")
    report.append("=" * 80)
    report.append(" KEY CORRECTIONS MADE")
    report.append("=" * 80)
    report.append("")
    
    report.append("1. Streaming Services:")
    report.append("   AWS Kinesis Firehose → Azure Stream Analytics/Event Hubs")
    report.append("   Generic 'streaming' → Azure Event Hubs")
    report.append("")
    
    report.append("2. MLOps Monitoring:")
    report.append("   Monitor service → Azure Machine Learning service")
    report.append("   MLOps is part of ML Workspace, not general monitoring")
    report.append("")
    
    report.append("3. Container Registry:")
    report.append("   KeyVault/Security → Azure Container Registry")
    report.append("   Registry operations belong to containerregistry service")
    report.append("")
    
    report.append("4. Privacy & Compliance:")
    report.append("   Generic Security → Microsoft Purview")
    report.append("   Data governance is Purview's domain")
    report.append("")
    
    report.append("5. AWS-Specific Names Corrected:")
    report.append("   VPC → Virtual Network (VNet)")
    report.append("   Target Group → Backend Pool")
    report.append("   API Stage → API Version")
    report.append("   Parameter → Secret")
    report.append("")
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    return '\n'.join(report)


def main():
    print("=" * 80)
    print(" AZURE EXPERT REVIEW & CORRECTIONS")
    print("=" * 80)
    
    script_dir = Path(__file__).parent
    input_csv = script_dir / 'redistribution_mapping_normalized.csv'
    output_csv = script_dir / 'redistribution_mapping_azure_expert.csv'
    report_file = script_dir / 'azure_expert_corrections_report.txt'
    
    if not input_csv.exists():
        print(f"❌ Error: {input_csv} not found")
        return 1
    
    print(f"\n📄 Reviewing: {input_csv}")
    print("   Applying Azure expert corrections...")
    
    # Apply corrections
    corrections_made, rows = apply_azure_expert_corrections(input_csv, output_csv)
    
    # Generate report
    report = generate_corrections_report(corrections_made, rows, report_file)
    
    print(report)
    
    print(f"\n✅ Files created:")
    print(f"  • {output_csv}")
    print(f"  • {report_file}")
    
    print("\n" + "=" * 80)
    print(" AZURE EXPERT REVIEW COMPLETE")
    print("=" * 80)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

